#include "aws_secret.hpp"
#include "aws_client.hpp"
#include "redshift/redshift_utils.hpp"

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/auth/SSOCredentialsProvider.h>
#include <aws/core/auth/STSCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/config/AWSConfigFileProfileConfigLoader.h>
#include <aws/core/config/AWSProfileConfigLoaderBase.h>
#include <aws/identity-management/auth/STSAssumeRoleCredentialsProvider.h>
#include <aws/rds/RDSClient.h>
#include <aws/sts/STSClient.h>

#include <sys/stat.h>

namespace duckdb {

//! We use a global here to store the path that is selected on the ICAPI::InitializeCurl call
static string SELECTED_CURL_CERT_PATH;

// we statically compile in libcurl, which means the cert file location of the build machine is the
// place curl will look. But not every distro has this file in the same location, so we search a
// number of common locations and use the first one we find.
static string certFileLocations[] = {
    // Arch, Debian-based, Gentoo
    "/etc/ssl/certs/ca-certificates.crt",
    // Red Hat 7 based
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    // Red hat 6 based
    "/etc/pki/tls/certs/ca-bundle.crt",
    // OpenSUSE
    "/etc/ssl/ca-bundle.pem",
    // Alpine
    "/etc/ssl/cert.pem"};

// enumerate create secret VALIDATION options without making a formal enum
static struct {
	const set<string> options = {"exists", "none"};
	const string default_ = "exists";
} CreateAwsSecretValidation;

//! See aws_client.hpp for rationale.
Aws::Client::ClientConfiguration BuildClientConfigWithCa() {
	Aws::Client::ClientConfiguration cfg;
	if (!SELECTED_CURL_CERT_PATH.empty()) {
		cfg.caFile = SELECTED_CURL_CERT_PATH;
	}
	return cfg;
}

//! Parse and set the remaining options
static void ParseCoreS3Config(CreateSecretInput &input, KeyValueSecret &secret) {
	vector<string> options = {"key_id",
	                          "secret",
	                          "region",
	                          "endpoint",
	                          "session_token",
	                          "url_style",
	                          "use_ssl",
	                          "s3_url_compatibility_mode",
	                          "http_proxy",
	                          "http_proxy_username",
	                          "http_proxy_password"};
	for (const auto &val : options) {
		auto set_region_param = input.options.find(val);
		if (set_region_param != input.options.end()) {
			secret.secret_map[Identifier(val)] = set_region_param->second;
		}
	}
}

//! This constructs the base S3 Type secret
static unique_ptr<KeyValueSecret> ConstructBaseS3Secret(vector<string> &prefix_paths_p, const Identifier &type,
                                                        const Identifier &provider, const Identifier &name) {
	auto return_value = make_uniq<KeyValueSecret>(prefix_paths_p, type, provider, name);
	return_value->redact_keys = {"secret", "session_token"};
	return return_value;
}

static Aws::Config::Profile GetProfile(const string &profile_name, const bool require_profile) {
	Aws::Config::Profile selected_profile;
	// get file path where aws config is stored.
	// comes from AWS_CONFIG_FILE
	auto config_file_path = Aws::Auth::GetConfigProfileFilename();
	// get the profile from within that file
	Aws::Map<Aws::String, Aws::Config::Profile> profiles;
	Aws::Config::AWSConfigFileProfileConfigLoader loader(config_file_path, true);
	if (loader.Load()) {
		profiles = loader.GetProfiles();
		for (const auto &entry : profiles) {
			const Aws::String &profileName = entry.first;
			if (profileName == profile_name) {
				selected_profile = entry.second;
				return selected_profile;
			}
		}
	}
	if (require_profile) {
		throw InvalidConfigurationException("Secret Validation Failure: no profile '%s' found in config file %s",
		                                    profile_name, config_file_path);
	}
	return selected_profile; // empty profile
}

//! Generate a custom credential provider chain for authentication
class DuckDBCustomAWSCredentialsProviderChain : public Aws::Auth::AWSCredentialsProviderChain {
public:
	explicit DuckDBCustomAWSCredentialsProviderChain(const string &credential_chain, const bool require_credentials,
	                                                 const string &profile = "", const string &assume_role_arn = "",
	                                                 const string &external_id = "",
	                                                 const string &web_identity_token_file = "",
	                                                 const string &session_name = "") {
		auto chain_list = StringUtil::Split(credential_chain, ';');

		for (const auto &item : chain_list) {
			// could not find the profile in the name
			if (item == "sts") {
				// STS chain in Create Secret statement.
				Aws::Config::Profile aws_profile;
				if (assume_role_arn.empty()) {
					throw InvalidConfigurationException(
					    "Chain value 'STS' is only supported with an ASSUME_ROLE_ARN value. "
					    "If the selected profile uses STS, add \"CHAIN 'config'\"");
				}
				aws_profile.SetName(profile);
				aws_profile.SetRoleArn(assume_role_arn);
				aws_profile.SetExternalId(external_id);
				AddSTSProvider(aws_profile);
			} else if (item == "sso") {
				// Pass an explicit ClientConfiguration so the SSO portal HTTPS call
				// uses the detected CA path. See BuildClientConfigWithCa() comment.
				auto sso_config = Aws::MakeShared<Aws::Client::ClientConfiguration>("DuckDBAwsSSO");
				if (!SELECTED_CURL_CERT_PATH.empty()) {
					sso_config->caFile = SELECTED_CURL_CERT_PATH;
				}
				if (profile.empty()) {
					AddProvider(std::make_shared<Aws::Auth::SSOCredentialsProvider>(Aws::String(), sso_config));
				} else {
					AddProvider(std::make_shared<Aws::Auth::SSOCredentialsProvider>(profile.c_str(), sso_config));
				}
			} else if (item == "env") {
				AddProvider(std::make_shared<Aws::Auth::EnvironmentAWSCredentialsProvider>());
			} else if (item == "instance") {
				/* Credentials provider implementation that loads credentials from the Amazon EC2 Instance Metadata
				 * Service. */
				AddProvider(std::make_shared<Aws::Auth::InstanceProfileCredentialsProvider>());
			} else if (item == "web_identity") {
				Aws::Client::ClientConfiguration::CredentialProviderConfiguration config;
				if (!assume_role_arn.empty()) {
					config.stsCredentialsProviderConfig.roleArn = assume_role_arn;
				}
				if (!web_identity_token_file.empty()) {
					config.stsCredentialsProviderConfig.tokenFilePath = web_identity_token_file;
				}
				if (!session_name.empty()) {
					config.stsCredentialsProviderConfig.sessionName = session_name;
				}
				AddProvider(std::make_shared<Aws::Auth::STSAssumeRoleWebIdentityCredentialsProvider>(config));
			} else if (item == "process") {
				if (profile.empty()) {
					AddProvider(std::make_shared<Aws::Auth::ProcessCredentialsProvider>());
				} else {
					AddProvider(std::make_shared<Aws::Auth::ProcessCredentialsProvider>(profile.c_str()));
				}
			} else if (item == "config") {
				if (profile.empty()) {
					AddProvider(std::make_shared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>());
				} else {
					AddConfigProvider(require_credentials, profile, assume_role_arn, external_id);
				}
			} else {
				throw InvalidInputException("Unknown provider found while parsing AWS credential chain string: '%s'",
				                            item);
			}
		}
	}

	void AddConfigProvider(const bool require_credentials, const string &profile_name, const string &assume_role_arn,
	                       const string &external_id) {
		auto profile = GetProfile(profile_name, require_credentials);
		if (!profile.GetRoleArn().empty() && !assume_role_arn.empty()) {
			throw InvalidInputException(
			    "Ambiguous role arn. Role_arn '%s' defined in profile '%s'. Role_arn '%s' defined in secret statement",
			    profile.GetRoleArn(), profile_name, assume_role_arn);
		}
		if (!profile.GetExternalId().empty() && !external_id.empty()) {
			throw InvalidInputException(
			    "Ambiguous external id. external_id '%s' defined in profile '%s'. external_id '%s' "
			    "defined in secret statement",
			    profile.GetExternalId(), profile_name, external_id);
		}
		if (profile.GetRoleArn().empty() && !assume_role_arn.empty()) {
			profile.SetRoleArn(assume_role_arn);
		}
		if (profile.GetExternalId().empty() && !external_id.empty()) {
			profile.SetExternalId(external_id);
		}
		if (!profile.GetRoleArn().empty()) {
			AddSTSProvider(profile);
		} else {
			AddProvider(std::make_shared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>(profile_name.c_str()));
		}
	}

	void AddSTSProvider(const Aws::Config::Profile &profile) {
		string assume_role_arn = profile.GetRoleArn();
		string external_id = profile.GetExternalId();
		Aws::Client::ClientConfiguration clientConfig = BuildClientConfigWithCa();
		auto sts_client = std::make_shared<Aws::STS::STSClient>(clientConfig);
		if (!external_id.empty()) {
			AddProvider(std::make_shared<Aws::Auth::STSAssumeRoleCredentialsProvider>(
			    assume_role_arn, Aws::String(), external_id, Aws::Auth::DEFAULT_CREDS_LOAD_FREQ_SECONDS, sts_client));
		} else {
			AddProvider(std::make_shared<Aws::Auth::STSAssumeRoleCredentialsProvider>(
			    assume_role_arn, Aws::String(), Aws::String(), Aws::Auth::DEFAULT_CREDS_LOAD_FREQ_SECONDS, sts_client));
		}
	}
};

string TryGetStringParam(CreateSecretInput &input, const string &param_name) {
	auto param_lookup = input.options.find(param_name);
	if (param_lookup != input.options.end()) {
		return param_lookup->second.ToString();
	} else {
		return "";
	}
}

static string ConstructErrorMessage(string chain, string profile, string assume_role, string external_id,
                                    string web_identity_token_file, string session_name) {
	string verb = "create";
	// these chains "generate" new aws keys. See their documentation in the header file
	// https://github.com/aws/aws-sdk-cpp/blob/main/src/aws-cpp-sdk-core/include/aws/core/auth/AWSCredentialsProvider.h
	// if a roll is assumed, secrets are also "generated"
	if (chain == "sts" || chain == "sso" || chain == "instance" || chain == "process" || chain == "web_identity" ||
	    !assume_role.empty()) {
		verb = "generate";
	}
	string prefix = StringUtil::Format("Secret Validation Failure: during `%s` using the following:\n", verb);
	prefix = profile.empty() ? prefix : prefix + StringUtil::Format("Profile: '%s'\n", profile);
	prefix = chain.empty() ? prefix : prefix + StringUtil::Format("Credential Chain: '%s'\n", chain);
	prefix = assume_role.empty() ? prefix : prefix + StringUtil::Format("Role-arn: '%s'\n", assume_role);
	prefix = external_id.empty() ? prefix : prefix + StringUtil::Format("External-id: '%s'\n", external_id);
	prefix = web_identity_token_file.empty()
	             ? prefix
	             : prefix + StringUtil::Format("Web Identity Token File: '%s'\n", web_identity_token_file);
	prefix = session_name.empty() ? prefix : prefix + StringUtil::Format("Session Name: '%s'\n", session_name);
	return prefix;
}

static string GenerateRDSSecretToken(std::shared_ptr<DuckDBCustomAWSCredentialsProviderChain> &provider,
                                     const string &user, const string &host, const string &port, const string &region) {
	Aws::Client::ClientConfiguration config = BuildClientConfigWithCa();
	config.region = region;
	Aws::RDS::RDSClient rds_client(provider, config);

	// https://github.com/aws/aws-sdk-cpp/issues/861#issuecomment-386643571
	// Aws::String token = rdsClient.GenerateConnectAuthToken(hostname.c_str(), aws_region.c_str(),
	// static_cast<unsigned>(port_int), username.c_str());

	uint64_t expiration_seconds = 900; // 15 min, this value is fixed, also used on consumer side
	string host_and_port = host + ":" + port;
	string host_and_port_with_prefix = "http://" + host_and_port;
	string host_and_port_with_suffix = host_and_port + "/";
	Aws::Http::URI uri(host_and_port_with_prefix.c_str());
	uri.AddQueryStringParameter("Action", "connect");
	uri.AddQueryStringParameter("DBUser", user.c_str());
	auto token = rds_client.GeneratePresignedUrl(uri, Aws::Http::HttpMethod::HTTP_GET, region.c_str(), "rds-db",
	                                             static_cast<long long>(expiration_seconds));
	Aws::Utils::StringUtils::Replace(token, host_and_port_with_prefix.c_str(), host_and_port_with_suffix.c_str());

	return string(token.c_str());
}

static unique_ptr<BaseSecret>
CreateRDSSecretWithProvider(std::shared_ptr<DuckDBCustomAWSCredentialsProviderChain> &provider,
                            CreateSecretInput &input, const string &region) {
	string user = TryGetStringParam(input, "rds_user");
	string host = TryGetStringParam(input, "rds_host");
	string port = TryGetStringParam(input, "rds_port");
	if (user.empty() || host.empty() || port.empty() || region.empty()) {
		throw InvalidInputException(
		    "Invalid RDS secret parameters, 'RDS_USER', 'RDS_HOST', 'RDS_PORT' and 'REGION' options must be specified");
	}

	vector<string> scope;
	auto result = ConstructBaseS3Secret(scope, input.type, input.provider, input.name);

	string template_secret_name = TryGetStringParam(input, "rds_template_secret_name");

	// When user creates a SECRET of type "rds", resulting secret is a "template"
	// that is used by duckdb-postgres to generate actual token. To effectively call
	// 'CreateAWSSecretFromCredentialChain' duckdb-postgres recreated the secret with
	// 'rds_template_secret_name' specified and reads its 'secret_token' field.
	// To allow it to do so, we put all the input fields into the resulting "template"
	// secret.
	// TODO: RDS token refresh mechanics should be improved
	bool generate_secret_token = !template_secret_name.empty();

	if (!generate_secret_token) {
		for (auto &en : input.options) {
			result->secret_map[Identifier(en.first)] = en.second;
		}
		return result;
	}

	// "rds_template_secret_name" was specified when creting the secret,
	// so we are generating and returning actual token in "session_token" field
	string token = GenerateRDSSecretToken(provider, user, host, port, region);

	// We do not throwing here if the resulting token was generated incorrectly,
	// instead the consumer must do appropriate checks and report the error without
	// including the whole input `CREATE SECRET` query into the error message.
	result->secret_map["session_token"] = Value(token);
	return result;
}

//! This is the actual callback function
static unique_ptr<BaseSecret> CreateAWSSecretFromCredentialChain(ClientContext &context, CreateSecretInput &input) {
	Aws::Auth::AWSCredentials credentials;

	string profile = TryGetStringParam(input, "profile");
	string assume_role = TryGetStringParam(input, "assume_role_arn");
	string external_id = TryGetStringParam(input, "external_id");
	string chain = TryGetStringParam(input, "chain");
	string web_identity_token_file = TryGetStringParam(input, "web_identity_token_file");
	string session_name = TryGetStringParam(input, "session_name");
	string validation = StringUtil::Lower(TryGetStringParam(input, "validation"));

	if (!assume_role.empty() && chain.empty()) {
		throw InvalidConfigurationException("Must pass CHAIN value when passing ASSUME_ROLE_ARN");
	}

	bool require_credentials = true; // aka default != "none"
	if (!validation.empty()) {
		if (CreateAwsSecretValidation.options.find(validation) == CreateAwsSecretValidation.options.end()) {
			throw InvalidInputException("Unknown AWS validation mode: `%s`", validation);
		}
		if (validation == "none") {
			require_credentials = false;
		}
	}

	// Region MUST be set according to the SDK https://docs.aws.amazon.com/sdkref/latest/guide/feature-region.html
	string region;
	// Get region from secret options
	auto region_param = input.options.find("region");
	if (region_param != input.options.end() && !region_param->second.ToString().empty()) {
		region = region_param->second.ToString();
	}

	// or from DuckDB settings (SET s3_region='us-east-1')
	if (region.empty()) {
		Value s3_region_setting;
		if (context.TryGetCurrentSetting("s3_region", s3_region_setting)) {
			region = s3_region_setting.ToString();
		}
	}

	// or from environment variables
	if (region.empty()) {
		if (const char *env = getenv("AWS_REGION")) {
			region = env;
		} else if (const char *env = getenv("AWS_DEFAULT_REGION")) {
			region = env;
		}
	}

	// or from AWS config profile
	if (region.empty()) {
		string profile_to_lookup = profile.empty() ? "default" : profile;
		auto aws_profile = GetProfile(profile_to_lookup, false);
		region = aws_profile.GetRegion();
	}

	if (input.type == "rds") {
		if (chain.empty()) {
			throw InvalidConfigurationException("Invalid RDS secret parameters, 'CHAIN' option must be specified");
		}
		auto provider = Aws::MakeShared<DuckDBCustomAWSCredentialsProviderChain>("rds", chain, require_credentials,
		                                                                         profile, assume_role, external_id,
		                                                                         web_identity_token_file, session_name);
		return CreateRDSSecretWithProvider(provider, input, region);
	}

	if (input.type == "redshift") {
		if (chain.empty()) {
			throw InvalidConfigurationException("Invalid Redshift secret parameters, 'CHAIN' option must be specified");
		}
		auto provider = Aws::MakeShared<DuckDBCustomAWSCredentialsProviderChain>(
		    "redshift", chain, require_credentials, profile, assume_role, external_id, web_identity_token_file,
		    session_name);
		return Redshift::CreateSecret(provider, input, region);
	}

	if (region.empty()) {
		DUCKDB_LOG_WARNING(
		    context,
		    "Set region explicitly using REGION 'us-east-1' in your CREATE SECRET statement, adding a region to your "
		    "profile in ~/.aws/config or configure the AWS_REGION or AWS_DEFAULT_REGION environment variables.")
	}

	if (!chain.empty()) {
		DuckDBCustomAWSCredentialsProviderChain provider(chain, require_credentials, profile, assume_role, external_id,
		                                                 web_identity_token_file, session_name);
		credentials = provider.GetAWSCredentials();
	} else {
		if (input.options.find("profile") != input.options.end()) {
			Aws::Auth::ProfileConfigFileAWSCredentialsProvider provider(profile.c_str());
			credentials = provider.GetAWSCredentials();
		} else {
			Aws::Auth::DefaultAWSCredentialsProviderChain provider;
			credentials = provider.GetAWSCredentials();
		}
	}

	if (credentials.IsEmpty() && chain.empty()) {
		// handle case where requested profile uses STS, but no chain was declared. In this case,
		// The aws-spp-sdk will not pick up credentials via sts. Unclear why.
		// Instead we need to find the profile and grab the arn&external_id using "config" chain.
		// Then we create the credentials using an sts provider. This (should) be the default behavior of the SDK
		// see https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/credproviders.html
		chain = "config";
		DuckDBCustomAWSCredentialsProviderChain provider(chain, require_credentials, profile, assume_role, external_id);
		credentials = provider.GetAWSCredentials();
	}

	if (credentials.IsEmpty() && require_credentials) {
		throw InvalidConfigurationException(
		    ConstructErrorMessage(chain, profile, assume_role, external_id, web_identity_token_file, session_name));
	}

	auto scope = input.scope;
	if (scope.empty()) {
		if (input.type == "s3") {
			scope.push_back("s3://");
			scope.push_back("s3n://");
			scope.push_back("s3a://");
		} else if (input.type == "r2") {
			scope.push_back("r2://");
		} else if (input.type == "gcs") {
			scope.push_back("gcs://");
			scope.push_back("gs://");
		} else if (input.type == "aws") {
			scope.push_back("");
		} else {
			throw InternalException("Unknown secret type found in aws extension: '%s'", input.type);
		}
	}

	auto result = ConstructBaseS3Secret(scope, input.type, input.provider, input.name);

	if (!region.empty()) {
		result->secret_map["region"] = region;
	}

	// Only auto is supported
	string refresh = TryGetStringParam(input, "refresh");

	// We have sneaked in this special handling where if you set the STS chain, you automatically enable refresh
	// TODO: remove this once refresh is set to auto by default for all credential_chain provider created secrets.
	if ((chain == "sts" || chain == "web_identity") && refresh.empty()) {
		refresh = "auto";
	}

	if (refresh == "auto") {
		child_list_t<Value> struct_fields;
		for (const auto &named_param : input.options) {
			auto lower_name = StringUtil::Lower(named_param.first);
			struct_fields.emplace_back(lower_name, named_param.second);
		}
		result->secret_map["refresh_info"] = Value::STRUCT(struct_fields);
	}

	if (!credentials.IsExpiredOrEmpty()) {
		result->secret_map["key_id"] = Value(credentials.GetAWSAccessKeyId());
		result->secret_map["secret"] = Value(credentials.GetAWSSecretKey());
		result->secret_map["session_token"] = Value(credentials.GetSessionToken());

		// Store credential expiration as epoch seconds so consumers (e.g., duckdb-iceberg)
		// can refresh proactively at ~80% TTL instead of guessing with a fixed timer.
		auto expiration = credentials.GetExpiration();
		if (expiration != Aws::Utils::DateTime()) {
			result->secret_map["expiration_epoch"] = Value::BIGINT(expiration.Seconds());
		}
	}

	ParseCoreS3Config(input, *result);

	// Set endpoint defaults TODO: move to consumer side of secret
	auto endpoint_lu = result->secret_map.find("endpoint");
	if (endpoint_lu == result->secret_map.end() || endpoint_lu->second.ToString().empty()) {
		if (input.type == "s3") {
			result->secret_map["endpoint"] = "s3.amazonaws.com";
		} else if (input.type == "r2") {
			if (input.options.find("account_id") != input.options.end()) {
				result->secret_map["endpoint"] = input.options["account_id"].ToString() + ".r2.cloudflarestorage.com";
			}
		} else if (input.type == "gcs") {
			result->secret_map["endpoint"] = "storage.googleapis.com";
		} else if (input.type == "aws") {
			// this is a nop?
		} else {
			throw InternalException("Unknown secret type found in httpfs extension: '%s'", input.type);
		}
	}

	// Set endpoint defaults TODO: move to consumer side of secret
	auto url_style_lu = result->secret_map.find("url_style");
	if (url_style_lu == result->secret_map.end() || url_style_lu->second.ToString().empty()) {
		if (input.type == "gcs" || input.type == "r2") {
			result->secret_map["url_style"] = "path";
		}
	}

	return std::move(result);
}

std::shared_ptr<Aws::Auth::AWSCredentialsProvider>
BuildAwsCredentialsProvider(const std::string &chain, bool require_credentials, const std::string &profile,
                            const std::string &assume_role_arn, const std::string &external_id,
                            const std::string &web_identity_token_file, const std::string &session_name) {
	if (chain.empty()) {
		if (!profile.empty()) {
			return Aws::MakeShared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>("DuckDBAwsProfile",
			                                                                            profile.c_str());
		}
		return Aws::MakeShared<Aws::Auth::DefaultAWSCredentialsProviderChain>("DuckDBAwsDefault");
	}
	return Aws::MakeShared<DuckDBCustomAWSCredentialsProviderChain>("DuckDBCustomChain", chain, require_credentials,
	                                                                 profile, assume_role_arn, external_id,
	                                                                 web_identity_token_file, session_name);
}

void CreateAwsSecretFunctions::InitializeCurlCertificates(DatabaseInstance &db) {
	for (string &caFile : certFileLocations) {
		struct stat buf;
		if (stat(caFile.c_str(), &buf) == 0) {
			SELECTED_CURL_CERT_PATH = caFile;
			DUCKDB_LOG_DEBUG(db, "aws.CaCertificateDetection: CA path: %s", SELECTED_CURL_CERT_PATH);
			return;
		}
	}
}

void CreateAwsSecretFunctions::Register(ExtensionLoader &loader) {
	// The s3/r2/gcs/aws secret types are registered by httpfs, and rds by the postgres
	// extension. 'redshift' is owned by this extension, so we must register the type
	// ourselves; without this CREATE SECRET fails with "Secret type 'redshift' not found".
	Redshift::RegisterSecret(loader);

	vector<string> types = {"s3", "r2", "gcs", "aws", "rds", "redshift"};

	for (const auto &type : types) {
		// Register the credential_chain secret provider
		CreateSecretFunction cred_chain_function = {type, "credential_chain", CreateAWSSecretFromCredentialChain};

		// Params for adding / overriding settings to the automatically fetched ones
		cred_chain_function.named_parameters["key_id"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["secret"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["region"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["session_token"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["endpoint"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["url_style"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["use_ssl"] = LogicalType::BOOLEAN;
		cred_chain_function.named_parameters["url_compatibility_mode"] = LogicalType::BOOLEAN;

		cred_chain_function.named_parameters["assume_role_arn"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["external_id"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["web_identity_token_file"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["session_name"] = LogicalType::VARCHAR;

		cred_chain_function.named_parameters["http_proxy"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["http_proxy_username"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["http_proxy_password"] = LogicalType::VARCHAR;

		cred_chain_function.named_parameters["refresh"] = LogicalType::VARCHAR;

		if (type == "r2") {
			cred_chain_function.named_parameters["account_id"] = LogicalType::VARCHAR;
		}

		if (type == "rds") {
			cred_chain_function.named_parameters["rds_user"] = LogicalType::VARCHAR;
			cred_chain_function.named_parameters["rds_host"] = LogicalType::VARCHAR;
			cred_chain_function.named_parameters["rds_port"] = LogicalType::VARCHAR;
			cred_chain_function.named_parameters["rds_template_secret_name"] = LogicalType::VARCHAR;
		}

		if (type == "redshift") {
			Redshift::AddNamedParameters(cred_chain_function);
		}

		// Param for configuring the chain that is used
		cred_chain_function.named_parameters["chain"] = LogicalType::VARCHAR;

		// Params for configuring the credential loading
		cred_chain_function.named_parameters["profile"] = LogicalType::VARCHAR;
		cred_chain_function.named_parameters["validation"] = LogicalType::VARCHAR;

		loader.RegisterFunction(cred_chain_function);
	}
}

} // namespace duckdb
