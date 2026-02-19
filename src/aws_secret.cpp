#include "aws_secret.hpp"

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
    // RedHat 7 based
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    // Redhat 6 based
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

//! Parse and set the remaining options
static void ParseCoreS3Config(CreateSecretInput &input, KeyValueSecret &secret) {
	vector<string> options = {"key_id",   "secret",        "region",
	                          "endpoint", "session_token", "url_style",
	                          "use_ssl",  "s3_url_compatibility_mode"};
	for (const auto &val : options) {
		auto set_region_param = input.options.find(val);
		if (set_region_param != input.options.end()) {
			secret.secret_map[val] = set_region_param->second;
		}
	}
}

//! This constructs the base S3 Type secret
static unique_ptr<KeyValueSecret> ConstructBaseS3Secret(vector<string> &prefix_paths_p, string &type, string &provider,
                                                        string &name) {
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
	                                                 const string &external_id = "") {
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
				if (profile.empty()) {
					AddProvider(std::make_shared<Aws::Auth::SSOCredentialsProvider>());
				} else {
					AddProvider(std::make_shared<Aws::Auth::SSOCredentialsProvider>(profile.c_str()));
				}
			} else if (item == "env") {
				AddProvider(std::make_shared<Aws::Auth::EnvironmentAWSCredentialsProvider>());
			} else if (item == "instance") {
				/* Credentials provider implementation that loads credentials from the Amazon EC2 Instance Metadata
				 * Service. */
				AddProvider(std::make_shared<Aws::Auth::InstanceProfileCredentialsProvider>());
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
		Aws::Client::ClientConfiguration clientConfig;
		if (!SELECTED_CURL_CERT_PATH.empty()) {
			clientConfig.caFile = SELECTED_CURL_CERT_PATH; // Set the CA file
		}
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

static string TryGetStringParam(CreateSecretInput &input, const string &param_name) {
	auto param_lookup = input.options.find(param_name);
	if (param_lookup != input.options.end()) {
		return param_lookup->second.ToString();
	} else {
		return "";
	}
}

static string ConstructErrorMessage(string chain, string profile, string assume_role, string external_id) {
	string verb = "create";
	// these chains "generate" new aws keys. See their documentation in the header file
	// https://github.com/aws/aws-sdk-cpp/blob/main/src/aws-cpp-sdk-core/include/aws/core/auth/AWSCredentialsProvider.h
	// if a roll is assumed, secrets are also "generated"
	if (chain == "sts" || chain == "sso" || chain == "instance" || chain == "process" || !assume_role.empty()) {
		verb = "generate";
	}
	string prefix = StringUtil::Format("Secret Validation Failure: during `%s` using the following:\n", verb);
	prefix = profile.empty() ? prefix : prefix + StringUtil::Format("Profile: '%s'\n", profile);
	prefix = chain.empty() ? prefix : prefix + StringUtil::Format("Credential Chain: '%s'\n", chain);
	prefix = assume_role.empty() ? prefix : prefix + StringUtil::Format("Role-arn: '%s'\n", assume_role);
	prefix = external_id.empty() ? prefix : prefix + StringUtil::Format("External-id: '%s'\n", external_id);
	return prefix;
}

//! This is the actual callback function
static unique_ptr<BaseSecret> CreateAWSSecretFromCredentialChain(ClientContext &context, CreateSecretInput &input) {
	Aws::Auth::AWSCredentials credentials;

	string profile = TryGetStringParam(input, "profile");
	string assume_role = TryGetStringParam(input, "assume_role_arn");
	string external_id = TryGetStringParam(input, "external_id");
	string chain = TryGetStringParam(input, "chain");
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

	if (!chain.empty()) {
		DuckDBCustomAWSCredentialsProviderChain provider(chain, require_credentials, profile, assume_role, external_id);
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
		throw InvalidConfigurationException(ConstructErrorMessage(chain, profile, assume_role, external_id));
	}

	//! If the profile is set we specify a specific profile
	auto s3_config = Aws::Client::ClientConfiguration(profile.c_str());
	auto region = s3_config.region;

	// TODO: We would also like to get the endpoint here, but it's currently not supported byq the AWS SDK:
	// 		 https://github.com/aws/aws-sdk-cpp/issues/2587

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
	if (chain == "sts" && refresh.empty()) {
		refresh = "auto";
	}

	if (refresh == "auto") {
		child_list_t<Value> struct_fields;
		for (const auto &named_param : input.options) {
			auto lower_name = StringUtil::Lower(named_param.first);
			struct_fields.push_back({lower_name, named_param.second});
		}
		result->secret_map["refresh_info"] = Value::STRUCT(struct_fields);
	}

	if (!credentials.IsExpiredOrEmpty()) {
		result->secret_map["key_id"] = Value(credentials.GetAWSAccessKeyId());
		result->secret_map["secret"] = Value(credentials.GetAWSSecretKey());
		result->secret_map["session_token"] = Value(credentials.GetSessionToken());
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
	vector<string> types = {"s3", "r2", "gcs", "aws"};

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

		cred_chain_function.named_parameters["refresh"] = LogicalType::VARCHAR;

		if (type == "r2") {
			cred_chain_function.named_parameters["account_id"] = LogicalType::VARCHAR;
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
