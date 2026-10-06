#include "aws_secret.hpp"
#include "aws_client.hpp"
#include "utils/utils.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/identifier.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/unique_ptr.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret.hpp"

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/auth/GeneralHTTPCredentialsProvider.h>
#include <aws/core/auth/SSOCredentialsProvider.h>
#include <aws/core/auth/STSCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/config/AWSConfigFileProfileConfigLoader.h>
#include <aws/core/config/AWSProfileConfig.h>
#include <aws/core/config/AWSProfileConfigLoaderBase.h>
#include <aws/core/utils/memory/stl/AWSAllocator.h>
#include <aws/core/utils/memory/stl/AWSMap.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/identity-management/auth/STSAssumeRoleCredentialsProvider.h>
#include <aws/rds/RDSClient.h>
#include <aws/sts/STSClient.h>

#include <memory>
#include <string>
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

//! See aws_client.hpp for rationale.
Aws::Client::ClientConfiguration BuildClientConfigWithCa() {
	Aws::Client::ClientConfiguration cfg;
	if (!SELECTED_CURL_CERT_PATH.empty()) {
		cfg.caFile = SELECTED_CURL_CERT_PATH;
	}
	return cfg;
}

namespace {

//===--------------------------------------------------------------------===//
// Configuration
//===--------------------------------------------------------------------===//

using AwsProvider = std::shared_ptr<Aws::Auth::AWSCredentialsProvider>;

struct AwsOptionDefinition {
	const char *name;
	LogicalType type;
	bool store_in_secret;
	bool include_in_refresh;
	const char *only_for_type;
	bool redact;
};

struct AwsCredentialOptions {
	string profile_name;
	bool profile_provided;
	string assume_role;
	string external_id;
	string credential_chain;
	string web_identity_token_file;
	string session_name;
	bool require_credentials;
};

struct R2SecretOptions {
	string account_id;
	bool account_id_provided;
};

struct RdsSecretOptions {
	string user;
	string host;
	string port;
	string template_secret_name;
};

struct ParsedAwsSecret {
	Identifier name;
	Identifier type;
	vector<string> scope;
	AwsCredentialOptions credentials;
	R2SecretOptions r2;
	RdsSecretOptions rds;
	string refresh;
};

struct AwsCredentialResult {
	Aws::Auth::AWSCredentials credentials;
	string chain;
	bool assumed_role;
};

constexpr const char *CREDENTIAL_CHAIN_PROVIDER = "credential_chain";

// The s3/r2/gcs/aws secret types are registered by httpfs, and rds by the postgres extension.
// Redshift has no secret type of its own: `ATTACH (TYPE redshift)` reads an 'aws' or 's3'
// secret, since all it needs is an AWS identity. See redshift_storage.cpp.
constexpr const char *SECRET_TYPES[] = {"s3", "r2", "gcs", "aws", "rds"};

const AwsOptionDefinition AWS_OPTION_DEFINITIONS[] = {
    {"key_id", LogicalType::VARCHAR, true, false, nullptr, false},
    {"secret", LogicalType::VARCHAR, true, false, nullptr, true},
    {"session_token", LogicalType::VARCHAR, true, false, nullptr, true},
    {"region", LogicalType::VARCHAR, true, true, nullptr, false},
    {"endpoint", LogicalType::VARCHAR, true, true, nullptr, false},
    {"url_style", LogicalType::VARCHAR, true, true, nullptr, false},
    {"use_ssl", LogicalType::BOOLEAN, true, true, nullptr, false},
    {"url_compatibility_mode", LogicalType::BOOLEAN, true, true, nullptr, false},
    {"http_proxy", LogicalType::VARCHAR, true, true, nullptr, false},
    {"http_proxy_username", LogicalType::VARCHAR, true, true, nullptr, false},
    {"http_proxy_password", LogicalType::VARCHAR, true, false, nullptr, true},
    {"assume_role_arn", LogicalType::VARCHAR, false, true, nullptr, false},
    {"external_id", LogicalType::VARCHAR, false, true, nullptr, false},
    {"web_identity_token_file", LogicalType::VARCHAR, false, true, nullptr, false},
    {"session_name", LogicalType::VARCHAR, false, true, nullptr, false},
    {"refresh", LogicalType::VARCHAR, false, true, nullptr, false},
    {"chain", LogicalType::VARCHAR, false, true, nullptr, false},
    {"profile", LogicalType::VARCHAR, false, true, nullptr, false},
    {"validation", LogicalType::VARCHAR, false, true, nullptr, false},
    {"account_id", LogicalType::VARCHAR, false, true, "r2", false},
    {"rds_user", LogicalType::VARCHAR, false, false, "rds", false},
    {"rds_host", LogicalType::VARCHAR, false, false, "rds", false},
    {"rds_port", LogicalType::VARCHAR, false, false, "rds", false},
    {"rds_template_secret_name", LogicalType::VARCHAR, false, false, "rds", false},
};

class DuckDBAwsCredentialsProviderChain : public Aws::Auth::AWSCredentialsProviderChain {
public:
	explicit DuckDBAwsCredentialsProviderChain(const vector<AwsProvider> &providers) {
		for (const auto &provider : providers) {
			AddProvider(provider);
		}
	}
};

//===--------------------------------------------------------------------===//
// Parsing and validation
//===--------------------------------------------------------------------===//

string TryGetStringParam(const CreateSecretInput &input, const string &param_name) {
	auto param_lookup = input.options.find(param_name);
	if (param_lookup != input.options.end()) {
		return param_lookup->second.ToString();
	} else {
		return "";
	}
}

vector<string> ResolveScope(const CreateSecretInput &input) {
	if (input.type == "rds") {
		return {};
	}

	auto scope = input.scope;
	if (!scope.empty()) {
		return scope;
	}

	if (input.type == "s3") {
		return {"s3://", "s3n://", "s3a://"};
	}
	if (input.type == "r2") {
		return {"r2://"};
	}
	if (input.type == "gcs") {
		return {"gcs://", "gs://"};
	}
	if (input.type == "aws") {
		return {""};
	}

	throw InternalException("Unknown secret type found in aws extension: '%s'", input.type);
}

string ResolveProfileName(const CreateSecretInput &input) {
	string profile = TryGetStringParam(input, "profile");

	if (profile.empty()) {
		// The SDK providers taking an explicit profile name store it verbatim, so an empty
		// string would select the literal profile "". Resolve the name here the way the SDK's
		// no-arg constructors do: AWS_PROFILE, then AWS_DEFAULT_PROFILE, then "default" (#177).
		profile = Aws::Auth::GetConfigProfileName().c_str();
	}

	return profile;
}

Aws::Config::Profile LoadProfile(const std::string &profile_name) {
	auto config_file_path = Aws::Auth::GetConfigProfileFilename();
	Aws::Config::AWSConfigFileProfileConfigLoader config_loader(config_file_path, true);
	if (config_loader.Load()) {
		for (const auto &[profile_name_entry, profile_entry] : config_loader.GetProfiles()) {
			if (profile_name == profile_name_entry) {
				return profile_entry;
			}
		}
	}

	auto credentials_file_path = Aws::Auth::ProfileConfigFileAWSCredentialsProvider::GetCredentialsProfileFilename();
	Aws::Config::AWSConfigFileProfileConfigLoader credentials_loader(credentials_file_path, false);
	if (credentials_loader.Load()) {
		for (const auto &[profile_name_entry, profile_entry] : credentials_loader.GetProfiles()) {
			if (profile_name == profile_name_entry) {
				return profile_entry;
			}
		}
	}

	return Aws::Config::Profile();
}

bool RequiresCredentials(const CreateSecretInput &input) {
	auto validation = StringUtil::Lower(TryGetStringParam(input, "validation"));
	if (validation.empty() || validation == "exists") {
		return true;
	}
	if (validation == "none") {
		return false;
	}

	throw InvalidInputException("Unknown AWS validation mode: `%s`", validation);
}

const AwsOptionDefinition *FindAwsOptionDefinition(const string &name) {
	for (const auto &definition : AWS_OPTION_DEFINITIONS) {
		if (StringUtil::CIEquals(name, definition.name)) {
			return &definition;
		}
	}
	return nullptr;
}

ParsedAwsSecret ParseOptions(const CreateSecretInput &input) {
	ParsedAwsSecret opt {};

	opt.name = input.name;
	opt.type = input.type;
	opt.scope = ResolveScope(input);
	opt.refresh = StringUtil::Lower(TryGetStringParam(input, "refresh"));
	if (!opt.refresh.empty() && opt.refresh != "auto") {
		throw InvalidInputException("Unknown AWS refresh mode: `%s`", opt.refresh);
	}

	auto &credentials = opt.credentials;
	credentials.profile_provided = input.options.find("profile") != input.options.end();
	credentials.profile_name = ResolveProfileName(input);
	credentials.assume_role = TryGetStringParam(input, "assume_role_arn");
	credentials.external_id = TryGetStringParam(input, "external_id");
	credentials.credential_chain = TryGetStringParam(input, "chain");
	credentials.web_identity_token_file = TryGetStringParam(input, "web_identity_token_file");
	credentials.session_name = TryGetStringParam(input, "session_name");
	credentials.require_credentials = RequiresCredentials(input);

	if (opt.type == "rds") {
		auto &rds = opt.rds;
		rds.user = TryGetStringParam(input, "rds_user");
		rds.host = TryGetStringParam(input, "rds_host");
		rds.port = TryGetStringParam(input, "rds_port");
		rds.template_secret_name = TryGetStringParam(input, "rds_template_secret_name");
	}

	if (opt.type == "r2") {
		auto &r2 = opt.r2;
		auto account_id = input.options.find("account_id");
		r2.account_id_provided = account_id != input.options.end();
		if (r2.account_id_provided) {
			r2.account_id = account_id->second.ToString();
		}
	}

	return opt;
}

void ValidateOptions(const ParsedAwsSecret &opt) {
	if (!opt.credentials.assume_role.empty() && opt.credentials.credential_chain.empty()) {
		throw InvalidConfigurationException("Must pass CHAIN value when passing ASSUME_ROLE_ARN");
	}

	if (opt.type == "rds" && opt.credentials.credential_chain.empty()) {
		throw InvalidConfigurationException("Invalid RDS secret parameters, 'CHAIN' option must be specified");
	}
}

//===--------------------------------------------------------------------===//
// Credential resolution
//===--------------------------------------------------------------------===//

string BuildCredentialErrorMessage(const string &chain, const AwsCredentialOptions &opt) {
	// These chains generate new credentials; assuming a role does so as well.
	const auto verb = chain == "sts" || chain == "sso" || chain == "instance" || chain == "container" ||
	                          chain == "process" || chain == "web_identity" || !opt.assume_role.empty()
	                      ? "generate"
	                      : "create";
	string message = StringUtil::Format("Secret Validation Failure: during `%s` using the following:\n", verb);

	auto append = [&](const char *label, const string &value) {
		if (!value.empty()) {
			message += StringUtil::Format("%s: '%s'\n", label, value);
		}
	};

	append("Profile", opt.profile_name);
	append("Credential Chain", chain);
	append("Role-arn", opt.assume_role);
	append("External-id", opt.external_id);
	append("Web Identity Token File", opt.web_identity_token_file);
	append("Session Name", opt.session_name);

	return message;
}

AwsProvider CreateSTSProvider(const AwsCredentialOptions &opt, const Aws::Config::Profile &profile,
                              const string &region) {
	string assume_role_arn = opt.assume_role.empty() ? profile.GetRoleArn() : opt.assume_role;
	string external_id = opt.external_id.empty() ? profile.GetExternalId() : opt.external_id;

	auto client_config = BuildClientConfigWithCa();
	if (!region.empty()) {
		client_config.region = region;
	}

	std::shared_ptr<Aws::STS::STSClient> sts_client;
	auto source_profile = profile.GetSourceProfile();
	if (source_profile.empty()) {
		sts_client = std::make_shared<Aws::STS::STSClient>(client_config);
	} else {
		auto source_provider =
		    std::make_shared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>(source_profile.c_str());
		sts_client = std::make_shared<Aws::STS::STSClient>(source_provider, client_config);
	}

	return std::make_shared<Aws::Auth::STSAssumeRoleCredentialsProvider>(
	    assume_role_arn, Aws::String(), external_id, Aws::Auth::DEFAULT_CREDS_LOAD_FREQ_SECONDS, sts_client);
}

AwsProvider CreateSSOProvider(const AwsCredentialOptions &opt) {
	auto sso_config = Aws::MakeShared<Aws::Client::ClientConfiguration>("DuckDBAwsSSO");
	if (!SELECTED_CURL_CERT_PATH.empty()) {
		sso_config->caFile = SELECTED_CURL_CERT_PATH;
	}

	return std::make_shared<Aws::Auth::SSOCredentialsProvider>(opt.profile_name, sso_config);
}

AwsProvider CreateContainerProvider() {
	using HTTPProvider = Aws::Auth::GeneralHTTPCredentialsProvider;

	auto relative_uri = FileSystem::GetEnvVariable(HTTPProvider::AWS_CONTAINER_CREDENTIALS_RELATIVE_URI);
	auto absolute_uri = FileSystem::GetEnvVariable(HTTPProvider::AWS_CONTAINER_CREDENTIALS_FULL_URI);
	auto auth_token = FileSystem::GetEnvVariable(HTTPProvider::AWS_CONTAINER_AUTHORIZATION_TOKEN);
	auto auth_token_file = FileSystem::GetEnvVariable(HTTPProvider::AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE);

	auto provider = std::make_shared<HTTPProvider>(relative_uri, absolute_uri, auth_token, auth_token_file);
	if (!provider->IsValid()) {
		throw InvalidConfigurationException(
		    "Chain value 'container' requires container credentials to be available: "
		    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI must be set in "
		    "the environment (ECS and EKS Pod Identity set these automatically)");
	}

	return provider;
}

AwsProvider CreateWebIdentityProvider(const AwsCredentialOptions &opt, const Aws::Config::Profile &profile,
                                      const string &region) {
	Aws::Client::ClientConfiguration::CredentialProviderConfiguration config;

	config.profile = opt.profile_name.c_str();
	config.region = region.c_str();

	auto role_arn = profile.GetRoleArn();
	if (!opt.assume_role.empty()) {
		role_arn = opt.assume_role.c_str();
	}
	config.stsCredentialsProviderConfig.roleArn = role_arn;

	auto token_file = profile.GetValue("web_identity_token_file");
	if (!opt.web_identity_token_file.empty()) {
		token_file = opt.web_identity_token_file.c_str();
	}
	config.stsCredentialsProviderConfig.tokenFilePath = token_file;

	auto session_name = profile.GetValue("role_session_name");
	if (!opt.session_name.empty()) {
		session_name = opt.session_name.c_str();
	}
	config.stsCredentialsProviderConfig.sessionName = session_name;

	return std::make_shared<Aws::Auth::STSAssumeRoleWebIdentityCredentialsProvider>(config);
}

AwsProvider CreateProcessProvider(const AwsCredentialOptions &opt) {
	return std::make_shared<Aws::Auth::ProcessCredentialsProvider>(opt.profile_name);
}

AwsProvider CreateConfigProvider(const AwsCredentialOptions &opt, const Aws::Config::Profile &profile,
                                 const string &region) {
	if (profile.GetName().empty() && opt.require_credentials) {
		throw InvalidConfigurationException(
		    "Secret Validation Failure: no profile '%s' found in config file %s or credentials file %s",
		    opt.profile_name, Aws::Auth::GetConfigProfileFilename(),
		    Aws::Auth::ProfileConfigFileAWSCredentialsProvider::GetCredentialsProfileFilename());
	}

	auto config_profile = profile;
	if (!config_profile.GetRoleArn().empty() && !opt.assume_role.empty()) {
		throw InvalidInputException(
		    "Ambiguous role arn. Role_arn '%s' defined in profile '%s'. Role_arn '%s' defined in secret statement",
		    config_profile.GetRoleArn(), opt.profile_name, opt.assume_role);
	}
	if (!config_profile.GetExternalId().empty() && !opt.external_id.empty()) {
		throw InvalidInputException("Ambiguous external id. external_id '%s' defined in profile '%s'. external_id '%s' "
		                            "defined in secret statement",
		                            config_profile.GetExternalId(), opt.profile_name, opt.external_id);
	}
	if (config_profile.GetRoleArn().empty() && !opt.assume_role.empty()) {
		config_profile.SetRoleArn(opt.assume_role);
	}
	if (config_profile.GetExternalId().empty() && !opt.external_id.empty()) {
		config_profile.SetExternalId(opt.external_id);
	}

	if (!config_profile.GetRoleArn().empty()) {
		return CreateSTSProvider(opt, config_profile, region);
	}
	return std::make_shared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>(opt.profile_name.c_str());
}

AwsProvider CreateCredentialProvider(const AwsCredentialOptions &options, const Aws::Config::Profile &profile,
                                     const string &region) {
	// If the user has not supplied a chain, fall back to SDK default behavior.
	if (options.credential_chain.empty()) {
		if (!options.profile_provided) {
			return std::make_shared<Aws::Auth::DefaultAWSCredentialsProviderChain>();
		}
		return std::make_shared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>(options.profile_name.c_str());
	}

	vector<AwsProvider> providers;

	for (const auto &chain : StringUtil::Split(options.credential_chain, ';')) {
		if (chain == "sts") {
			if (options.assume_role.empty()) {
				throw InvalidConfigurationException(
				    "Chain value 'STS' is only supported with an ASSUME_ROLE_ARN value. "
				    "If the selected profile uses STS, add \"CHAIN 'config'\"");
			}
			providers.emplace_back(CreateSTSProvider(options, profile, region));
		} else if (chain == "sso") {
			providers.emplace_back(CreateSSOProvider(options));
		} else if (chain == "env") {
			providers.emplace_back(std::make_shared<Aws::Auth::EnvironmentAWSCredentialsProvider>());
		} else if (chain == "instance") {
			providers.emplace_back(std::make_shared<Aws::Auth::InstanceProfileCredentialsProvider>());
		} else if (chain == "container") {
			providers.emplace_back(CreateContainerProvider());
		} else if (chain == "web_identity") {
			providers.emplace_back(CreateWebIdentityProvider(options, profile, region));
		} else if (chain == "process") {
			providers.emplace_back(CreateProcessProvider(options));
		} else if (chain == "config") {
			providers.emplace_back(CreateConfigProvider(options, profile, region));
		} else {
			throw InvalidInputException("Unknown provider found while parsing AWS credential chain string: '%s'",
			                            chain);
		}
	}

	return std::make_shared<DuckDBAwsCredentialsProviderChain>(providers);
}

bool HasAssumeRole(const Aws::Config::Profile &profile, const AwsCredentialOptions &opt, const std::string &chain) {
	if (chain == "sts") {
		return true;
	}
	if (chain == "config") {
		// In this case the configuration file led to the creation of an STS provider.
		if (!profile.GetRoleArn().empty() || !opt.assume_role.empty()) {
			return true;
		}
	}

	return false;
}

AwsCredentialResult LoadCredentials(const AwsCredentialOptions &opt, const Aws::Config::Profile &profile,
                                    const string &region) {
	auto provider = CreateCredentialProvider(opt, profile, region);
	auto credentials = provider->GetAWSCredentials();
	auto chain = opt.credential_chain;

	// handle case where requested profile uses STS, but no chain was declared. In this case,
	// The aws-spp-sdk will not pick up credentials via sts. Unclear why.
	// Instead we need to find the profile and grab the arn&external_id using "config" chain.
	// Then we create the credentials using an sts provider. This (should) be the default behavior of the SDK
	// see https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/credproviders.html
	if (credentials.IsEmpty() && chain.empty()) {
		chain = "config";
		auto config_options = opt;
		config_options.credential_chain = chain;

		provider = CreateCredentialProvider(config_options, profile, region);
		credentials = provider->GetAWSCredentials();
	}

	const bool assumed_role = HasAssumeRole(profile, opt, chain);
	return {std::move(credentials), std::move(chain), assumed_role};
}

void ValidateCredentials(const AwsCredentialResult &result, const AwsCredentialOptions &opt) {
	if (!opt.require_credentials || !result.credentials.IsExpiredOrEmpty()) {
		return;
	}

	throw InvalidConfigurationException(BuildCredentialErrorMessage(result.chain, opt));
}

//===--------------------------------------------------------------------===//
// Secret construction
//===--------------------------------------------------------------------===//

unique_ptr<KeyValueSecret> ConstructBaseSecret(const vector<string> &prefix_paths_p, const Identifier &type,
                                               const Identifier &name) {
	auto return_value = make_uniq<KeyValueSecret>(prefix_paths_p, type, CREDENTIAL_CHAIN_PROVIDER, name);
	for (const auto &definition : AWS_OPTION_DEFINITIONS) {
		if (definition.redact) {
			return_value->redact_keys.insert(definition.name);
		}
	}
	return return_value;
}

void SetSecretExpiration(KeyValueSecret &secret, const Aws::Auth::AWSCredentials &credentials, bool assumed_role) {
	// Store credential expiration as epoch milliseconds so consumers (e.g., duckdb-iceberg)
	// can refresh proactively at ~80% TTL instead of guessing with a fixed timer.
	if (assumed_role) {
		// For the STS chain we cannot read the real expiration from `credentials.GetExpiration()`:
		// the SDK's STSAssumeRoleCredentialsProvider builds the returned AWSCredentials with the
		// 3-arg constructor, which leaves m_expiration at its default sentinel (time_point::max,
		// i.e. year 294247). The true expiry is kept private in the provider's m_expiry and is
		// never exposed. Since we always request STS credentials with a duration of
		// DEFAULT_CREDS_LOAD_FREQ_SECONDS, compute the expiration from now() + that duration.
		int64_t now_epoch_ms = Timestamp::GetEpochMs(Timestamp::GetCurrentTimestamp());
		int64_t expiration_epoch_ms = now_epoch_ms + (Aws::Auth::DEFAULT_CREDS_LOAD_FREQ_SECONDS * 1000LL);
		secret.secret_map["expiration_epoch_ms"] = Value::BIGINT(expiration_epoch_ms);
		return;
	}

	auto expiration = credentials.GetExpiration();
	if (expiration != Aws::Utils::DateTime()) {
		secret.secret_map["expiration_epoch_ms"] = Value::BIGINT(expiration.Millis());
	}
}

void SetSecretRefresh(KeyValueSecret &secret, const case_insensitive_map_t<Value> &input_options,
                      const std::string &refresh) {
	child_list_t<Value> refresh_fields;
	for (const auto &option : input_options) {
		const auto *definition = FindAwsOptionDefinition(option.first);
		if (!definition) {
			continue;
		}
		if (definition->store_in_secret) {
			secret.secret_map[Identifier(definition->name)] = option.second;
		}
		if (refresh == "auto" && definition->include_in_refresh) {
			refresh_fields.emplace_back(StringUtil::Lower(definition->name), option.second);
		}
	}
	if (refresh == "auto") {
		secret.secret_map["refresh_info"] = Value::STRUCT(refresh_fields);
	}
}

void SetSecretEndpoint(KeyValueSecret &secret, const ParsedAwsSecret &opt) {
	auto endpoint_lu = secret.secret_map.find("endpoint");
	if (endpoint_lu != secret.secret_map.end() && !endpoint_lu->second.ToString().empty()) {
		return;
	}

	if (opt.type == "s3") {
		secret.secret_map["endpoint"] = "s3.amazonaws.com";
	} else if (opt.type == "r2") {
		if (opt.r2.account_id_provided) {
			secret.secret_map["endpoint"] = opt.r2.account_id + ".r2.cloudflarestorage.com";
		}
	} else if (opt.type == "gcs") {
		secret.secret_map["endpoint"] = "storage.googleapis.com";
	} else if (opt.type == "aws") {
		// this is a nop?
	} else {
		throw InternalException("Unknown secret type found in httpfs extension: '%s'", opt.type);
	}
}

void SetSecretUrlType(KeyValueSecret &secret, const Identifier &type) {
	auto url_style_lu = secret.secret_map.find("url_style");
	if (url_style_lu != secret.secret_map.end() && !url_style_lu->second.ToString().empty()) {
		return;
	}
	if (type == "gcs" || type == "r2") {
		secret.secret_map["url_style"] = "path";
	}
}

unique_ptr<KeyValueSecret> BuildSecret(const ParsedAwsSecret &opt, const case_insensitive_map_t<Value> &input_options,
                                       const AwsCredentialResult &result, const std::string &region) {
	auto secret = ConstructBaseSecret(opt.scope, opt.type, opt.name);
	auto refresh = opt.refresh;
	const auto &credentials = result.credentials;

	if (!region.empty()) {
		secret->secret_map["region"] = region;
	}

	// Temporary credentials must retain the inputs needed to regenerate them.
	// TODO: remove this once refresh is set to auto by default for all credential_chain provider created secrets.
	if ((result.assumed_role || result.chain == "web_identity") && opt.refresh.empty()) {
		refresh = "auto";
	}

	if (!credentials.IsExpiredOrEmpty()) {
		secret->secret_map["key_id"] = Value(credentials.GetAWSAccessKeyId());
		secret->secret_map["secret"] = Value(credentials.GetAWSSecretKey());
		secret->secret_map["session_token"] = Value(credentials.GetSessionToken());

		// Store credential expiration as epoch milliseconds so consumers (e.g., duckdb-iceberg)
		// can refresh proactively at ~80% TTL instead of guessing with a fixed timer.
		SetSecretExpiration(*secret, credentials, result.assumed_role);
	}

	SetSecretRefresh(*secret, input_options, refresh);
	SetSecretEndpoint(*secret, opt);
	SetSecretUrlType(*secret, opt.type);

	return secret;
}

//===--------------------------------------------------------------------===//
// RDS secrets
//===--------------------------------------------------------------------===//

void ValidateRDSOptions(const RdsSecretOptions &opt, const string &region) {
	if (opt.user.empty() || opt.host.empty() || opt.port.empty() || region.empty()) {
		throw InvalidInputException(
		    "Invalid RDS secret parameters, 'RDS_USER', 'RDS_HOST', 'RDS_PORT' and 'REGION' options must be specified");
	}
}

string GenerateRDSSecretToken(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider, const string &user,
                              const string &host, const string &port, const string &region) {
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

	return token;
}

unique_ptr<KeyValueSecret> BuildRDSSecret(const ParsedAwsSecret &opt,
                                          const case_insensitive_map_t<Value> &input_options,
                                          const AwsProvider &provider, const string &region) {
	auto secret = ConstructBaseSecret(opt.scope, opt.type, opt.name);
	if (opt.rds.template_secret_name.empty()) {
		for (const auto &option : input_options) {
			secret->secret_map[Identifier(option.first)] = option.second;
		}
		return secret;
	}

	auto token = GenerateRDSSecretToken(provider, opt.rds.user, opt.rds.host, opt.rds.port, region);
	secret->secret_map["session_token"] = Value(token);
	return secret;
}

//===--------------------------------------------------------------------===//
// Entry point
//===--------------------------------------------------------------------===//

unique_ptr<BaseSecret> CreateAWSSecretFromCredentialChain(ClientContext &ctx, CreateSecretInput &input) {
	auto options = ParseOptions(input);
	ValidateOptions(options);

	auto profile = LoadProfile(options.credentials.profile_name);
	auto region = ResolveAwsRegion(ctx, TryGetStringParam(input, "region"), options.credentials.profile_name);

	if (options.type == "rds") {
		ValidateRDSOptions(options.rds, region);
		auto provider = CreateCredentialProvider(options.credentials, profile, region);
		return BuildRDSSecret(options, input.options, provider, region);
	}

	if (region.empty()) {
		DUCKDB_LOG_WARNING(
		    ctx,
		    "Set region explicitly using REGION 'us-east-1' in your CREATE SECRET statement, adding a region to your "
		    "profile in ~/.aws/config or configure the AWS_REGION or AWS_DEFAULT_REGION environment variables.");
	}

	auto result = LoadCredentials(options.credentials, profile, region);
	ValidateCredentials(result, options.credentials);

	return BuildSecret(options, input.options, result, region);
}

} // namespace

std::shared_ptr<Aws::Auth::AWSCredentialsProvider> CreateAwsCredentialsProvider() {
	return Aws::MakeShared<Aws::Auth::DefaultAWSCredentialsProviderChain>("DuckDBAwsDefault");
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
	for (const auto *type_name : SECRET_TYPES) {
		const string type(type_name);
		// Register the credential_chain secret provider
		CreateSecretFunction cred_chain_function = {type, CREDENTIAL_CHAIN_PROVIDER,
		                                            CreateAWSSecretFromCredentialChain};

		for (const auto &definition : AWS_OPTION_DEFINITIONS) {
			if (definition.only_for_type && type != definition.only_for_type) {
				continue;
			}
			cred_chain_function.named_parameters[definition.name] = definition.type;
		}

		loader.RegisterFunction(cred_chain_function);
	}
}

} // namespace duckdb
