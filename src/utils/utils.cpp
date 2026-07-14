#include "utils/utils.hpp"

#include "aws_client.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_helper.hpp"

#include <cstdlib>

namespace duckdb {

namespace {

string RegionFromSetting(ClientContext &context) {
	Value s3_region_setting;
	if (context.TryGetCurrentSetting("s3_region", s3_region_setting)) {
		return s3_region_setting.ToString();
	}
	return "";
}

string RegionFromEnvironment() {
	if (const char *env = getenv("AWS_REGION")) {
		return env;
	}
	if (const char *env = getenv("AWS_DEFAULT_REGION")) {
		return env;
	}
	return "";
}

string RegionFromProfile(const string &profile_name) {
	auto profile = GetAwsProfile(profile_name.empty() ? "default" : profile_name, false);
	return profile.GetRegion().c_str();
}

} // namespace

string ResolveAwsRegion(ClientContext &context, const string &explicit_region, const string &profile_name) {
	if (!explicit_region.empty()) {
		return explicit_region;
	}
	auto region = RegionFromSetting(context);
	if (!region.empty()) {
		return region;
	}
	region = RegionFromEnvironment();
	if (!region.empty()) {
		return region;
	}
	return RegionFromProfile(profile_name);
}

const vector<string> &AwsSecretTypes() {
	static const vector<string> aws_secret_types = {"aws", "s3"};
	return aws_secret_types;
}

bool IsAwsSecretType(const string &type) {
	for (const auto &candidate : AwsSecretTypes()) {
		if (type == candidate) {
			return true;
		}
	}
	return false;
}

unique_ptr<SecretEntry> FindAwsSecret(ClientContext &context, const string &secret_name) {
	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);

	if (!secret_name.empty()) {
		auto secret_entry = secret_manager.GetSecretByName(transaction, secret_name);
		if (!secret_entry) {
			throw BinderException("Secret with name \"%s\" not found", secret_name);
		}
		const auto &type = secret_entry->secret->GetType().GetIdentifierName();
		if (!IsAwsSecretType(type)) {
			throw BinderException("Secret \"%s\" is of type \"%s\", but an AWS identity is required; pass a secret of "
			                      "type \"aws\" or \"s3\"",
			                      secret_name, type);
		}
		return secret_entry;
	}

	auto all_secrets = secret_manager.AllSecrets(transaction);
	for (const auto &wanted_type : AwsSecretTypes()) {
		vector<const SecretEntry *> matches;
		for (const auto &entry : all_secrets) {
			if (entry.secret->GetType().GetIdentifierName() == wanted_type) {
				matches.push_back(&entry);
			}
		}
		if (matches.size() > 1) {
			throw BinderException("Found %d secrets of type \"%s\"; name the one to use with a SECRET option",
			                      matches.size(), wanted_type);
		}
		if (matches.size() == 1) {
			return make_uniq<SecretEntry>(*matches[0]);
		}
	}
	throw BinderException("No AWS credentials found. Create a secret holding them, e.g. "
	                      "CREATE SECRET (TYPE aws, PROVIDER credential_chain, REGION '<region>')");
}

string GetSecretString(const KeyValueSecret &secret, const string &key) {
	auto value = secret.TryGetValue(Identifier(key));
	if (value.IsNull()) {
		return "";
	}
	return value.ToString();
}

std::shared_ptr<Aws::Auth::AWSCredentialsProvider> CredentialsProviderFromSecret(const KeyValueSecret &secret,
                                                                                 const string &service) {
	auto key_id = GetSecretString(secret, "key_id");
	auto secret_key = GetSecretString(secret, "secret");
	auto session_token = GetSecretString(secret, "session_token");
	if (key_id.empty() || secret_key.empty()) {
		throw InvalidConfigurationException(
		    "Secret \"%s\" holds no AWS credentials (no 'key_id'/'secret'), so it cannot be used to reach %s",
		    secret.GetName().GetIdentifierName(), service);
	}
	return Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>(service.c_str(), key_id.c_str(), secret_key.c_str(),
	                                                                session_token.c_str());
}

string EscapeConnectionValue(const string &value) {
	string result = "'";
	for (auto c : value) {
		if (c == '\\' || c == '\'') {
			result += '\\';
		}
		result += c;
	}
	result += "'";
	return result;
}

const char *const POSTGRES_EXTENSION_NAME = "postgres";

optional_ptr<StorageExtension> FindPostgresStorageExtension(const DBConfig &config) {
	// Registered as "postgres_scanner", which is what "postgres" aliases to.
	return StorageExtension::Find(config, ExtensionHelper::ApplyExtensionAlias(POSTGRES_EXTENSION_NAME));
}

optional_ptr<StorageExtension> RequirePostgresStorageExtension(ClientContext &context, const string &attach_type) {
	auto &db_config = DBConfig::GetConfig(context);
	auto postgres_extension = FindPostgresStorageExtension(db_config);
	if (!postgres_extension) {
		Catalog::TryAutoLoad(context, POSTGRES_EXTENSION_NAME);
		postgres_extension = FindPostgresStorageExtension(db_config);
	}
	if (!postgres_extension || !postgres_extension->attach) {
		throw InvalidConfigurationException("Attaching %s requires the postgres extension, which could not be loaded. "
		                                    "Run 'INSTALL postgres; LOAD postgres;' and retry",
		                                    attach_type);
	}
	return postgres_extension;
}

} // namespace duckdb
