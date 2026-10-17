#include "aws_default_secret_storage.hpp"
#include "aws_secret.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/settings.hpp"

namespace duckdb {

static constexpr const char *DEFAULT_CREDENTIALS_SETTING = "aws_default_credentials";

static CreateSecretInput DefaultSecretInput(const string &type, const string &name, const string &provider) {
	CreateSecretInput input;
	input.type = Identifier(type);
	input.provider = Identifier(provider);
	input.name = Identifier(name);
	input.storage_type = Identifier(AwsDefaultSecretStorage::STORAGE_NAME);
	input.persist_type = SecretPersistType::TEMPORARY;
	input.on_conflict = OnCreateConflict::REPLACE_ON_CONFLICT;
	return input;
}

static unique_ptr<const BaseSecret> SecretWithoutCredentials(const string &type, const string &name,
                                                             const string &provider) {
	return CreateAWSSecretWithoutCredentials(DefaultSecretInput(type, name, provider));
}

AwsDefaultSecretStorage::AwsDefaultSecretStorage() : SecretStorage(STORAGE_NAME, TIE_BREAK_OFFSET) {
	s3_secret = SecretWithoutCredentials("s3", S3_SECRET_NAME, "lazy");
	aws_secret = SecretWithoutCredentials("aws", AWS_SECRET_NAME, "lazy");
}

void AwsDefaultSecretStorage::Register(ExtensionLoader &loader) {
	auto &db = loader.GetDatabaseInstance();
	auto &config = DBConfig::GetConfig(db);
	config.AddExtensionOption(DEFAULT_CREDENTIALS_SETTING,
	                          "Use the credentials the default AWS credential chain finds when no secret matches",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(true));
	SecretManager::Get(db).LoadSecretStorage(make_uniq<AwsDefaultSecretStorage>());
}

bool AwsDefaultSecretStorage::IsDefaultSecret(const SecretEntry &entry) {
	return entry.storage_mode == STORAGE_NAME;
}

unique_ptr<SecretEntry> AwsDefaultSecretStorage::GetDefaultAwsSecret(ClientContext &context) {
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto match = SecretManager::Get(context).LookupSecret(transaction, "", "aws");
	if (!match.HasMatch() || !IsDefaultSecret(*match.secret_entry)) {
		return nullptr;
	}
	return std::move(match.secret_entry);
}

static bool DefaultCredentialsEnabled(ClientContext &context) {
	Value enabled;
	if (context.TryGetCurrentSetting(DEFAULT_CREDENTIALS_SETTING, enabled) && !enabled.IsNull() &&
	    !enabled.GetValue<bool>()) {
		return false;
	}
	// the credential chain reads files and the environment outside of the file systems of DuckDB
	return Settings::Get<EnableExternalAccessSetting>(context);
}

//! Whether S3 is configured through the httpfs settings, which a default S3 secret would override
static bool S3ConfiguredBySettings(ClientContext &context) {
	for (auto name : {"s3_access_key_id", "s3_secret_access_key", "s3_session_token", "s3_endpoint"}) {
		Value value;
		if (context.TryGetCurrentSetting(name, value) && !value.IsNull() && !value.ToString().empty()) {
			return true;
		}
	}
	return false;
}

unique_ptr<SecretEntry> AwsDefaultSecretStorage::MakeEntry(const BaseSecret &secret) {
	auto entry = make_uniq<SecretEntry>(secret.Clone());
	entry->persist_type = SecretPersistType::TEMPORARY;
	entry->storage_mode = STORAGE_NAME;
	return entry;
}

void AwsDefaultSecretStorage::SetSecrets(unique_ptr<const BaseSecret> resolved_s3) {
	// the identity and region only: the endpoint and URL style keep coming from the settings
	auto &resolved_kv = resolved_s3->Cast<KeyValueSecret>();
	auto s3 = make_uniq<KeyValueSecret>(resolved_kv);
	s3->secret_map.erase(Identifier("endpoint"));
	s3->secret_map.erase(Identifier("url_style"));
	auto &s3_kv = *s3;
	auto aws = make_uniq<KeyValueSecret>(vector<string> {""}, Identifier("aws"), s3_kv.GetProvider(),
	                                     Identifier(AWS_SECRET_NAME));
	aws->redact_keys = s3_kv.redact_keys;
	// the identity, without what only applies to S3 requests
	for (auto &entry : s3_kv.secret_map) {
		auto &key = entry.first.GetIdentifierName();
		if (key != "endpoint" && key != "url_style" && key != "refresh_info") {
			aws->secret_map[entry.first] = entry.second;
		}
	}
	aws_secret = std::move(aws);
	s3_secret = std::move(s3);
}

void AwsDefaultSecretStorage::Resolve(ClientContext &context) {
	resolved = true;
	auto input = DefaultSecretInput("s3", S3_SECRET_NAME, "credential_chain");
	input.options["validation"] = Value("none");
	input.options["refresh"] = Value("auto");
	try {
		auto result = CreateAWSSecretFromCredentialChain(context, input);
		if (!result->Cast<KeyValueSecret>().TryGetValue("key_id").IsNull()) {
			SetSecrets(std::move(result));
			return;
		}
		DUCKDB_LOG_DEBUG(context, "aws.DefaultCredentials: the default credential chain found no credentials");
	} catch (std::exception &ex) {
		ErrorData error(ex);
		DUCKDB_LOG_DEBUG(context, "aws.DefaultCredentials: resolving the default credential chain failed: %s",
		                 error.RawMessage());
	}
	// no credentials: requests stay unsigned, as without the default secrets
	SetSecrets(SecretWithoutCredentials("s3", S3_SECRET_NAME, "none"));
}

optional_ptr<const BaseSecret> AwsDefaultSecretStorage::SecretOfType(const string &type) const {
	if (dropped) {
		return nullptr;
	}
	if (type == "s3") {
		return s3_secret.get();
	}
	if (type == "aws") {
		return aws_secret.get();
	}
	return nullptr;
}

SecretMatch AwsDefaultSecretStorage::LookupSecret(const string &path, const string &type,
                                                  optional_ptr<CatalogTransaction> transaction) {
	SecretMatch best_match;
	if (type != "s3" && type != "aws") {
		return best_match;
	}
	if (!transaction || !transaction->context || !DefaultCredentialsEnabled(*transaction->context)) {
		return best_match;
	}
	if (type == "s3" && S3ConfiguredBySettings(*transaction->context)) {
		return best_match;
	}
	lock_guard<mutex> guard(lock);
	if (dropped) {
		return best_match;
	}
	if (!resolved) {
		Resolve(*transaction->context);
	}
	auto entry = MakeEntry(*SecretOfType(type));
	return SelectBestMatch(*entry, path, tie_break_offset, best_match);
}

unique_ptr<SecretEntry> AwsDefaultSecretStorage::StoreSecret(unique_ptr<const BaseSecret> secret,
                                                             OnCreateConflict on_conflict,
                                                             optional_ptr<CatalogTransaction> transaction) {
	// only the refresh of the S3 secret is stored here, which replaces both
	if (secret->GetName() != Identifier(S3_SECRET_NAME) || on_conflict != OnCreateConflict::REPLACE_ON_CONFLICT) {
		throw InvalidInputException("Secrets cannot be created in the '%s' secret storage", STORAGE_NAME);
	}
	lock_guard<mutex> guard(lock);
	resolved = true;
	dropped = false;
	SetSecrets(std::move(secret));
	return MakeEntry(*s3_secret);
}

vector<SecretEntry> AwsDefaultSecretStorage::AllSecrets(optional_ptr<CatalogTransaction> transaction) {
	vector<SecretEntry> result;
	lock_guard<mutex> guard(lock);
	if (!dropped) {
		result.push_back(*MakeEntry(*aws_secret));
		result.push_back(*MakeEntry(*s3_secret));
	}
	return result;
}

void AwsDefaultSecretStorage::DropSecretByName(const Identifier &name, OnEntryNotFound on_entry_not_found,
                                               optional_ptr<CatalogTransaction> transaction) {
	lock_guard<mutex> guard(lock);
	if (dropped || (name != Identifier(AWS_SECRET_NAME) && name != Identifier(S3_SECRET_NAME))) {
		if (on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) {
			throw InvalidInputException("Failed to remove non-existent secret with name %s", name);
		}
		return;
	}
	// both are views of one identity; dropped, they are not resolved again for the lifetime of the database
	dropped = true;
}

unique_ptr<SecretEntry> AwsDefaultSecretStorage::GetSecretByName(const string &name,
                                                                 optional_ptr<CatalogTransaction> transaction) {
	lock_guard<mutex> guard(lock);
	if (dropped) {
		return nullptr;
	}
	if (Identifier(name) == Identifier(AWS_SECRET_NAME)) {
		return MakeEntry(*aws_secret);
	}
	if (Identifier(name) == Identifier(S3_SECRET_NAME)) {
		return MakeEntry(*s3_secret);
	}
	return nullptr;
}

} // namespace duckdb
