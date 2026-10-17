#pragma once

#include "duckdb/main/secret/secret_storage.hpp"

namespace duckdb {

class ExtensionLoader;

//! Holds the secrets the default AWS credential chain resolves to, the way the AWS CLI finds credentials without
//! configuration: one of type 'aws' for the AWS identity (RDS, Redshift) and one of type 's3' for S3 paths. They are
//! listed with provider 'lazy' until the first lookup resolves the chain, to 'credential_chain' or to 'none' when it
//! finds no credentials. The tie-break offset makes any explicit secret that matches a path win over them.
class AwsDefaultSecretStorage : public SecretStorage {
public:
	static constexpr const char *STORAGE_NAME = "aws_default";
	static constexpr const char *AWS_SECRET_NAME = "__aws_default";
	static constexpr const char *S3_SECRET_NAME = "__aws_default_s3";
	static constexpr int64_t TIE_BREAK_OFFSET = 1000000000000LL;

	AwsDefaultSecretStorage();

	static void Register(ExtensionLoader &loader);
	//! The default AWS identity, resolving the credential chain if needed; nullptr when it is switched off
	static unique_ptr<SecretEntry> GetDefaultAwsSecret(ClientContext &context);
	static bool IsDefaultSecret(const SecretEntry &entry);

public:
	unique_ptr<SecretEntry> StoreSecret(unique_ptr<const BaseSecret> secret, OnCreateConflict on_conflict,
	                                    optional_ptr<CatalogTransaction> transaction = nullptr) override;
	vector<SecretEntry> AllSecrets(optional_ptr<CatalogTransaction> transaction = nullptr) override;
	void DropSecretByName(const Identifier &name, OnEntryNotFound on_entry_not_found,
	                      optional_ptr<CatalogTransaction> transaction = nullptr) override;
	SecretMatch LookupSecret(const string &path, const string &type,
	                         optional_ptr<CatalogTransaction> transaction = nullptr) override;
	unique_ptr<SecretEntry> GetSecretByName(const string &name,
	                                        optional_ptr<CatalogTransaction> transaction = nullptr) override;

private:
	//! Resolves the credential chain once; afterwards the result is used until it is refreshed or dropped
	void Resolve(ClientContext &context);
	//! Sets both secrets from the S3 secret the chain resolved to
	void SetSecrets(unique_ptr<const BaseSecret> s3);
	optional_ptr<const BaseSecret> SecretOfType(const string &type) const;
	static unique_ptr<SecretEntry> MakeEntry(const BaseSecret &secret);

private:
	mutex lock;
	bool resolved = false;
	bool dropped = false;
	unique_ptr<const BaseSecret> s3_secret;
	unique_ptr<const BaseSecret> aws_secret;
};

} // namespace duckdb
