#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/storage/storage_extension.hpp"

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <memory>

namespace duckdb {

//! Resolve the AWS region to use, taking the first of these that yields a value:
//!
//!   1. `explicit_region`, i.e. whatever the statement itself specified
//!   2. DuckDB's `s3_region` setting (SET s3_region='us-east-1')
//!   3. the AWS_REGION / AWS_DEFAULT_REGION environment variables
//!   4. the region configured on the AWS profile (the 'default' profile when unnamed)
//!
//! Returns "" when no source supplies one. The SDK requires a region for every client, so
//! callers must either supply a default or fail; see
//! https://docs.aws.amazon.com/sdkref/latest/guide/feature-region.html
string ResolveAwsRegion(ClientContext &context, const string &explicit_region, const string &profile_name);

//! Secret types that carry an AWS identity, in the order they should be preferred: 'aws' is the
//! generic one, 's3' holds the same credentials alongside bucket settings.
const vector<string> &AwsSecretTypes();

//! Whether a secret of this type can be used to authenticate an AWS API call.
bool IsAwsSecretType(const string &type);

//! Find the secret holding the AWS identity to authenticate with. A named secret must be one of
//! AwsSecretTypes(); when unnamed, there must be exactly one secret of the most-preferred type
//! that is present. Throws rather than returning null.
unique_ptr<SecretEntry> FindAwsSecret(ClientContext &context, const string &secret_name);

//! Read a string field out of a key-value secret, "" when the field is not set.
string GetSecretString(const KeyValueSecret &secret, const string &key);

//! A credentials provider for the AWS identity the secret resolved to. `service` only names the
//! caller in SDK allocation tags. Throws when the secret carries no credentials.
std::shared_ptr<Aws::Auth::AWSCredentialsProvider> CredentialsProviderFromSecret(const KeyValueSecret &secret,
                                                                                 const string &service);

//! Quote a value for a libpq connection string. Backslashes and single quotes must be escaped
//! with a backslash; quoting the whole value keeps empty values and embedded spaces valid.
string EscapeConnectionValue(const string &value);

//! The name of the postgres extension, for autoloading it.
extern const char *const POSTGRES_EXTENSION_NAME;

//! The postgres extension's storage extension, or null when it is not loaded. Redshift and RDS's
//! postgres engines speak the Postgres wire protocol, so attaching one hands off to postgres once
//! the endpoint is resolved.
optional_ptr<StorageExtension> FindPostgresStorageExtension(const DBConfig &config);

//! The postgres storage extension, autoloading the postgres extension if it is not loaded yet.
//! `attach_type` only names the caller in the error thrown when it cannot be loaded.
optional_ptr<StorageExtension> RequirePostgresStorageExtension(ClientContext &context, const string &attach_type);

//! The message to report for a failed postgres attach. Postgres quotes the entire connection
//! string back, which buries the server's own diagnostic and puts `password` - for Redshift and
//! RDS a live, AWS-generated credential - in the error and in whatever log it lands in. Returns
//! the server's message alone when the connection got far enough to produce one, and otherwise
//! the full message with the password redacted.
string PostgresAttachErrorMessage(std::exception &ex, const string &password);

} // namespace duckdb
