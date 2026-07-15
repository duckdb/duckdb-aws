#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/storage/storage_extension.hpp"

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

//! The default-enabled commercial AWS regions, used as the sweep set for multi-region listing functions
//! (e.g. the no-argument cloudformation_describe_stacks). Hardcoded for now — see the FIXME in utils.cpp.
const vector<string> &GetDefaultAwsRegions();

//! Secret types that carry an AWS identity, in the order they should be preferred: 'aws' is the
//! generic one, 's3' holds the same credentials alongside bucket settings.
const vector<string> &AwsSecretTypes();

//! Whether a secret of this type can be used to authenticate an AWS API call.
bool IsAwsSecretType(const string &type);

//! Find the secret holding the AWS identity to authenticate with. A named secret must be one of
//! AwsSecretTypes(); when unnamed, there must be exactly one secret of the most-preferred type
//! that is present. Throws rather than returning null.
unique_ptr<SecretEntry> FindAwsSecret(ClientContext &context, const string &secret_name);

//! The name of the postgres extension, for autoloading it.
extern const char *const POSTGRES_EXTENSION_NAME;

//! The postgres extension's storage extension, or null when it is not loaded. Redshift speaks the
//! Postgres wire protocol, so attaching one hands off to postgres once the endpoint is resolved.
optional_ptr<StorageExtension> FindPostgresStorageExtension(const DBConfig &config);

} // namespace duckdb
