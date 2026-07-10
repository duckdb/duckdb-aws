#pragma once

#include "duckdb.hpp"

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

} // namespace duckdb
