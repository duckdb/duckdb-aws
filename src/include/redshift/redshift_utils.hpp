#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <memory>

namespace duckdb {

class ExtensionLoader;

//! Everything the aws extension knows about Redshift secrets.
struct Redshift {
	//! Register the 'redshift' secret type. Unlike s3/r2/gcs/aws (owned by httpfs) and
	//! rds (owned by the postgres extension), no other extension owns 'redshift', so we
	//! must register it here or CREATE SECRET fails with "Secret type 'redshift' not found".
	static void RegisterSecret(ExtensionLoader &loader);

	//! Add the redshift_* named parameters to a CREATE SECRET function of type 'redshift'.
	static void AddNamedParameters(CreateSecretFunction &function);

	//! Mints temporary IAM credentials for a Redshift cluster and returns a secret holding
	//! them alongside the connection details, ready to be consumed by a Postgres-protocol
	//! ATTACH. Because the minted credentials are short-lived, this secret is intended for
	//! immediate use rather than as a long-lived / persistent secret.
	static unique_ptr<BaseSecret> CreateSecret(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
	                                           CreateSecretInput &input, const string &region);
};

} // namespace duckdb
