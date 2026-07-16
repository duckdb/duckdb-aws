#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <memory>

namespace duckdb {

class ExtensionLoader;

//! The subset of an RDS DB instance description that we need to open a connection to it. Filled in
//! from the `DescribeDBInstances` API, i.e. what `aws rds describe-db-instances
//! --db-instance-identifier <id>` reports.
struct RdsInstanceInfo {
	string endpoint_address;
	int32_t endpoint_port = 0;
	//! The engine the instance runs, e.g. 'postgres', 'aurora-postgresql', 'mysql' or 'oracle-se2'.
	//! Only the Postgres-flavored ones can be attached; see RdsEngineIsPostgres.
	string engine;
	string engine_version;
	//! The instance's initial database, which may be unset - RDS does not require one.
	string db_name;
	string master_username;
	string status;
	bool iam_auth_enabled = false;
};

//! Whether an RDS engine speaks the Postgres wire protocol, i.e. whether the postgres extension
//! can connect to it. Covers both 'postgres' (RDS for PostgreSQL) and 'aurora-postgresql'.
bool RdsEngineIsPostgres(const string &engine);

struct Rds {
	//! Register the 'rds' storage extension, which is what makes `ATTACH '<instance-id>' (TYPE rds)`
	//! resolve here.
	static void RegisterStorageExtension(ExtensionLoader &loader);

	//! Look up a DB instance by identifier via the RDS `DescribeDBInstances` API. Throws when the
	//! instance does not exist or exposes no endpoint (e.g. while it is still being created).
	static RdsInstanceInfo DescribeDBInstance(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
	                                          const string &instance_id, const string &region);

	//! Mint a short-lived (15 minute) IAM authentication token for `db_user` on the given endpoint,
	//! to be used as the database password. Unlike Redshift's GetClusterCredentialsWithIAM this is
	//! not an API call: the token is a request to the endpoint presigned with the AWS identity the
	//! provider holds, so the database user must already exist and be granted `rds_iam`.
	//! See https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html
	static string GenerateAuthToken(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
	                                const string &host, int32_t port, const string &region, const string &db_user);
};

} // namespace duckdb
