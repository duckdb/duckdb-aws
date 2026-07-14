#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <memory>

namespace duckdb {

class ExtensionLoader;

//! The subset of a Redshift cluster description that we need to open a Postgres-protocol
//! connection to it. Filled in from the `DescribeClusters` API.
struct RedshiftClusterInfo {
	string endpoint_address;
	int32_t endpoint_port = 0;
	string db_name;
	string master_username;
	string cluster_status;
};

//! Short-lived database credentials minted by `GetClusterCredentialsWithIAM`.
struct RedshiftIamCredentials {
	string db_user;
	string db_password;
	string expiration;
};

struct Redshift {
	//! Register the 'redshift' storage extension, which is what makes
	static void RegisterStorageExtension(ExtensionLoader &loader);

	//! Look up a cluster by identifier via the Redshift `DescribeClusters` API. Throws when the
	//! cluster does not exist or exposes no endpoint (e.g. while it is still being created).
	static RedshiftClusterInfo DescribeCluster(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
	                                           const string &cluster_id, const string &region);

	//! Mint temporary database credentials for a cluster via `GetClusterCredentialsWithIAM`. The
	//! provider supplies (and signs with) the AWS identity; the returned credentials are scoped to
	//! the cluster and short-lived (see duration_seconds, default ~900s).
	static RedshiftIamCredentials
	GetClusterCredentials(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider, const string &cluster_id,
	                      const string &db_name, const string &region, int duration_seconds);
};

} // namespace duckdb
