#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <memory>

namespace duckdb {

class ExtensionLoader;

enum class RedshiftTargetType : uint8_t {
	PROVISIONED_CLUSTER,
	PROVISIONED_NAMESPACE,
	SERVERLESS_NAMESPACE,
	SERVERLESS_WORKGROUP,
};

//! The Redshift target metadata needed to open a Postgres-protocol connection.
//! `credential_target` is a cluster identifier for provisioned Redshift and a workgroup
//! name for Redshift Serverless.
struct RedshiftTargetInfo {
	string credential_target;
	string endpoint_address;
	int32_t endpoint_port = 0;
	string db_name;
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
	static RedshiftTargetInfo DescribeCluster(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
	                                          const string &cluster_id, const string &region);

	//! Resolve a provisioned Redshift namespace ARN's account/resource components to the cluster
	//! identifier whose ClusterNamespaceArn matches. DescribeClusters is paginated when necessary.
	static string ClusterIdentifierFromNamespace(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
	                                             const string &account_id, const string &resource,
	                                             const string &region);

	//! Mint temporary database credentials for a cluster via `GetClusterCredentialsWithIAM`. The
	//! provider supplies (and signs with) the AWS identity; the returned credentials are scoped to
	//! the cluster and short-lived (see duration_seconds, default ~900s).
	static RedshiftIamCredentials
	GetClusterCredentials(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider, const string &cluster_id,
	                      const string &db_name, const string &region, int duration_seconds);
};

struct RedshiftServerless {
	//! Resolve a workgroup or namespace ARN resource ID to the single workgroup endpoint that serves it.
	static RedshiftTargetInfo ResolveTarget(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
	                                        const string &account_id, RedshiftTargetType target_type,
	                                        const string &resource_id, const string &region);

	//! Request temporary database credentials for a Serverless workgroup via GetCredentials.
	static RedshiftIamCredentials GetCredentials(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
	                                             const string &workgroup_name, const string &db_name,
	                                             const string &region, int duration_seconds);
};

} // namespace duckdb
