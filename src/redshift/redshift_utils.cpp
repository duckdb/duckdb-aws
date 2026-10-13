#include "redshift/redshift_utils.hpp"

#include "aws_client.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <aws/redshift/RedshiftClient.h>
#include <aws/redshift/model/DescribeClustersRequest.h>
#include <aws/redshift/model/GetClusterCredentialsWithIAMRequest.h>

namespace duckdb {

namespace {

Aws::Redshift::RedshiftClient MakeClient(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                         const string &region) {
	Aws::Client::ClientConfiguration config = BuildClientConfigWithCa();
	config.region = region;
	return Aws::Redshift::RedshiftClient(provider, config);
}

} // namespace

RedshiftClusterInfo Redshift::DescribeCluster(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                              const string &cluster_id, const string &region) {
	auto redshift_client = MakeClient(provider, region);

	Aws::Redshift::Model::DescribeClustersRequest request;
	request.SetClusterIdentifier(cluster_id.c_str());

	auto outcome = redshift_client.DescribeClusters(request);
	if (!outcome.IsSuccess()) {
		throw InvalidConfigurationException("DescribeClusters failed for Redshift cluster '%s' in region '%s': %s",
		                                    cluster_id, region, string(outcome.GetError().GetMessage().c_str()));
	}

	// The identifier is unique within an account+region, so a successful lookup by identifier
	// returns exactly one cluster.
	auto &clusters = outcome.GetResult().GetClusters();
	if (clusters.empty()) {
		throw InvalidConfigurationException("No Redshift cluster named '%s' found in region '%s'", cluster_id, region);
	}
	auto &cluster = clusters.front();

	RedshiftClusterInfo info;
	info.endpoint_address = string(cluster.GetEndpoint().GetAddress().c_str());
	info.endpoint_port = cluster.GetEndpoint().GetPort();
	info.db_name = string(cluster.GetDBName().c_str());
	info.master_username = string(cluster.GetMasterUsername().c_str());
	info.cluster_status = string(cluster.GetClusterStatus().c_str());

	// A cluster only has an endpoint once it is available; a paused/resuming/creating cluster
	// describes fine but cannot be connected to. Report the status rather than letting the
	// Postgres connect fail against an empty host.
	if (info.endpoint_address.empty()) {
		throw InvalidConfigurationException(
		    "Redshift cluster '%s' has no endpoint to connect to (cluster status: '%s')", cluster_id,
		    info.cluster_status);
	}
	return info;
}

string Redshift::ClusterIdentifierFromNamespace(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                                const string &account_id, const string &resource,
                                                const string &region) {
	auto redshift_client = MakeClient(provider, region);
	Aws::Redshift::Model::DescribeClustersRequest request;
	auto expected_suffix = ":" + account_id + ":" + resource;

	while (true) {
		auto outcome = redshift_client.DescribeClusters(request);
		if (!outcome.IsSuccess()) {
			throw InvalidConfigurationException(
			    "DescribeClusters failed while resolving Redshift namespace '%s' in account '%s' and region '%s': %s",
			    resource, account_id, region, string(outcome.GetError().GetMessage().c_str()));
		}

		for (auto &cluster : outcome.GetResult().GetClusters()) {
			auto namespace_arn = string(cluster.GetClusterNamespaceArn().c_str());
			if (StringUtil::EndsWith(namespace_arn, expected_suffix)) {
				return string(cluster.GetClusterIdentifier().c_str());
			}
		}

		auto marker = outcome.GetResult().GetMarker();
		if (marker.empty()) {
			break;
		}
		request.SetMarker(marker);
	}

	throw InvalidConfigurationException("No Redshift cluster found for namespace '%s' in account '%s' and region '%s'",
	                                    resource, account_id, region);
}

RedshiftIamCredentials
Redshift::GetClusterCredentials(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                const string &cluster_id, const string &db_name, const string &region,
                                int duration_seconds) {
	auto redshift_client = MakeClient(provider, region);

	Aws::Redshift::Model::GetClusterCredentialsWithIAMRequest request;
	request.SetClusterIdentifier(cluster_id.c_str());
	if (!db_name.empty()) {
		request.SetDbName(db_name.c_str());
	}
	if (duration_seconds > 0) {
		request.SetDurationSeconds(duration_seconds);
	}

	auto outcome = redshift_client.GetClusterCredentialsWithIAM(request);
	if (!outcome.IsSuccess()) {
		throw InvalidConfigurationException("GetClusterCredentialsWithIAM failed for Redshift cluster '%s': %s",
		                                    cluster_id, string(outcome.GetError().GetMessage().c_str()));
	}

	auto &api_result = outcome.GetResult();
	RedshiftIamCredentials creds;
	creds.db_user = string(api_result.GetDbUser().c_str());
	creds.db_password = string(api_result.GetDbPassword().c_str());
	creds.expiration = string(api_result.GetExpiration().ToGmtString(Aws::Utils::DateFormat::ISO_8601).c_str());
	return creds;
}

} // namespace duckdb
