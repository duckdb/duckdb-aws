#include "rds/rds_utils.hpp"

#include "aws_client.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <aws/rds/RDSClient.h>
#include <aws/rds/model/DescribeDBInstancesRequest.h>

namespace duckdb {

namespace {

Aws::RDS::RDSClient MakeClient(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                               const string &region) {
	Aws::Client::ClientConfiguration config = BuildClientConfigWithCa();
	config.region = region;
	return Aws::RDS::RDSClient(provider, config);
}

} // namespace

bool RdsEngineIsPostgres(const string &engine) {
	auto lower = StringUtil::Lower(engine);
	return lower == "postgres" || lower == "aurora-postgresql";
}

RdsInstanceInfo Rds::DescribeDBInstance(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                        const string &instance_id, const string &region) {
	auto rds_client = MakeClient(provider, region);

	Aws::RDS::Model::DescribeDBInstancesRequest request;
	request.SetDBInstanceIdentifier(instance_id.c_str());

	auto outcome = rds_client.DescribeDBInstances(request);
	if (!outcome.IsSuccess()) {
		throw InvalidConfigurationException("DescribeDBInstances failed for RDS instance '%s' in region '%s': %s",
		                                    instance_id, region, string(outcome.GetError().GetMessage().c_str()));
	}

	// The identifier is unique within an account+region, so a successful lookup by identifier
	// returns exactly one instance.
	auto &instances = outcome.GetResult().GetDBInstances();
	if (instances.empty()) {
		throw InvalidConfigurationException("No RDS instance named '%s' found in region '%s'", instance_id, region);
	}
	auto &instance = instances.front();

	RdsInstanceInfo info;
	info.endpoint_address = string(instance.GetEndpoint().GetAddress().c_str());
	info.endpoint_port = instance.GetEndpoint().GetPort();
	info.engine = string(instance.GetEngine().c_str());
	info.engine_version = string(instance.GetEngineVersion().c_str());
	info.db_name = string(instance.GetDBName().c_str());
	info.master_username = string(instance.GetMasterUsername().c_str());
	info.status = string(instance.GetDBInstanceStatus().c_str());
	info.iam_auth_enabled = instance.GetIAMDatabaseAuthenticationEnabled();

	// An instance only has an endpoint once it is available; a stopped/creating instance describes
	// fine but cannot be connected to. Report the status rather than letting the connect fail
	// against an empty host.
	if (info.endpoint_address.empty()) {
		throw InvalidConfigurationException("RDS instance '%s' has no endpoint to connect to (instance status: '%s')",
		                                    instance_id, info.status);
	}
	return info;
}

string Rds::GenerateAuthToken(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider, const string &host,
                              int32_t port, const string &region, const string &db_user) {
	auto rds_client = MakeClient(provider, region);
	auto token =
	    rds_client.GenerateConnectAuthToken(host.c_str(), region.c_str(), static_cast<unsigned>(port), db_user.c_str());
	if (token.empty()) {
		throw InvalidConfigurationException(
		    "Could not generate an RDS IAM authentication token for user '%s' on '%s'. The AWS credentials in the "
		    "secret could not be resolved",
		    db_user, host);
	}
	return string(token.c_str());
}

} // namespace duckdb
