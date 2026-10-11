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

	// https://github.com/aws/aws-sdk-cpp/issues/861#issuecomment-386643571
	// Aws::String token = rdsClient.GenerateConnectAuthToken(hostname.c_str(), aws_region.c_str(),
	// static_cast<unsigned>(port_int), username.c_str());

	uint64_t expiration_seconds = 900; // 15 min, this value is fixed, also used on consumer side
	string host_and_port = host + ":" + std::to_string(port);
	string host_and_port_with_prefix = "http://" + host_and_port;
	string host_and_port_with_suffix = host_and_port + "/";
	Aws::Http::URI uri(host_and_port_with_prefix.c_str());
	uri.AddQueryStringParameter("Action", "connect");
	uri.AddQueryStringParameter("DBUser", db_user.c_str());
	auto token = rds_client.GeneratePresignedUrl(uri, Aws::Http::HttpMethod::HTTP_GET, region.c_str(), "rds-db",
	                                             static_cast<long long>(expiration_seconds));
	Aws::Utils::StringUtils::Replace(token, host_and_port_with_prefix.c_str(), host_and_port_with_suffix.c_str());

	return string(token.c_str());
}

int32_t Rds::ParsePort(const std::string &port_str) {
	try {
		return std::stoi(port_str);
	} catch (const std::exception &) {
		throw InvalidInputException("'PORT' must be an integer, got '%s'", port_str);
	}
}

} // namespace duckdb
