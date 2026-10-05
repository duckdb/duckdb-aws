#include "redshift/redshift_utils.hpp"

#include "aws_client.hpp"

#include "duckdb/common/exception.hpp"

#include <aws/redshift-serverless/RedshiftServerlessClient.h>
#include <aws/redshift-serverless/model/GetCredentialsRequest.h>
#include <aws/redshift-serverless/model/GetNamespaceRequest.h>
#include <aws/redshift-serverless/model/ListNamespacesRequest.h>
#include <aws/redshift-serverless/model/ListWorkgroupsRequest.h>

namespace duckdb {

namespace {

using RedshiftServerlessClient = Aws::RedshiftServerless::RedshiftServerlessClient;
using Namespace = Aws::RedshiftServerless::Model::Namespace;
using Workgroup = Aws::RedshiftServerless::Model::Workgroup;

RedshiftServerlessClient MakeClient(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                    const string &region) {
	Aws::Client::ClientConfiguration config = BuildClientConfigWithCa();
	config.region = region;
	return RedshiftServerlessClient(provider, config);
}

Namespace FindNamespaceById(RedshiftServerlessClient &client, const string &account_id, const string &resource_id,
                            const string &region) {
	Aws::RedshiftServerless::Model::ListNamespacesRequest request;
	while (true) {
		auto outcome = client.ListNamespaces(request);
		if (!outcome.IsSuccess()) {
			throw InvalidConfigurationException(
			    "ListNamespaces failed while resolving Redshift Serverless namespace '%s' in account '%s' and region "
			    "'%s': %s",
			    resource_id, account_id, region, string(outcome.GetError().GetMessage().c_str()));
		}
		for (const auto &namespace_info : outcome.GetResult().GetNamespaces()) {
			if (namespace_info.GetNamespaceId() == resource_id.c_str()) {
				return namespace_info;
			}
		}
		auto next_token = outcome.GetResult().GetNextToken();
		if (next_token.empty()) {
			break;
		}
		request.SetNextToken(next_token);
	}
	throw InvalidConfigurationException(
	    "No Redshift Serverless namespace found for resource '%s' in account '%s' and region '%s'", resource_id,
	    account_id, region);
}

Namespace GetNamespaceByName(RedshiftServerlessClient &client, const string &namespace_name, const string &region) {
	Aws::RedshiftServerless::Model::GetNamespaceRequest request;
	request.SetNamespaceName(namespace_name.c_str());
	auto outcome = client.GetNamespace(request);
	if (!outcome.IsSuccess()) {
		throw InvalidConfigurationException(
		    "GetNamespace failed for Redshift Serverless namespace '%s' in region '%s': %s", namespace_name, region,
		    string(outcome.GetError().GetMessage().c_str()));
	}
	return outcome.GetResult().GetNamespace();
}

Workgroup FindWorkgroupById(RedshiftServerlessClient &client, const string &account_id, const string &resource_id,
                            const string &region) {
	Aws::RedshiftServerless::Model::ListWorkgroupsRequest request;
	while (true) {
		auto outcome = client.ListWorkgroups(request);
		if (!outcome.IsSuccess()) {
			throw InvalidConfigurationException("ListWorkgroups failed while resolving Redshift Serverless target in "
			                                    "account '%s' and region '%s': %s",
			                                    account_id, region, string(outcome.GetError().GetMessage().c_str()));
		}
		for (const auto &workgroup : outcome.GetResult().GetWorkgroups()) {
			if (workgroup.GetWorkgroupId() == resource_id.c_str()) {
				return workgroup;
			}
		}
		auto next_token = outcome.GetResult().GetNextToken();
		if (next_token.empty()) {
			break;
		}
		request.SetNextToken(next_token);
	}
	throw InvalidConfigurationException(
	    "No Redshift Serverless workgroup found for resource '%s' in account '%s' and region '%s'", resource_id,
	    account_id, region);
}

Workgroup FindWorkgroupByNamespace(RedshiftServerlessClient &client, const string &namespace_name,
                                   const string &region) {
	Aws::RedshiftServerless::Model::ListWorkgroupsRequest request;
	while (true) {
		auto outcome = client.ListWorkgroups(request);
		if (!outcome.IsSuccess()) {
			throw InvalidConfigurationException(
			    "ListWorkgroups failed while resolving Redshift Serverless namespace '%s' in region '%s': %s",
			    namespace_name, region, string(outcome.GetError().GetMessage().c_str()));
		}
		for (const auto &workgroup : outcome.GetResult().GetWorkgroups()) {
			if (workgroup.GetNamespaceName() == namespace_name.c_str()) {
				return workgroup;
			}
		}
		auto next_token = outcome.GetResult().GetNextToken();
		if (next_token.empty()) {
			break;
		}
		request.SetNextToken(next_token);
	}
	throw InvalidConfigurationException("Redshift Serverless namespace '%s' has no associated workgroup in region '%s'",
	                                    namespace_name, region);
}

} // namespace

RedshiftTargetInfo RedshiftServerless::ResolveTarget(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                                     const string &account_id, RedshiftTargetType target_type,
                                                     const string &resource_id, const string &region) {
	auto client = MakeClient(provider, region);
	Namespace namespace_info;
	Workgroup workgroup;
	if (target_type == RedshiftTargetType::SERVERLESS_NAMESPACE) {
		namespace_info = FindNamespaceById(client, account_id, resource_id, region);
		auto namespace_name = string(namespace_info.GetNamespaceName().c_str());
		workgroup = FindWorkgroupByNamespace(client, namespace_name, region);
	} else if (target_type == RedshiftTargetType::SERVERLESS_WORKGROUP) {
		workgroup = FindWorkgroupById(client, account_id, resource_id, region);
		namespace_info = GetNamespaceByName(client, string(workgroup.GetNamespaceName().c_str()), region);
	} else {
		throw InternalException("Invalid target type passed to Redshift Serverless resolution");
	}

	RedshiftTargetInfo info;
	info.credential_target = string(workgroup.GetWorkgroupName().c_str());
	info.endpoint_address = string(workgroup.GetEndpoint().GetAddress().c_str());
	info.endpoint_port = workgroup.GetEndpoint().GetPort();
	info.db_name = string(namespace_info.GetDbName().c_str());
	if (info.endpoint_address.empty() || info.endpoint_port == 0) {
		throw InvalidConfigurationException("Redshift Serverless workgroup '%s' has no endpoint to connect to",
		                                    info.credential_target);
	}
	return info;
}

RedshiftIamCredentials
RedshiftServerless::GetCredentials(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                   const string &workgroup_name, const string &db_name, const string &region,
                                   int duration_seconds) {
	auto client = MakeClient(provider, region);
	Aws::RedshiftServerless::Model::GetCredentialsRequest request;
	request.SetWorkgroupName(workgroup_name.c_str());
	if (!db_name.empty()) {
		request.SetDbName(db_name.c_str());
	}
	if (duration_seconds > 0) {
		request.SetDurationSeconds(duration_seconds);
	}

	auto outcome = client.GetCredentials(request);
	if (!outcome.IsSuccess()) {
		throw InvalidConfigurationException("GetCredentials failed for Redshift Serverless workgroup '%s': %s",
		                                    workgroup_name, string(outcome.GetError().GetMessage().c_str()));
	}

	const auto &result = outcome.GetResult();
	RedshiftIamCredentials credentials;
	credentials.db_user = string(result.GetDbUser().c_str());
	credentials.db_password = string(result.GetDbPassword().c_str());
	credentials.expiration = string(result.GetExpiration().ToGmtString(Aws::Utils::DateFormat::ISO_8601).c_str());
	return credentials;
}

} // namespace duckdb
