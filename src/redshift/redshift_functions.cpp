#include "redshift/redshift_functions.hpp"

#include "aws_client.hpp"
#include "aws_http_client.hpp"
#include "utils/utils.hpp"

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/settings.hpp"
#include "duckdb/parallel/task_executor.hpp"

#include <aws/redshift-serverless/RedshiftServerlessClient.h>
#include <aws/redshift-serverless/model/ListWorkgroupsRequest.h>
#include <aws/redshift-serverless/model/WorkgroupStatus.h>
#include <aws/redshift/RedshiftClient.h>
#include <aws/redshift/model/DescribeClustersRequest.h>

namespace duckdb {

namespace {

using CredentialsProvider = std::shared_ptr<Aws::Auth::AWSCredentialsProvider>;
//! One row per cluster or workgroup: `region` first, the listing's own columns, `error` last
using Rows = vector<vector<Value>>;

string FromAws(const Aws::String &s) {
	return {s.data(), s.size()};
}

Value StringOrNull(bool set, const Aws::String &s) {
	return set ? Value(FromAws(s)) : Value(LogicalType::VARCHAR);
}

Value PortOrNull(bool set, int32_t port) {
	return set ? Value::INTEGER(port) : Value(LogicalType::INTEGER);
}

template <class OUTCOME>
[[noreturn]] void ThrowAwsError(const char *call, const string &region, const OUTCOME &outcome) {
	const auto &error = outcome.GetError();
	throw IOException("%s failed in region '%s': %s - %s", call, region, FromAws(error.GetExceptionName()),
	                  FromAws(error.GetMessage()));
}

Aws::Client::ClientConfiguration ConfigFor(const string &region) {
	auto config = BuildClientConfigWithCa();
	config.region = region.c_str();
	return config;
}

void ListClusters(const CredentialsProvider &provider, const string &region, Rows &rows) {
	Aws::Redshift::RedshiftClient client(provider, ConfigFor(region));
	Aws::Redshift::Model::DescribeClustersRequest request;
	Aws::String marker;
	do {
		if (!marker.empty()) {
			request.SetMarker(marker);
		}
		auto outcome = client.DescribeClusters(request);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("Redshift DescribeClusters", region, outcome);
		}
		for (const auto &cluster : outcome.GetResult().GetClusters()) {
			const auto &endpoint = cluster.GetEndpoint();
			rows.push_back({Value(region),
			                StringOrNull(cluster.ClusterIdentifierHasBeenSet(), cluster.GetClusterIdentifier()),
			                StringOrNull(cluster.ClusterNamespaceArnHasBeenSet(), cluster.GetClusterNamespaceArn()),
			                StringOrNull(cluster.ClusterStatusHasBeenSet(), cluster.GetClusterStatus()),
			                StringOrNull(endpoint.AddressHasBeenSet(), endpoint.GetAddress()),
			                PortOrNull(endpoint.PortHasBeenSet(), endpoint.GetPort()), Value(LogicalType::VARCHAR)});
		}
		marker = outcome.GetResult().GetMarker();
	} while (!marker.empty());
}

void ListWorkgroups(const CredentialsProvider &provider, const string &region, Rows &rows) {
	Aws::RedshiftServerless::RedshiftServerlessClient client(provider, ConfigFor(region));
	Aws::RedshiftServerless::Model::ListWorkgroupsRequest request;
	Aws::String token;
	do {
		if (!token.empty()) {
			request.SetNextToken(token);
		}
		auto outcome = client.ListWorkgroups(request);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("Redshift Serverless ListWorkgroups", region, outcome);
		}
		for (const auto &workgroup : outcome.GetResult().GetWorkgroups()) {
			const auto &endpoint = workgroup.GetEndpoint();
			auto status =
			    Aws::RedshiftServerless::Model::WorkgroupStatusMapper::GetNameForWorkgroupStatus(workgroup.GetStatus());
			rows.push_back({Value(region),
			                StringOrNull(workgroup.WorkgroupNameHasBeenSet(), workgroup.GetWorkgroupName()),
			                StringOrNull(workgroup.WorkgroupArnHasBeenSet(), workgroup.GetWorkgroupArn()),
			                StringOrNull(workgroup.StatusHasBeenSet(), status),
			                StringOrNull(endpoint.AddressHasBeenSet(), endpoint.GetAddress()),
			                PortOrNull(endpoint.PortHasBeenSet(), endpoint.GetPort()), Value(LogicalType::VARCHAR)});
		}
		token = outcome.GetResult().GetNextToken();
	} while (!token.empty());
}

//! What one listing function lists: its name, its columns between `region` and `error`, and the call for one region
struct RedshiftListing : public TableFunctionInfo {
	RedshiftListing(const char *fn_name_p, const char *action_p, vector<pair<string, LogicalType>> columns_p,
	                void (*list_region_p)(const CredentialsProvider &, const string &, Rows &))
	    : fn_name(fn_name_p), action(action_p), columns(std::move(columns_p)), list_region(list_region_p) {
	}
	const char *fn_name;
	const char *action;
	vector<pair<string, LogicalType>> columns;
	void (*list_region)(const CredentialsProvider &provider, const string &region, Rows &rows);
};

struct ListBindData : public TableFunctionData {
	explicit ListBindData(const RedshiftListing &listing_p) : listing(listing_p) {
	}
	const RedshiftListing &listing;
	//! Empty: every default region, with an error row for each that fails
	string region;
	string secret_name;
};

struct ListState : public GlobalTableFunctionState {
	Rows rows;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<FunctionData> ListBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                  vector<Identifier> &names) {
	auto &listing = input.info->Cast<RedshiftListing>();
	auto result = make_uniq<ListBindData>(listing);
	for (auto &np : input.named_parameters) {
		auto key = StringUtil::Lower(np.first.GetIdentifierName());
		if (np.second.IsNull() || StringValue::Get(np.second).empty()) {
			throw InvalidInputException("%s: %s must not be NULL or empty", listing.fn_name, key);
		}
		if (key == "region") {
			result->region = StringValue::Get(np.second);
		} else {
			result->secret_name = StringValue::Get(np.second);
		}
	}
	names.emplace_back("region");
	return_types.emplace_back(LogicalType::VARCHAR);
	for (auto &column : listing.columns) {
		names.emplace_back(column.first);
		return_types.push_back(column.second);
	}
	names.emplace_back("error");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

//! Called from init rather than bind so it also stops statements prepared before enable_external_access was switched
//! off.
unique_ptr<GlobalTableFunctionState> ListInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &data = input.bind_data->Cast<ListBindData>();
	if (!Settings::Get<EnableExternalAccessSetting>(context)) {
		throw PermissionException("%s: %s is disabled through configuration", data.listing.fn_name,
		                          data.listing.action);
	}
	return make_uniq<ListState>();
}

//! One region of a sweep; its error becomes a row rather than aborting the sweep, as in s3tables_functions.cpp.
struct ListRegionTask : public BaseExecutorTask {
	ListRegionTask(TaskExecutor &executor, DatabaseInstance &db_p, const ListBindData &data_p,
	               CredentialsProvider provider_p, string region_p, Rows &slot_p)
	    : BaseExecutorTask(executor), db(db_p), data(data_p), provider(std::move(provider_p)),
	      region(std::move(region_p)), slot(slot_p) {
	}
	void ExecuteTask() override {
		// Scheduler threads do not inherit the caller's AwsInstanceBinding
		AwsInstanceBinding aws_binding(db);
		try {
			data.listing.list_region(provider, region, slot);
		} catch (std::exception &ex) {
			EmitError(ErrorData(ex).RawMessage());
		} catch (...) {
			EmitError("unknown error");
		}
	}
	void EmitError(const string &message) {
		slot.clear();
		vector<Value> row {Value(region)};
		for (auto &column : data.listing.columns) {
			row.emplace_back(column.second);
		}
		row.emplace_back(message);
		slot.push_back(std::move(row));
	}
	DatabaseInstance &db;
	const ListBindData &data;
	CredentialsProvider provider;
	string region;
	Rows &slot;
};

void ListFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<ListBindData>();
	auto &state = data_p.global_state->Cast<ListState>();
	if (!state.ran) {
		state.ran = true;
		auto &db = DatabaseInstance::GetDatabase(context);
		AwsInstanceBinding aws_binding(db);
		auto entry = FindAwsSecret(context, data.secret_name);
		auto provider = CredentialsProviderFromSecret(entry->secret->Cast<KeyValueSecret>(), "Redshift");
		if (!data.region.empty()) {
			data.listing.list_region(provider, data.region, state.rows);
		} else {
			const auto &regions = GetDefaultAwsRegions();
			// Fixed-size, so the tasks' references into it stay valid
			vector<Rows> slots(regions.size());
			TaskExecutor executor(context);
			for (idx_t i = 0; i < regions.size(); i++) {
				executor.ScheduleTask(make_uniq<ListRegionTask>(executor, db, data, provider, regions[i], slots[i]));
			}
			executor.WorkOnTasks();
			for (auto &slot : slots) {
				for (auto &row : slot) {
					state.rows.push_back(std::move(row));
				}
			}
		}
	}
	auto count = MinValue<idx_t>(state.rows.size() - state.cursor, STANDARD_VECTOR_SIZE);
	for (idx_t row_idx = 0; row_idx < count; row_idx++) {
		auto &row = state.rows[state.cursor + row_idx];
		for (idx_t col = 0; col < output.ColumnCount(); col++) {
			output.data[col].Append(row[col]);
		}
	}
	output.CheckCardinality(count);
	state.cursor += count;
}

TableFunction ListingFunction(const char *name, const char *action, vector<pair<string, LogicalType>> columns,
                              void (*list_region)(const CredentialsProvider &, const string &, Rows &)) {
	const auto options = [](TypedKwargs &kwargs) {
		kwargs.Add("region", LogicalType::VARCHAR).Add("secret", LogicalType::VARCHAR);
	};
	TableFunction function(name, FunctionSignature().WithTypedKwargs("options", options), ListFun, ListBind, ListInit);
	function.function_info = make_shared_ptr<RedshiftListing>(name, action, std::move(columns), list_region);
	return function;
}

} // namespace

void RedshiftFunctions::Register(ExtensionLoader &loader) {
	const string regions_doc =
	    "`region` lists one region and throws its error; without it every default region is "
	    "listed in parallel, and a region that cannot be listed becomes one row with `error` set.";
	loader.RegisterFunction(Documented(
	    ListingFunction("redshift_clusters", "listing Redshift clusters",
	                    {{"cluster_identifier", LogicalType::VARCHAR},
	                     {"namespace_arn", LogicalType::VARCHAR},
	                     {"status", LogicalType::VARCHAR},
	                     {"endpoint_address", LogicalType::VARCHAR},
	                     {"endpoint_port", LogicalType::INTEGER}},
	                    ListClusters),
	    "Lists the provisioned Redshift clusters (DescribeClusters) with their namespace ARN, status and endpoint. " +
	        regions_doc,
	    "FROM redshift_clusters(region := 'us-east-1')", "redshift"));
	loader.RegisterFunction(Documented(
	    ListingFunction("redshift_serverless_workgroups", "listing Redshift Serverless workgroups",
	                    {{"workgroup_name", LogicalType::VARCHAR},
	                     {"arn", LogicalType::VARCHAR},
	                     {"status", LogicalType::VARCHAR},
	                     {"endpoint_address", LogicalType::VARCHAR},
	                     {"endpoint_port", LogicalType::INTEGER}},
	                    ListWorkgroups),
	    "Lists the Redshift Serverless workgroups (ListWorkgroups) with their ARN, status and endpoint. " + regions_doc,
	    "FROM redshift_serverless_workgroups(region := 'us-east-1')", "redshift"));
}

} // namespace duckdb
