#include "redshift/redshift_resource.hpp"

#include "arn.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/external_resource_type_registry.hpp"
#include "duckdb/main/query_result.hpp"

namespace duckdb {

namespace {

//! The same SQL-adapter shape as s3tables_resource.cpp, over the public redshift_clusters and
//! redshift_serverless_workgroups functions. Clusters and workgroups are created and deleted in AWS: create refuses,
//! and without a destroy callback DESTROY forgets the registration and detaches what was attached through it.

//! One of the two types: the listing it is a view of, and which of its columns are the ARN and the name
struct RedshiftResourceType : public TableFunctionInfo {
	RedshiftResourceType(string name_p, string noun_p, string source_p, string arn_service_p, string arn_resource_p,
	                     string arn_column_p, string name_column_p)
	    : name(std::move(name_p)), noun(std::move(noun_p)), source(std::move(source_p)),
	      arn_service(std::move(arn_service_p)), arn_resource(std::move(arn_resource_p)),
	      arn_column(std::move(arn_column_p)), name_column(std::move(name_column_p)) {
	}
	string name;
	string noun;
	string source;
	//! The service and resource prefix of the ARN the handle holds
	string arn_service;
	string arn_resource;
	string arn_column;
	string name_column;
};

struct AdapterBindData : public TableFunctionData {
	AdapterBindData(const RedshiftResourceType &type_p, const Value &input_p) : type(type_p), input(input_p) {
	}
	const RedshiftResourceType &type;
	Value input; // params (create/list) or handle (status)
};

struct AdapterState : public GlobalTableFunctionState {
	unique_ptr<QueryResult> result;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> AdapterInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<AdapterState>();
}

//! Read one key out of a params/handle MAP; "" when absent or NULL.
string MapLookup(const Value &map_value, const string &key) {
	if (map_value.IsNull()) {
		return string();
	}
	for (auto &entry : MapValue::GetChildren(map_value)) {
		auto &kv = StructValue::GetChildren(entry);
		if (!kv[0].IsNull() && StringValue::Get(kv[0]) == key) {
			return kv[1].IsNull() ? string() : StringValue::Get(kv[1]);
		}
	}
	return string();
}

unique_ptr<QueryResult> RunSQL(ClientContext &context, const string &sql, const string &callback) {
	Connection con(DatabaseInstance::GetDatabase(context));
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("%s failed: %s", callback, res->GetError());
	}
	return res;
}

void EmitRows(AdapterState &state, DataChunk &output) {
	idx_t total = state.result->RowCount();
	idx_t to_emit = MinValue<idx_t>(total - state.cursor, STANDARD_VECTOR_SIZE);
	auto rows = state.result->Collection().GetRows();
	for (idx_t row_idx = 0; row_idx < to_emit; row_idx++) {
		for (idx_t col = 0; col < output.ColumnCount(); col++) {
			output.data[col].Append(rows.GetValue(col, state.cursor + row_idx));
		}
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

unique_ptr<FunctionData> AdapterBind(TableFunctionBindInput &input) {
	return make_uniq<AdapterBindData>(input.info->Cast<RedshiftResourceType>(), input.inputs[0]);
}

//===--------------------------------------------------------------------===//
// list(params MAP) -> TABLE(handle MAP, name VARCHAR, reference VARCHAR, state VARCHAR)
//
// Every cluster or workgroup in `region`, or in all default regions. The handle is the ARN, which is also the
// reference: `ATTACH '<reference>'` attaches it. The state is 'ready' while it is available, otherwise its status. A
// region that could not be listed is left out: the list contract has no per-row error channel.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> ListBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                  vector<Identifier> &names) {
	names = {"handle", "name", "reference", "state"};
	return_types = {LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR), LogicalType::VARCHAR,
	                LogicalType::VARCHAR, LogicalType::VARCHAR};
	return AdapterBind(input);
}

void ListFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<AdapterState>();
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();
	auto &type = bind.type;
	if (!state.ran) {
		auto region = MapLookup(bind.input, "region");
		auto sql =
		    StringUtil::Format("SELECT MAP {'arn': %s} AS handle, %s AS name, %s AS reference, "
		                       "CASE WHEN lower(status) = 'available' THEN 'ready' ELSE lower(status) END AS state "
		                       "FROM %s(%s) WHERE error IS NULL ORDER BY region, name",
		                       type.arn_column, type.name_column, type.arn_column, type.source,
		                       region.empty() ? string() : "region := " + Value(region).ToSQLString());
		state.result = RunSQL(context, sql, type.name + " list");
		state.ran = true;
	}
	EmitRows(state, output);
}

//===--------------------------------------------------------------------===//
// status(handle MAP) -> TABLE(state VARCHAR, result MAP)
//
// The handle's ARN, looked up in the region it names, so REGISTER of a wrong ARN fails now. Found, it is 'ready', as
// for the S3 types. The result attaches the ARN through the 'arn' storage type, as `ATTACH '<arn>'` does.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> StatusBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                    vector<Identifier> &names) {
	names = {"state", "result"};
	return_types = {LogicalType::VARCHAR, LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)};
	return AdapterBind(input);
}

void StatusFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<AdapterState>();
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();
	auto &type = bind.type;
	if (!state.ran) {
		auto callback = type.name + " status";
		auto arn_string = MapLookup(bind.input, "arn");
		auto arn = ParsedArn::IsArn(arn_string) ? ParsedArn::Parse(arn_string) : ParsedArn();
		if (arn.service != type.arn_service || arn.region.empty() ||
		    !StringUtil::StartsWith(arn.resource, type.arn_resource) || arn.resource == type.arn_resource) {
			throw InvalidInputException(
			    "%s: expected an ARN of the form 'arn:<partition>:%s:<region>:<account>:%s<id>', got '%s'", callback,
			    type.arn_service, type.arn_resource, arn_string);
		}
		auto sql = StringUtil::Format("SELECT 'ready' AS state, MAP {'uri': %s, 'attached_db_type': 'arn'} AS result "
		                              "FROM %s(region := %s) WHERE %s = %s",
		                              type.arn_column, type.source, Value(arn.region).ToSQLString(), type.arn_column,
		                              Value(arn.raw).ToSQLString());
		state.result = RunSQL(context, sql, callback);
		if (state.result->RowCount() == 0) {
			throw IOException("%s: no %s with ARN '%s' in region '%s'", callback, type.noun, arn.raw, arn.region);
		}
		state.ran = true;
	}
	EmitRows(state, output);
}

//===--------------------------------------------------------------------===//
// create(params MAP) -> TABLE(handle MAP): refused, see the top of the file
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> CreateBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                    vector<Identifier> &names) {
	names = {"handle"};
	return_types = {LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)};
	return AdapterBind(input);
}

void CreateFun(ClientContext &, TableFunctionInput &data_p, DataChunk &) {
	auto &type = data_p.bind_data->Cast<AdapterBindData>().type;
	throw NotImplementedException(
	    "%s create: this extension does not create Redshift %ss; create it in AWS, then "
	    "find it with SHOW ALL EXTERNAL RESOURCES WITH TYPE '%s' and attach it by the reference listed there, or "
	    "REGISTER EXTERNAL RESOURCE '%s' AS <name> FROM MAP {'arn': '<reference>'}",
	    type.name, type.noun, type.name, type.name);
}

void RegisterType(ExtensionLoader &loader, const shared_ptr<RedshiftResourceType> &type, const string &prefix) {
	ExternalResourceType resource_type;
	resource_type.name = type->name;
	resource_type.kind = "catalog";
	resource_type.create_function = prefix + "__create";
	resource_type.status_function = prefix + "__status";
	resource_type.list_function = prefix + "__list";
	resource_type.origin = "extension";

	const auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);
	TableFunction create_fn(Identifier(resource_type.create_function), {map_vv}, CreateFun, CreateBind, AdapterInit);
	TableFunction status_fn(Identifier(resource_type.status_function), {map_vv}, StatusFun, StatusBind, AdapterInit);
	TableFunction list_fn(Identifier(resource_type.list_function), {map_vv}, ListFun, ListBind, AdapterInit);
	for (auto *fn : {&create_fn, &status_fn, &list_fn}) {
		fn->function_info = type;
		loader.RegisterFunction(*fn);
	}
	ExternalResourceTypeRegistry::Get(loader.GetDatabaseInstance()).Add(std::move(resource_type));
}

} // namespace

void RedshiftResource::Register(ExtensionLoader &loader) {
	// A cluster is handled by its namespace ARN: DescribeClusters reports no cluster ARN, and the namespace ARN is the
	// one the 'arn' storage type resolves to the cluster's endpoint
	RegisterType(loader,
	             make_shared_ptr<RedshiftResourceType>("aws.redshift.cluster", "cluster", "redshift_clusters",
	                                                   "redshift", "namespace:", "namespace_arn", "cluster_identifier"),
	             "__aws__redshift__cluster");
	RegisterType(loader,
	             make_shared_ptr<RedshiftResourceType>("aws.redshift-serverless.workgroup", "workgroup",
	                                                   "redshift_serverless_workgroups", "redshift-serverless",
	                                                   "workgroup/", "arn", "workgroup_name"),
	             "__aws__redshift_serverless__workgroup");
}

} // namespace duckdb
