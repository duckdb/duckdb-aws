#include "system_tables_resource.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/external_resource_type_registry.hpp"
#include "duckdb/main/query_result.hpp"

namespace duckdb {

static constexpr const char *SYSTEM_TABLE_TYPE = "aws:system-table";

namespace {

//! The same SQL-adapter shape as s3tables_resource.cpp: every callback is a query over the public
//! aws_system_tables / s3tables_* functions.

struct AdapterBindData : public TableFunctionData {
	Value input; // params (list) or handle (status)
};

struct AdapterState : public GlobalTableFunctionState {
	unique_ptr<QueryResult> result;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> AdapterInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<AdapterState>();
}

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

unique_ptr<QueryResult> RunSQL(ClientContext &context, const string &sql, const char *callback) {
	Connection con(DatabaseInstance::GetDatabase(context));
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("%s failed: %s", callback, res->GetError());
	}
	return res;
}

string SecretKwarg(const string &secret_name, bool leading_comma) {
	if (secret_name.empty()) {
		return string();
	}
	return string(leading_comma ? ", " : "") + "secret := " + Value(secret_name).ToSQLString();
}

//! A table ARN, arn:<partition>:s3tables:<region>:<account>:bucket/<bucket>/table/<id>, split into
//! the bucket ARN the listing functions take and the bucket name the path starts with.
struct TableArn {
	string raw;
	string bucket_arn;
	string bucket;
};

TableArn ParseTableArn(const string &arn, const char *callback) {
	static const string bucket_marker = ":bucket/";
	static const string table_marker = "/table/";
	auto bucket_pos = arn.find(bucket_marker);
	auto table_pos = arn.find(table_marker);
	if (!StringUtil::StartsWith(arn, "arn:") || arn.find(":s3tables:") == string::npos || bucket_pos == string::npos ||
	    table_pos == string::npos || table_pos < bucket_pos || table_pos + table_marker.size() >= arn.size()) {
		throw InvalidInputException(
		    "%s: expected a table ARN of the form "
		    "'arn:<partition>:s3tables:<region>:<account>:bucket/<bucket>/table/<id>', got '%s'",
		    callback, arn);
	}
	TableArn result;
	result.raw = arn;
	result.bucket_arn = arn.substr(0, table_pos);
	result.bucket = arn.substr(bucket_pos + bucket_marker.size(), table_pos - bucket_pos - bucket_marker.size());
	return result;
}

//! The listing's row: the handle is the table ARN alone, the name is the path.
const char *ROW_SQL = "MAP {'arn': table_arn} AS handle, bucket || '/' || namespace || '/' || name AS name, "
                      "table_arn AS reference, 'ready' AS state";

const char *METADATA_SQL =
    "MAP {'region': region, 'bucket': bucket, 'namespace': namespace, 'table': name, 'service': service, "
    "'type': coalesce(type, ''), 'managed_by_service': coalesce(managed_by_service, ''), "
    "'created_at': coalesce(created_at, ''), 'modified_at': coalesce(modified_at, '')} AS metadata";

void EmitRows(AdapterState &state, DataChunk &output) {
	idx_t total = state.result->RowCount();
	idx_t to_emit = MinValue<idx_t>(total - state.cursor, STANDARD_VECTOR_SIZE);
	auto rows = state.result->Collection().GetRows();
	for (idx_t i = 0; i < to_emit; i++) {
		for (idx_t col = 0; col < output.ColumnCount(); col++) {
			output.data[col].SetValue(i, rows.GetValue(col, state.cursor + i));
		}
	}
	output.SetCardinality(to_emit);
	state.cursor += to_emit;
}

void AddListColumns(vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);
	names.emplace_back("handle");
	return_types.emplace_back(map_vv);
	names.emplace_back("name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("reference");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("state");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("metadata");
	return_types.emplace_back(map_vv);
}

//===--------------------------------------------------------------------===//
// list(params MAP) -> TABLE(handle MAP, name VARCHAR, reference VARCHAR, state VARCHAR, metadata MAP)
//
// Every table of every aws-* bucket, in `region` or in all default regions. A region or bucket
// that could not be listed is left out: the list contract has no per-row error channel.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> ListBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                  vector<Identifier> &names) {
	auto result = make_uniq<AdapterBindData>();
	result->input = input.inputs[0];
	AddListColumns(return_types, names);
	return std::move(result);
}

void ListFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<AdapterState>();
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();
	if (!state.ran) {
		auto region = MapLookup(bind.input, "region");
		auto secret = MapLookup(bind.input, "secret");
		auto source = "aws_system_tables(" + (region.empty() ? string() : Value(region).ToSQLString()) +
		              SecretKwarg(secret, !region.empty()) + ")";
		state.result = RunSQL(context,
		                      "SELECT " + string(ROW_SQL) + ", " + METADATA_SQL + " FROM " + source +
		                          " WHERE error IS NULL ORDER BY region, bucket, namespace, name",
		                      "aws:system-table list");
		state.ran = true;
	}
	EmitRows(state, output);
}

//===--------------------------------------------------------------------===//
// create(params MAP) -> TABLE(handle MAP)
//
// Enabling a family of system tables is a configuration call in the owning service, in one region
// (see aws_system_table_families). Not implemented yet: the registry requires a create callback, so
// this one says so instead of silently doing nothing.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> CreateBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                    vector<Identifier> &names) {
	auto result = make_uniq<AdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

void CreateFun(ClientContext &, TableFunctionInput &, DataChunk &) {
	throw NotImplementedException("aws:system-table: enabling a family of system tables from DuckDB is not supported "
	                              "yet; enable it in the owning service (see aws_system_table_families()) and it is "
	                              "listed by SHOW ALL EXTERNAL RESOURCES");
}

//===--------------------------------------------------------------------===//
// status(handle MAP) -> TABLE(state VARCHAR, result MAP)
//
// The table exists or it does not; found, it is 'ready'. It attaches as its bucket through the
// 'arn' storage route (iceberg, endpoint_type s3_tables) with the namespace as the default schema,
// so `ATTACH TO EXTERNAL RESOURCE t AS c` makes the table reachable as c.<name>.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> StatusBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                    vector<Identifier> &names) {
	auto result = make_uniq<AdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("state");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("result");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

void StatusFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<AdapterState>();
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();
	if (!state.ran) {
		auto arn_string = MapLookup(bind.input, "arn");
		if (arn_string.empty()) {
			throw InvalidInputException("aws:system-table status: handle is missing 'arn'");
		}
		auto arn = ParseTableArn(arn_string, "aws:system-table status");
		auto secret = MapLookup(bind.input, "secret");
		auto sql = "SELECT 'ready' AS state, MAP {'uri': " + Value(arn.bucket_arn).ToSQLString() +
		           ", 'attached_db_type': 'arn', 'default_schema': namespace} AS result FROM s3tables_tables(" +
		           Value(arn.bucket_arn).ToSQLString() + SecretKwarg(secret, true) +
		           ") WHERE table_arn = " + Value(arn.raw).ToSQLString();
		state.result = RunSQL(context, sql, "aws:system-table status");
		if (state.result->RowCount() == 0) {
			throw IOException("aws:system-table status: no table with ARN '%s' in bucket '%s'", arn.raw, arn.bucket);
		}
		state.ran = true;
	}
	EmitRows(state, output);
}

} // namespace

void SystemTablesResource::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	loader.RegisterFunction(TableFunction("__aws__system_table__create", {map_vv}, CreateFun, CreateBind, AdapterInit));
	loader.RegisterFunction(TableFunction("__aws__system_table__status", {map_vv}, StatusFun, StatusBind, AdapterInit));
	loader.RegisterFunction(TableFunction("__aws__system_table__list", {map_vv}, ListFun, ListBind, AdapterInit));

	// No destroy, and create refuses: enabling a family of system tables is a service configuration call in
	// one region (see aws_system_table_families), to be added with the clients it needs. No resolve either:
	// the account is the registry of these tables, and a bucket attaches by ARN without a local name.
	ExternalResourceType type;
	type.name = SYSTEM_TABLE_TYPE;
	type.kind = "catalog";
	type.create_function = "__aws__system_table__create";
	type.status_function = "__aws__system_table__status";
	type.list_function = "__aws__system_table__list";
	type.origin = "extension";
	ExternalResourceTypeRegistry::Get(loader.GetDatabaseInstance()).Add(std::move(type));
}

} // namespace duckdb
