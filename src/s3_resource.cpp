#include "s3_resource.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/external_resource_type_registry.hpp"
#include "duckdb/main/query_result.hpp"

namespace duckdb {

//! The external-resource type name, also stamped as a tag on every bucket this recipe creates, so
//! s3_bucket_tags shows which buckets DuckDB made after the process that made them is gone.
static constexpr const char *S3_BUCKET_TYPE = "aws:s3:bucket";
static constexpr const char *RESOURCE_TYPE_TAG = "duckdb-external-resource-type";

namespace {

//! Thin native adapters over the public s3_* functions, run as SQL on an internal connection: the
//! same shape as s3tables_resource.cpp, so a recipe reads as the sequence of calls it is.

struct AdapterBindData : public TableFunctionData {
	Value input; // params (create/list) or handle (status/destroy)
};

struct AdapterState : public GlobalTableFunctionState {
	bool done = false;
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

//! The handle is `name` plus `region`: an S3 bucket ARN carries no region, and every call after
//! create needs one to start from. `list` emits the same two keys, so discovery can match an
//! externally-listed bucket against a locally managed one.
Value HandleFor(const string &name, const string &region) {
	vector<Value> keys {Value("name"), Value("region")};
	vector<Value> values {Value(name), region.empty() ? Value(LogicalType::VARCHAR) : Value(region)};
	return Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
}

//! Rebuild the handle from the two keys the s3_* functions read, refusing one without a name
//! before any AWS call.
Value CheckedHandle(const Value &handle, const char *callback) {
	auto name = MapLookup(handle, "name");
	if (name.empty()) {
		throw InvalidInputException("%s: handle is missing 'name'", callback);
	}
	return HandleFor(name, MapLookup(handle, "region"));
}

unique_ptr<QueryResult> RunSQL(ClientContext &context, const string &sql, const char *callback) {
	Connection con(DatabaseInstance::GetDatabase(context));
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("%s failed: %s", callback, res->GetError());
	}
	return res;
}

//! 12 hex characters, for a default bucket name. S3 bucket names are 3-63 characters of lowercase
//! letters, digits, hyphens and dots, so 'duckdb-<12hex>' is always valid.
string ShortRandHex() {
	auto uuid_str = UUID::ToString(UUID::GenerateRandomUUID());
	return uuid_str.substr(0, 8) + uuid_str.substr(9, 4);
}

//===--------------------------------------------------------------------===//
// create(params MAP) -> TABLE(handle MAP)
//
// CreateBucket is synchronous, so this returns the handle of a bucket that already exists.
// Params: `name` (defaults to duckdb-<rand>), `region` (defaults to the usual resolution order).
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> CreateBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                    vector<Identifier> &names) {
	auto result = make_uniq<AdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

void CreateFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<AdapterState>();
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();

	auto name = MapLookup(bind.input, "name");
	if (name.empty()) {
		name = "duckdb-" + ShortRandHex();
	}
	auto region = MapLookup(bind.input, "region");

	vector<Value> tag_keys {Value(string(RESOURCE_TYPE_TAG))};
	vector<Value> tag_values {Value(string(S3_BUCKET_TYPE))};
	auto tags = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(tag_keys), std::move(tag_values));

	auto sql = "SELECT handle FROM s3_create_bucket(" + Value(name).ToSQLString();
	if (!region.empty()) {
		sql += ", region := " + Value(region).ToSQLString();
	}
	sql += ", tags := " + tags.ToSQLString() + ")";

	auto res = RunSQL(context, sql, "s3 create");
	output.data[0].Append(res->Collection().GetRows().GetValue(0, 0));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// status(handle MAP) -> TABLE(state VARCHAR, result MAP)
//
// There is no provisioning to wait for: a bucket either exists or it does not, so a successful
// HeadBucket *is* 'ready'. This is also the adoption path: REGISTER EXTERNAL RESOURCE skips create
// and resolves a user-supplied handle through here, so a wrong name has to fail now. The `uri` is
// what a DuckDB reader puts in front of a key; nothing attaches a bucket, so there is no
// `attached_db_type`.
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
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();
	auto handle = CheckedHandle(bind.input, "s3 status");

	auto sql = "SELECT 'ready' AS state, "
	           "MAP {'uri': 's3://' || name || '/', 'arn': arn, 'region': region} AS result "
	           "FROM s3_get_bucket(" +
	           handle.ToSQLString() + ")";
	auto res = RunSQL(context, sql, "s3 status");
	auto rows = res->Collection().GetRows();
	output.data[0].Append(rows.GetValue(0, 0));
	output.data[1].Append(rows.GetValue(1, 0));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// destroy(handle MAP) -> TABLE(status VARCHAR)
//
// DeleteBucket only succeeds on an empty bucket. Resource teardown never empties a bucket;
// deleting its contents requires an explicit s3_delete_bucket call with cascade := true.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> DestroyBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                     vector<Identifier> &names) {
	auto result = make_uniq<AdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("status");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

void DestroyFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<AdapterState>();
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();
	auto handle = CheckedHandle(bind.input, "s3 destroy");

	auto sql = "SELECT status FROM s3_delete_bucket(" + handle.ToSQLString() + ", cascade := false)";
	auto res = RunSQL(context, sql, "s3 destroy");
	output.data[0].Append(res->Collection().GetRows().GetValue(0, 0));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// list(params MAP) -> TABLE(handle MAP, reference VARCHAR, state VARCHAR, metadata MAP)
//
// Every bucket the account owns, not just the ones DuckDB made: the pre-existing buckets are the
// interesting ones, and this is what makes them show up in SHOW ALL EXTERNAL RESOURCES as
// unmanaged rows ready to be REGISTERed. An optional `region` param filters to one region.
//===--------------------------------------------------------------------===//

struct ListState : public GlobalTableFunctionState {
	unique_ptr<QueryResult> result;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> ListInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<ListState>();
}

unique_ptr<FunctionData> ListBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                  vector<Identifier> &names) {
	auto result = make_uniq<AdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("reference");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("state");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("metadata");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

void ListFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<ListState>();
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();

	if (!state.ran) {
		auto region = MapLookup(bind.input, "region");
		string source = region.empty() ? "s3_buckets()" : "s3_buckets(region := " + Value(region).ToSQLString() + ")";
		auto sql = "SELECT MAP {'name': name, 'region': region} AS handle, 's3://' || name || '/' AS reference, "
		           "       'ready' AS state, "
		           "       MAP {'region': region, 'created_at': created_at::VARCHAR} AS metadata "
		           "FROM " +
		           source;
		state.result = RunSQL(context, sql, "s3 list");
		state.ran = true;
	}

	idx_t total = state.result->RowCount();
	idx_t remaining = total - state.cursor;
	idx_t to_emit = MinValue<idx_t>(remaining, STANDARD_VECTOR_SIZE);
	auto rows = state.result->Collection().GetRows();
	for (idx_t i = 0; i < to_emit; i++) {
		idx_t row = state.cursor + i;
		output.data[0].Append(rows.GetValue(0, row));
		output.data[1].Append(rows.GetValue(1, row));
		output.data[2].Append(rows.GetValue(2, row));
		output.data[3].Append(rows.GetValue(3, row));
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

} // namespace

void S3Resource::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	TableFunction create_fn("__aws__s3__bucket__create", {map_vv}, CreateFun, CreateBind, AdapterInit);
	loader.RegisterFunction(create_fn);
	TableFunction status_fn("__aws__s3__bucket__status", {map_vv}, StatusFun, StatusBind, AdapterInit);
	loader.RegisterFunction(status_fn);
	TableFunction destroy_fn("__aws__s3__bucket__destroy", {map_vv}, DestroyFun, DestroyBind, AdapterInit);
	loader.RegisterFunction(destroy_fn);
	TableFunction list_fn("__aws__s3__bucket__list", {map_vv}, ListFun, ListBind, ListInit);
	loader.RegisterFunction(list_fn);

	ExternalResourceType type;
	type.name = S3_BUCKET_TYPE;
	type.kind = "storage";
	type.create_function = "__aws__s3__bucket__create";
	type.status_function = "__aws__s3__bucket__status";
	type.destroy_function = "__aws__s3__bucket__destroy";
	type.list_function = "__aws__s3__bucket__list";
	type.origin = "extension";
	ExternalResourceTypeRegistry::Get(loader.GetDatabaseInstance()).Add(std::move(type));
}

} // namespace duckdb
