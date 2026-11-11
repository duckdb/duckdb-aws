#include "s3tables_resource.hpp"

#include "utils/utils.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/external_resource_type_registry.hpp"
#include "duckdb/main/query_result.hpp"

namespace duckdb {

//! The external-resource type name, also stamped as a tag on every bucket this recipe creates, so
//! s3tables_table_bucket_tags shows which buckets DuckDB made after the process that made them is gone.
static constexpr const char *S3TABLES_TYPE = "aws:s3tables:table-bucket";
static constexpr const char *RESOURCE_TYPE_TAG = "duckdb-external-resource-type";

namespace {

//! Thin native adapters over the public s3tables_* functions, run as SQL on an internal connection
//! — the same shape as src/quack_on_ec2_resource.cpp, so a recipe stays readable as the sequence of
//! calls it is. Nothing here is a SQL macro: the type is registered from C++, so `LOAD aws` is all
//! a user needs.

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

//! The handle: one key, the ARN. It already encodes partition, region, account and name, so there
//! is nothing to keep in sync — and `list` can emit a byte-identical handle, which is what lets
//! discovery match an externally-listed bucket against a locally managed one.
Value HandleForArn(const string &arn) {
	vector<Value> keys {Value("arn")};
	vector<Value> values {Value(arn)};
	return Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
}

string HandleArn(const Value &handle, const char *callback) {
	auto arn = MapLookup(handle, "arn");
	if (arn.empty()) {
		throw InvalidInputException("%s: handle is missing 'arn'", callback);
	}
	return arn;
}

unique_ptr<QueryResult> RunSQL(ClientContext &context, const string &sql, const char *callback) {
	Connection con(DatabaseInstance::GetDatabase(context));
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("%s failed: %s", callback, res->GetError());
	}
	return res;
}

//! 12 hex characters, for a default bucket name. S3 Tables bucket names are 3-63 characters of
//! lowercase letters, digits and hyphens, so 'duckdb-<12hex>' is always valid.
string ShortRandHex() {
	auto uuid_str = UUID::ToString(UUID::GenerateRandomUUID());
	return uuid_str.substr(0, 8) + uuid_str.substr(9, 4);
}

//===--------------------------------------------------------------------===//
// create(params MAP) -> TABLE(handle MAP)
//
// CreateTableBucket is synchronous, so this returns the handle of a bucket that already exists.
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
	vector<Value> tag_values {Value(string(S3TABLES_TYPE))};
	auto tags = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(tag_keys), std::move(tag_values));

	auto sql = "SELECT handle FROM s3tables_create_table_bucket(" + Value(name).ToSQLString();
	if (!region.empty()) {
		sql += ", region := " + Value(region).ToSQLString();
	}
	sql += ", tags := " + tags.ToSQLString() + ")";

	auto res = RunSQL(context, sql, "s3tables create");
	auto handle = res->Collection().GetRows().GetValue(0, 0);
	// An empty ARN can mean a shadowing SQL macro or a lost response body (e.g. a 2xx PUT).
	// Reject it here rather than passing an unusable handle to status.
	if (MapLookup(handle, "arn").empty()) {
		throw IOException(
		    "s3tables create: s3tables_create_table_bucket returned an empty ARN for '%s'. "
		    "If an AWS create request was sent, "
		    "the bucket may already exist; list it with s3tables_table_buckets() and adopt it with REGISTER "
		    "EXTERNAL RESOURCE",
		    name);
	}
	output.data[0].Append(handle);
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// status(handle MAP) -> TABLE(state VARCHAR, result MAP)
//
// There is no provisioning to wait for: a table bucket either exists or it does not, so a
// successful GetTableBucket *is* 'ready'. The callback is not therefore pointless — it is the
// adoption path too, since REGISTER EXTERNAL RESOURCE skips create and resolves a user-supplied
// handle through here, and a bad ARN has to fail now rather than at first query.
//
// `uri` is the ARN and `attached_db_type` is 'arn': this extension registers the "arn" storage
// extension, so one front door decides how an S3 Tables ARN attaches (iceberg with
// endpoint_type=s3_tables) instead of that knowledge being duplicated here.
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
	auto arn = HandleArn(bind.input, "s3tables status");

	auto sql = "SELECT 'ready' AS state, MAP {'uri': arn, 'attached_db_type': 'arn'} AS result "
	           "FROM s3tables_get_table_bucket(" +
	           Value(arn).ToSQLString() + ")";
	auto res = RunSQL(context, sql, "s3tables status");
	auto rows = res->Collection().GetRows();
	output.data[0].Append(rows.GetValue(0, 0));
	output.data[1].Append(rows.GetValue(1, 0));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// destroy(handle MAP) -> TABLE(status VARCHAR)
//
// DeleteTableBucket only succeeds on an empty bucket. Resource teardown never deletes tables or
// namespaces and never seals the bucket; cascading requires an explicit
// s3tables_delete_table_bucket call with cascade := true.
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
	auto arn = HandleArn(bind.input, "s3tables destroy");

	auto sql =
	    "SELECT status FROM s3tables_delete_table_bucket(" + HandleForArn(arn).ToSQLString() + ", cascade := false)";
	auto res = RunSQL(context, sql, "s3tables destroy");
	output.data[0].Append(res->Collection().GetRows().GetValue(0, 0));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// list(params MAP) -> TABLE(handle MAP, name VARCHAR, reference VARCHAR, state VARCHAR, metadata MAP)
//
// Every table bucket in the account, not just the ones DuckDB made — that asymmetry with
// quack-on-ec2 (which filters its stacks by provenance tag) is the point: for S3 Tables the
// pre-existing buckets are the interesting ones, and this is what makes them show up in
// SHOW ALL EXTERNAL RESOURCES as unmanaged rows ready to be REGISTERed.
//
// An optional `region` param lists one region; otherwise every default region is swept in
// parallel. Regions that answer with an error (S3 Tables is not offered everywhere, and opted-out
// regions deny outright) come back as sentinel rows and are dropped here — the framework's list
// contract has no per-row error channel to report them through.
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
	names.emplace_back("name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("reference");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("state");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("metadata");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

//! The columns list and resolve share. A table bucket exists or it does not, so its state is always 'ready'.
const char *BUCKET_ROW_SQL = "MAP {'arn': arn} AS handle, name, arn AS reference, 'ready' AS state";

//! Emit the next vector of the buffered rows, one output column per result column.
void EmitRows(ListState &state, DataChunk &output) {
	idx_t total = state.result->RowCount();
	idx_t remaining = total - state.cursor;
	idx_t to_emit = MinValue<idx_t>(remaining, STANDARD_VECTOR_SIZE);
	auto rows = state.result->Collection().GetRows();
	for (idx_t i = 0; i < to_emit; i++) {
		idx_t row = state.cursor + i;
		for (idx_t col = 0; col < output.ColumnCount(); col++) {
			output.data[col].Append(rows.GetValue(col, row));
		}
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

void ListFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<ListState>();
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();

	if (!state.ran) {
		auto region = MapLookup(bind.input, "region");
		string source =
		    region.empty() ? "s3tables_table_buckets()" : "s3tables_table_buckets(" + Value(region).ToSQLString() + ")";
		auto sql = "SELECT " + string(BUCKET_ROW_SQL) +
		           ",     MAP {'region': region, 'name': name, 'type': type, 'created_at': created_at, "
		           "            'owner_account_id': owner_account_id} AS metadata "
		           "FROM " +
		           source + " WHERE error IS NULL";
		state.result = RunSQL(context, sql, "s3tables list");
		state.ran = true;
	}
	EmitRows(state, output);
}

//===--------------------------------------------------------------------===//
// resolve(name VARCHAR) -> TABLE(handle MAP, name VARCHAR, reference VARCHAR, state VARCHAR)
//
// The table buckets called `name`, so a bucket seen in SHOW ALL EXTERNAL RESOURCES can be
// REGISTERed by name. There is no get-by-name API and a bucket name is only unique within a
// region, so a bare name filters the sweep and can match several; an ARN names one bucket and is
// fetched directly.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> ResolveBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                     vector<Identifier> &names) {
	auto result = make_uniq<AdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("reference");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("state");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

void ResolveFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<ListState>();
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();

	if (!state.ran) {
		if (bind.input.IsNull()) {
			throw InvalidInputException("s3tables resolve: the name must not be NULL");
		}
		auto name = StringValue::Get(bind.input);
		auto name_sql = Value(name).ToSQLString();
		string source = StringUtil::StartsWith(name, "arn:")
		                    ? "s3tables_get_table_bucket(" + name_sql + ")"
		                    : "s3tables_table_buckets() WHERE error IS NULL AND name = " + name_sql;
		state.result = RunSQL(context, "SELECT " + string(BUCKET_ROW_SQL) + " FROM " + source, "s3tables resolve");
		state.ran = true;
	}
	EmitRows(state, output);
}

} // namespace

void S3TablesResource::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	TableFunction create_fn("__aws__s3tables__table_bucket__create", {map_vv}, CreateFun, CreateBind, AdapterInit);
	loader.RegisterFunction(create_fn);
	TableFunction status_fn("__aws__s3tables__table_bucket__status", {map_vv}, StatusFun, StatusBind, AdapterInit);
	loader.RegisterFunction(status_fn);
	TableFunction destroy_fn("__aws__s3tables__table_bucket__destroy", {map_vv}, DestroyFun, DestroyBind, AdapterInit);
	loader.RegisterFunction(destroy_fn);
	TableFunction list_fn("__aws__s3tables__table_bucket__list", {map_vv}, ListFun, ListBind, ListInit);
	loader.RegisterFunction(list_fn);
	TableFunction resolve_fn("__aws__s3tables__table_bucket__resolve", {LogicalType::VARCHAR}, ResolveFun, ResolveBind,
	                         ListInit);
	loader.RegisterFunction(resolve_fn);

	ExternalResourceType type;
	type.name = S3TABLES_TYPE;
	type.kind = "catalog";
	type.create_function = "__aws__s3tables__table_bucket__create";
	type.status_function = "__aws__s3tables__table_bucket__status";
	type.destroy_function = "__aws__s3tables__table_bucket__destroy";
	type.resolve_function = "__aws__s3tables__table_bucket__resolve";
	type.list_function = "__aws__s3tables__table_bucket__list";
	type.origin = "extension";
	ExternalResourceTypeRegistry::Get(loader.GetDatabaseInstance()).Add(std::move(type));
}

} // namespace duckdb
