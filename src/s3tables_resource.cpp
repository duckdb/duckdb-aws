#include "s3tables_resource.hpp"

#include "utils/utils.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/external_resource_type_registry.hpp"
#include "duckdb/main/materialized_query_result.hpp"

namespace duckdb {

//! The external-resource type name, also stamped as a tag on every bucket this recipe creates, so
//! a bucket carries its own provenance: the resource manager's notion of "managed" lives in memory
//! and dies with the process, but the tag survives, and destroy consults it before cascading.
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

unique_ptr<MaterializedQueryResult> RunSQL(ClientContext &context, const string &sql, const char *callback) {
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

	// The resource-type tag is what makes the bucket self-describing: destroy reads it back to
	// decide whether this bucket is ours to empty (see DestroyFun).
	vector<Value> tag_keys {Value(string(RESOURCE_TYPE_TAG))};
	vector<Value> tag_values {Value(string(S3TABLES_TYPE))};
	auto tags = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(tag_keys), std::move(tag_values));

	auto sql = "SELECT handle FROM s3tables_create_table_bucket(" + Value(name).ToSQLString();
	if (!region.empty()) {
		sql += ", region := " + Value(region).ToSQLString();
	}
	sql += ", tags := " + tags.ToSQLString() + ")";

	auto res = RunSQL(context, sql, "s3tables create");
	output.data[0].Append(res->GetValue(0, 0));
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
	output.data[0].Append(res->GetValue(0, 0));
	output.data[1].Append(res->GetValue(1, 0));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// destroy(handle MAP) -> TABLE(status VARCHAR)
//
// DeleteTableBucket only succeeds on an empty bucket, so a bucket with data needs the cascade in
// s3tables_delete_table_bucket (seal, empty, delete). Whether to cascade is NOT a flag someone has
// to remember: it is read off the bucket itself. A bucket carrying this recipe's resource-type tag
// was provisioned by DuckDB and is ours to empty; a bucket that was merely REGISTERed is someone
// else's data, and is deleted only if it is already empty.
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

	auto tag_sql = "SELECT count(*) FROM s3tables_table_bucket_tags(" + Value(arn).ToSQLString() +
	               ") WHERE key = " + Value(string(RESOURCE_TYPE_TAG)).ToSQLString() +
	               " AND value = " + Value(string(S3TABLES_TYPE)).ToSQLString();
	auto tag_res = RunSQL(context, tag_sql, "s3tables destroy");
	auto duckdb_managed = tag_res->GetValue(0, 0).GetValue<int64_t>() > 0;

	auto sql = "SELECT status FROM s3tables_delete_table_bucket(" + HandleForArn(arn).ToSQLString() +
	           ", cascade := " + string(duckdb_managed ? "true" : "false") + ")";
	auto res = RunSQL(context, sql, "s3tables destroy");
	output.data[0].Append(res->GetValue(0, 0));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// list(params MAP) -> TABLE(handle MAP, reference VARCHAR, state VARCHAR, metadata MAP)
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
	unique_ptr<MaterializedQueryResult> result;
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
		string source =
		    region.empty() ? "s3tables_table_buckets()" : "s3tables_table_buckets(" + Value(region).ToSQLString() + ")";
		auto sql = "SELECT MAP {'arn': arn} AS handle, arn AS reference, 'ready' AS state, "
		           "       MAP {'region': region, 'name': name, 'type': type, 'created_at': created_at, "
		           "            'owner_account_id': owner_account_id} AS metadata "
		           "FROM " +
		           source + " WHERE error IS NULL";
		state.result = RunSQL(context, sql, "s3tables list");
		state.ran = true;
	}

	idx_t total = state.result->RowCount();
	idx_t remaining = total - state.cursor;
	idx_t to_emit = MinValue<idx_t>(remaining, STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < to_emit; i++) {
		idx_t row = state.cursor + i;
		output.data[0].Append(state.result->GetValue(0, row));
		output.data[1].Append(state.result->GetValue(1, row));
		output.data[2].Append(state.result->GetValue(2, row));
		output.data[3].Append(state.result->GetValue(3, row));
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
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

	ExternalResourceType type;
	type.name = S3TABLES_TYPE;
	type.kind = "catalog";
	type.create_function = "__aws__s3tables__table_bucket__create";
	type.status_function = "__aws__s3tables__table_bucket__status";
	type.destroy_function = "__aws__s3tables__table_bucket__destroy";
	type.list_function = "__aws__s3tables__table_bucket__list";
	type.origin = "extension";
	ExternalResourceTypeRegistry::Get(loader.GetDatabaseInstance()).Add(std::move(type));
}

} // namespace duckdb
