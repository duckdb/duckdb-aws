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
		auto source = "aws_system_tables(" + (region.empty() ? string() : "region := " + Value(region).ToSQLString()) +
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
// Enables a family of system tables: `type` names the resource type the family is the inventory of
// (see aws_system_table_families), `region` is required and names the one region it is enabled in,
// and a family may need a scope, `bucket` for S3 Metadata. The handle is the family, its region and
// scope. Only the S3 Metadata family can be enabled with the AWS SDK this extension links; the Glue
// catalog export and Athena need PutDataCatalogExportConfiguration and CreateSystemTableConfiguration,
// which arrived in aws-sdk-cpp after the version the vcpkg port pins.
//===--------------------------------------------------------------------===//

const char *S3_METADATA_FAMILY = "s3-metadata";
const char *S3_BUCKET_TYPE = "aws:s3:bucket";

unique_ptr<FunctionData> CreateBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                    vector<Identifier> &names) {
	auto result = make_uniq<AdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

Value FamilyHandle(const string &family, const string &type, const string &region, const string &bucket,
                   const string &secret) {
	vector<Value> keys {Value("family"), Value("type"), Value("region")};
	vector<Value> values {Value(family), Value(type), Value(region)};
	if (!bucket.empty()) {
		keys.emplace_back("bucket");
		values.emplace_back(bucket);
	}
	if (!secret.empty()) {
		keys.emplace_back("secret");
		values.emplace_back(secret);
	}
	return Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
}

void CreateFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<AdapterState>();
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();
	if (state.ran) {
		return;
	}
	state.ran = true;
	auto type = MapLookup(bind.input, "type");
	auto region = MapLookup(bind.input, "region");
	auto bucket = MapLookup(bind.input, "bucket");
	auto secret = MapLookup(bind.input, "secret");
	if (type.empty()) {
		throw InvalidInputException("aws:system-table create: TYPE is required, the resource type whose system tables "
		                            "to enable (see aws_system_table_families())");
	}
	if (region.empty()) {
		throw InvalidInputException(
		    "aws:system-table create: REGION is required, system tables are enabled per region");
	}
	if (type != S3_BUCKET_TYPE) {
		auto known = RunSQL(context,
		                    "SELECT count(*) FROM aws_system_table_families() WHERE resource_type = " +
		                        Value(type).ToSQLString(),
		                    "aws:system-table create");
		if (known->Collection().GetRows().GetValue(0, 0).GetValue<int64_t>() == 0) {
			throw InvalidInputException("aws:system-table create: no system tables are known for type '%s'; "
			                            "aws_system_table_families() lists the known ones",
			                            type);
		}
		throw NotImplementedException("aws:system-table create: enabling the system tables of '%s' needs an AWS SDK "
		                              "newer than the one this extension was built with; enable them in the owning "
		                              "service (see aws_system_table_families()) and they are listed by "
		                              "SHOW ALL EXTERNAL RESOURCES",
		                              type);
	}
	if (bucket.empty()) {
		throw InvalidInputException("aws:system-table create: BUCKET is required for '%s', the general purpose bucket "
		                            "whose objects the journal and inventory tables describe",
		                            type);
	}
	string sql = "SELECT table_bucket_arn FROM s3_create_bucket_metadata_configuration(" + Value(bucket).ToSQLString() +
	             ", region := " + Value(region).ToSQLString() + SecretKwarg(secret, true) + ")";
	RunSQL(context, sql, "aws:system-table create");
	output.data[0].SetValue(0, FamilyHandle(S3_METADATA_FAMILY, type, region, bucket, secret));
	output.SetCardinality(1);
}

//===--------------------------------------------------------------------===//
// status(handle MAP) -> TABLE(state VARCHAR, result MAP)
//
// A table handle (`arn`): the table exists or it does not; found, it is 'ready'. A family handle
// (`family`, `region`, scope): 'enabling' while the service is still creating or backfilling its
// tables, 'ready' once the journal table is ACTIVE, with the state of each table in the result.
// Either attaches as the aws-* bucket through the 'arn' storage route (iceberg, endpoint_type
// s3_tables) with the namespace as the default schema, so `ATTACH TO EXTERNAL RESOURCE t AS c`
// makes the tables reachable as c.<name>.
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
		auto secret = MapLookup(bind.input, "secret");
		if (arn_string.empty()) {
			if (MapLookup(bind.input, "family") != S3_METADATA_FAMILY) {
				throw InvalidInputException("aws:system-table status: handle has neither 'arn' nor a known 'family'");
			}
			auto bucket = MapLookup(bind.input, "bucket");
			auto region = MapLookup(bind.input, "region");
			// the journal table is what the configuration always creates: ACTIVE means the family is usable; the
			// inventory, when enabled, keeps BACKFILLING for a while and is reported, not waited for
			auto sql = "SELECT CASE WHEN journal_status = 'ACTIVE' THEN 'ready' ELSE 'enabling' END AS state, "
			           "MAP {'uri': table_bucket_arn, 'attached_db_type': 'arn', 'default_schema': namespace, "
			           "'journal': coalesce(journal_status, ''), 'inventory': coalesce(inventory_status, 'disabled')} "
			           "AS result FROM s3_bucket_metadata_configuration(" +
			           Value(bucket).ToSQLString() + ", region := " + Value(region).ToSQLString() +
			           SecretKwarg(secret, true) + ")";
			state.result = RunSQL(context, sql, "aws:system-table status");
			if (state.result->RowCount() == 0) {
				throw IOException("aws:system-table status: bucket '%s' in '%s' has no S3 Metadata configuration "
				                  "(destroyed outside DuckDB?)",
				                  bucket, region);
			}
			state.ran = true;
			EmitRows(state, output);
			return;
		}
		auto arn = ParseTableArn(arn_string, "aws:system-table status");
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

//===--------------------------------------------------------------------===//
// destroy(handle MAP) -> TABLE(status VARCHAR)
//
// Turns a family off so that there is no system table for it anymore: for S3 Metadata that is
// DeleteBucketMetadataConfiguration, and S3 deletes the bucket's journal and inventory tables with
// it. The objects in the general purpose bucket are untouched, as is everything else in aws-s3.
// A table handle, a row found by SHOW ALL EXTERNAL RESOURCES, is refused: a system table is not
// deleted on its own, its family is.
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
	auto &bind = data_p.bind_data->Cast<AdapterBindData>();
	if (state.ran) {
		return;
	}
	state.ran = true;
	if (!MapLookup(bind.input, "arn").empty()) {
		throw InvalidInputException("aws:system-table destroy: a system table is not deleted on its own; destroy the "
		                            "resource that enabled its family, or disable the family in the owning service");
	}
	if (MapLookup(bind.input, "family") != S3_METADATA_FAMILY) {
		throw InvalidInputException("aws:system-table destroy: handle has no known 'family'");
	}
	auto sql = "SELECT status FROM s3_delete_bucket_metadata_configuration(" +
	           Value(MapLookup(bind.input, "bucket")).ToSQLString() +
	           ", region := " + Value(MapLookup(bind.input, "region")).ToSQLString() +
	           SecretKwarg(MapLookup(bind.input, "secret"), true) + ")";
	auto res = RunSQL(context, sql, "aws:system-table destroy");
	output.data[0].SetValue(0, res->Collection().GetRows().GetValue(0, 0));
	output.SetCardinality(1);
}

} // namespace

void SystemTablesResource::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	loader.RegisterFunction(TableFunction("__aws__system_table__create", {map_vv}, CreateFun, CreateBind, AdapterInit));
	loader.RegisterFunction(TableFunction("__aws__system_table__status", {map_vv}, StatusFun, StatusBind, AdapterInit));
	loader.RegisterFunction(TableFunction("__aws__system_table__list", {map_vv}, ListFun, ListBind, AdapterInit));
	loader.RegisterFunction(
	    TableFunction("__aws__system_table__destroy", {map_vv}, DestroyFun, DestroyBind, AdapterInit));

	// No resolve: the account is the registry of these tables, and a bucket attaches by ARN without a local name.
	ExternalResourceType type;
	type.name = SYSTEM_TABLE_TYPE;
	type.kind = "catalog";
	type.create_function = "__aws__system_table__create";
	type.status_function = "__aws__system_table__status";
	type.destroy_function = "__aws__system_table__destroy";
	type.list_function = "__aws__system_table__list";
	type.origin = "extension";
	ExternalResourceTypeRegistry::Get(loader.GetDatabaseInstance()).Add(std::move(type));
}

} // namespace duckdb
