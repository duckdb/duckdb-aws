#include "system_tables_functions.hpp"

#include "utils/utils.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/query_result.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"

namespace duckdb {

namespace {

//! Everything here is SQL over the s3tables_* functions, run on an internal connection: the system
//! tables are ordinary S3 tables in the account's AWS-managed buckets, and composing by name keeps
//! them mockable (a macro of the same name stands in for AWS in tests) and consumable from other
//! extensions without linking anything.

unique_ptr<QueryResult> RunSQL(ClientContext &context, const string &sql, const char *fn_name) {
	Connection con(DatabaseInstance::GetDatabase(context));
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("%s failed: %s", fn_name, res->GetError());
	}
	return res;
}

string StringParam(TableFunctionBindInput &input, const char *key) {
	for (auto &np : input.named_parameters) {
		if (StringUtil::Lower(np.first.GetIdentifierName()) == key && !np.second.IsNull()) {
			return StringValue::Get(np.second);
		}
	}
	return string();
}

//! `, secret := '<name>'` when a secret was named, else nothing; appended inside a call's parentheses.
string SecretKwarg(const string &secret_name, bool leading_comma) {
	if (secret_name.empty()) {
		return string();
	}
	return string(leading_comma ? ", " : "") + "secret := " + Value(secret_name).ToSQLString();
}

//! AWS-managed table buckets are named aws-<service>: aws-s3, aws-catalog, aws-athena, aws-redshift, ...
string ServiceOf(const string &bucket) {
	static const string prefix = "aws-";
	return StringUtil::StartsWith(bucket, prefix) ? bucket.substr(prefix.size()) : string();
}

//===--------------------------------------------------------------------===//
// aws_system_tables([region := | regions := ] [, secret := ])
//
// Every table of every AWS-managed table bucket (ListTableBuckets type 'aws', then ListTables),
// one row per table, with `error` set instead on a region or bucket that could not be listed.
// `region` lists one region, its errors thrown; `regions` a list of them; neither sweeps the default
// regions, as s3tables_table_buckets does.
//===--------------------------------------------------------------------===//

struct SystemTablesBindData : public TableFunctionData {
	//! NULL for the sweep, a VARCHAR region, or a LIST of regions; passed through to s3tables_table_buckets
	Value regions;
	string secret_name;
};

struct SystemTablesState : public GlobalTableFunctionState {
	vector<vector<Value>> rows;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> SystemTablesInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<SystemTablesState>();
}

unique_ptr<FunctionData> SystemTablesBind(ClientContext &, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<SystemTablesBindData>();
	for (auto &np : input.named_parameters) {
		auto key = StringUtil::Lower(np.first.GetIdentifierName());
		if ((key == "region" || key == "regions") && !np.second.IsNull()) {
			if (!result->regions.IsNull()) {
				throw InvalidInputException("aws_system_tables: pass either region := or regions :=, not both");
			}
			result->regions = np.second;
		}
	}
	result->secret_name = StringParam(input, "secret");

	for (auto &col : {"region", "bucket", "bucket_arn", "service", "namespace", "name", "table_arn", "type",
	                  "managed_by_service", "created_at", "modified_at", "error"}) {
		names.emplace_back(col);
		return_types.emplace_back(LogicalType::VARCHAR);
	}
	return std::move(result);
}

void SystemTablesFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<SystemTablesBindData>();
	auto &state = data_p.global_state->Cast<SystemTablesState>();

	if (!state.ran) {
		state.ran = true;
		auto buckets_sql = "SELECT region, arn, name, error FROM s3tables_table_buckets(" +
		                   (data.regions.IsNull() ? string() : data.regions.ToSQLString()) +
		                   SecretKwarg(data.secret_name, !data.regions.IsNull()) +
		                   ") WHERE error IS NOT NULL OR type = 'aws' ORDER BY region, name";
		auto buckets = RunSQL(context, buckets_sql, "aws_system_tables");
		auto bucket_rows = buckets->Collection().GetRows();
		for (idx_t i = 0; i < buckets->RowCount(); i++) {
			auto region = bucket_rows.GetValue(0, i);
			auto arn = bucket_rows.GetValue(1, i);
			auto bucket = bucket_rows.GetValue(2, i);
			auto error = bucket_rows.GetValue(3, i);
			Value null_value(LogicalType::VARCHAR);
			if (!error.IsNull()) {
				state.rows.push_back({region, null_value, null_value, null_value, null_value, null_value, null_value,
				                      null_value, null_value, null_value, null_value, error});
				continue;
			}
			auto service = Value(ServiceOf(StringValue::Get(bucket)));
			auto tables_sql = "SELECT namespace, name, type, table_arn, managed_by_service, created_at, modified_at "
			                  "FROM s3tables_tables(" +
			                  arn.ToSQLString() + SecretKwarg(data.secret_name, true) + ") ORDER BY namespace, name";
			unique_ptr<QueryResult> tables;
			try {
				tables = RunSQL(context, tables_sql, "aws_system_tables");
			} catch (std::exception &ex) {
				// one bucket the caller may not read must not hide the others
				state.rows.push_back({region, bucket, arn, service, null_value, null_value, null_value, null_value,
				                      null_value, null_value, null_value, Value(ErrorData(ex).RawMessage())});
				continue;
			}
			auto table_rows = tables->Collection().GetRows();
			for (idx_t j = 0; j < tables->RowCount(); j++) {
				state.rows.push_back({region, bucket, arn, service, table_rows.GetValue(0, j),
				                      table_rows.GetValue(1, j), table_rows.GetValue(3, j), table_rows.GetValue(2, j),
				                      table_rows.GetValue(4, j), table_rows.GetValue(5, j), table_rows.GetValue(6, j),
				                      null_value});
			}
		}
	}

	idx_t count = MinValue<idx_t>(state.rows.size() - state.cursor, STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < count; i++) {
		auto &row = state.rows[state.cursor + i];
		for (idx_t col = 0; col < output.ColumnCount(); col++) {
			output.data[col].SetValue(i, row[col]);
		}
	}
	output.SetCardinality(count);
	state.cursor += count;
}

//===--------------------------------------------------------------------===//
// aws_system_table(bucket, namespace, name [, region := , secret := ])
//
// Scans one system table: the bucket's current metadata location for the table, read with
// iceberg_scan. `bucket` is a bucket name, found in `region` (default: the usual region
// resolution), or a table bucket ARN, which carries its own region. The data files are plain S3
// objects, so the S3 secret that signs the scan is the usual one.
//===--------------------------------------------------------------------===//

unique_ptr<TableRef> SystemTableBindReplace(ClientContext &context, TableFunctionBindInput &input) {
	for (idx_t i = 0; i < 3; i++) {
		if (input.inputs[i].IsNull()) {
			throw InvalidInputException("aws_system_table: bucket, namespace and name must not be NULL");
		}
	}
	auto bucket = StringValue::Get(input.inputs[0]);
	auto namespace_name = StringValue::Get(input.inputs[1]);
	auto name = StringValue::Get(input.inputs[2]);
	auto secret_name = StringParam(input, "secret");

	string bucket_arn;
	if (StringUtil::StartsWith(bucket, "arn:")) {
		bucket_arn = bucket;
	} else {
		auto region = ResolveAwsRegion(context, StringParam(input, "region"), "");
		if (region.empty()) {
			throw InvalidInputException("aws_system_table: no region for bucket '%s': pass region := '<region>' or set "
			                            "s3_region, AWS_REGION or the profile's region",
			                            bucket);
		}
		auto sql = "SELECT arn FROM s3tables_table_buckets(" + Value(region).ToSQLString() +
		           SecretKwarg(secret_name, true) + ") WHERE name = " + Value(bucket).ToSQLString();
		auto res = RunSQL(context, sql, "aws_system_table");
		if (res->RowCount() == 0) {
			throw InvalidInputException("aws_system_table: no table bucket '%s' in region '%s'", bucket, region);
		}
		bucket_arn = res->Collection().GetRows().GetValue(0, 0).ToString();
	}

	auto sql = "SELECT metadata_location FROM s3tables_table_metadata_location(" + Value(bucket_arn).ToSQLString() +
	           ", " + Value(namespace_name).ToSQLString() + ", " + Value(name).ToSQLString() +
	           SecretKwarg(secret_name, true) + ")";
	auto res = RunSQL(context, sql, "aws_system_table");
	auto location = res->Collection().GetRows().GetValue(0, 0);
	if (location.IsNull()) {
		throw IOException("aws_system_table: '%s.%s' in %s has no metadata yet (the table is still being created)",
		                  namespace_name, name, bucket_arn);
	}

	Parser parser(context);
	parser.ParseQuery("SELECT * FROM iceberg_scan(" + location.ToSQLString() + ")");
	auto select = unique_ptr_cast<SQLStatement, SelectStatement>(std::move(parser.statements[0]));
	return make_uniq<SubqueryRef>(std::move(select));
}

//===--------------------------------------------------------------------===//
// aws_system_table_families()
//
// The known families of system tables: which service writes them, where they land, and which
// external resource type they are the inventory of. The enable callbacks are what a
// `CREATE EXTERNAL RESOURCE 'aws:system-table'` will run; none is filled in yet.
//===--------------------------------------------------------------------===//

struct FamilyRow {
	const char *family;
	const char *bucket;
	const char *namespace_pattern;
	const char *table_pattern;
	const char *resource_type;
	const char *enabled_by;
};

const FamilyRow FAMILIES[] = {
    {"glue-catalog-export", "aws-catalog", "glue", "%", "aws:glue", "glue PutDataCatalogExportConfiguration"},
    {"glue-catalog-export", "aws-catalog", "catalog_metadata", "%", "aws:glue",
     "glue PutDataCatalogExportConfiguration"},
    {"s3-metadata", "aws-s3", "b\\_%", "journal", "aws:s3:bucket", "s3 CreateBucketMetadataConfiguration"},
    {"s3-metadata", "aws-s3", "b\\_%", "inventory", "aws:s3:bucket", "s3 CreateBucketMetadataConfiguration"},
    {"s3-metadata", "aws-s3", "b\\_%", "annotation", "aws:s3:bucket", "s3 CreateBucketMetadataConfiguration"},
    {"athena-system-tables", "aws-athena", "metadata", "%", "aws:athena", "athena CreateSystemTableConfiguration"},
    {"redshift-system-tables", "aws-redshift", "%", "sys\\_%", "aws:redshift", "redshift EnableLogging s3table"},
    {"cloudwatch-logs", "aws-cloudwatch", "logs", "%", "aws:cloudwatch", "observabilityadmin CreateS3TableIntegration"},
};

struct FamiliesState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<GlobalTableFunctionState> FamiliesInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<FamiliesState>();
}

unique_ptr<FunctionData> FamiliesBind(ClientContext &, TableFunctionBindInput &, vector<LogicalType> &return_types,
                                      vector<Identifier> &names) {
	for (auto &col :
	     {"family", "bucket", "namespace_pattern", "table_pattern", "resource_type", "enabled_by", "enable_function"}) {
		names.emplace_back(col);
		return_types.emplace_back(LogicalType::VARCHAR);
	}
	return make_uniq<TableFunctionData>();
}

void FamiliesFun(ClientContext &, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<FamiliesState>();
	if (state.done) {
		return;
	}
	idx_t count = sizeof(FAMILIES) / sizeof(FAMILIES[0]);
	for (idx_t i = 0; i < count; i++) {
		auto &f = FAMILIES[i];
		output.data[0].SetValue(i, Value(f.family));
		output.data[1].SetValue(i, Value(f.bucket));
		output.data[2].SetValue(i, Value(f.namespace_pattern));
		output.data[3].SetValue(i, Value(f.table_pattern));
		output.data[4].SetValue(i, Value(f.resource_type));
		output.data[5].SetValue(i, Value(f.enabled_by));
		output.data[6].SetValue(i, Value(LogicalType::VARCHAR));
	}
	output.SetCardinality(count);
	state.done = true;
}

} // namespace

void SystemTablesFunctions::Register(ExtensionLoader &loader) {
	auto with_secret = [](TypedKwargs &options) {
		options.Add("secret", LogicalType::VARCHAR);
	};

	FunctionSignature tables_signature;
	tables_signature.WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("region", LogicalType::VARCHAR)
		    .Add("regions", LogicalType::LIST(LogicalType::VARCHAR))
		    .Add("secret", LogicalType::VARCHAR);
	});
	loader.RegisterFunction(TableFunction("aws_system_tables", std::move(tables_signature), SystemTablesFun,
	                                      SystemTablesBind, SystemTablesInit));

	FunctionSignature table_signature;
	table_signature.AddParameter("bucket", LogicalType::VARCHAR)
	    .AddParameter("namespace", LogicalType::VARCHAR)
	    .AddParameter("name", LogicalType::VARCHAR)
	    .WithTypedKwargs("options", [](TypedKwargs &options) {
		    options.Add("region", LogicalType::VARCHAR).Add("secret", LogicalType::VARCHAR);
	    });
	TableFunction table_fn("aws_system_table", std::move(table_signature), nullptr, nullptr, nullptr);
	table_fn.bind_replace = SystemTableBindReplace;
	loader.RegisterFunction(table_fn);

	TableFunction families_fn("aws_system_table_families", {}, FamiliesFun, FamiliesBind, FamiliesInit);
	loader.RegisterFunction(families_fn);
}

} // namespace duckdb
