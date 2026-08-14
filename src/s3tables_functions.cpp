#include "s3tables_functions.hpp"
#include "aws_client.hpp"
#include "utils/utils.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parallel/task_executor.hpp"

#include <aws/core/utils/DateTime.h>
#include <aws/s3tables/S3TablesClient.h>
#include <aws/s3tables/model/CreateTableBucketRequest.h>
#include <aws/s3tables/model/DeleteNamespaceRequest.h>
#include <aws/s3tables/model/DeleteTableBucketPolicyRequest.h>
#include <aws/s3tables/model/DeleteTableBucketRequest.h>
#include <aws/s3tables/model/DeleteTableRequest.h>
#include <aws/s3tables/model/GetTableBucketPolicyRequest.h>
#include <aws/s3tables/model/GetTableBucketRequest.h>
#include <aws/s3tables/model/ListNamespacesRequest.h>
#include <aws/s3tables/model/ListTableBucketsRequest.h>
#include <aws/s3tables/model/ListTablesRequest.h>
#include <aws/s3tables/model/ListTagsForResourceRequest.h>
#include <aws/s3tables/model/PutTableBucketPolicyRequest.h>
#include <aws/s3tables/model/TableBucketType.h>
#include <aws/s3tables/model/TagResourceRequest.h>
#include <aws/s3tables/model/TableType.h>

namespace duckdb {

namespace {

//! See the identically-named helper in cloudformation_functions.cpp: copying by range is exact
//! whether or not the SDK was built with USE_AWS_MEMORY_MANAGEMENT.
string FromAws(const Aws::String &s) {
	return {s.data(), s.size()};
}

string IsoTime(const Aws::Utils::DateTime &dt) {
	return FromAws(dt.ToGmtString(Aws::Utils::DateFormat::ISO_8601));
}

//===--------------------------------------------------------------------===//
// Shared plumbing
//===--------------------------------------------------------------------===//

//! A table bucket ARN, split into the parts the API and the client config need:
//! arn:<partition>:s3tables:<region>:<account>:bucket/<name>
struct TableBucketArn {
	string raw;
	string region;
	string account_id;
	string name;
};

//! Parse and validate a table bucket ARN. Deliberately stricter than arn_storage.cpp's generic
//! ParseArn: every one of these functions needs the region (to build the client) and can only act
//! on a *bucket* resource, so a table ARN or a foreign service is rejected up front with a message
//! naming the function, rather than surfacing later as an opaque AWS error.
TableBucketArn ParseTableBucketArn(const string &arn, const string &fn_name) {
	auto parts = StringUtil::Split(arn, ':');
	// arn : partition : service : region : account : resource — the resource may itself contain ':'
	if (parts.size() < 6 || parts[0] != "arn") {
		throw InvalidInputException("%s: expected a table bucket ARN of the form "
		                            "'arn:<partition>:s3tables:<region>:<account>:bucket/<name>', got '%s'",
		                            fn_name, arn);
	}
	if (StringUtil::Lower(parts[2]) != "s3tables") {
		throw InvalidInputException("%s: '%s' is an ARN for service '%s', not 's3tables'", fn_name, arn, parts[2]);
	}
	TableBucketArn result;
	result.raw = arn;
	result.region = parts[3];
	result.account_id = parts[4];
	if (result.region.empty()) {
		throw InvalidInputException("%s: table bucket ARN '%s' does not specify a region", fn_name, arn);
	}

	static const string prefix = "bucket/";
	auto resource = parts[5];
	if (!StringUtil::StartsWith(resource, prefix) || resource.size() == prefix.size()) {
		throw InvalidInputException("%s: expected a table *bucket* ARN (resource 'bucket/<name>'), got '%s'", fn_name,
		                            arn);
	}
	result.name = resource.substr(prefix.size());
	// A table ARN is '<bucket-arn>/table/<id>' — same resource prefix, so catch it here rather than
	// silently treating the whole tail as a bucket name.
	if (result.name.find('/') != string::npos) {
		throw InvalidInputException("%s: '%s' names an object inside a table bucket, not the bucket itself", fn_name,
		                            arn);
	}
	return result;
}

//! Credentials for an S3 Tables call. A named `secret` must resolve; unnamed, an AWS secret is
//! preferred when the instance has exactly one usable one (the same secret that ATTACH of an
//! s3tables ARN authenticates with, so browsing and attaching never disagree), and the SDK's own
//! chain is the fallback when there is none. FindAwsSecret throws rather than returning null, so
//! the "is there one?" probe is a try/catch.
std::shared_ptr<Aws::Auth::AWSCredentialsProvider> ResolveProvider(ClientContext &context, const string &secret_name) {
	if (!secret_name.empty()) {
		auto entry = FindAwsSecret(context, secret_name);
		auto &secret = dynamic_cast<const KeyValueSecret &>(*entry->secret);
		return CredentialsProviderFromSecret(secret, "S3Tables");
	}
	try {
		auto entry = FindAwsSecret(context, "");
		auto &secret = dynamic_cast<const KeyValueSecret &>(*entry->secret);
		return CredentialsProviderFromSecret(secret, "S3Tables");
	} catch (const std::exception &) {
		// No usable AWS secret: fall back to the environment/profile/instance chain, exactly as the
		// cloudformation_* functions do.
		return BuildAwsCredentialsProvider("", /*require_credentials=*/true);
	}
}

Aws::S3Tables::S3TablesClient MakeClient(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                         const string &region) {
	auto cfg = BuildClientConfigWithCa();
	cfg.region = region.c_str();
	return Aws::S3Tables::S3TablesClient(provider, cfg);
}

//! Uniform "the AWS call failed" error. The exception name is kept because it is what distinguishes
//! the cases callers act on (NotFoundException vs AccessDeniedException vs ConflictException).
template <class OUTCOME>
[[noreturn]] void ThrowAwsError(const char *call, const OUTCOME &outcome) {
	const auto &err = outcome.GetError();
	throw IOException("S3 Tables %s failed: %s - %s", call, FromAws(err.GetExceptionName()), FromAws(err.GetMessage()));
}

//! Read the optional `secret` named parameter shared by every function here.
string SecretParam(TableFunctionBindInput &input) {
	for (auto &np : input.named_parameters) {
		if (StringUtil::Lower(np.first.GetIdentifierName()) == "secret" && !np.second.IsNull()) {
			return StringValue::Get(np.second);
		}
	}
	return string();
}

bool BoolParam(TableFunctionBindInput &input, const char *key, bool default_value) {
	for (auto &np : input.named_parameters) {
		if (StringUtil::Lower(np.first.GetIdentifierName()) == key && !np.second.IsNull()) {
			return BooleanValue::Get(np.second);
		}
	}
	return default_value;
}

//! S3 Tables namespaces are a list in the API but single-level in the service today. Joining with
//! '.' keeps one VARCHAR column that reads like the schema name it becomes once attached, and is
//! what every other API here wants back as the `namespace` argument.
string JoinNamespace(const Aws::Vector<Aws::String> &parts) {
	vector<string> converted;
	for (auto &p : parts) {
		converted.push_back(FromAws(p));
	}
	return StringUtil::Join(converted, ".");
}

//===--------------------------------------------------------------------===//
// s3tables_table_buckets([region | region_list])
//
// ListTableBuckets, paginated. Three overloads mirroring cloudformation_describe_stacks: no
// argument sweeps the default regions in parallel, a single VARCHAR is one region (its error is
// thrown), a LIST(VARCHAR) is those regions in parallel. S3 Tables is not offered in every region,
// so a sweep *will* hit regions that answer with an error - those become one sentinel row each
// (region + error set, everything else NULL) instead of failing the whole listing.
//===--------------------------------------------------------------------===//

struct TableBucketRow {
	string region;
	string arn;
	string name;
	string owner_account_id;
	string table_bucket_id;
	string type;
	string created_at;
	string error;
};

void ListRegionTableBuckets(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider, const string &region,
                            vector<TableBucketRow> &out) {
	auto client = MakeClient(provider, region);

	Aws::String token;
	do {
		Aws::S3Tables::Model::ListTableBucketsRequest req;
		if (!token.empty()) {
			req.SetContinuationToken(token);
		}
		auto outcome = client.ListTableBuckets(req);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("ListTableBuckets", outcome);
		}
		const auto &res = outcome.GetResult();
		for (const auto &bucket : res.GetTableBuckets()) {
			TableBucketRow row;
			row.region = region;
			row.arn = FromAws(bucket.GetArn());
			row.name = FromAws(bucket.GetName());
			row.owner_account_id = FromAws(bucket.GetOwnerAccountId());
			row.table_bucket_id = FromAws(bucket.GetTableBucketId());
			row.type =
			    FromAws(Aws::S3Tables::Model::TableBucketTypeMapper::GetNameForTableBucketType(bucket.GetType()));
			row.created_at = IsoTime(bucket.GetCreatedAt());
			out.push_back(std::move(row));
		}
		token = res.GetContinuationToken();
	} while (!token.empty());
}

//! One region's listing as a scheduler task. It catches its own error instead of calling PushError,
//! which would abort the whole sweep — see the same pattern in cloudformation_functions.cpp.
struct ListRegionTask : public BaseExecutorTask {
	ListRegionTask(TaskExecutor &executor, std::shared_ptr<Aws::Auth::AWSCredentialsProvider> provider_p,
	               string region_p, vector<TableBucketRow> &slot_p)
	    : BaseExecutorTask(executor), provider(std::move(provider_p)), region(std::move(region_p)), slot(slot_p) {
	}
	void ExecuteTask() override {
		try {
			ListRegionTableBuckets(provider, region, slot);
		} catch (const std::exception &e) {
			EmitError(e.what());
		} catch (...) {
			EmitError("unknown error");
		}
	}
	void EmitError(const string &message) {
		slot.clear();
		TableBucketRow err;
		err.region = region;
		err.error = message;
		slot.push_back(std::move(err));
	}
	std::shared_ptr<Aws::Auth::AWSCredentialsProvider> provider;
	string region;
	vector<TableBucketRow> &slot;
};

struct TableBucketsBindData : public TableFunctionData {
	vector<string> regions;
	bool throw_on_region_error = false; // true only for the single-VARCHAR overload
	string secret_name;
};

struct TableBucketsState : public GlobalTableFunctionState {
	vector<TableBucketRow> rows;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> TableBucketsInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<TableBucketsState>();
}

unique_ptr<FunctionData> TableBucketsBind(ClientContext &, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<TableBucketsBindData>();
	result->secret_name = SecretParam(input);

	if (input.inputs.empty()) {
		result->regions = GetDefaultAwsRegions();
	} else if (input.inputs[0].type().id() == LogicalTypeId::LIST) {
		if (input.inputs[0].IsNull()) {
			throw InvalidInputException("s3tables_table_buckets: region list must not be NULL");
		}
		for (auto &child : ListValue::GetChildren(input.inputs[0])) {
			if (child.IsNull()) {
				continue;
			}
			auto r = StringValue::Get(child);
			if (!r.empty()) {
				result->regions.push_back(r);
			}
		}
		if (result->regions.empty()) {
			throw InvalidInputException("s3tables_table_buckets: region list must not be empty");
		}
	} else {
		if (input.inputs[0].IsNull()) {
			throw InvalidInputException("s3tables_table_buckets: region must not be NULL");
		}
		auto r = StringValue::Get(input.inputs[0]);
		if (r.empty()) {
			throw InvalidInputException("s3tables_table_buckets: region must not be empty");
		}
		result->regions.push_back(r);
		result->throw_on_region_error = true;
	}

	names.emplace_back("region");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("arn");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("owner_account_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("table_bucket_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("type");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("created_at");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("error");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

void TableBucketsFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<TableBucketsBindData>();
	auto &state = data_p.global_state->Cast<TableBucketsState>();

	if (!state.ran) {
		auto provider = ResolveProvider(context, data.secret_name);
		if (data.throw_on_region_error) {
			ListRegionTableBuckets(provider, data.regions[0], state.rows);
		} else {
			// Fixed-size `slots` so the vector never reallocates while tasks hold references into it.
			vector<vector<TableBucketRow>> slots(data.regions.size());
			TaskExecutor executor(context);
			for (idx_t i = 0; i < data.regions.size(); i++) {
				executor.ScheduleTask(make_uniq<ListRegionTask>(executor, provider, data.regions[i], slots[i]));
			}
			executor.WorkOnTasks();
			for (auto &slot : slots) {
				for (auto &row : slot) {
					state.rows.push_back(std::move(row));
				}
			}
		}
		state.ran = true;
	}

	idx_t remaining = state.rows.size() - state.cursor;
	idx_t to_emit = MinValue<idx_t>(remaining, STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < to_emit; i++) {
		auto &r = state.rows[state.cursor + i];
		// arn is always set for a real bucket and empty on an error sentinel, so empty -> NULL
		// distinguishes the two row kinds without a separate flag column.
		output.data[0].Append(Value(r.region));
		output.data[1].Append(r.arn.empty() ? Value() : Value(r.arn));
		output.data[2].Append(r.name.empty() ? Value() : Value(r.name));
		output.data[3].Append(r.owner_account_id.empty() ? Value() : Value(r.owner_account_id));
		output.data[4].Append(r.table_bucket_id.empty() ? Value() : Value(r.table_bucket_id));
		output.data[5].Append(r.type.empty() ? Value() : Value(r.type));
		output.data[6].Append(r.created_at.empty() ? Value() : Value(r.created_at));
		output.data[7].Append(r.error.empty() ? Value() : Value(r.error));
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

//===--------------------------------------------------------------------===//
// s3tables_namespaces(table_bucket_arn)
//
// ListNamespaces, paginated. A namespace is what a schema of the attached catalog maps to.
//===--------------------------------------------------------------------===//

struct NamespaceRow {
	string namespace_name;
	string namespace_id;
	string created_at;
	string created_by;
	string owner_account_id;
};

void ListAllNamespaces(Aws::S3Tables::S3TablesClient &client, const string &bucket_arn, vector<NamespaceRow> &out) {
	Aws::String token;
	do {
		Aws::S3Tables::Model::ListNamespacesRequest req;
		req.SetTableBucketARN(bucket_arn.c_str());
		if (!token.empty()) {
			req.SetContinuationToken(token);
		}
		auto outcome = client.ListNamespaces(req);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("ListNamespaces", outcome);
		}
		const auto &res = outcome.GetResult();
		for (const auto &ns : res.GetNamespaces()) {
			NamespaceRow row;
			row.namespace_name = JoinNamespace(ns.GetNamespace());
			row.namespace_id = FromAws(ns.GetNamespaceId());
			row.created_at = IsoTime(ns.GetCreatedAt());
			row.created_by = FromAws(ns.GetCreatedBy());
			row.owner_account_id = FromAws(ns.GetOwnerAccountId());
			out.push_back(std::move(row));
		}
		token = res.GetContinuationToken();
	} while (!token.empty());
}

struct ArnBindData : public TableFunctionData {
	TableBucketArn arn;
	string namespace_filter;
	string secret_name;
};

struct NamespacesState : public GlobalTableFunctionState {
	vector<NamespaceRow> rows;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> NamespacesInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<NamespacesState>();
}

unique_ptr<FunctionData> NamespacesBind(ClientContext &, TableFunctionBindInput &input,
                                        vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<ArnBindData>();
	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("s3tables_namespaces: the table bucket ARN must not be NULL");
	}
	result->arn = ParseTableBucketArn(StringValue::Get(input.inputs[0]), "s3tables_namespaces");
	result->secret_name = SecretParam(input);

	names.emplace_back("namespace");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("namespace_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("created_at");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("created_by");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("owner_account_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

void NamespacesFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<ArnBindData>();
	auto &state = data_p.global_state->Cast<NamespacesState>();

	if (!state.ran) {
		auto provider = ResolveProvider(context, data.secret_name);
		auto client = MakeClient(provider, data.arn.region);
		ListAllNamespaces(client, data.arn.raw, state.rows);
		state.ran = true;
	}

	idx_t remaining = state.rows.size() - state.cursor;
	idx_t to_emit = MinValue<idx_t>(remaining, STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < to_emit; i++) {
		auto &r = state.rows[state.cursor + i];
		output.data[0].Append(Value(r.namespace_name));
		output.data[1].Append(r.namespace_id.empty() ? Value() : Value(r.namespace_id));
		output.data[2].Append(r.created_at.empty() ? Value() : Value(r.created_at));
		output.data[3].Append(r.created_by.empty() ? Value() : Value(r.created_by));
		output.data[4].Append(r.owner_account_id.empty() ? Value() : Value(r.owner_account_id));
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

//===--------------------------------------------------------------------===//
// s3tables_tables(table_bucket_arn [, namespace])
//
// ListTables. With a namespace it is one paginated call; without, every namespace is enumerated
// first and then listed in turn (the API has no all-namespaces form).
//===--------------------------------------------------------------------===//

struct TableRow {
	string namespace_name;
	string name;
	string type;
	string table_arn;
	string created_at;
	string modified_at;
	string managed_by_service;
	string namespace_id;
};

void ListNamespaceTables(Aws::S3Tables::S3TablesClient &client, const string &bucket_arn, const string &ns,
                         vector<TableRow> &out) {
	Aws::String token;
	do {
		Aws::S3Tables::Model::ListTablesRequest req;
		req.SetTableBucketARN(bucket_arn.c_str());
		req.SetNamespace(ns.c_str());
		if (!token.empty()) {
			req.SetContinuationToken(token);
		}
		auto outcome = client.ListTables(req);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("ListTables", outcome);
		}
		const auto &res = outcome.GetResult();
		for (const auto &table : res.GetTables()) {
			TableRow row;
			row.namespace_name = JoinNamespace(table.GetNamespace());
			row.name = FromAws(table.GetName());
			row.type = FromAws(Aws::S3Tables::Model::TableTypeMapper::GetNameForTableType(table.GetType()));
			row.table_arn = FromAws(table.GetTableARN());
			row.created_at = IsoTime(table.GetCreatedAt());
			row.modified_at = IsoTime(table.GetModifiedAt());
			row.managed_by_service = FromAws(table.GetManagedByService());
			row.namespace_id = FromAws(table.GetNamespaceId());
			out.push_back(std::move(row));
		}
		token = res.GetContinuationToken();
	} while (!token.empty());
}

//! Every table in the bucket, or just one namespace's when `ns_filter` is set.
void ListBucketTables(Aws::S3Tables::S3TablesClient &client, const string &bucket_arn, const string &ns_filter,
                      vector<TableRow> &out) {
	if (!ns_filter.empty()) {
		ListNamespaceTables(client, bucket_arn, ns_filter, out);
		return;
	}
	vector<NamespaceRow> namespaces;
	ListAllNamespaces(client, bucket_arn, namespaces);
	for (auto &ns : namespaces) {
		ListNamespaceTables(client, bucket_arn, ns.namespace_name, out);
	}
}

struct TablesState : public GlobalTableFunctionState {
	vector<TableRow> rows;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> TablesInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<TablesState>();
}

unique_ptr<FunctionData> TablesBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                    vector<Identifier> &names) {
	auto result = make_uniq<ArnBindData>();
	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("s3tables_tables: the table bucket ARN must not be NULL");
	}
	result->arn = ParseTableBucketArn(StringValue::Get(input.inputs[0]), "s3tables_tables");
	if (input.inputs.size() > 1) {
		if (input.inputs[1].IsNull()) {
			throw InvalidInputException("s3tables_tables: the namespace must not be NULL");
		}
		result->namespace_filter = StringValue::Get(input.inputs[1]);
		if (result->namespace_filter.empty()) {
			throw InvalidInputException("s3tables_tables: the namespace must not be empty");
		}
	}
	result->secret_name = SecretParam(input);

	names.emplace_back("namespace");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("type");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("table_arn");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("created_at");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("modified_at");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("managed_by_service");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("namespace_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

void TablesFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<ArnBindData>();
	auto &state = data_p.global_state->Cast<TablesState>();

	if (!state.ran) {
		auto provider = ResolveProvider(context, data.secret_name);
		auto client = MakeClient(provider, data.arn.region);
		ListBucketTables(client, data.arn.raw, data.namespace_filter, state.rows);
		state.ran = true;
	}

	idx_t remaining = state.rows.size() - state.cursor;
	idx_t to_emit = MinValue<idx_t>(remaining, STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < to_emit; i++) {
		auto &r = state.rows[state.cursor + i];
		output.data[0].Append(Value(r.namespace_name));
		output.data[1].Append(Value(r.name));
		output.data[2].Append(r.type.empty() ? Value() : Value(r.type));
		output.data[3].Append(r.table_arn.empty() ? Value() : Value(r.table_arn));
		output.data[4].Append(r.created_at.empty() ? Value() : Value(r.created_at));
		output.data[5].Append(r.modified_at.empty() ? Value() : Value(r.modified_at));
		output.data[6].Append(r.managed_by_service.empty() ? Value() : Value(r.managed_by_service));
		output.data[7].Append(r.namespace_id.empty() ? Value() : Value(r.namespace_id));
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

//===--------------------------------------------------------------------===//
// s3tables_create_table_bucket(name [, region := , dry_run := ])
//
// CreateTableBucket is synchronous: it returns the ARN of a bucket that exists. The `handle` column
// is the MAP the external-resource framework would carry — a single 'arn' key, because the ARN
// already encodes partition, region, account and name, and a handle with redundant fields cannot
// drift out of sync with what a listing returns.
//===--------------------------------------------------------------------===//

struct CreateBucketBindData : public TableFunctionData {
	string name;
	string region;
	string secret_name;
	vector<std::pair<string, string>> tags;
	bool dry_run = false;
};

struct OnceState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<GlobalTableFunctionState> OnceInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<OnceState>();
}

unique_ptr<FunctionData> CreateBucketBind(ClientContext &context, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<CreateBucketBindData>();
	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("s3tables_create_table_bucket: the bucket name must not be NULL");
	}
	result->name = StringValue::Get(input.inputs[0]);
	if (result->name.empty()) {
		throw InvalidInputException("s3tables_create_table_bucket: the bucket name must not be empty");
	}
	result->secret_name = SecretParam(input);
	result->dry_run = BoolParam(input, "dry_run", false);
	for (auto &np : input.named_parameters) {
		auto key = StringUtil::Lower(np.first.GetIdentifierName());
		if (key == "region" && !np.second.IsNull()) {
			result->region = StringValue::Get(np.second);
		} else if (key == "tags" && !np.second.IsNull()) {
			for (auto &entry : MapValue::GetChildren(np.second)) {
				auto &kv = StructValue::GetChildren(entry);
				if (kv[0].IsNull()) {
					continue;
				}
				result->tags.emplace_back(StringValue::Get(kv[0]), kv[1].IsNull() ? string() : StringValue::Get(kv[1]));
			}
		}
	}
	// Unlike cloudformation_create_stack (where region is mandatory), fall back to the usual
	// resolution order — an s3tables user has normally already set a region for the S3 secret.
	if (result->region.empty()) {
		result->region = ResolveAwsRegion(context, "", "");
	}
	if (result->region.empty()) {
		throw InvalidInputException(
		    "s3tables_create_table_bucket: no region — pass region := or set s3_region / AWS_REGION");
	}

	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("arn");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("region");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

Value HandleForArn(const string &arn) {
	vector<Value> keys {Value("arn")};
	vector<Value> values {Value(arn)};
	return Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
}

void CreateBucketFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<CreateBucketBindData>();
	auto &state = data_p.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}

	string arn;
	if (data.dry_run) {
		// Nothing above this point mutates; stop here and leave the ARN NULL, since no bucket exists
		// to name (the same contract cloudformation_create_stack's dry_run has).
		state.done = true;
		output.data[0].Append(Value(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)));
		output.data[1].Append(Value());
		output.data[2].Append(Value(data.name));
		output.data[3].Append(Value(data.region));
		output.CheckCardinality(1);
		return;
	}

	auto provider = ResolveProvider(context, data.secret_name);
	auto client = MakeClient(provider, data.region);
	Aws::S3Tables::Model::CreateTableBucketRequest req;
	req.SetName(data.name.c_str());
	// Provenance, so a bucket can say what made it long after this instance is gone — the
	// external-resource manager's own view of "managed" is in-memory and dies with the process.
	// Caller-supplied tags win, so a recipe can stamp its own resource-type tag.
	Aws::Map<Aws::String, Aws::String> tags;
	tags["created-by"] = "duckdb";
	tags["duckdb-version"] = DuckDB::LibraryVersion();
	for (auto &tag : data.tags) {
		tags[tag.first.c_str()] = tag.second.c_str();
	}
	req.SetTags(tags);
	auto outcome = client.CreateTableBucket(req);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("CreateTableBucket", outcome);
	}
	arn = FromAws(outcome.GetResult().GetArn());

	output.data[0].Append(HandleForArn(arn));
	output.data[1].Append(Value(arn));
	output.data[2].Append(Value(data.name));
	output.data[3].Append(Value(data.region));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// s3tables_get_table_bucket(table_bucket_arn)
//
// GetTableBucket: the singular of s3tables_table_buckets, and the cheapest "does this exist and
// can I reach it" probe there is — which is what the resource recipe's status callback needs.
//===--------------------------------------------------------------------===//

struct GetBucketState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<GlobalTableFunctionState> GetBucketInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<GetBucketState>();
}

unique_ptr<FunctionData> GetBucketBind(ClientContext &, TableFunctionBindInput &input,
                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<ArnBindData>();
	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("s3tables_get_table_bucket: the table bucket ARN must not be NULL");
	}
	result->arn = ParseTableBucketArn(StringValue::Get(input.inputs[0]), "s3tables_get_table_bucket");
	result->secret_name = SecretParam(input);

	names.emplace_back("arn");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("region");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("owner_account_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("table_bucket_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("type");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("created_at");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

void GetBucketFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<ArnBindData>();
	auto &state = data_p.global_state->Cast<GetBucketState>();
	if (state.done) {
		return;
	}
	auto provider = ResolveProvider(context, data.secret_name);
	auto client = MakeClient(provider, data.arn.region);
	Aws::S3Tables::Model::GetTableBucketRequest req;
	req.SetTableBucketARN(data.arn.raw.c_str());
	auto outcome = client.GetTableBucket(req);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("GetTableBucket", outcome);
	}
	const auto &res = outcome.GetResult();
	output.data[0].Append(Value(FromAws(res.GetArn())));
	output.data[1].Append(Value(FromAws(res.GetName())));
	output.data[2].Append(Value(data.arn.region));
	output.data[3].Append(Value(FromAws(res.GetOwnerAccountId())));
	output.data[4].Append(Value(FromAws(res.GetTableBucketId())));
	output.data[5].Append(
	    Value(FromAws(Aws::S3Tables::Model::TableBucketTypeMapper::GetNameForTableBucketType(res.GetType()))));
	output.data[6].Append(Value(IsoTime(res.GetCreatedAt())));
	output.CheckCardinality(1);
	state.done = true;
}

//===--------------------------------------------------------------------===//
// s3tables_table_bucket_tags(table_bucket_arn)
//
// ListTagsForResource as (key, value) rows. Tags are how a table bucket carries provenance that
// outlives the process — see the resource-type tag the s3tables recipe stamps at create.
//===--------------------------------------------------------------------===//

struct TagsState : public GlobalTableFunctionState {
	vector<std::pair<string, string>> rows;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> TagsInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<TagsState>();
}

unique_ptr<FunctionData> TagsBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                  vector<Identifier> &names) {
	auto result = make_uniq<ArnBindData>();
	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("s3tables_table_bucket_tags: the table bucket ARN must not be NULL");
	}
	result->arn = ParseTableBucketArn(StringValue::Get(input.inputs[0]), "s3tables_table_bucket_tags");
	result->secret_name = SecretParam(input);

	names.emplace_back("key");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("value");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

void TagsFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<ArnBindData>();
	auto &state = data_p.global_state->Cast<TagsState>();

	if (!state.ran) {
		auto provider = ResolveProvider(context, data.secret_name);
		auto client = MakeClient(provider, data.arn.region);
		Aws::S3Tables::Model::ListTagsForResourceRequest req;
		req.SetResourceArn(data.arn.raw.c_str());
		auto outcome = client.ListTagsForResource(req);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("ListTagsForResource", outcome);
		}
		for (const auto &tag : outcome.GetResult().GetTags()) {
			state.rows.emplace_back(FromAws(tag.first), FromAws(tag.second));
		}
		state.ran = true;
	}

	idx_t remaining = state.rows.size() - state.cursor;
	idx_t to_emit = MinValue<idx_t>(remaining, STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < to_emit; i++) {
		auto &r = state.rows[state.cursor + i];
		output.data[0].Append(Value(r.first));
		output.data[1].Append(Value(r.second));
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

//===--------------------------------------------------------------------===//
// s3tables_delete_table_bucket(arn | handle [, cascade := , seal := , dry_run := ])
//
// DeleteTableBucket only succeeds on an empty bucket — AWS offers no force flag — so emptying it
// is necessarily a client-side cascade, in three steps:
//
//   1. SEAL: put a resource policy that Denies the data-mutating actions, so no concurrent writer
//      can add a table between the enumeration and the final delete (the race that otherwise makes
//      step 3 fail intermittently).
//   2. EMPTY: delete every table, then every namespace.
//   3. DELETE: DeleteTableBucket, which also takes the seal policy with it.
//
// Two deliberate choices in the seal:
//   - It denies *writes* only, never Delete*/List*/Get*/…Policy actions. A seal that denied
//     everything would be atomic, but a crash between steps 1 and 3 would leave a bucket nobody —
//     including its owner — can empty or unlock. Failing open on an unknown write action is much
//     cheaper than bricking the resource.
//   - If the bucket already carries a resource policy, it is NOT sealed: overwriting a policy
//      someone else wrote is not ours to do. The delete proceeds unsealed and says so.
// On any failure after we installed the seal, it is removed again, so a bucket that survives a
// failed teardown is left exactly as it was found.
//===--------------------------------------------------------------------===//

//! The data-mutating action set. Kept as data (not a wildcard) precisely so a future action we do
//! not know about fails open — see the header comment.
const char *const SEAL_DENIED_ACTIONS[] = {"s3tables:CreateNamespace",
                                           "s3tables:CreateTable",
                                           "s3tables:PutTableData",
                                           "s3tables:UpdateTableMetadataLocation",
                                           "s3tables:RenameTable",
                                           "s3tables:PutTableBucketReplication",
                                           "s3tables:PutTableReplication",
                                           "s3tables:PutTablePolicy",
                                           "s3tables:PutTableBucketMaintenanceConfiguration",
                                           "s3tables:PutTableMaintenanceConfiguration"};

string SealPolicy(const TableBucketArn &arn) {
	string actions;
	for (auto &action : SEAL_DENIED_ACTIONS) {
		if (!actions.empty()) {
			actions += ", ";
		}
		actions += "\"" + string(action) + "\"";
	}
	// The bucket itself and everything under it: a table's ARN is '<bucket-arn>/table/<id>'.
	return "{\"Version\":\"2012-10-17\",\"Statement\":[{"
	       "\"Sid\":\"DuckDBTeardownSeal\","
	       "\"Effect\":\"Deny\","
	       "\"Principal\":\"*\","
	       "\"Action\":[" +
	       actions +
	       "],"
	       "\"Resource\":[\"" +
	       arn.raw + "\",\"" + arn.raw + "/table/*\"]}]}";
}

//! True when the bucket has no resource policy (so ours can be installed without clobbering one).
//! A NotFoundException is the "no policy" answer, not an error.
bool HasBucketPolicy(Aws::S3Tables::S3TablesClient &client, const string &bucket_arn) {
	Aws::S3Tables::Model::GetTableBucketPolicyRequest req;
	req.SetTableBucketARN(bucket_arn.c_str());
	auto outcome = client.GetTableBucketPolicy(req);
	if (outcome.IsSuccess()) {
		return true;
	}
	auto name = FromAws(outcome.GetError().GetExceptionName());
	if (StringUtil::Contains(name, "NotFound")) {
		return false;
	}
	ThrowAwsError("GetTableBucketPolicy", outcome);
}

struct DeleteBucketBindData : public TableFunctionData {
	TableBucketArn arn;
	string secret_name;
	bool cascade = false;
	bool seal = true;
	bool dry_run = false;
};

//! Read the ARN out of either a plain VARCHAR or the resource framework's handle MAP.
string ArnFromInput(const Value &input, const string &fn_name) {
	if (input.IsNull()) {
		throw InvalidInputException("%s: the table bucket ARN must not be NULL", fn_name);
	}
	if (input.type().id() != LogicalTypeId::MAP) {
		return StringValue::Get(input);
	}
	for (auto &entry : MapValue::GetChildren(input)) {
		auto &kv = StructValue::GetChildren(entry);
		if (!kv[0].IsNull() && StringValue::Get(kv[0]) == "arn" && !kv[1].IsNull()) {
			return StringValue::Get(kv[1]);
		}
	}
	throw InvalidInputException("%s: handle is missing 'arn'", fn_name);
}

unique_ptr<FunctionData> DeleteBucketBind(ClientContext &, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<DeleteBucketBindData>();
	result->arn = ParseTableBucketArn(ArnFromInput(input.inputs[0], "s3tables_delete_table_bucket"),
	                                  "s3tables_delete_table_bucket");
	result->secret_name = SecretParam(input);
	result->cascade = BoolParam(input, "cascade", false);
	result->seal = BoolParam(input, "seal", true);
	result->dry_run = BoolParam(input, "dry_run", false);

	names.emplace_back("status");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("sealed");
	return_types.emplace_back(LogicalType::BOOLEAN);
	names.emplace_back("deleted_tables");
	return_types.emplace_back(LogicalType::BIGINT);
	names.emplace_back("deleted_namespaces");
	return_types.emplace_back(LogicalType::BIGINT);
	names.emplace_back("warning");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

//! Steps 1-2: seal, then delete every table and namespace. Returns via the out-params so the caller
//! can report partial progress on the error path.
void EmptyTableBucket(Aws::S3Tables::S3TablesClient &client, const TableBucketArn &arn, idx_t &deleted_tables,
                      idx_t &deleted_namespaces) {
	vector<NamespaceRow> namespaces;
	ListAllNamespaces(client, arn.raw, namespaces);
	for (auto &ns : namespaces) {
		vector<TableRow> tables;
		ListNamespaceTables(client, arn.raw, ns.namespace_name, tables);
		for (auto &table : tables) {
			Aws::S3Tables::Model::DeleteTableRequest req;
			req.SetTableBucketARN(arn.raw.c_str());
			req.SetNamespace(ns.namespace_name.c_str());
			req.SetName(table.name.c_str());
			auto outcome = client.DeleteTable(req);
			if (!outcome.IsSuccess()) {
				ThrowAwsError("DeleteTable", outcome);
			}
			deleted_tables++;
		}
		Aws::S3Tables::Model::DeleteNamespaceRequest req;
		req.SetTableBucketARN(arn.raw.c_str());
		req.SetNamespace(ns.namespace_name.c_str());
		auto outcome = client.DeleteNamespace(req);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("DeleteNamespace", outcome);
		}
		deleted_namespaces++;
	}
}

void DeleteBucketFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = data_p.bind_data->Cast<DeleteBucketBindData>();
	auto &state = data_p.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}

	auto provider = ResolveProvider(context, data.secret_name);
	auto client = MakeClient(provider, data.arn.region);

	idx_t deleted_tables = 0;
	idx_t deleted_namespaces = 0;
	bool sealed = false;
	string warning;

	if (data.dry_run) {
		// Count what a cascade would remove, touching nothing.
		vector<NamespaceRow> namespaces;
		ListAllNamespaces(client, data.arn.raw, namespaces);
		deleted_namespaces = namespaces.size();
		for (auto &ns : namespaces) {
			vector<TableRow> tables;
			ListNamespaceTables(client, data.arn.raw, ns.namespace_name, tables);
			deleted_tables += tables.size();
		}
		if (!data.cascade && (deleted_tables > 0 || deleted_namespaces > 0)) {
			warning = "bucket is not empty and cascade := false, so the delete would fail";
		}
		output.data[0].Append(Value("dry_run"));
		output.data[1].Append(Value::BOOLEAN(false));
		output.data[2].Append(Value::BIGINT(NumericCast<int64_t>(deleted_tables)));
		output.data[3].Append(Value::BIGINT(NumericCast<int64_t>(deleted_namespaces)));
		output.data[4].Append(warning.empty() ? Value() : Value(warning));
		output.CheckCardinality(1);
		state.done = true;
		return;
	}

	if (data.cascade) {
		if (data.seal) {
			if (HasBucketPolicy(client, data.arn.raw)) {
				warning = "table bucket already has a resource policy, so it was not sealed: a concurrent writer "
				          "could add a table while it is being emptied";
			} else {
				Aws::S3Tables::Model::PutTableBucketPolicyRequest req;
				req.SetTableBucketARN(data.arn.raw.c_str());
				req.SetResourcePolicy(SealPolicy(data.arn).c_str());
				auto outcome = client.PutTableBucketPolicy(req);
				if (outcome.IsSuccess()) {
					sealed = true;
				} else {
					// The seal is an optimisation, not a correctness requirement: without it the
					// cascade still empties the bucket, it just races a concurrent writer.
					warning = "could not seal the table bucket (" + FromAws(outcome.GetError().GetExceptionName()) +
					          "): emptying it unsealed";
				}
			}
		}
		try {
			EmptyTableBucket(client, data.arn, deleted_tables, deleted_namespaces);
		} catch (...) {
			// Leave a surviving bucket exactly as it was found.
			if (sealed) {
				Aws::S3Tables::Model::DeleteTableBucketPolicyRequest unseal;
				unseal.SetTableBucketARN(data.arn.raw.c_str());
				client.DeleteTableBucketPolicy(unseal);
			}
			throw;
		}
	}

	Aws::S3Tables::Model::DeleteTableBucketRequest req;
	req.SetTableBucketARN(data.arn.raw.c_str());
	auto outcome = client.DeleteTableBucket(req);
	if (!outcome.IsSuccess()) {
		if (sealed) {
			Aws::S3Tables::Model::DeleteTableBucketPolicyRequest unseal;
			unseal.SetTableBucketARN(data.arn.raw.c_str());
			client.DeleteTableBucketPolicy(unseal);
		}
		ThrowAwsError("DeleteTableBucket", outcome);
	}

	output.data[0].Append(Value("deleted"));
	output.data[1].Append(Value::BOOLEAN(sealed));
	output.data[2].Append(Value::BIGINT(NumericCast<int64_t>(deleted_tables)));
	output.data[3].Append(Value::BIGINT(NumericCast<int64_t>(deleted_namespaces)));
	output.data[4].Append(warning.empty() ? Value() : Value(warning));
	output.CheckCardinality(1);
	state.done = true;
}

} // namespace

//===--------------------------------------------------------------------===//
// Registration
//===--------------------------------------------------------------------===//

void S3TablesFunctions::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	// s3tables_table_buckets() | (region) | (region_list)
	TableFunctionSet buckets_set("s3tables_table_buckets");
	for (auto &args :
	     vector<vector<LogicalType>> {{}, {LogicalType::VARCHAR}, {LogicalType::LIST(LogicalType::VARCHAR)}}) {
		TableFunction fn(args, TableBucketsFun, TableBucketsBind, TableBucketsInit);
		fn.named_parameters["secret"] = LogicalType::VARCHAR;
		buckets_set.AddFunction(fn);
	}
	loader.RegisterFunction(buckets_set);

	TableFunction namespaces_fn("s3tables_namespaces", {LogicalType::VARCHAR}, NamespacesFun, NamespacesBind,
	                            NamespacesInit);
	namespaces_fn.named_parameters["secret"] = LogicalType::VARCHAR;
	loader.RegisterFunction(namespaces_fn);

	TableFunctionSet tables_set("s3tables_tables");
	for (auto &args :
	     vector<vector<LogicalType>> {{LogicalType::VARCHAR}, {LogicalType::VARCHAR, LogicalType::VARCHAR}}) {
		TableFunction fn(args, TablesFun, TablesBind, TablesInit);
		fn.named_parameters["secret"] = LogicalType::VARCHAR;
		tables_set.AddFunction(fn);
	}
	loader.RegisterFunction(tables_set);

	TableFunction create_fn("s3tables_create_table_bucket", {LogicalType::VARCHAR}, CreateBucketFun, CreateBucketBind,
	                        OnceInit);
	create_fn.named_parameters["region"] = LogicalType::VARCHAR;
	create_fn.named_parameters["tags"] = map_vv;
	create_fn.named_parameters["secret"] = LogicalType::VARCHAR;
	create_fn.named_parameters["dry_run"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(create_fn);

	TableFunction get_fn("s3tables_get_table_bucket", {LogicalType::VARCHAR}, GetBucketFun, GetBucketBind,
	                     GetBucketInit);
	get_fn.named_parameters["secret"] = LogicalType::VARCHAR;
	loader.RegisterFunction(get_fn);

	TableFunction tags_fn("s3tables_table_bucket_tags", {LogicalType::VARCHAR}, TagsFun, TagsBind, TagsInit);
	tags_fn.named_parameters["secret"] = LogicalType::VARCHAR;
	loader.RegisterFunction(tags_fn);

	// Takes the ARN directly, or the handle MAP the external-resource framework passes around.
	TableFunctionSet delete_set("s3tables_delete_table_bucket");
	for (auto &args : vector<vector<LogicalType>> {{LogicalType::VARCHAR}, {map_vv}}) {
		TableFunction fn(args, DeleteBucketFun, DeleteBucketBind, OnceInit);
		fn.named_parameters["cascade"] = LogicalType::BOOLEAN;
		fn.named_parameters["seal"] = LogicalType::BOOLEAN;
		fn.named_parameters["secret"] = LogicalType::VARCHAR;
		fn.named_parameters["dry_run"] = LogicalType::BOOLEAN;
		delete_set.AddFunction(fn);
	}
	loader.RegisterFunction(delete_set);
}

} // namespace duckdb
