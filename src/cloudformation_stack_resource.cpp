#include "cloudformation_stack_resource.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/interval.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/query_result.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/external_resource_type_registry.hpp"

namespace duckdb {

// aws.cloudformation.stack: any CloudFormation stack as an external resource. There is no built-in template: the
// 'template' create param is required and is passed through to cloudformation_create_stack (a URL or an inline
// template body), 'region' names the region, and every other create param is a parameter of the template.
//
// A stack is attachable when its template exposes the connection in Outputs named with a DuckDB prefix: DuckDBUri
// (the ATTACH path), DuckDBAttachedDbType (the TYPE) and any further DuckDB<Option> (an ATTACH option, snake-cased:
// DuckDBToken is 'token'). The status callback reports those and nothing else, since DuckDB hands every key of
// the status result but uri and attached_db_type to ATTACH as an option. A stack whose template exposes no such
// output is created, listed, resolved and destroyed like any other, but cannot be attached.

// The external-resource type name, also stamped as a stack tag at create time so the list callback can
// discover this type's stacks by filtering DescribeStacks output on it.
static constexpr const char *STACK_TYPE = "aws.cloudformation.stack";
static constexpr const char *RESOURCE_TYPE_TAG = "duckdb-external-resource-type";
//! Outputs with this prefix are the connection: see above
static constexpr const char *CONNECTION_OUTPUT_PREFIX = "DuckDB";

// Lifetime, for a template that declares a MaxDurationHours parameter (whole hours, 0 = unbounded) and arms a
// self-shutdown with it, as the quack template does. The optional 'max_duration' create param sets it. Its effective
// value is stamped on the stack as an absolute UTC deadline; when left to the template, the default is read through a
// dry run of cloudformation_create_stack. The resource terminates itself at that point but its stack lingers, so
// listing reaps stacks past the deadline (see StackListFun). Start is not tagged: CloudFormation records it as the
// stack's CreationTime. A template without the parameter is unbounded.
static constexpr const char *EXPIRES_AT_TAG = "duckdb-expires-at";
static constexpr const char *MAX_DURATION_TEMPLATE_PARAM = "MaxDurationHours";
// Covers the gap between stack creation and the boot that arms the shutdown timer, so a stack is only reaped
// once its resource has certainly gone.
static constexpr int64_t EXPIRY_MARGIN_SECONDS = 600;

namespace {

// The recipe callbacks are thin native table functions that adapt the generic cloudformation_* shapes to
// the external-resource contract: create(params)->handle, status(handle)->(state,result), destroy(handle).
// The adaptation itself lives in the SQL each callback runs against the cloudformation_* functions on an
// internal connection (same pattern as create_external_resource) — so no user-authored SQL macros.

struct StackAdapterBindData : public TableFunctionData {
	Value input; // params (create) or handle (status/destroy)
};

struct StackAdapterState : public GlobalTableFunctionState {
	bool done = false;
};

static unique_ptr<GlobalTableFunctionState> StackAdapterInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<StackAdapterState>();
}

// create(params MAP) -> TABLE(handle MAP). cloudformation_create_stack takes only the template positionally;
// the recipe params supply the (required) template and region and the template_parameters. `template`, `region`
// and `max_duration` are pulled out here in C++ and everything else becomes template_parameters — built as a literal
// MAP so it is NOT assembled inline in the table-function argument (where `e.key`-style identifiers get silently
// coerced to strings by the identifier-conversion rule, which would defeat the filter and leak `region`).
static unique_ptr<FunctionData> StackCreateBind(ClientContext &, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<StackAdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

static void StackCreateFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<StackAdapterState>();
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<StackAdapterBindData>();

	// Split the params MAP in C++: required `template` and `region`, optional `max_duration`, rest ->
	// template_parameters.
	string template_url;
	string region;
	string max_duration;
	vector<Value> tp_keys, tp_values;
	if (!bind.input.IsNull()) {
		for (auto &entry : MapValue::GetChildren(bind.input)) {
			auto &kv = StructValue::GetChildren(entry);
			auto key = kv[0].IsNull() ? string() : StringValue::Get(kv[0]);
			if (key == "template") {
				if (!kv[1].IsNull()) {
					template_url = StringValue::Get(kv[1]);
				}
			} else if (key == "region") {
				if (!kv[1].IsNull()) {
					region = StringValue::Get(kv[1]);
				}
			} else if (key == "max_duration") {
				if (!kv[1].IsNull()) {
					max_duration = StringValue::Get(kv[1]);
				}
			} else {
				tp_keys.push_back(kv[0]);
				tp_values.push_back(kv[1]);
			}
		}
	}
	if (template_url.empty()) {
		throw InvalidInputException(
		    "aws.cloudformation.stack create: the 'template' param is required (URL or body of a "
		    "CloudFormation template)");
	}
	if (region.empty()) {
		throw InvalidInputException("aws.cloudformation.stack create: the 'region' param is required");
	}
	// Whole hours, as the template parameter takes them. -1 = not given, left to the template's default.
	int64_t hours = -1;
	if (!max_duration.empty()) {
		if (!TryCast::Operation<string_t, int64_t>(string_t(max_duration), hours, false) || hours < 0) {
			throw InvalidInputException(
			    "aws.cloudformation.stack create: 'max_duration' must be a whole, non-negative number of "
			    "hours (0 = unbounded), got '%s'",
			    max_duration);
		}
		tp_keys.emplace_back(string(MAX_DURATION_TEMPLATE_PARAM));
		tp_values.emplace_back(max_duration);
	}

	// Pass literals only — no inline map-building in the table-function argument (see comment above).
	string args = Value(template_url).ToSQLString() + ", region := " + Value(region).ToSQLString();
	if (!tp_keys.empty()) {
		auto template_params = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, tp_keys, tp_values);
		args += ", template_parameters := " + template_params.ToSQLString();
	}

	Connection con(DatabaseInstance::GetDatabase(context));

	// Left to the template: a dry run reports the effective parameters, defaults included, at the cost of one
	// read-only GetTemplateSummary call. It has to be known before create, as tags are set then. Skipped when
	// the caller gave the duration, since nothing is left to find out.
	if (hours < 0) {
		auto dry = con.Query("SELECT parameters[" + Value(string(MAX_DURATION_TEMPLATE_PARAM)).ToSQLString() +
		                     "] FROM cloudformation_create_stack(" + args + ", dry_run := true)");
		if (dry->HasError()) {
			throw IOException("aws.cloudformation.stack create failed: %s", dry->GetError());
		}
		auto effective = dry->Collection().GetValue(0, 0);
		if (effective.IsNull() ||
		    !TryCast::Operation<string_t, int64_t>(string_t(StringValue::Get(effective)), hours, false)) {
			hours = 0; // the template declares no (usable) max duration: unbounded
		}
	}
	string expires_at;
	if (hours > 0) {
		timestamp_t deadline(Timestamp::GetCurrentTimestamp().value + hours * Interval::MICROS_PER_HOUR);
		expires_at = Timestamp::ToString(deadline) + "+00";
	}

	// Provenance tag so the list callback can discover these stacks by filtering on it (added to, not
	// replacing, cloudformation_create_stack's own auto-tags like created-by), plus the deadline when bounded.
	vector<Value> tag_keys {Value(string(RESOURCE_TYPE_TAG))};
	vector<Value> tag_values {Value(string(STACK_TYPE))};
	if (!expires_at.empty()) {
		tag_keys.emplace_back(string(EXPIRES_AT_TAG));
		tag_values.emplace_back(expires_at);
	}
	auto resource_tag = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, tag_keys, tag_values);
	auto sql =
	    "SELECT handle FROM cloudformation_create_stack(" + args + ", tags := " + resource_tag.ToSQLString() + ")";

	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("aws.cloudformation.stack create failed: %s", res->GetError());
	}
	output.data[0].Append(res->Collection().GetValue(0, 0));
	state.done = true;
}

// DuckDBAttachedDbType -> attached_db_type, DuckDBToken -> token, DuckDBURI -> uri: the key after the prefix, with an
// underscore before each upper-case letter that follows a lower-case letter or a digit, lower-cased.
static string ConnectionKey(const string &output_key) {
	string key;
	auto rest = output_key.substr(strlen(CONNECTION_OUTPUT_PREFIX));
	for (idx_t i = 0; i < rest.size(); i++) {
		auto c = rest[i];
		auto is_upper = c >= 'A' && c <= 'Z';
		if (i > 0 && is_upper) {
			auto previous = rest[i - 1];
			if ((previous >= 'a' && previous <= 'z') || StringUtil::CharacterIsDigit(previous)) {
				key += '_';
			}
		}
		key += StringUtil::CharacterToLower(c);
	}
	return key;
}

// status(handle MAP) -> TABLE(state VARCHAR, result MAP). Maps the CloudFormation stack status onto the terminal
// 'ready'/'failed' states the poll loop expects, and projects the DuckDB-prefixed stack Outputs into the connection
// (uri, attached_db_type and the ATTACH options; see the top of this file). Other outputs are not reported: DuckDB
// would hand them to ATTACH as options.
static unique_ptr<FunctionData> StackStatusBind(ClientContext &, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<StackAdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("state");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("result");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

static void StackStatusFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<StackAdapterState>();
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<StackAdapterBindData>();
	Connection con(DatabaseInstance::GetDatabase(context));
	auto sql = "SELECT CASE WHEN status IN ('CREATE_COMPLETE', 'UPDATE_COMPLETE') THEN 'ready' "
	           "            WHEN status LIKE '%ROLLBACK%' OR status LIKE '%FAILED%' OR status LIKE 'DELETE_%' "
	           "                 THEN 'failed' "
	           "            ELSE 'pending' END AS state, "
	           "       outputs "
	           "FROM cloudformation_describe_stack(" +
	           bind.input.ToSQLString() + ")";
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("aws.cloudformation.stack status failed: %s", res->GetError());
	}
	auto rows = res->Collection().GetRows();
	auto outputs = rows.GetValue(1, 0);
	vector<Value> keys, values;
	if (!outputs.IsNull()) {
		for (auto &entry : MapValue::GetChildren(outputs)) {
			auto &kv = StructValue::GetChildren(entry);
			if (kv[0].IsNull() || kv[1].IsNull()) {
				continue;
			}
			auto output_key = StringValue::Get(kv[0]);
			if (!StringUtil::StartsWith(output_key, CONNECTION_OUTPUT_PREFIX) ||
			    output_key.size() == strlen(CONNECTION_OUTPUT_PREFIX)) {
				continue;
			}
			keys.emplace_back(ConnectionKey(output_key));
			values.push_back(kv[1]);
		}
	}
	output.data[0].Append(rows.GetValue(0, 0));
	output.data[1].Append(Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, keys, values));
	state.done = true;
}

// destroy(handle MAP) -> TABLE(status VARCHAR)
static unique_ptr<FunctionData> StackDestroyBind(ClientContext &, TableFunctionBindInput &input,
                                                 vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<StackAdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("status");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

static void StackDestroyFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<StackAdapterState>();
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<StackAdapterBindData>();
	Connection con(DatabaseInstance::GetDatabase(context));
	auto sql = "SELECT 'deleting' AS status FROM cloudformation_delete_stack(" + bind.input.ToSQLString() + ")";
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("aws.cloudformation.stack destroy failed: %s", res->GetError());
	}
	output.data[0].Append(Value("deleting"));
	state.done = true;
}

// The columns list and resolve share: the handle create returns, byte-identical so it round-trips through
// status/destroy verbatim, the stack name as the provider's name for the resource, the stack id (ARN) as its
// reference, and the CloudFormation status folded onto the external-resource states.
static string StackRowSQL() {
	return "MAP {'stack_name': stack_name, 'stack_id': stack_id, 'region': region} AS handle, "
	       "stack_name AS name, "
	       "stack_id AS reference, "
	       "CASE WHEN status IN ('CREATE_COMPLETE', 'UPDATE_COMPLETE') THEN 'ready' "
	       "     WHEN status LIKE 'DELETE_%' THEN 'deleting' "
	       "     WHEN status LIKE '%ROLLBACK%' OR status LIKE '%FAILED%' THEN 'failed' "
	       "     ELSE 'pending' END AS state";
}

// Only stacks carrying the provenance tag stamped at create are this type's.
static string IsStackTypeSQL() {
	return "tags[" + Value(string(RESOURCE_TYPE_TAG)).ToSQLString() + "] = " + Value(string(STACK_TYPE)).ToSQLString();
}

// __aws__expired(deadline VARCHAR) -> BOOLEAN: whether the duckdb-expires-at deadline create wrote (UTC, with its
// +00 offset) is EXPIRY_MARGIN_SECONDS behind now. A deadline that does not parse is never expired. Provided as a
// function of this extension rather than spelled with TIMESTAMPTZ in the listing SQL: that arithmetic comes from
// icu, and where icu is loadable rather than built in, autoloading it while an expression is being bound is not safe.
static bool IsExpired(string_t deadline_str) {
	timestamp_t deadline;
	if (Timestamp::TryConvertTimestamp(deadline_str.GetData(), deadline_str.GetSize(), deadline, true) !=
	    TimestampCastResult::SUCCESS) {
		return false;
	}
	return Timestamp::GetCurrentTimestamp().value - deadline.value > EXPIRY_MARGIN_SECONDS * Interval::MICROS_PER_SEC;
}

static void ExpiredFun(DataChunk &args, ExpressionState &, Vector &result) {
	UnaryExecutor::Execute<string_t, bool>(args.data[0], result, args.size(), IsExpired);
}

// list(params MAP) -> TABLE(handle MAP, name VARCHAR, reference VARCHAR, state VARCHAR, metadata MAP). Discovers
// existing stacks of this type (identified by the provenance tag stamped at create). The connection (uri/token) is
// deliberately NOT surfaced here — list is discovery; status produces that.
// Listing also reaps stacks past their duckdb-expires-at tag (plus EXPIRY_MARGIN_SECONDS) and reports them as
// 'deleting'.
struct StackListState : public GlobalTableFunctionState {
	unique_ptr<QueryResult> result;
	vector<Value> states; // per-row state, overriding the query's for stacks reaped during this listing
	idx_t cursor = 0;
	bool ran = false;
};

static unique_ptr<GlobalTableFunctionState> StackListInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<StackListState>();
}

static unique_ptr<FunctionData> StackListBind(ClientContext &, TableFunctionBindInput &input,
                                              vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<StackAdapterBindData>();
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

static void StackListFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<StackListState>();
	auto &bind = data_p.bind_data->Cast<StackAdapterBindData>();

	if (!state.ran) {
		// Optional 'region' param: if given, list just that region; otherwise sweep all regions — the parallel
		// fan-out lives inside cloudformation_describe_stacks, so this stays a single-call SQL adapter.
		string one_region;
		if (!bind.input.IsNull()) {
			for (auto &entry : MapValue::GetChildren(bind.input)) {
				auto &kv = StructValue::GetChildren(entry);
				auto key = kv[0].IsNull() ? string() : StringValue::Get(kv[0]);
				if (key == "region" && !kv[1].IsNull()) {
					one_region = StringValue::Get(kv[1]);
				}
			}
		}
		string source = one_region.empty() ? "cloudformation_describe_stacks()"
		                                   : "cloudformation_describe_stacks(" + Value(one_region).ToSQLString() + ")";

		auto sql = "SELECT " + StackRowSQL() +
		           ",     MAP {'stack_status': status, 'creation_time': creation_time, "
		           "            'last_updated_time': last_updated_time, 'description': description, "
		           "            'expires_at': tags[" +
		           Value(string(EXPIRES_AT_TAG)).ToSQLString() +
		           "]} AS metadata, "
		           // Only a stack that finished creating can have a box that armed its own shutdown; anything
		           // else is still in flight, failed, or already going away.
		           "       status = 'CREATE_COMPLETE' AND __aws__expired(tags[" +
		           Value(string(EXPIRES_AT_TAG)).ToSQLString() +
		           "]) AS expired "
		           "FROM " +
		           source + " WHERE error IS NULL AND " + IsStackTypeSQL();

		Connection con(DatabaseInstance::GetDatabase(context));
		state.result = con.Query(sql);
		if (state.result->HasError()) {
			throw IOException("aws.cloudformation.stack list failed: %s", state.result->GetError());
		}
		auto rows = state.result->Collection().GetRows();
		for (idx_t row = 0; row < state.result->RowCount(); row++) {
			auto row_state = rows.GetValue(3, row);
			auto expired = rows.GetValue(5, row);
			if (!expired.IsNull() && BooleanValue::Get(expired)) {
				// Best effort: a failed delete keeps the stack listed as-is, and the next listing retries.
				auto del =
				    con.Query("SELECT * FROM cloudformation_delete_stack(" + rows.GetValue(0, row).ToSQLString() + ")");
				if (!del->HasError()) {
					row_state = Value("deleting");
				}
			}
			state.states.push_back(row_state);
		}
		state.ran = true;
	}

	idx_t total = state.result->RowCount();
	idx_t remaining = total - state.cursor;
	idx_t to_emit = remaining < (idx_t)STANDARD_VECTOR_SIZE ? remaining : (idx_t)STANDARD_VECTOR_SIZE;
	auto rows = state.result->Collection().GetRows();
	for (idx_t i = 0; i < to_emit; i++) {
		idx_t row = state.cursor + i;
		output.data[0].Append(rows.GetValue(0, row));
		output.data[1].Append(rows.GetValue(1, row));
		output.data[2].Append(rows.GetValue(2, row));
		output.data[3].Append(state.states[row]);
		output.data[4].Append(rows.GetValue(4, row));
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

// resolve(name VARCHAR) -> TABLE(handle MAP, name VARCHAR, reference VARCHAR, state VARCHAR). This type's
// stacks called `name`, so a resource seen in SHOW ALL EXTERNAL RESOURCES can be registered by name. A stack
// name is only unique within a region, so a bare name sweeps the regions and can match several; a stack id (ARN)
// names its region and is described directly. Stacks without the provenance tag are not this type's.
struct StackResolveState : public GlobalTableFunctionState {
	unique_ptr<QueryResult> result;
	idx_t cursor = 0;
	bool ran = false;
};

static unique_ptr<GlobalTableFunctionState> StackResolveInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<StackResolveState>();
}

static unique_ptr<FunctionData> StackResolveBind(ClientContext &, TableFunctionBindInput &input,
                                                 vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<StackAdapterBindData>();
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

static void StackResolveFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<StackResolveState>();
	auto &bind = data_p.bind_data->Cast<StackAdapterBindData>();

	if (!state.ran) {
		if (bind.input.IsNull()) {
			throw InvalidInputException("aws.cloudformation.stack resolve: the name must not be NULL");
		}
		auto name = StringValue::Get(bind.input);
		auto name_sql = Value(name).ToSQLString();
		// arn:<partition>:cloudformation:<region>:<account>:stack/<name>/<id>
		auto arn_parts = StringUtil::Split(name, ':');
		string source;
		if (arn_parts.size() > 5 && arn_parts[0] == "arn" && arn_parts[2] == "cloudformation") {
			source = "cloudformation_describe_stack(MAP {'stack_id': " + name_sql +
			         ", 'region': " + Value(arn_parts[3]).ToSQLString() + "}) WHERE " + IsStackTypeSQL();
		} else {
			source = "cloudformation_describe_stacks() WHERE error IS NULL AND stack_name = " + name_sql + " AND " +
			         IsStackTypeSQL();
		}
		Connection con(DatabaseInstance::GetDatabase(context));
		state.result = con.Query("SELECT " + StackRowSQL() + " FROM " + source);
		if (state.result->HasError()) {
			throw IOException("aws.cloudformation.stack resolve failed: %s", state.result->GetError());
		}
		state.ran = true;
	}

	idx_t total = state.result->RowCount();
	idx_t remaining = total - state.cursor;
	idx_t to_emit = remaining < (idx_t)STANDARD_VECTOR_SIZE ? remaining : (idx_t)STANDARD_VECTOR_SIZE;
	auto rows = state.result->Collection().GetRows();
	for (idx_t i = 0; i < to_emit; i++) {
		idx_t row = state.cursor + i;
		for (idx_t col = 0; col < 4; col++) {
			output.data[col].Append(rows.GetValue(col, row));
		}
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

} // namespace

void CloudFormationStackResource::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	ScalarFunction expired_fn("__aws__expired", {LogicalType::VARCHAR}, LogicalType::BOOLEAN, ExpiredFun);
	loader.RegisterFunction(expired_fn);

	// Native callbacks (no SQL macros): thin adapters over cloudformation_*.
	TableFunction create_fn("__aws__cloudformation__stack__create",
	                        FunctionSignature().AddPositionalOnly("input", map_vv), StackCreateFun, StackCreateBind,
	                        StackAdapterInit);
	loader.RegisterFunction(create_fn);
	TableFunction status_fn("__aws__cloudformation__stack__status",
	                        FunctionSignature().AddPositionalOnly("input", map_vv), StackStatusFun, StackStatusBind,
	                        StackAdapterInit);
	loader.RegisterFunction(status_fn);
	TableFunction destroy_fn("__aws__cloudformation__stack__destroy",
	                         FunctionSignature().AddPositionalOnly("input", map_vv), StackDestroyFun, StackDestroyBind,
	                         StackAdapterInit);
	loader.RegisterFunction(destroy_fn);
	// Also wired into the resource-type registry below (as this type's `list_function`), so
	// `SHOW ALL EXTERNAL RESOURCES` can discover existing stacks that are not locally managed.
	TableFunction list_fn("__aws__cloudformation__stack__list", FunctionSignature().AddPositionalOnly("input", map_vv),
	                      StackListFun, StackListBind, StackListInit);
	loader.RegisterFunction(list_fn);
	// The type's `resolve_function`: a discovered stack's name (or stack id) back to its handle.
	TableFunction resolve_fn("__aws__cloudformation__stack__resolve",
	                         FunctionSignature().AddPositionalOnly("name", LogicalType::VARCHAR), StackResolveFun,
	                         StackResolveBind, StackResolveInit);
	loader.RegisterFunction(resolve_fn);

	// Register the resource type on the C++ side (origin = "extension"), so `LOAD aws;` is all a user needs. Kind
	// 'storage': a stack need not be attachable, so DuckDB must not require uri and attached_db_type of its status.
	ExternalResourceType type;
	type.name = STACK_TYPE;
	type.kind = "storage";
	type.create_function = "__aws__cloudformation__stack__create";
	type.status_function = "__aws__cloudformation__stack__status";
	type.destroy_function = "__aws__cloudformation__stack__destroy";
	type.resolve_function = "__aws__cloudformation__stack__resolve";
	type.list_function = "__aws__cloudformation__stack__list";
	type.origin = "extension";
	ExternalResourceTypeRegistry::Get(loader.GetDatabaseInstance()).Add(std::move(type));
}

} // namespace duckdb
