#include "quack_on_ec2_resource.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/materialized_query_result.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/external_resource_type_registry.hpp"

namespace duckdb {

// Default CloudFormation template for a quack-on-EC2 stack; overridable per-call via the 'template' create
// param. Its Outputs expose the keys read by the status callback below (Endpoint, Token).
static constexpr const char *QUACK_ON_EC2_TEMPLATE =
    "https://test-wasm-carlo.s3.us-east-1.amazonaws.com/duckdb-quack-ec2-template.yaml";

// The external-resource type name, also stamped as a stack tag at create time so the list callback can
// discover quack-on-ec2 stacks by filtering DescribeStacks output on it.
static constexpr const char *QUACK_ON_EC2_TYPE = "aws:cloudformation:quack-on-ec2";
static constexpr const char *RESOURCE_TYPE_TAG = "duckdb-external-resource-type";

namespace {

// The recipe callbacks are thin native table functions that adapt the generic cloudformation_* shapes to
// the external-resource contract: create(params)->handle, status(handle)->(state,result), destroy(handle).
// The adaptation itself lives in the SQL each callback runs against the cloudformation_* functions on an
// internal connection (same pattern as create_external_resource) — so no user-authored SQL macros.

struct QuackAdapterBindData : public TableFunctionData {
	Value input; // params (create) or handle (status/destroy)
};

struct QuackAdapterState : public GlobalTableFunctionState {
	bool done = false;
};

static unique_ptr<GlobalTableFunctionState> QuackAdapterInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<QuackAdapterState>();
}

// create(params MAP) -> TABLE(handle MAP). cloudformation_create_stack takes only the template positionally;
// the recipe params supply the (required) region and the template_parameters. `template` and `region` are
// pulled out here in C++ and everything else becomes template_parameters — built as a literal MAP so it is
// NOT assembled inline in the table-function argument (where `e.key`-style identifiers get silently coerced
// to strings by the identifier-conversion rule, which would defeat the filter and leak `region`).
static unique_ptr<FunctionData> QuackCreateBind(ClientContext &, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<QuackAdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

static void QuackCreateFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<QuackAdapterState>();
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<QuackAdapterBindData>();

	// Split the params MAP in C++: `template` (default), required `region`, rest -> template_parameters.
	string template_url = QUACK_ON_EC2_TEMPLATE;
	string region;
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
			} else {
				tp_keys.push_back(kv[0]);
				tp_values.push_back(kv[1]);
			}
		}
	}
	if (region.empty()) {
		throw InvalidInputException("quack-on-ec2 create: the 'region' param is required");
	}

	// Pass literals only — no inline map-building in the table-function argument (see comment above).
	auto sql = "SELECT handle FROM cloudformation_create_stack(" + Value(template_url).ToSQLString() +
	           ", region := " + Value(region).ToSQLString();
	if (!tp_keys.empty()) {
		auto template_params = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, tp_keys, tp_values);
		sql += ", template_parameters := " + template_params.ToSQLString();
	}
	// Provenance tag so the list callback can discover these stacks by filtering on it (added to, not
	// replacing, cloudformation_create_stack's own auto-tags like created-by).
	vector<Value> tag_keys {Value(string(RESOURCE_TYPE_TAG))};
	vector<Value> tag_values {Value(string(QUACK_ON_EC2_TYPE))};
	auto resource_tag = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, tag_keys, tag_values);
	sql += ", tags := " + resource_tag.ToSQLString();
	sql += ")";

	Connection con(DatabaseInstance::GetDatabase(context));
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("quack-on-ec2 create failed: %s", res->GetError());
	}
	output.data[0].Append(res->GetValue(0, 0));
	state.done = true;
}

// status(handle MAP) -> TABLE(state VARCHAR, result MAP). Maps the CloudFormation stack status onto the
// terminal 'ready'/'failed' states the poll loop expects, and projects the stack Outputs into the connect
// endpoint (uri + attached_db_type + token). cloudformation_describe_stack is unchanged by 0002.
static unique_ptr<FunctionData> QuackStatusBind(ClientContext &, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<QuackAdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("state");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("result");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	return std::move(result);
}

static void QuackStatusFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<QuackAdapterState>();
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<QuackAdapterBindData>();
	Connection con(DatabaseInstance::GetDatabase(context));
	auto sql = "SELECT CASE WHEN status = 'CREATE_COMPLETE' THEN 'ready' "
	           "            WHEN status LIKE '%ROLLBACK%' OR status LIKE '%FAILED%' THEN 'failed' "
	           "            ELSE 'pending' END AS state, "
	           "       MAP {'uri': outputs['QuackURI'], 'attached_db_type': 'quack', "
	           "            'token': split_part(split_part(outputs['Token'], '{\"1\":\"', 2), '\"}', 1)} AS result "
	           "FROM cloudformation_describe_stack(" +
	           bind.input.ToSQLString() + ")";
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("quack-on-ec2 status failed: %s", res->GetError());
	}
	output.data[0].Append(res->GetValue(0, 0));
	output.data[1].Append(res->GetValue(1, 0));
	state.done = true;
}

// destroy(handle MAP) -> TABLE(status VARCHAR)
static unique_ptr<FunctionData> QuackDestroyBind(ClientContext &, TableFunctionBindInput &input,
                                                 vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<QuackAdapterBindData>();
	result->input = input.inputs[0];
	names.emplace_back("status");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

static void QuackDestroyFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<QuackAdapterState>();
	if (state.done) {
		return;
	}
	auto &bind = data_p.bind_data->Cast<QuackAdapterBindData>();
	Connection con(DatabaseInstance::GetDatabase(context));
	auto sql = "SELECT 'deleting' AS status FROM cloudformation_delete_stack(" + bind.input.ToSQLString() + ")";
	auto res = con.Query(sql);
	if (res->HasError()) {
		throw IOException("quack-on-ec2 destroy failed: %s", res->GetError());
	}
	output.data[0].Append(Value("deleting"));
	state.done = true;
}

// list(params MAP) -> TABLE(handle MAP, reference VARCHAR, state VARCHAR, metadata MAP). Discovers existing
// quack-on-ec2 stacks (identified by the provenance tag stamped at create) and shapes each into a row whose
// `handle` is byte-identical to what create returns, so it round-trips through status/destroy verbatim. The
// connect blob (uri/token) is deliberately NOT surfaced here — list is discovery; resolve/status produce that.
struct QuackListState : public GlobalTableFunctionState {
	unique_ptr<MaterializedQueryResult> result;
	idx_t cursor = 0;
	bool ran = false;
};

static unique_ptr<GlobalTableFunctionState> QuackListInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<QuackListState>();
}

static unique_ptr<FunctionData> QuackListBind(ClientContext &, TableFunctionBindInput &input,
                                              vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<QuackAdapterBindData>();
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

static void QuackListFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<QuackListState>();
	auto &bind = data_p.bind_data->Cast<QuackAdapterBindData>();

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

		auto sql = "SELECT MAP {'stack_name': stack_name, 'stack_id': stack_id, 'region': region} AS handle, "
		           "       stack_id AS reference, "
		           "       CASE WHEN status IN ('CREATE_COMPLETE', 'UPDATE_COMPLETE') THEN 'ready' "
		           "            WHEN status LIKE 'DELETE_%' THEN 'deleting' "
		           "            WHEN status LIKE '%ROLLBACK%' OR status LIKE '%FAILED%' THEN 'failed' "
		           "            ELSE 'pending' END AS state, "
		           "       MAP {'stack_status': status, 'creation_time': creation_time, "
		           "            'last_updated_time': last_updated_time, 'description': description} AS metadata "
		           "FROM " +
		           source + " WHERE error IS NULL AND tags[" + Value(string(RESOURCE_TYPE_TAG)).ToSQLString() +
		           "] = " + Value(string(QUACK_ON_EC2_TYPE)).ToSQLString();

		Connection con(DatabaseInstance::GetDatabase(context));
		state.result = con.Query(sql);
		if (state.result->HasError()) {
			throw IOException("quack-on-ec2 list failed: %s", state.result->GetError());
		}
		state.ran = true;
	}

	idx_t total = state.result->RowCount();
	idx_t remaining = total - state.cursor;
	idx_t to_emit = remaining < (idx_t)STANDARD_VECTOR_SIZE ? remaining : (idx_t)STANDARD_VECTOR_SIZE;
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

void QuackOnEc2Resource::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	// Native callbacks (no SQL macros): thin adapters over cloudformation_*.
	TableFunction create_fn("__aws__cloudformation__quack_on_ec2__create", {map_vv}, QuackCreateFun, QuackCreateBind,
	                        QuackAdapterInit);
	loader.RegisterFunction(create_fn);
	TableFunction status_fn("__aws__cloudformation__quack_on_ec2__status", {map_vv}, QuackStatusFun, QuackStatusBind,
	                        QuackAdapterInit);
	loader.RegisterFunction(status_fn);
	TableFunction destroy_fn("__aws__cloudformation__quack_on_ec2__destroy", {map_vv}, QuackDestroyFun,
	                         QuackDestroyBind, QuackAdapterInit);
	loader.RegisterFunction(destroy_fn);
	// Registered as a plain callable function only. Wiring it into the resource-type registry (a `list_function`
	// slot) is a separate duckdb-side change, done elsewhere.
	TableFunction list_fn("__aws__cloudformation__quack_on_ec2__list", {map_vv}, QuackListFun, QuackListBind,
	                      QuackListInit);
	loader.RegisterFunction(list_fn);

	// Register the resource type on the C++ side (origin = "extension"), so `LOAD aws;` is all a user needs.
	ExternalResourceType type;
	type.name = "aws:cloudformation:quack-on-ec2";
	type.kind = "catalog";
	type.create_function = "__aws__cloudformation__quack_on_ec2__create";
	type.status_function = "__aws__cloudformation__quack_on_ec2__status";
	type.destroy_function = "__aws__cloudformation__quack_on_ec2__destroy";
	type.origin = "extension";
	ExternalResourceTypeRegistry::Get(loader.GetDatabaseInstance()).Add(std::move(type));
}

} // namespace duckdb
