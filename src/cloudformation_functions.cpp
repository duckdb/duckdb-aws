#include "cloudformation_functions.hpp"
#include "aws_client.hpp"
#include "utils/utils.hpp"

#include "duckdb.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/insertion_order_preserving_map.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parallel/task_executor.hpp"

#include <aws/cloudformation/CloudFormationClient.h>
#include <aws/cloudformation/model/Capability.h>
#include <aws/cloudformation/model/CreateStackRequest.h>
#include <aws/cloudformation/model/DeleteStackRequest.h>
#include <aws/cloudformation/model/DescribeStacksRequest.h>
#include <aws/cloudformation/model/GetTemplateSummaryRequest.h>
#include <aws/cloudformation/model/ListStacksRequest.h>
#include <aws/cloudformation/model/Parameter.h>
#include <aws/cloudformation/model/StackStatus.h>
#include <aws/cloudformation/model/Tag.h>
#include <aws/core/utils/DateTime.h>
#include <aws/core/utils/json/JsonSerializer.h>

#include <cctype>
#include <set>

namespace duckdb {

namespace {

//! Aws::String only differs from duckdb's string when the SDK is built with
//! USE_AWS_MEMORY_MANAGEMENT (a custom allocator). Copying by range rather than
//! via the C string is exact under both builds: no strlen, and embedded NULs survive.
string FromAws(const Aws::String &s) {
	return {s.data(), s.size()};
}

//! Case-sensitive, insertion-order-preserving string map. The index map must be
//! spelled out because the type defaults to case-insensitive matching, which is
//! wrong for case-sensitive keys like AWS tag keys.
using OrderedStringMap = InsertionOrderPreservingMap<string, string, unordered_map<string, idx_t>>;

OrderedStringMap UnpackStringMap(const Value &map_value) {
	OrderedStringMap out;
	if (map_value.IsNull()) {
		return out;
	}
	auto &children = MapValue::GetChildren(map_value);
	for (auto &child : children) {
		auto &kv = StructValue::GetChildren(child);
		if (kv[0].IsNull()) {
			continue;
		}
		out[StringValue::Get(kv[0])] = kv[1].IsNull() ? string() : StringValue::Get(kv[1]);
	}
	return out;
}

//! Case-insensitive variant: keys are matched/looked-up case-insensitively but
//! stored with their original case (e.g. for case-sensitive CFN parameter names).
case_insensitive_map_t<string> UnpackStringMapCI(const Value &map_value) {
	case_insensitive_map_t<string> out;
	if (map_value.IsNull()) {
		return out;
	}
	auto &children = MapValue::GetChildren(map_value);
	for (auto &child : children) {
		auto &kv = StructValue::GetChildren(child);
		if (kv[0].IsNull()) {
			continue;
		}
		out[StringValue::Get(kv[0])] = kv[1].IsNull() ? string() : StringValue::Get(kv[1]);
	}
	return out;
}

bool LooksLikeUrl(const string &s) {
	return StringUtil::StartsWith(s, "http://") || StringUtil::StartsWith(s, "https://");
}

//! Coerce a free-form string into a CFN-name-safe fragment ([a-zA-Z0-9-]).
string SanitizeNameFragment(const string &in) {
	string out;
	for (char c : in) {
		if (std::isalnum(static_cast<unsigned char>(c)) || c == '-') {
			out += c;
		} else {
			out += '-';
		}
	}
	return out;
}

//! Stem of a URL's last path segment: https://host/path/quack.yaml -> "quack".
string UrlBasenameStem(const string &url) {
	auto slash = url.find_last_of('/');
	string base = (slash == string::npos) ? url : url.substr(slash + 1);
	auto qmark = base.find('?');
	if (qmark != string::npos) {
		base = base.substr(0, qmark);
	}
	auto dot = base.find_last_of('.');
	if (dot != string::npos && dot > 0) {
		base = base.substr(0, dot);
	}
	return SanitizeNameFragment(base);
}

//! 12 hex characters of randomness from a fresh UUID. Keeping suffixes short
//! ensures the resulting CFN ARN stays within CloudFormation's 128-char
//! StackName API limit even in the longest-named regions.
string ShortRandHex() {
	auto uuid_str = UUID::ToString(UUID::GenerateRandomUUID());
	// UUID layout: 8-4-4-4-12. First 12 hex = first segment (8) + second segment (4).
	return uuid_str.substr(0, 8) + uuid_str.substr(9, 4);
}

//! Per-process session id used for the duckdb-session-id auto-tag on every
//! stack this extension creates. Lazy-initialised on first use, then stable
//! for the lifetime of the duckdb-aws extension load.
const string &SessionId() {
	static const string id = ShortRandHex();
	return id;
}

//! CFN's StackName API parameter is capped at 128 chars. The ARN is
//! `arn:aws:cloudformation:<region>:<account>:stack/<name>/<cfn-uuid>` —
//! structural+region(≤14)+account(12)+slashes(2)+cfn-uuid(36) ≤ 94, so the
//! name budget is 128 - 94 = 34 chars (worst case across regions).
constexpr idx_t MAX_STACK_NAME_LEN = 34;
constexpr idx_t MAX_PREFIX_LEN = MAX_STACK_NAME_LEN - 12 - 1; // 21: '<prefix>-<12hex>'

//! Reserved option keys configure the AWS client; everything else in `options`
//! must match a parameter the template declares.
const std::set<string> RESERVED_OPTION_KEYS = {
    "region", "chain", "profile", "assume_role_arn", "external_id", "web_identity_token_file", "session_name"};
} // namespace

//===--------------------------------------------------------------------===//
// cloudformation_create_stack(template) [name :=, template_parameters :=,
//                                        tags :=, region :=, dry_run :=]
//===--------------------------------------------------------------------===//

struct CloudFormationCreateStackBindData : public TableFunctionData {
	string template_arg;
	string name_arg;
	//! Case-sensitive: CloudFormation treats `foo` and `Foo` as distinct parameters.
	OrderedStringMap template_parameters;
	string region;
	OrderedStringMap tags_override;
	bool dry_run = false;
	bool finished = false;
};

static unique_ptr<FunctionData> CloudFormationCreateStackBind(ClientContext &context, TableFunctionBindInput &input,
                                                              vector<LogicalType> &return_types,
                                                              vector<string> &names) {
	auto result = make_uniq<CloudFormationCreateStackBindData>();

	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("cloudformation_create_stack: the template argument must not be NULL");
	}
	result->template_arg = StringValue::Get(input.inputs[0]);

	for (auto &np : input.named_parameters) {
		auto key = StringUtil::Lower(np.first.GetIdentifierName());
		if (key == "name") {
			if (!np.second.IsNull()) {
				result->name_arg = StringValue::Get(np.second);
			}
		} else if (key == "region") {
			if (!np.second.IsNull()) {
				result->region = StringValue::Get(np.second);
			}
		} else if (key == "template_parameters") {
			result->template_parameters = UnpackStringMap(np.second);
		} else if (key == "tags") {
			result->tags_override = UnpackStringMap(np.second);
		} else if (key == "dry_run") {
			result->dry_run = !np.second.IsNull() && BooleanValue::Get(np.second);
		}
	}

	// region is validated in the execution function, not here: throwing during bind
	// would preempt column resolution, and the tests rely on a missing output column
	// surfacing as a binder error rather than being masked by this check.

	// The schema does not depend on dry_run: a dry run resolves and validates
	// exactly as a real create does, it just never calls CreateStack. Only the
	// handle differs - it is NULL when nothing was created, which also stops a
	// dry-run row from being fed to cloudformation_describe_stack/_delete_stack.
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("region");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("parameters");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("tags");
	return_types.emplace_back(LogicalType::LIST(LogicalType::VARCHAR));
	names.emplace_back("capabilities");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("description");

	return std::move(result);
}

namespace {

//! Everything cloudformation_create_stack derives from its arguments before it
//! mutates anything: the resolved stack name, the parameters and tags that would
//! be sent, and the capabilities the template demands. Producing this is a
//! read-only operation (one GetTemplateSummary call), so it is shared by the real
//! create path and by dry_run.
struct ResolvedStackRequest {
	string stack_name;
	bool template_is_url = false;
	Aws::Vector<Aws::CloudFormation::Model::Parameter> parameters;
	Aws::Vector<Aws::CloudFormation::Model::Tag> tags;
	Aws::Vector<Aws::CloudFormation::Model::Capability> capabilities;
	string description;
};

//! Resolve the caller's arguments into a validated CreateStack request. Throws on
//! any input the template cannot accept, so callers reach CreateStack only with a
//! request CloudFormation has a chance of honouring.
ResolvedStackRequest ResolveStackRequest(Aws::CloudFormation::CloudFormationClient &client,
                                         const CloudFormationCreateStackBindData &data) {
	ResolvedStackRequest resolved;
	resolved.template_is_url = LooksLikeUrl(data.template_arg);

	// Ask CloudFormation to parse the template: declared parameters, required
	// capabilities, and the Metadata section.
	Aws::CloudFormation::Model::GetTemplateSummaryRequest summary_req;
	if (resolved.template_is_url) {
		summary_req.SetTemplateURL(data.template_arg.c_str());
	} else {
		summary_req.SetTemplateBody(data.template_arg.c_str());
	}
	auto summary_outcome = client.GetTemplateSummary(summary_req);
	if (!summary_outcome.IsSuccess()) {
		const auto &err = summary_outcome.GetError();
		throw IOException("CloudFormation GetTemplateSummary failed: %s - %s", FromAws(err.GetExceptionName()),
		                  FromAws(err.GetMessage()));
	}
	const auto &summary = summary_outcome.GetResult();
	resolved.capabilities = summary.GetCapabilities();
	resolved.description = FromAws(summary.GetDescription());

	// A declared parameter with no default must be supplied by the caller.
	// Track those separately so we can report the ones left unsatisfied below.
	std::set<string> declared_params;
	std::set<string> unsatisfied_params;
	for (const auto &pd : summary.GetParameters()) {
		auto key = FromAws(pd.GetParameterKey());
		declared_params.insert(key);
		if (!pd.DefaultValueHasBeenSet()) {
			unsatisfied_params.insert(key);
		}
	}

	string metadata_stack_name;
	if (!summary.GetMetadata().empty()) {
		Aws::Utils::Json::JsonValue meta(summary.GetMetadata());
		if (meta.WasParseSuccessful()) {
			auto view = meta.View();
			if (view.KeyExists("StackName")) {
				metadata_stack_name = FromAws(view.GetString("StackName"));
			}
		}
	}

	// Resolve the stack name. Cap autogenerated prefixes so the full ARN
	// stays within CloudFormation's 128-char StackName API limit. Reject
	// explicit names that exceed the limit.
	if (!data.name_arg.empty()) {
		// Explicit name
		if (data.name_arg.size() > MAX_STACK_NAME_LEN) {
			throw InvalidInputException("cloudformation_create_stack: explicit name '%s' is %llu chars; max %llu "
			                            "(resulting CFN stack ARN length is bounded to 128 chars)",
			                            data.name_arg, (unsigned long long)data.name_arg.size(),
			                            (unsigned long long)MAX_STACK_NAME_LEN);
		}
		resolved.stack_name = data.name_arg;
	} else {
		// Auto-generate prefix, then append UUID
		string prefix;
		if (!metadata_stack_name.empty()) {
			prefix = SanitizeNameFragment(metadata_stack_name);
		} else if (resolved.template_is_url) {
			prefix = UrlBasenameStem(data.template_arg);
		}
		if (prefix.empty()) {
			prefix = "duckdb-aws";
		}
		if (prefix.size() > MAX_PREFIX_LEN) {
			prefix = prefix.substr(0, MAX_PREFIX_LEN);
		}
		resolved.stack_name = prefix + "-" + ShortRandHex();
	}

	// Every key must name a parameter the template declares. No key is reserved:
	// credentials come from CREATE SECRET, so a template is free to declare a
	// parameter called Region or Profile without it being swallowed as config.
	for (auto &kv : data.template_parameters) {
		if (!declared_params.count(kv.first)) {
			throw InvalidInputException(
			    "cloudformation_create_stack: template_parameters['%s'] is not a parameter declared by the template",
			    kv.first);
		}
		unsatisfied_params.erase(kv.first);
		Aws::CloudFormation::Model::Parameter param;
		param.SetParameterKey(kv.first.c_str());
		param.SetParameterValue(kv.second.c_str());
		resolved.parameters.push_back(param);
	}

	// Whatever is left declares no default and was not supplied: CreateStack
	// would fail server-side. Report every one of them, not just the first.
	if (!unsatisfied_params.empty()) {
		throw InvalidInputException("cloudformation_create_stack: the template requires parameter(s) %s, which have no "
		                            "default and were not supplied in template_parameters",
		                            StringUtil::Join(unsatisfied_params, ", "));
	}

	// Tags: provenance auto-tags first, then caller-supplied extras (which
	// override on key collision because they're applied last). operator[] gives
	// last-wins override while keeping insertion order.
	OrderedStringMap tags;
	tags["created-by"] = "duckdb-aws";
	tags["created-by-version"] = DUCKDB_AWS_GIT_SHA;
	tags["duckdb-version"] = DuckDB::LibraryVersion();
	tags["duckdb-session-id"] = SessionId();
	if (!metadata_stack_name.empty()) {
		tags["stack-name"] = metadata_stack_name;
	}
	for (auto &kv : data.tags_override) {
		tags[kv.first] = kv.second;
	}
	for (auto &kv : tags) {
		Aws::CloudFormation::Model::Tag t;
		t.SetKey(kv.first.c_str());
		t.SetValue(kv.second.c_str());
		resolved.tags.push_back(t);
	}

	return resolved;
}

} // namespace

static void CloudFormationCreateStackFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = (CloudFormationCreateStackBindData &)*data_p.bind_data;
	if (data.finished) {
		return;
	}

	const string &region = data.region;
	if (region.empty()) {
		throw InvalidInputException(
		    "cloudformation_create_stack: region is required - set the region:= named parameter");
	}

	// Credentials come from CREATE SECRET / the default chain, exactly as they do
	// for describe_stack, delete_stack and list_stacks. Accepting per-call
	// credential overrides here and nowhere else meant a stack created under an
	// assumed role could not be deleted through this extension.
	auto provider = BuildAwsCredentialsProvider("", /*require_credentials=*/true);
	auto client_config = BuildClientConfigWithCa();
	client_config.region = region.c_str();
	Aws::CloudFormation::CloudFormationClient cloudformation_client(provider, client_config);

	auto resolved = ResolveStackRequest(cloudformation_client, data);

	// A dry run stops here: everything above is read-only, everything below
	// mutates. The handle stays NULL because no stack exists to refer to.
	Value handle(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	if (!data.dry_run) {
		Aws::CloudFormation::Model::CreateStackRequest req;
		req.SetStackName(resolved.stack_name.c_str());
		if (resolved.template_is_url) {
			req.SetTemplateURL(data.template_arg.c_str());
		} else {
			req.SetTemplateBody(data.template_arg.c_str());
		}
		if (!resolved.parameters.empty()) {
			req.SetParameters(resolved.parameters);
		}
		if (!resolved.capabilities.empty()) {
			req.SetCapabilities(resolved.capabilities);
		}
		if (!resolved.tags.empty()) {
			req.SetTags(resolved.tags);
		}

		auto outcome = cloudformation_client.CreateStack(req);
		if (!outcome.IsSuccess()) {
			const auto &err = outcome.GetError();
			throw IOException("CloudFormation CreateStack failed: %s - %s", FromAws(err.GetExceptionName()),
			                  FromAws(err.GetMessage()));
		}
		string stack_id = FromAws(outcome.GetResult().GetStackId());

		vector<Value> keys;
		vector<Value> values;
		keys.emplace_back("stack_name");
		values.emplace_back(resolved.stack_name);
		keys.emplace_back("stack_id");
		values.emplace_back(stack_id);
		keys.emplace_back("region");
		values.emplace_back(region);
		handle = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
	}

	vector<Value> param_keys;
	vector<Value> param_values;
	for (const auto &p : resolved.parameters) {
		param_keys.emplace_back(FromAws(p.GetParameterKey()));
		param_values.emplace_back(FromAws(p.GetParameterValue()));
	}
	vector<Value> tag_keys;
	vector<Value> tag_values;
	for (const auto &t : resolved.tags) {
		tag_keys.emplace_back(FromAws(t.GetKey()));
		tag_values.emplace_back(FromAws(t.GetValue()));
	}
	vector<Value> capabilities;
	for (const auto &c : resolved.capabilities) {
		capabilities.emplace_back(FromAws(Aws::CloudFormation::Model::CapabilityMapper::GetNameForCapability(c)));
	}

	output.data[0].Append(handle);
	output.data[1].Append(Value(resolved.stack_name));
	output.data[2].Append(Value(region));
	output.data[3].Append(
	    Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(param_keys), std::move(param_values)));
	output.data[4].Append(
	    Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(tag_keys), std::move(tag_values)));
	output.data[5].Append(Value::LIST(LogicalType::VARCHAR, std::move(capabilities)));
	output.data[6].Append(resolved.description.empty() ? Value() : Value(resolved.description));
	output.CheckCardinality(1);
	data.finished = true;
}

//===--------------------------------------------------------------------===//
// Shared handle parsing (cloudformation_describe_stack / cloudformation_outputs / cloudformation_delete_stack)
//===--------------------------------------------------------------------===//

namespace {

struct CloudFormationHandle {
	string stack_ref; // stack_id (ARN) when present, else stack_name
	string stack_name;
	string stack_id;
	string region;
};

CloudFormationHandle ParseHandle(const Value &handle_value, const char *fn_name) {
	auto kvs = UnpackStringMapCI(handle_value);
	CloudFormationHandle h;
	auto get = [&](const string &key) -> string {
		auto it = kvs.find(key);
		return it != kvs.end() ? it->second : string();
	};
	h.stack_id = get("stack_id");
	h.stack_name = get("stack_name");
	h.region = get("region");
	h.stack_ref = !h.stack_id.empty() ? h.stack_id : h.stack_name;
	if (h.stack_ref.empty()) {
		throw InvalidInputException("%s: handle must contain 'stack_id' or 'stack_name'", fn_name);
	}
	if (h.region.empty()) {
		throw InvalidInputException("%s: handle is missing 'region'", fn_name);
	}
	return h;
}

} // namespace

//===--------------------------------------------------------------------===//
// cloudformation_describe_stack(handle)
//===--------------------------------------------------------------------===//

struct CloudFormationDescribeStackBindData : public TableFunctionData {
	CloudFormationHandle handle;
	bool finished = false;
};

static unique_ptr<FunctionData> CloudFormationDescribeStackBind(ClientContext &context, TableFunctionBindInput &input,
                                                                vector<LogicalType> &return_types,
                                                                vector<string> &names) {
	auto result = make_uniq<CloudFormationDescribeStackBindData>();
	result->handle = ParseHandle(input.inputs[0], "cloudformation_describe_stack");

	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("region");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("status");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("status_reason");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("creation_time");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("last_updated_time");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("description");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("tags");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("outputs");

	return std::move(result);
}

static void CloudFormationDescribeStackFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = (CloudFormationDescribeStackBindData &)*data_p.bind_data;
	if (data.finished) {
		return;
	}

	auto provider = BuildAwsCredentialsProvider("", /*require_credentials=*/true);
	auto cfg = BuildClientConfigWithCa();
	cfg.region = data.handle.region.c_str();
	Aws::CloudFormation::CloudFormationClient cloudformation_client(provider, cfg);

	Aws::CloudFormation::Model::DescribeStacksRequest req;
	req.SetStackName(data.handle.stack_ref.c_str());
	auto outcome = cloudformation_client.DescribeStacks(req);
	if (!outcome.IsSuccess()) {
		const auto &err = outcome.GetError();
		throw IOException("CloudFormation DescribeStacks failed: %s - %s", FromAws(err.GetExceptionName()),
		                  FromAws(err.GetMessage()));
	}
	const auto &stacks = outcome.GetResult().GetStacks();
	if (stacks.empty()) {
		throw IOException("CloudFormation DescribeStacks returned no stack for '%s'", data.handle.stack_ref);
	}
	const auto &stack = stacks[0];

	string status =
	    FromAws(Aws::CloudFormation::Model::StackStatusMapper::GetNameForStackStatus(stack.GetStackStatus()));
	string reason = FromAws(stack.GetStackStatusReason());
	string created = FromAws(stack.GetCreationTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601));
	string updated;
	if (stack.LastUpdatedTimeHasBeenSet()) {
		updated = FromAws(stack.GetLastUpdatedTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601));
	}
	string description = FromAws(stack.GetDescription());

	vector<Value> tag_keys;
	vector<Value> tag_values;
	for (const auto &t : stack.GetTags()) {
		tag_keys.emplace_back(FromAws(t.GetKey()));
		tag_values.emplace_back(FromAws(t.GetValue()));
	}
	auto tags = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(tag_keys), std::move(tag_values));

	vector<Value> output_keys;
	vector<Value> output_values;
	for (const auto &o : stack.GetOutputs()) {
		output_keys.emplace_back(FromAws(o.GetOutputKey()));
		output_values.emplace_back(FromAws(o.GetOutputValue()));
	}
	auto outputs =
	    Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(output_keys), std::move(output_values));

	output.data[0].Append(Value(data.handle.region));
	output.data[1].Append(Value(FromAws(stack.GetStackName())));
	output.data[2].Append(Value(FromAws(stack.GetStackId())));
	output.data[3].Append(Value(status));
	output.data[4].Append(reason.empty() ? Value() : Value(reason));
	output.data[5].Append(created.empty() ? Value() : Value(created));
	output.data[6].Append(updated.empty() ? Value() : Value(updated));
	output.data[7].Append(description.empty() ? Value() : Value(description));
	output.data[8].Append(tags);
	output.data[9].Append(outputs);
	output.CheckCardinality(1);
	data.finished = true;
}

//===--------------------------------------------------------------------===//
// cloudformation_delete_stack(handle)
//===--------------------------------------------------------------------===//

struct CloudFormationDeleteStackBindData : public TableFunctionData {
	CloudFormationHandle handle;
	Value handle_value; // original MAP, echoed back verbatim
	bool dry_run = false;
	bool finished = false;
};

static unique_ptr<FunctionData> CloudFormationDeleteStackBind(ClientContext &context, TableFunctionBindInput &input,
                                                              vector<LogicalType> &return_types,
                                                              vector<string> &names) {
	auto result = make_uniq<CloudFormationDeleteStackBindData>();
	result->handle = ParseHandle(input.inputs[0], "cloudformation_delete_stack");
	result->handle_value = input.inputs[0];

	for (auto &np : input.named_parameters) {
		auto key = StringUtil::Lower(np.first.GetIdentifierName());
		if (key == "dry_run") {
			result->dry_run = !np.second.IsNull() && BooleanValue::Get(np.second);
		}
	}

	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("handle");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("region");
	return_types.emplace_back(LogicalType::BOOLEAN);
	names.emplace_back("exists");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("status");
	return_types.emplace_back(LogicalType::BOOLEAN);
	names.emplace_back("termination_protection");

	return std::move(result);
}

static void CloudFormationDeleteStackFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = (CloudFormationDeleteStackBindData &)*data_p.bind_data;
	if (data.finished) {
		return;
	}

	auto provider = BuildAwsCredentialsProvider("", /*require_credentials=*/true);
	auto cfg = BuildClientConfigWithCa();
	cfg.region = data.handle.region.c_str();
	Aws::CloudFormation::CloudFormationClient cloudformation_client(provider, cfg);

	// Describe first, on both paths, so the row says the same thing whether or not
	// the delete fired. DeleteStack itself performs these checks server-side, so a
	// failure here is never worth aborting a real delete over: swallow it and let
	// DeleteStack report the authoritative error. On a dry run there is no such
	// second chance, so anything other than "no such stack" is raised.
	Value exists;                 // NULL when DescribeStacks could not answer
	Value status;                 // NULL when the stack is gone or unknown
	Value termination_protection; // NULL when not reported by CloudFormation
	Aws::CloudFormation::Model::DescribeStacksRequest desc_req;
	desc_req.SetStackName(data.handle.stack_ref.c_str());
	auto desc_outcome = cloudformation_client.DescribeStacks(desc_req);
	if (desc_outcome.IsSuccess()) {
		const auto &stacks = desc_outcome.GetResult().GetStacks();
		if (stacks.empty()) {
			exists = Value::BOOLEAN(false);
		} else {
			const auto &stack = stacks[0];
			exists = Value::BOOLEAN(true);
			status = Value(
			    FromAws(Aws::CloudFormation::Model::StackStatusMapper::GetNameForStackStatus(stack.GetStackStatus())));
			if (stack.EnableTerminationProtectionHasBeenSet()) {
				termination_protection = Value::BOOLEAN(stack.GetEnableTerminationProtection());
			}
		}
	} else {
		const auto &err = desc_outcome.GetError();
		// CloudFormation reports an absent stack as ValidationError. DeleteStack is
		// idempotent there - it succeeds - so a dry run must report the absence
		// rather than raise, or it would predict a failure that never happens.
		if (FromAws(err.GetExceptionName()) == "ValidationError") {
			exists = Value::BOOLEAN(false);
		} else if (data.dry_run) {
			throw IOException("CloudFormation DescribeStacks failed: %s - %s", FromAws(err.GetExceptionName()),
			                  FromAws(err.GetMessage()));
		}
	}

	// A dry run stops here. The handle is NULL because nothing was deleted, which
	// also keeps a dry-run row from being mistaken for proof of deletion.
	Value handle(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	if (!data.dry_run) {
		Aws::CloudFormation::Model::DeleteStackRequest req;
		req.SetStackName(data.handle.stack_ref.c_str());
		auto outcome = cloudformation_client.DeleteStack(req);
		if (!outcome.IsSuccess()) {
			const auto &err = outcome.GetError();
			throw IOException("CloudFormation DeleteStack failed: %s - %s", FromAws(err.GetExceptionName()),
			                  FromAws(err.GetMessage()));
		}
		// Pass-through: echo the input handle byte-for-byte. Any extra keys the
		// caller put in (annotations, timestamps, custom metadata) survive intact.
		handle = data.handle_value;
	}

	output.data[0].Append(handle);
	output.data[1].Append(data.handle.stack_name.empty() ? Value() : Value(data.handle.stack_name));
	output.data[2].Append(data.handle.stack_id.empty() ? Value() : Value(data.handle.stack_id));
	output.data[3].Append(Value(data.handle.region));
	output.data[4].Append(exists);
	output.data[5].Append(status);
	output.data[6].Append(termination_protection);
	output.CheckCardinality(1);
	data.finished = true;
}

//===--------------------------------------------------------------------===//
// cloudformation_list_stacks([region := ...] [status_filter := ...])
//===--------------------------------------------------------------------===//

struct CloudFormationListStacksRow {
	string region;
	string stack_name;
	string stack_id;
	string status;
	string status_reason;
	string creation_time;
	string last_updated_time;
	string description;
};

struct CloudFormationListStacksBindData : public TableFunctionData {
	string region;
	vector<Aws::CloudFormation::Model::StackStatus> status_filter;
	bool initialized = false;
	vector<CloudFormationListStacksRow> rows;
	idx_t cursor = 0;
};

static unique_ptr<FunctionData> CloudFormationListStacksBind(ClientContext &context, TableFunctionBindInput &input,
                                                             vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<CloudFormationListStacksBindData>();

	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("cloudformation_list_stacks: region must not be NULL");
	}
	result->region = StringValue::Get(input.inputs[0]);
	if (result->region.empty()) {
		throw InvalidInputException("cloudformation_list_stacks: region must not be empty");
	}

	for (auto &np : input.named_parameters) {
		auto key = StringUtil::Lower(np.first.GetIdentifierName());
		if (key == "status_filter") {
			if (!np.second.IsNull()) {
				auto &children = ListValue::GetChildren(np.second);
				for (auto &child : children) {
					if (child.IsNull()) {
						continue;
					}
					auto str = StringValue::Get(child);
					auto status_enum =
					    Aws::CloudFormation::Model::StackStatusMapper::GetStackStatusForName(str.c_str());
					if (status_enum == Aws::CloudFormation::Model::StackStatus::NOT_SET) {
						throw InvalidInputException(
						    "cloudformation_list_stacks: unknown stack status '%s' in status_filter", str);
					}
					result->status_filter.push_back(status_enum);
				}
			}
		}
	}

	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("region");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("status");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("status_reason");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("creation_time");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("last_updated_time");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("description");

	return std::move(result);
}

static void CloudFormationListStacksFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = (CloudFormationListStacksBindData &)*data_p.bind_data;

	if (!data.initialized) {
		auto provider = BuildAwsCredentialsProvider("", /*require_credentials=*/true);
		auto cfg = BuildClientConfigWithCa();
		cfg.region = data.region.c_str();
		Aws::CloudFormation::CloudFormationClient cloudformation_client(provider, cfg);

		Aws::String next_token;
		do {
			Aws::CloudFormation::Model::ListStacksRequest req;
			if (!data.status_filter.empty()) {
				req.SetStackStatusFilter(data.status_filter);
			}
			if (!next_token.empty()) {
				req.SetNextToken(next_token);
			}
			auto outcome = cloudformation_client.ListStacks(req);
			if (!outcome.IsSuccess()) {
				const auto &err = outcome.GetError();
				throw IOException("CloudFormation ListStacks failed: %s - %s", FromAws(err.GetExceptionName()),
				                  FromAws(err.GetMessage()));
			}
			const auto &res = outcome.GetResult();
			for (const auto &s : res.GetStackSummaries()) {
				CloudFormationListStacksRow row;
				row.region = data.region;
				row.stack_name = FromAws(s.GetStackName());
				row.stack_id = FromAws(s.GetStackId());
				row.status =
				    FromAws(Aws::CloudFormation::Model::StackStatusMapper::GetNameForStackStatus(s.GetStackStatus()));
				row.status_reason = FromAws(s.GetStackStatusReason());
				row.creation_time = FromAws(s.GetCreationTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601));
				if (s.LastUpdatedTimeHasBeenSet()) {
					row.last_updated_time =
					    FromAws(s.GetLastUpdatedTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601));
				}
				row.description = FromAws(s.GetTemplateDescription());
				data.rows.push_back(row);
			}
			next_token = res.GetNextToken();
		} while (!next_token.empty());
		data.initialized = true;
	}

	idx_t remaining = data.rows.size() - data.cursor;
	idx_t to_emit = std::min(remaining, (idx_t)STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < to_emit; i++) {
		auto &r = data.rows[data.cursor + i];
		output.data[0].Append(Value(r.region));
		output.data[1].Append(Value(r.stack_name));
		output.data[2].Append(Value(r.stack_id));
		output.data[3].Append(Value(r.status));
		output.data[4].Append(r.status_reason.empty() ? Value() : Value(r.status_reason));
		output.data[5].Append(r.creation_time.empty() ? Value() : Value(r.creation_time));
		output.data[6].Append(r.last_updated_time.empty() ? Value() : Value(r.last_updated_time));
		output.data[7].Append(r.description.empty() ? Value() : Value(r.description));
	}
	output.CheckCardinality(to_emit);
	data.cursor += to_emit;
}

//===--------------------------------------------------------------------===//
// cloudformation_describe_stacks([region | region_list])
//
// DescribeStacks with no stack name: every stack in the region(s) (paginated),
// carrying tags and outputs — the tag-and-output-bearing counterpart to the
// tag-less cloudformation_list_stacks. DELETE_COMPLETE stacks are not returned.
//
// Three overloads: no argument sweeps all default regions in parallel; a single
// VARCHAR is one region (its error is thrown); a LIST(VARCHAR) is those regions
// in parallel. The parallel variants fan out one task per region over DuckDB's
// scheduler and SKIP a region that errors (denied/unreachable) rather than
// failing the whole sweep.
//===--------------------------------------------------------------------===//

struct CloudFormationDescribeStacksRow {
	string region;
	string stack_name;
	string stack_id;
	string status;
	string status_reason;
	string creation_time;
	string last_updated_time;
	string description;
	Value tags;
	Value outputs;
	// Empty for a real stack; the AWS error message for a failed-region sentinel row (region set, all stack
	// columns NULL). Discriminates the two row kinds: real stacks have error IS NULL. Named generically (not
	// region_error) so it can carry other, non-region error conditions later.
	string error;
};

// Fetch all stacks in one region (paginated), appending to `out`. Throws on AWS error.
static void DescribeRegionStacks(const string &region, vector<CloudFormationDescribeStacksRow> &out) {
	auto provider = BuildAwsCredentialsProvider("", /*require_credentials=*/true);
	auto cfg = BuildClientConfigWithCa();
	cfg.region = region.c_str();
	Aws::CloudFormation::CloudFormationClient cloudformation_client(provider, cfg);

	Aws::String next_token;
	do {
		Aws::CloudFormation::Model::DescribeStacksRequest req;
		if (!next_token.empty()) {
			req.SetNextToken(next_token);
		}
		auto outcome = cloudformation_client.DescribeStacks(req);
		if (!outcome.IsSuccess()) {
			const auto &err = outcome.GetError();
			throw IOException("CloudFormation DescribeStacks failed: %s - %s", FromAws(err.GetExceptionName()),
			                  FromAws(err.GetMessage()));
		}
		const auto &res = outcome.GetResult();
		for (const auto &stack : res.GetStacks()) {
			CloudFormationDescribeStacksRow row;
			row.region = region;
			row.stack_name = FromAws(stack.GetStackName());
			row.stack_id = FromAws(stack.GetStackId());
			row.status =
			    FromAws(Aws::CloudFormation::Model::StackStatusMapper::GetNameForStackStatus(stack.GetStackStatus()));
			row.status_reason = FromAws(stack.GetStackStatusReason());
			row.creation_time = FromAws(stack.GetCreationTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601));
			if (stack.LastUpdatedTimeHasBeenSet()) {
				row.last_updated_time =
				    FromAws(stack.GetLastUpdatedTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601));
			}
			row.description = FromAws(stack.GetDescription());

			vector<Value> tag_keys;
			vector<Value> tag_values;
			for (const auto &t : stack.GetTags()) {
				tag_keys.emplace_back(FromAws(t.GetKey()));
				tag_values.emplace_back(FromAws(t.GetValue()));
			}
			row.tags =
			    Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(tag_keys), std::move(tag_values));

			vector<Value> output_keys;
			vector<Value> output_values;
			for (const auto &o : stack.GetOutputs()) {
				output_keys.emplace_back(FromAws(o.GetOutputKey()));
				output_values.emplace_back(FromAws(o.GetOutputValue()));
			}
			row.outputs = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(output_keys),
			                         std::move(output_values));

			out.push_back(std::move(row));
		}
		next_token = res.GetNextToken();
	} while (!next_token.empty());
}

// One region's DescribeStacks as a scheduler task. Catches its own AWS error (never PushError, which would
// abort the whole sweep via WorkOnTasks) and replaces its slot with a single 'error' sentinel row, so
// a dead region is surfaced-but-not-fatal instead of silently vanishing.
struct DescribeRegionTask : public BaseExecutorTask {
	DescribeRegionTask(TaskExecutor &executor, string region_p, vector<CloudFormationDescribeStacksRow> &slot_p)
	    : BaseExecutorTask(executor), region(std::move(region_p)), slot(slot_p) {
	}
	void ExecuteTask() override {
		try {
			DescribeRegionStacks(region, slot);
		} catch (const std::exception &e) {
			EmitError(e.what());
		} catch (...) {
			EmitError("unknown error");
		}
	}
	void EmitError(const string &message) {
		slot.clear();
		CloudFormationDescribeStacksRow err;
		err.region = region;
		err.error = message;
		err.tags = Value(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));    // NULL
		err.outputs = Value(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)); // NULL
		slot.push_back(std::move(err));
	}
	string region;
	vector<CloudFormationDescribeStacksRow> &slot;
};

struct CloudFormationDescribeStacksBindData : public TableFunctionData {
	vector<string> regions;
	bool throw_on_region_error = false; // true only for the single-VARCHAR overload
	bool initialized = false;
	vector<CloudFormationDescribeStacksRow> rows;
	idx_t cursor = 0;
};

static unique_ptr<FunctionData> CloudFormationDescribeStacksBind(ClientContext &context, TableFunctionBindInput &input,
                                                                 vector<LogicalType> &return_types,
                                                                 vector<string> &names) {
	auto result = make_uniq<CloudFormationDescribeStacksBindData>();

	if (input.inputs.empty()) {
		// No argument: sweep all default regions in parallel.
		result->regions = GetDefaultAwsRegions();
	} else if (input.inputs[0].type().id() == LogicalTypeId::LIST) {
		// Explicit region list: parallel, skip-on-error.
		if (input.inputs[0].IsNull()) {
			throw InvalidInputException("cloudformation_describe_stacks: region list must not be NULL");
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
			throw InvalidInputException("cloudformation_describe_stacks: region list must not be empty");
		}
	} else {
		// Single explicit region: surface its error rather than silently skipping.
		if (input.inputs[0].IsNull()) {
			throw InvalidInputException("cloudformation_describe_stacks: region must not be NULL");
		}
		auto r = StringValue::Get(input.inputs[0]);
		if (r.empty()) {
			throw InvalidInputException("cloudformation_describe_stacks: region must not be empty");
		}
		result->regions.push_back(r);
		result->throw_on_region_error = true;
	}

	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("region");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_name");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("stack_id");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("status");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("status_reason");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("creation_time");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("last_updated_time");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("description");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("tags");
	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("outputs");
	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("error");

	return std::move(result);
}

static void CloudFormationDescribeStacksFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = (CloudFormationDescribeStacksBindData &)*data_p.bind_data;

	if (!data.initialized) {
		if (data.throw_on_region_error) {
			// Single explicit region: run inline and let its error propagate.
			DescribeRegionStacks(data.regions[0], data.rows);
		} else {
			// Parallel fan-out: one task per region into its own slot; a region that errors is skipped. Fixed-size
			// `slots` so the vector never reallocates while tasks hold references into it.
			vector<vector<CloudFormationDescribeStacksRow>> slots(data.regions.size());
			TaskExecutor executor(context);
			for (idx_t i = 0; i < data.regions.size(); i++) {
				executor.ScheduleTask(make_uniq<DescribeRegionTask>(executor, data.regions[i], slots[i]));
			}
			executor.WorkOnTasks();
			for (auto &slot : slots) {
				for (auto &row : slot) {
					data.rows.push_back(std::move(row));
				}
			}
		}
		data.initialized = true;
	}

	idx_t remaining = data.rows.size() - data.cursor;
	idx_t to_emit = std::min(remaining, (idx_t)STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < to_emit; i++) {
		auto &r = data.rows[data.cursor + i];
		// stack_name/stack_id/status are always set for a real stack and empty for an 'error' sentinel,
		// so empty -> NULL cleanly distinguishes the two without special-casing.
		output.data[0].Append(Value(r.region));
		output.data[1].Append(r.stack_name.empty() ? Value() : Value(r.stack_name));
		output.data[2].Append(r.stack_id.empty() ? Value() : Value(r.stack_id));
		output.data[3].Append(r.status.empty() ? Value() : Value(r.status));
		output.data[4].Append(r.status_reason.empty() ? Value() : Value(r.status_reason));
		output.data[5].Append(r.creation_time.empty() ? Value() : Value(r.creation_time));
		output.data[6].Append(r.last_updated_time.empty() ? Value() : Value(r.last_updated_time));
		output.data[7].Append(r.description.empty() ? Value() : Value(r.description));
		output.data[8].Append(r.tags);
		output.data[9].Append(r.outputs);
		output.data[10].Append(r.error.empty() ? Value() : Value(r.error));
	}
	output.CheckCardinality(to_emit);
	data.cursor += to_emit;
}

//===--------------------------------------------------------------------===//
// duckdb_aws_session_id() scalar function
//===--------------------------------------------------------------------===//

static void DuckDBAwsSessionIdFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	auto data = ConstantVector::GetData<string_t>(result);
	data[0] = StringVector::AddString(result, SessionId());
}

//===--------------------------------------------------------------------===//
// Registration
//===--------------------------------------------------------------------===//

void CloudFormationFunctions::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	// The template is the only positional argument: it is what the verb acts on.
	// Everything else modifies the call.
	TableFunction create_fn("cloudformation_create_stack", {LogicalType::VARCHAR}, CloudFormationCreateStackFun,
	                        CloudFormationCreateStackBind);
	create_fn.named_parameters["name"] = LogicalType::VARCHAR;
	create_fn.named_parameters["region"] = LogicalType::VARCHAR;
	create_fn.named_parameters["template_parameters"] = map_vv;
	create_fn.named_parameters["tags"] = map_vv;
	// Typed BOOLEAN rather than a string key: a value that failed to parse would
	// fall through to false and create a real stack.
	create_fn.named_parameters["dry_run"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(create_fn);

	TableFunction describe_fn("cloudformation_describe_stack", {map_vv}, CloudFormationDescribeStackFun,
	                          CloudFormationDescribeStackBind);
	loader.RegisterFunction(describe_fn);

	TableFunction delete_fn("cloudformation_delete_stack", {map_vv}, CloudFormationDeleteStackFun,
	                        CloudFormationDeleteStackBind);
	delete_fn.named_parameters["dry_run"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(delete_fn);

	TableFunction list_fn("cloudformation_list_stacks", {LogicalType::VARCHAR}, CloudFormationListStacksFun,
	                      CloudFormationListStacksBind);
	list_fn.named_parameters["status_filter"] = LogicalType::LIST(LogicalType::VARCHAR);
	loader.RegisterFunction(list_fn);

	// Overloaded: no arg -> all default regions (parallel); VARCHAR -> one region; LIST(VARCHAR) -> those
	// regions (parallel). Bind dispatches on the argument shape.
	TableFunctionSet describe_all_set("cloudformation_describe_stacks");
	describe_all_set.AddFunction(TableFunction({}, CloudFormationDescribeStacksFun, CloudFormationDescribeStacksBind));
	describe_all_set.AddFunction(
	    TableFunction({LogicalType::VARCHAR}, CloudFormationDescribeStacksFun, CloudFormationDescribeStacksBind));
	describe_all_set.AddFunction(TableFunction({LogicalType::LIST(LogicalType::VARCHAR)},
	                                           CloudFormationDescribeStacksFun, CloudFormationDescribeStacksBind));
	loader.RegisterFunction(describe_all_set);

	ScalarFunction session_id_fn("duckdb_aws_session_id", {}, LogicalType::VARCHAR, DuckDBAwsSessionIdFunction);
	loader.RegisterFunction(session_id_fn);
}

} // namespace duckdb
