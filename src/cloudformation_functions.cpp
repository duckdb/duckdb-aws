#include "cloudformation_functions.hpp"
#include "aws_client.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

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

struct StringKV {
	string key;
	string value;
};

vector<StringKV> UnpackStringMap(const Value &map_value) {
	vector<StringKV> out;
	if (map_value.IsNull()) {
		return out;
	}
	auto &children = MapValue::GetChildren(map_value);
	for (auto &child : children) {
		auto &kv = StructValue::GetChildren(child);
		if (kv[0].IsNull()) {
			continue;
		}
		out.push_back({StringValue::Get(kv[0]), kv[1].IsNull() ? string() : StringValue::Get(kv[1])});
	}
	return out;
}

const string *FindCI(const vector<StringKV> &kvs, const string &key) {
	auto lowered = StringUtil::Lower(key);
	for (auto &kv : kvs) {
		if (StringUtil::Lower(kv.key) == lowered) {
			return &kv.value;
		}
	}
	return nullptr;
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
    "region",      "chain",                   "profile",     "assume_role_arn",
    "external_id", "web_identity_token_file", "session_name"};

} // namespace

//===--------------------------------------------------------------------===//
// cloudformation_create_stack(template, name, options) [region :=, tags :=]
//===--------------------------------------------------------------------===//

struct CloudFormationCreateStackBindData : public TableFunctionData {
	string template_arg;
	string name_arg;
	vector<StringKV> options;
	bool has_region_override = false;
	string region_override;
	vector<StringKV> tags_override;
	bool finished = false;
};

static unique_ptr<FunctionData> CloudFormationCreateStackBind(ClientContext &context, TableFunctionBindInput &input,
                                                   vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<CloudFormationCreateStackBindData>();

	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("cloudformation_create_stack: the template argument must not be NULL");
	}
	result->template_arg = StringValue::Get(input.inputs[0]);
	if (!input.inputs[1].IsNull()) {
		result->name_arg = StringValue::Get(input.inputs[1]);
	}
	result->options = UnpackStringMap(input.inputs[2]);

	for (auto &np : input.named_parameters) {
		auto key = StringUtil::Lower(np.first);
		if (key == "region") {
			if (!np.second.IsNull()) {
				result->has_region_override = true;
				result->region_override = StringValue::Get(np.second);
			}
		} else if (key == "tags") {
			result->tags_override = UnpackStringMap(np.second);
		}
	}

	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("handle");

	return std::move(result);
}

static void CloudFormationCreateStackFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = (CloudFormationCreateStackBindData &)*data_p.bind_data;
	if (data.finished) {
		return;
	}

	// Region: explicit override wins over options['region'].
	string region;
	if (data.has_region_override) {
		region = data.region_override;
	} else if (auto *r = FindCI(data.options, "region")) {
		region = *r;
	}
	if (region.empty()) {
		throw InvalidInputException(
		    "cloudformation_create_stack: region is required - set options['region'] or the region:= named parameter");
	}

	auto opt = [&](const string &key) -> string {
		auto *v = FindCI(data.options, key);
		return v ? *v : string();
	};

	auto provider = BuildAwsCredentialsProvider(opt("chain"), /*require_credentials=*/true, opt("profile"),
	                                            opt("assume_role_arn"), opt("external_id"),
	                                            opt("web_identity_token_file"), opt("session_name"));
	auto client_config = BuildClientConfigWithCa();
	client_config.region = region.c_str();
	Aws::CloudFormation::CloudFormationClient cfn(provider, client_config);

	bool template_is_url = LooksLikeUrl(data.template_arg);

	// Ask CloudFormation to parse the template: declared parameters, required
	// capabilities, and the Metadata section.
	Aws::CloudFormation::Model::GetTemplateSummaryRequest summary_req;
	if (template_is_url) {
		summary_req.SetTemplateURL(data.template_arg.c_str());
	} else {
		summary_req.SetTemplateBody(data.template_arg.c_str());
	}
	auto summary_outcome = cfn.GetTemplateSummary(summary_req);
	if (!summary_outcome.IsSuccess()) {
		const auto &err = summary_outcome.GetError();
		throw IOException("CloudFormation GetTemplateSummary failed: %s - %s", string(err.GetExceptionName().c_str()),
		                  string(err.GetMessage().c_str()));
	}
	const auto &summary = summary_outcome.GetResult();

	std::set<string> declared_params;
	for (const auto &pd : summary.GetParameters()) {
		declared_params.insert(string(pd.GetParameterKey().c_str()));
	}

	string metadata_stack_name;
	if (!summary.GetMetadata().empty()) {
		Aws::Utils::Json::JsonValue meta(summary.GetMetadata());
		if (meta.WasParseSuccessful()) {
			auto view = meta.View();
			if (view.KeyExists("StackName")) {
				metadata_stack_name = string(view.GetString("StackName").c_str());
			}
		}
	}

	// Resolve the stack name. Cap autogenerated prefixes so the full ARN
	// stays within CloudFormation's 128-char StackName API limit. Reject
	// explicit names that exceed the limit.
	string stack_name;
	if (!data.name_arg.empty()) {
		if (data.name_arg.size() > MAX_STACK_NAME_LEN) {
			throw InvalidInputException(
			    "cloudformation_create_stack: explicit name '%s' is %llu chars; max %llu "
			    "(to keep the resulting CFN stack ARN within the 128-char API limit)",
			    data.name_arg, (unsigned long long)data.name_arg.size(),
			    (unsigned long long)MAX_STACK_NAME_LEN);
		}
		stack_name = data.name_arg;
	} else {
		string prefix;
		if (!metadata_stack_name.empty()) {
			prefix = SanitizeNameFragment(metadata_stack_name);
		} else if (template_is_url) {
			prefix = UrlBasenameStem(data.template_arg);
		}
		if (prefix.empty()) {
			prefix = "duckdb-aws";
		}
		if (prefix.size() > MAX_PREFIX_LEN) {
			prefix = prefix.substr(0, MAX_PREFIX_LEN);
		}
		stack_name = prefix + "-" + ShortRandHex();
	}

	// Route every non-reserved option key to a declared template parameter.
	Aws::Vector<Aws::CloudFormation::Model::Parameter> cloudformation_params;
	for (auto &kv : data.options) {
		if (RESERVED_OPTION_KEYS.count(StringUtil::Lower(kv.key))) {
			continue;
		}
		if (!declared_params.count(kv.key)) {
			throw InvalidInputException(
			    "cloudformation_create_stack: option '%s' is not a parameter declared by the template", kv.key);
		}
		Aws::CloudFormation::Model::Parameter p;
		p.SetParameterKey(kv.key.c_str());
		p.SetParameterValue(kv.value.c_str());
		cloudformation_params.push_back(p);
	}

	// Tags: provenance auto-tags first, then caller-supplied extras (which
	// override on key collision because they're applied last).
	vector<StringKV> tag_kv;
	auto set_tag = [&](const string &k, const string &v) {
		for (auto &existing : tag_kv) {
			if (existing.key == k) {
				existing.value = v;
				return;
			}
		}
		tag_kv.push_back({k, v});
	};
	set_tag("created-by", "duckdb-aws");
	set_tag("created-by-version", DUCKDB_AWS_GIT_SHA);
	set_tag("duckdb-version", DuckDB::LibraryVersion());
	set_tag("managed-by", "duckdb-aws");
	set_tag("duckdb-session-id", SessionId());
	if (!metadata_stack_name.empty()) {
		set_tag("stack-name", metadata_stack_name);
	}
	for (auto &kv : data.tags_override) {
		set_tag(kv.key, kv.value);
	}
	Aws::Vector<Aws::CloudFormation::Model::Tag> cloudformation_tags;
	for (auto &kv : tag_kv) {
		Aws::CloudFormation::Model::Tag t;
		t.SetKey(kv.key.c_str());
		t.SetValue(kv.value.c_str());
		cloudformation_tags.push_back(t);
	}

	Aws::CloudFormation::Model::CreateStackRequest req;
	req.SetStackName(stack_name.c_str());
	if (template_is_url) {
		req.SetTemplateURL(data.template_arg.c_str());
	} else {
		req.SetTemplateBody(data.template_arg.c_str());
	}
	if (!cloudformation_params.empty()) {
		req.SetParameters(cloudformation_params);
	}
	if (!summary.GetCapabilities().empty()) {
		req.SetCapabilities(summary.GetCapabilities());
	}
	if (!cloudformation_tags.empty()) {
		req.SetTags(cloudformation_tags);
	}

	auto outcome = cfn.CreateStack(req);
	if (!outcome.IsSuccess()) {
		const auto &err = outcome.GetError();
		throw IOException("CloudFormation CreateStack failed: %s - %s", string(err.GetExceptionName().c_str()),
		                  string(err.GetMessage().c_str()));
	}
	string stack_id(outcome.GetResult().GetStackId().c_str());

	vector<Value> keys;
	vector<Value> values;
	keys.emplace_back("stack_name");
	values.emplace_back(stack_name);
	keys.emplace_back("stack_id");
	values.emplace_back(stack_id);
	keys.emplace_back("region");
	values.emplace_back(region);
	auto handle = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));

	output.SetValue(0, 0, handle);
	output.SetCardinality(1);
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
	auto kvs = UnpackStringMap(handle_value);
	CloudFormationHandle h;
	if (auto *v = FindCI(kvs, "stack_id")) {
		h.stack_id = *v;
	}
	if (auto *v = FindCI(kvs, "stack_name")) {
		h.stack_name = *v;
	}
	if (auto *v = FindCI(kvs, "region")) {
		h.region = *v;
	}
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
                                                     vector<LogicalType> &return_types, vector<string> &names) {
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
	Aws::CloudFormation::CloudFormationClient cfn(provider, cfg);

	Aws::CloudFormation::Model::DescribeStacksRequest req;
	req.SetStackName(data.handle.stack_ref.c_str());
	auto outcome = cfn.DescribeStacks(req);
	if (!outcome.IsSuccess()) {
		const auto &err = outcome.GetError();
		throw IOException("CloudFormation DescribeStacks failed: %s - %s", string(err.GetExceptionName().c_str()),
		                  string(err.GetMessage().c_str()));
	}
	const auto &stacks = outcome.GetResult().GetStacks();
	if (stacks.empty()) {
		throw IOException("CloudFormation DescribeStacks returned no stack for '%s'", data.handle.stack_ref);
	}
	const auto &stack = stacks[0];

	string status(
	    Aws::CloudFormation::Model::StackStatusMapper::GetNameForStackStatus(stack.GetStackStatus()).c_str());
	string reason(stack.GetStackStatusReason().c_str());
	string created(stack.GetCreationTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601).c_str());
	string updated;
	if (stack.LastUpdatedTimeHasBeenSet()) {
		updated = string(stack.GetLastUpdatedTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601).c_str());
	}
	string description(stack.GetDescription().c_str());

	vector<Value> tag_keys;
	vector<Value> tag_values;
	for (const auto &t : stack.GetTags()) {
		tag_keys.emplace_back(string(t.GetKey().c_str()));
		tag_values.emplace_back(string(t.GetValue().c_str()));
	}
	auto tags = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(tag_keys), std::move(tag_values));

	vector<Value> output_keys;
	vector<Value> output_values;
	for (const auto &o : stack.GetOutputs()) {
		output_keys.emplace_back(string(o.GetOutputKey().c_str()));
		output_values.emplace_back(string(o.GetOutputValue().c_str()));
	}
	auto outputs =
	    Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(output_keys), std::move(output_values));

	output.SetValue(0, 0, Value(data.handle.region));
	output.SetValue(1, 0, Value(string(stack.GetStackName().c_str())));
	output.SetValue(2, 0, Value(string(stack.GetStackId().c_str())));
	output.SetValue(3, 0, Value(status));
	output.SetValue(4, 0, reason.empty() ? Value() : Value(reason));
	output.SetValue(5, 0, created.empty() ? Value() : Value(created));
	output.SetValue(6, 0, updated.empty() ? Value() : Value(updated));
	output.SetValue(7, 0, description.empty() ? Value() : Value(description));
	output.SetValue(8, 0, tags);
	output.SetValue(9, 0, outputs);
	output.SetCardinality(1);
	data.finished = true;
}

//===--------------------------------------------------------------------===//
// cloudformation_delete_stack(handle)
//===--------------------------------------------------------------------===//

struct CloudFormationDeleteStackBindData : public TableFunctionData {
	CloudFormationHandle handle;
	Value handle_value;   // original MAP, echoed back verbatim
	bool finished = false;
};

static unique_ptr<FunctionData> CloudFormationDeleteStackBind(ClientContext &context, TableFunctionBindInput &input,
                                                   vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<CloudFormationDeleteStackBindData>();
	result->handle = ParseHandle(input.inputs[0], "cloudformation_delete_stack");
	result->handle_value = input.inputs[0];

	return_types.emplace_back(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	names.emplace_back("handle");

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
	Aws::CloudFormation::CloudFormationClient cfn(provider, cfg);

	Aws::CloudFormation::Model::DeleteStackRequest req;
	req.SetStackName(data.handle.stack_ref.c_str());
	auto outcome = cfn.DeleteStack(req);
	if (!outcome.IsSuccess()) {
		const auto &err = outcome.GetError();
		throw IOException("CloudFormation DeleteStack failed: %s - %s", string(err.GetExceptionName().c_str()),
		                  string(err.GetMessage().c_str()));
	}

	// Pass-through: echo the input handle byte-for-byte. Any extra keys the
	// caller put in (annotations, timestamps, custom metadata) survive intact.
	output.SetValue(0, 0, data.handle_value);
	output.SetCardinality(1);
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
                                                             vector<LogicalType> &return_types,
                                                             vector<string> &names) {
	auto result = make_uniq<CloudFormationListStacksBindData>();

	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("cloudformation_list_stacks: region must not be NULL");
	}
	result->region = StringValue::Get(input.inputs[0]);
	if (result->region.empty()) {
		throw InvalidInputException("cloudformation_list_stacks: region must not be empty");
	}

	for (auto &np : input.named_parameters) {
		auto key = StringUtil::Lower(np.first);
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
		Aws::CloudFormation::CloudFormationClient cfn(provider, cfg);

		Aws::String next_token;
		do {
			Aws::CloudFormation::Model::ListStacksRequest req;
			if (!data.status_filter.empty()) {
				req.SetStackStatusFilter(data.status_filter);
			}
			if (!next_token.empty()) {
				req.SetNextToken(next_token);
			}
			auto outcome = cfn.ListStacks(req);
			if (!outcome.IsSuccess()) {
				const auto &err = outcome.GetError();
				throw IOException("CloudFormation ListStacks failed: %s - %s",
				                  string(err.GetExceptionName().c_str()), string(err.GetMessage().c_str()));
			}
			const auto &res = outcome.GetResult();
			for (const auto &s : res.GetStackSummaries()) {
				CloudFormationListStacksRow row;
				row.region = data.region;
				row.stack_name = string(s.GetStackName().c_str());
				row.stack_id = string(s.GetStackId().c_str());
				row.status = string(
				    Aws::CloudFormation::Model::StackStatusMapper::GetNameForStackStatus(s.GetStackStatus()).c_str());
				row.status_reason = string(s.GetStackStatusReason().c_str());
				row.creation_time =
				    string(s.GetCreationTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601).c_str());
				if (s.LastUpdatedTimeHasBeenSet()) {
					row.last_updated_time =
					    string(s.GetLastUpdatedTime().ToGmtString(Aws::Utils::DateFormat::ISO_8601).c_str());
				}
				row.description = string(s.GetTemplateDescription().c_str());
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
		output.SetValue(0, i, Value(r.region));
		output.SetValue(1, i, Value(r.stack_name));
		output.SetValue(2, i, Value(r.stack_id));
		output.SetValue(3, i, Value(r.status));
		output.SetValue(4, i, r.status_reason.empty() ? Value() : Value(r.status_reason));
		output.SetValue(5, i, r.creation_time.empty() ? Value() : Value(r.creation_time));
		output.SetValue(6, i, r.last_updated_time.empty() ? Value() : Value(r.last_updated_time));
		output.SetValue(7, i, r.description.empty() ? Value() : Value(r.description));
	}
	output.SetCardinality(to_emit);
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

	TableFunction create_fn("cloudformation_create_stack", {LogicalType::VARCHAR, LogicalType::VARCHAR, map_vv},
	                        CloudFormationCreateStackFun, CloudFormationCreateStackBind);
	create_fn.named_parameters["region"] = LogicalType::VARCHAR;
	create_fn.named_parameters["tags"] = map_vv;
	loader.RegisterFunction(create_fn);

	TableFunction describe_fn("cloudformation_describe_stack", {map_vv}, CloudFormationDescribeStackFun, CloudFormationDescribeStackBind);
	loader.RegisterFunction(describe_fn);

	TableFunction delete_fn("cloudformation_delete_stack", {map_vv}, CloudFormationDeleteStackFun, CloudFormationDeleteStackBind);
	loader.RegisterFunction(delete_fn);

	TableFunction list_fn("cloudformation_list_stacks", {LogicalType::VARCHAR}, CloudFormationListStacksFun,
	                      CloudFormationListStacksBind);
	list_fn.named_parameters["status_filter"] = LogicalType::LIST(LogicalType::VARCHAR);
	loader.RegisterFunction(list_fn);

	ScalarFunction session_id_fn("duckdb_aws_session_id", {}, LogicalType::VARCHAR, DuckDBAwsSessionIdFunction);
	loader.RegisterFunction(session_id_fn);
}

} // namespace duckdb
