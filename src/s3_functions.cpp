#include "s3_functions.hpp"
#include "aws_client.hpp"
#include "aws_http_client.hpp"
#include "utils/utils.hpp"

#include "duckdb.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/optional.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/settings.hpp"

#include <aws/common/byte_buf.h>
#include <aws/common/host_utils.h>
#include <aws/core/http/HttpResponse.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/core/utils/memory/stl/AWSStringStream.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/BucketLocationConstraint.h>
#include <aws/s3/model/BucketVersioningStatus.h>
#include <aws/s3/model/CORSConfiguration.h>
#include <aws/s3/model/CORSRule.h>
#include <aws/s3/model/CreateBucketConfiguration.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/Delete.h>
#include <aws/s3/model/DeleteBucketCorsRequest.h>
#include <aws/s3/model/DeleteBucketPolicyRequest.h>
#include <aws/s3/model/DeleteBucketRequest.h>
#include <aws/s3/model/DeleteBucketTaggingRequest.h>
#include <aws/s3/model/DeleteObjectsRequest.h>
#include <aws/s3/model/DeletePublicAccessBlockRequest.h>
#include <aws/s3/model/GetBucketCorsRequest.h>
#include <aws/s3/model/GetBucketPolicyRequest.h>
#include <aws/s3/model/GetBucketPolicyStatusRequest.h>
#include <aws/s3/model/GetBucketTaggingRequest.h>
#include <aws/s3/model/GetBucketVersioningRequest.h>
#include <aws/s3/model/GetPublicAccessBlockRequest.h>
#include <aws/s3/model/HeadBucketRequest.h>
#include <aws/s3/model/ListBucketsRequest.h>
#include <aws/s3/model/ListBucketsResult.h>
#include <aws/s3/model/ListObjectVersionsRequest.h>
#include <aws/s3/model/ObjectIdentifier.h>
#include <aws/s3/model/PublicAccessBlockConfiguration.h>
#include <aws/s3/model/PutBucketCorsRequest.h>
#include <aws/s3/model/PutBucketPolicyRequest.h>
#include <aws/s3/model/PutBucketTaggingRequest.h>
#include <aws/s3/model/PutBucketVersioningRequest.h>
#include <aws/s3/model/PutPublicAccessBlockRequest.h>
#include <aws/s3/model/Tag.h>
#include <aws/s3/model/Tagging.h>
#include <aws/s3/model/VersioningConfiguration.h>

#include <algorithm>
#include <functional>
#include <map>
#include <sstream>

namespace duckdb {

namespace {

//! See the identically-named helper in cloudformation_functions.cpp: copying by range is exact
//! whether or not the SDK was built with USE_AWS_MEMORY_MANAGEMENT.
string FromAws(const Aws::String &value) {
	return {value.data(), value.size()};
}

//===--------------------------------------------------------------------===//
// Shared plumbing
//===--------------------------------------------------------------------===//

struct S3BindData : public TableFunctionData {
	S3BindData(const char *fn_name_p, const char *action_p) : fn_name(fn_name_p), action(action_p) {
	}
	const char *fn_name;
	const char *action;
	string secret_name;
};

//! Called from init rather than bind so it also stops statements prepared before
//! enable_external_access was switched off.
void CheckExternalAccess(ClientContext &context, const S3BindData &data) {
	if (!Settings::Get<EnableExternalAccessSetting>(context)) {
		throw PermissionException("%s: %s is disabled through configuration", data.fn_name, data.action);
	}
}

struct OnceState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<GlobalTableFunctionState> OnceInit(ClientContext &context, TableFunctionInitInput &input) {
	CheckExternalAccess(context, input.bind_data->Cast<S3BindData>());
	return make_uniq<OnceState>();
}

void AddColumn(vector<LogicalType> &types, vector<Identifier> &names, const char *name, LogicalType type) {
	names.emplace_back(name);
	types.push_back(std::move(type));
}

//! An optional VARCHAR option: absent is "", but an explicit NULL or '' is a mistake worth naming.
string StringOption(TableFunctionBindInput &input, const char *key, const char *fn_name) {
	auto entry = input.named_parameters.find(key);
	if (entry == input.named_parameters.end()) {
		return string();
	}
	if (entry->second.IsNull()) {
		throw InvalidInputException("%s: %s must not be NULL", fn_name, key);
	}
	auto value = StringValue::Get(entry->second);
	if (value.empty()) {
		throw InvalidInputException("%s: %s must not be empty", fn_name, key);
	}
	return value;
}

optional<bool> BoolOption(TableFunctionBindInput &input, const char *key, const char *fn_name) {
	auto entry = input.named_parameters.find(key);
	if (entry == input.named_parameters.end()) {
		return {};
	}
	if (entry->second.IsNull()) {
		throw InvalidInputException("%s: %s must not be NULL", fn_name, key);
	}
	return BooleanValue::Get(entry->second);
}

//! The settings s3_create_bucket and s3_update_bucket share; an absent one is left as it is.
struct BucketSettings {
	optional<bool> versioning;
	optional<bool> block_public_access;
	optional<bool> public_read;
	//! Origins of the browser CORS rule; an empty list removes the rule.
	optional<vector<string>> cors_origins;
	//! Methods of that rule; empty means the GET/HEAD default.
	vector<string> cors_methods;
};

optional<vector<string>> ListOption(TableFunctionBindInput &input, const char *key, const char *fn_name) {
	auto entry = input.named_parameters.find(key);
	if (entry == input.named_parameters.end()) {
		return {};
	}
	if (entry->second.IsNull()) {
		throw InvalidInputException("%s: %s must not be NULL", fn_name, key);
	}
	vector<string> result;
	for (auto &child : ListValue::GetChildren(entry->second)) {
		if (child.IsNull()) {
			throw InvalidInputException("%s: %s must not contain NULL", fn_name, key);
		}
		result.push_back(StringValue::Get(child));
	}
	return result;
}

//! Validate origin patterns at bind so S3's MalformedXML error does not hide the bad entry.
void CheckCorsOrigin(const string &origin, const char *fn_name) {
	if (origin == "*") {
		return;
	}
	auto invalid_origin = [&]() {
		throw InvalidInputException("%s: cors_origins entry '%s' is not an origin; expected http(s)://host[:port] "
		                            "with at most one '*', or '*'",
		                            fn_name, origin);
	};
	string rest;
	if (StringUtil::StartsWith(origin, "https://")) {
		rest = origin.substr(8);
	} else if (StringUtil::StartsWith(origin, "http://")) {
		rest = origin.substr(7);
	}
	if (rest.empty() || rest.find_first_of("/?#@\\%") != string::npos ||
	    std::count(origin.begin(), origin.end(), '*') > 1 ||
	    std::any_of(rest.begin(), rest.end(), [](unsigned char c) { return c <= 0x20 || c == 0x7f; })) {
		invalid_origin();
	}
	string host;
	string port;
	if (rest.front() == '[') {
		auto close = rest.find(']');
		if (close == string::npos) {
			invalid_origin();
		}
		host = rest.substr(1, close - 1);
		if (host.empty() || std::any_of(host.begin(), host.end(), [](char c) {
			    return !StringUtil::CharacterIsHex(c) && c != ':' && c != '.' && c != '*';
		    })) {
			invalid_origin();
		}
		if (host.find('*') == string::npos) {
			auto ipv6 = host;
			auto last_colon = ipv6.rfind(':');
			if (last_colon != string::npos && ipv6.find('.') != string::npos) {
				auto ipv4 = ipv6.substr(last_colon + 1);
				if (!aws_host_utils_is_ipv4(aws_byte_cursor_from_array(ipv4.data(), ipv4.size()))) {
					invalid_origin();
				}
				// An embedded IPv4 address occupies two IPv6 groups.
				ipv6 = ipv6.substr(0, last_colon + 1) + "0:0";
			}
			if (!aws_host_utils_is_ipv6(aws_byte_cursor_from_array(ipv6.data(), ipv6.size()), false)) {
				invalid_origin();
			}
		}
		if (close + 1 < rest.size()) {
			if (rest[close + 1] != ':' || close + 2 == rest.size()) {
				invalid_origin();
			}
			port = rest.substr(close + 2);
		}
	} else {
		auto colon = rest.find(':');
		host = rest.substr(0, colon);
		if (host.empty() || std::any_of(host.begin(), host.end(), [](char c) {
			    return !StringUtil::CharacterIsAlphaNumeric(c) && c != '.' && c != '-' && c != '_' && c != '*';
		    })) {
			invalid_origin();
		}
		if (std::count(host.begin(), host.end(), '.') == 3 &&
		    std::all_of(host.begin(), host.end(), [](char c) { return StringUtil::CharacterIsDigit(c) || c == '.'; }) &&
		    !aws_host_utils_is_ipv4(aws_byte_cursor_from_array(host.data(), host.size()))) {
			invalid_origin();
		}
		if (colon != string::npos) {
			port = rest.substr(colon + 1);
			if (port.empty()) {
				invalid_origin();
			}
		}
	}
	uint32_t port_number = 0;
	for (auto c : port) {
		if (c == '*') {
			continue;
		}
		if (!StringUtil::CharacterIsDigit(c)) {
			invalid_origin();
		}
		port_number = port_number * 10 + (c - '0');
		if (port_number > 65535) {
			invalid_origin();
		}
	}
}

//! The methods a CORS rule can name; anything else is a PutBucketCors error S3 reports as
//! MalformedXML, so it is caught here instead.
string CheckCorsMethod(const string &method, const char *fn_name) {
	auto upper = StringUtil::Upper(method);
	for (auto allowed : {"GET", "HEAD", "PUT", "POST", "DELETE"}) {
		if (upper == allowed) {
			return upper;
		}
	}
	throw InvalidInputException("%s: cors_methods entry '%s' is not one of GET, HEAD, PUT, POST, DELETE", fn_name,
	                            method);
}

BucketSettings SettingsOption(TableFunctionBindInput &input, const char *fn_name) {
	BucketSettings result;
	result.versioning = BoolOption(input, "versioning", fn_name);
	result.block_public_access = BoolOption(input, "block_public_access", fn_name);
	result.public_read = BoolOption(input, "public_read", fn_name);
	if (result.public_read.value_or(false) && result.block_public_access.value_or(false)) {
		throw InvalidInputException("%s: public_read := true and block_public_access := true contradict each other",
		                            fn_name);
	}
	result.cors_origins = ListOption(input, "cors_origins", fn_name);
	if (result.cors_origins) {
		for (auto &origin : *result.cors_origins) {
			CheckCorsOrigin(origin, fn_name);
		}
	}
	auto methods = ListOption(input, "cors_methods", fn_name);
	if (methods) {
		if (!result.cors_origins || result.cors_origins->empty()) {
			throw InvalidInputException("%s: cors_methods needs a non-empty cors_origins", fn_name);
		}
		for (auto &method : *methods) {
			result.cors_methods.push_back(CheckCorsMethod(method, fn_name));
		}
		if (result.cors_methods.empty()) {
			throw InvalidInputException("%s: cors_methods must not be empty", fn_name);
		}
	}
	return result;
}

//! The `tags` MAP option. A NULL value means "remove this key", which only s3_update_bucket can
//! honour; `allow_unset` is false where there is nothing to remove from.
struct TagOption {
	std::map<string, string> set;
	vector<string> unset;

	bool empty() const {
		return set.empty() && unset.empty();
	}
};

TagOption TagsOption(TableFunctionBindInput &input, const char *fn_name, bool allow_unset) {
	TagOption result;
	auto entry = input.named_parameters.find("tags");
	if (entry == input.named_parameters.end()) {
		return result;
	}
	if (entry->second.IsNull()) {
		throw InvalidInputException("%s: tags must not be NULL", fn_name);
	}
	for (auto &pair : MapValue::GetChildren(entry->second)) {
		auto &kv = StructValue::GetChildren(pair);
		if (kv[0].IsNull()) {
			throw InvalidInputException("%s: tag keys must not be NULL", fn_name);
		}
		auto key = StringValue::Get(kv[0]);
		if (kv[1].IsNull()) {
			if (!allow_unset) {
				throw InvalidInputException("%s: tag '%s' has a NULL value; use '' for an empty value", fn_name, key);
			}
			result.unset.push_back(key);
		} else {
			result.set[key] = StringValue::Get(kv[1]);
		}
	}
	return result;
}

//! A bucket as named by the caller: a bare name, or the handle MAP s3_create_bucket returned. The
//! region is only where the first request goes; see LocateBucket.
struct BucketRef {
	string name;
	string region;
};

BucketRef BucketFromInput(TableFunctionBindInput &input, const char *fn_name) {
	auto &value = input.inputs[0];
	if (value.IsNull()) {
		throw InvalidInputException("%s: the bucket name must not be NULL", fn_name);
	}
	BucketRef result;
	if (value.type().id() == LogicalTypeId::MAP) {
		for (auto &entry : MapValue::GetChildren(value)) {
			auto &kv = StructValue::GetChildren(entry);
			if (kv[0].IsNull() || kv[1].IsNull()) {
				continue;
			}
			auto key = StringValue::Get(kv[0]);
			if (key == "name") {
				result.name = StringValue::Get(kv[1]);
			} else if (key == "region") {
				result.region = StringValue::Get(kv[1]);
			}
		}
		if (result.name.empty()) {
			throw InvalidInputException("%s: handle is missing 'name'", fn_name);
		}
	} else {
		result.name = StringValue::Get(value);
		if (result.name.empty()) {
			throw InvalidInputException("%s: the bucket name must not be empty", fn_name);
		}
	}
	auto region = StringOption(input, "region", fn_name);
	if (!region.empty()) {
		result.region = region;
	}
	return result;
}

Value HandleFor(const string &name, const string &region) {
	vector<Value> keys {Value("name"), Value("region")};
	vector<Value> values {Value(name), Value(region)};
	return Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
}

//! Bucket ARNs carry no region, only the partition, which the region prefix determines. Only the
//! public partitions are mapped; the isolated ones are not reachable from here anyway.
string BucketArn(const string &name, const string &region) {
	string partition = "aws";
	if (StringUtil::StartsWith(region, "cn-")) {
		partition = "aws-cn";
	} else if (StringUtil::StartsWith(region, "us-gov-")) {
		partition = "aws-us-gov";
	}
	return "arn:" + partition + ":s3:::" + name;
}

//! `region` is the caller's choice after the usual resolution order (argument, secret, s3_region,
//! environment, profile); empty means nothing configured one and the SDK's own default stands.
struct S3Access {
	std::shared_ptr<Aws::Auth::AWSCredentialsProvider> provider;
	Aws::S3::S3ClientConfiguration config;
	string region;
};

//! Credentials resolve exactly as for the other control-plane functions, so listing, creating and
//! deleting never disagree about who is acting; see FindAwsSecret for the ambiguity rules.
S3Access ResolveAccess(ClientContext &context, const string &secret_name, const string &explicit_region) {
	auto entry = FindAwsSecret(context, secret_name);
	auto &secret = entry->secret->Cast<KeyValueSecret>();
	S3Access access {CredentialsProviderFromSecret(secret, "S3"),
	                 Aws::S3::S3ClientConfiguration(BuildClientConfigWithCa()), string()};
	auto requested = explicit_region.empty() ? GetSecretString(secret, "region") : explicit_region;
	access.region = ResolveAwsRegion(context, requested, FromAws(access.config.profileName));
	if (!access.region.empty()) {
		access.config.region = access.region.c_str();
	}
	access.config.useUSEast1RegionalEndPointOption = Aws::S3::US_EAST_1_REGIONAL_ENDPOINT_OPTION::REGIONAL;
	return access;
}

unique_ptr<Aws::S3::S3Client> MakeClient(const S3Access &access, const string &region) {
	auto config = access.config;
	config.region = region.c_str();
	return make_uniq<Aws::S3::S3Client>(access.provider, nullptr, config);
}

//! Uniform "the AWS call failed" error. HEAD responses carry no body, so the SDK cannot name
//! those errors; the status code is all there is to report.
template <class OUTCOME>
[[noreturn]] void ThrowAwsError(const char *call, const OUTCOME &outcome) {
	const auto &error = outcome.GetError();
	auto name = FromAws(error.GetExceptionName());
	if (name.empty()) {
		name = "HTTP " + to_string(static_cast<int>(error.GetResponseCode()));
	}
	throw IOException("S3 %s failed: %s - %s", call, name, FromAws(error.GetMessage()));
}

//! Bucket names are global, but every call must go to the bucket's own region. HeadBucket from
//! the configured region answers with the real one: in the result when the request was routed
//! right, otherwise in the x-amz-bucket-region header of the refusal.
string LocateBucket(const S3Access &access, const string &name) {
	auto client = MakeClient(access, FromAws(access.config.region));
	Aws::S3::Model::HeadBucketRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client->HeadBucket(request);
	if (outcome.IsSuccess()) {
		auto region = FromAws(outcome.GetResult().GetBucketRegion());
		return region.empty() ? FromAws(access.config.region) : region;
	}
	const auto &error = outcome.GetError();
	const auto &headers = error.GetResponseHeaders();
	auto hint = headers.find("x-amz-bucket-region");
	if (hint != headers.end() && !hint->second.empty()) {
		return FromAws(hint->second);
	}
	if (error.GetResponseCode() == Aws::Http::HttpResponseCode::NOT_FOUND) {
		throw IOException("S3 HeadBucket failed: NoSuchBucket - bucket '%s' does not exist", name);
	}
	ThrowAwsError("HeadBucket", outcome);
}

//! The bucket's tag set; a bucket without one answers NoSuchTagSet, which is an empty set here.
std::map<string, string> GetTags(Aws::S3::S3Client &client, const string &name) {
	Aws::S3::Model::GetBucketTaggingRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client.GetBucketTagging(request);
	std::map<string, string> result;
	if (!outcome.IsSuccess()) {
		if (FromAws(outcome.GetError().GetExceptionName()) == "NoSuchTagSet") {
			return result;
		}
		ThrowAwsError("GetBucketTagging", outcome);
	}
	for (const auto &tag : outcome.GetResult().GetTagSet()) {
		result[FromAws(tag.GetKey())] = FromAws(tag.GetValue());
	}
	return result;
}

//! PutBucketTagging replaces the whole set, and an empty set is only expressible as a delete.
void PutTags(Aws::S3::S3Client &client, const string &name, const std::map<string, string> &tags) {
	if (tags.empty()) {
		Aws::S3::Model::DeleteBucketTaggingRequest request;
		request.SetBucket(name.c_str());
		auto outcome = client.DeleteBucketTagging(request);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("DeleteBucketTagging", outcome);
		}
		return;
	}
	Aws::Vector<Aws::S3::Model::Tag> tag_set;
	for (auto &tag : tags) {
		Aws::S3::Model::Tag entry;
		entry.SetKey(tag.first.c_str());
		entry.SetValue(tag.second.c_str());
		tag_set.push_back(std::move(entry));
	}
	Aws::S3::Model::Tagging tagging;
	tagging.SetTagSet(std::move(tag_set));
	Aws::S3::Model::PutBucketTaggingRequest request;
	request.SetBucket(name.c_str());
	request.SetTagging(std::move(tagging));
	auto outcome = client.PutBucketTagging(request);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("PutBucketTagging", outcome);
	}
}

Value TagsValue(const std::map<string, string> &tags) {
	vector<Value> keys;
	vector<Value> values;
	for (auto &tag : tags) {
		keys.emplace_back(tag.first);
		values.emplace_back(tag.second);
	}
	return Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
}

//! S3 versioning cannot be turned off once enabled, only suspended, so false means Suspended.
void PutVersioning(Aws::S3::S3Client &client, const string &name, bool enabled) {
	Aws::S3::Model::VersioningConfiguration configuration;
	configuration.SetStatus(enabled ? Aws::S3::Model::BucketVersioningStatus::Enabled
	                                : Aws::S3::Model::BucketVersioningStatus::Suspended);
	Aws::S3::Model::PutBucketVersioningRequest request;
	request.SetBucket(name.c_str());
	request.SetVersioningConfiguration(std::move(configuration));
	auto outcome = client.PutBucketVersioning(request);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("PutBucketVersioning", outcome);
	}
}

//! The versioning status as S3 names it, NULL for a bucket that was never versioned.
Value GetVersioning(Aws::S3::S3Client &client, const string &name) {
	Aws::S3::Model::GetBucketVersioningRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client.GetBucketVersioning(request);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("GetBucketVersioning", outcome);
	}
	auto status = outcome.GetResult().GetStatus();
	if (status == Aws::S3::Model::BucketVersioningStatus::NOT_SET) {
		return Value();
	}
	return Value(FromAws(Aws::S3::Model::BucketVersioningStatusMapper::GetNameForBucketVersioningStatus(status)));
}

//! The bucket's own public-access block; nullopt when it has none (the account-level setting, if
//! any, then applies). Buckets created since April 2023 start with all four on.
optional<Aws::S3::Model::PublicAccessBlockConfiguration> GetPublicAccessBlockConfig(Aws::S3::S3Client &client,
                                                                                    const string &name) {
	Aws::S3::Model::GetPublicAccessBlockRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client.GetPublicAccessBlock(request);
	if (!outcome.IsSuccess()) {
		if (FromAws(outcome.GetError().GetExceptionName()) == "NoSuchPublicAccessBlockConfiguration") {
			return {};
		}
		ThrowAwsError("GetPublicAccessBlock", outcome);
	}
	return outcome.GetResult().GetPublicAccessBlockConfiguration();
}

void PutPublicAccessBlockConfig(Aws::S3::S3Client &client, const string &name,
                                Aws::S3::Model::PublicAccessBlockConfiguration configuration) {
	Aws::S3::Model::PutPublicAccessBlockRequest request;
	request.SetBucket(name.c_str());
	request.SetPublicAccessBlockConfiguration(std::move(configuration));
	auto outcome = client.PutPublicAccessBlock(request);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("PutPublicAccessBlock", outcome);
	}
}

//! block_public_access sets all four blocks together; only public_read moves two of them (see
//! SetPolicyBlocks).
void PutPublicAccessBlock(Aws::S3::S3Client &client, const string &name, bool blocked) {
	Aws::S3::Model::PublicAccessBlockConfiguration configuration;
	configuration.SetBlockPublicAcls(blocked);
	configuration.SetIgnorePublicAcls(blocked);
	configuration.SetBlockPublicPolicy(blocked);
	configuration.SetRestrictPublicBuckets(blocked);
	PutPublicAccessBlockConfig(client, name, std::move(configuration));
}

//! True only when all four blocks are on; NULL when the bucket has no configuration of its own.
Value GetPublicAccessBlock(Aws::S3::S3Client &client, const string &name) {
	auto configuration = GetPublicAccessBlockConfig(client, name);
	if (!configuration) {
		return Value();
	}
	return Value::BOOLEAN(configuration->GetBlockPublicAcls() && configuration->GetIgnorePublicAcls() &&
	                      configuration->GetBlockPublicPolicy() && configuration->GetRestrictPublicBuckets());
}

//! public_read changes only policy blocks; legacy buckets without a configuration have no ACL blocks.
optional<Aws::S3::Model::PublicAccessBlockConfiguration> SetPolicyBlocks(Aws::S3::S3Client &client, const string &name,
                                                                         bool blocked) {
	auto previous = GetPublicAccessBlockConfig(client, name);
	auto configuration = previous.value_or(Aws::S3::Model::PublicAccessBlockConfiguration());
	if (!previous) {
		configuration.SetBlockPublicAcls(false);
		configuration.SetIgnorePublicAcls(false);
	}
	configuration.SetBlockPublicPolicy(blocked);
	configuration.SetRestrictPublicBuckets(blocked);
	PutPublicAccessBlockConfig(client, name, std::move(configuration));
	return previous;
}

//===--------------------------------------------------------------------===//
// Bucket policy: the duckdb-public-read statement
//===--------------------------------------------------------------------===//

//! The one statement public_read manages, found again by this Sid. Anything else in the policy is
//! someone else's and is carried over untouched.
constexpr const char *PUBLIC_READ_SID = "duckdb-public-read";

//! The policy document, empty when the bucket has none.
string GetPolicy(Aws::S3::S3Client &client, const string &name) {
	Aws::S3::Model::GetBucketPolicyRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client.GetBucketPolicy(request);
	if (!outcome.IsSuccess()) {
		if (FromAws(outcome.GetError().GetExceptionName()) == "NoSuchBucketPolicy") {
			return string();
		}
		ThrowAwsError("GetBucketPolicy", outcome);
	}
	std::stringstream document;
	document << outcome.GetResult().GetPolicy().rdbuf();
	return document.str();
}

//! PutBucketPolicy replaces the whole document, and no policy is only expressible as a delete.
void PutPolicy(Aws::S3::S3Client &client, const string &name, const string &document) {
	if (document.empty()) {
		Aws::S3::Model::DeleteBucketPolicyRequest request;
		request.SetBucket(name.c_str());
		auto outcome = client.DeleteBucketPolicy(request);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("DeleteBucketPolicy", outcome);
		}
		return;
	}
	auto body = Aws::MakeShared<Aws::StringStream>("duckdb");
	*body << document;
	Aws::S3::Model::PutBucketPolicyRequest request;
	request.SetBucket(name.c_str());
	request.SetBody(body);
	request.SetContentType("application/json");
	auto outcome = client.PutBucketPolicy(request);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("PutBucketPolicy", outcome);
	}
}

//! S3's own verdict on whether the policy grants public access; a bucket without a policy is not public.
bool GetPolicyIsPublic(Aws::S3::S3Client &client, const string &name) {
	Aws::S3::Model::GetBucketPolicyStatusRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client.GetBucketPolicyStatus(request);
	if (!outcome.IsSuccess()) {
		if (FromAws(outcome.GetError().GetExceptionName()) == "NoSuchBucketPolicy") {
			return false;
		}
		ThrowAwsError("GetBucketPolicyStatus", outcome);
	}
	return outcome.GetResult().GetPolicyStatus().GetIsPublic();
}

//! `document` with the duckdb-public-read statement added or removed; "" when no statement is left,
//! which PutPolicy turns into a delete. Only s3:GetObject is granted: anonymous callers can read a
//! key they know, not enumerate the bucket. A `Statement` that is a single object rather than an
//! array is valid IAM and is handled.
string WithPublicReadStatement(const string &document, const string &bucket_arn, bool present, const string &name) {
	using Aws::Utils::Json::JsonValue;
	using Aws::Utils::Json::JsonView;
	JsonValue policy = document.empty() ? JsonValue().WithString("Version", "2012-10-17")
	                                    : JsonValue(Aws::String(document.data(), document.size()));
	if (!policy.WasParseSuccessful()) {
		throw IOException("bucket '%s' has a policy this function cannot parse (%s); edit it in AWS instead", name,
		                  FromAws(policy.GetErrorMessage()));
	}
	vector<JsonValue> kept;
	auto keep_unless_ours = [&](const JsonView &statement) {
		if (!statement.IsObject() || !statement.KeyExists("Sid") || !statement.GetObject("Sid").IsString() ||
		    FromAws(statement.GetString("Sid")) != PUBLIC_READ_SID) {
			kept.push_back(statement.Materialize());
		}
	};
	auto view = policy.View();
	if (view.KeyExists("Statement")) {
		auto statements = view.GetObject("Statement");
		if (statements.IsListType()) {
			auto array = statements.AsArray();
			for (size_t i = 0; i < array.GetLength(); i++) {
				keep_unless_ours(array[i]);
			}
		} else {
			keep_unless_ours(statements);
		}
	}
	if (present) {
		JsonValue statement;
		statement.WithString("Sid", PUBLIC_READ_SID)
		    .WithString("Effect", "Allow")
		    .WithString("Principal", "*")
		    .WithString("Action", "s3:GetObject")
		    .WithString("Resource", Aws::String(bucket_arn + "/*"));
		kept.push_back(std::move(statement));
	}
	if (kept.empty()) {
		return string();
	}
	Aws::Utils::Array<JsonValue> statements(kept.size());
	for (size_t i = 0; i < kept.size(); i++) {
		statements[i] = std::move(kept[i]);
	}
	policy.WithArray("Statement", std::move(statements));
	return FromAws(policy.View().WriteCompact());
}

//! S3 refuses a public policy while BlockPublicPolicy is on, so granting lifts the policy blocks
//! first. A failed policy write restores the prior configuration best-effort; restoration failures
//! are reported. Revocation re-enables the blocks only when no foreign public statement remains.
void SetPublicRead(Aws::S3::S3Client &client, const string &name, const string &region, bool enabled) {
	auto document = WithPublicReadStatement(GetPolicy(client, name), BucketArn(name, region), enabled, name);
	if (!enabled) {
		PutPolicy(client, name, document);
		if (!GetPolicyIsPublic(client, name)) {
			SetPolicyBlocks(client, name, true);
		}
		return;
	}
	auto previous_blocks = SetPolicyBlocks(client, name, false);
	try {
		PutPolicy(client, name, document);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		try {
			if (previous_blocks) {
				PutPublicAccessBlockConfig(client, name, std::move(*previous_blocks));
			} else {
				Aws::S3::Model::DeletePublicAccessBlockRequest request;
				request.SetBucket(name.c_str());
				auto outcome = client.DeletePublicAccessBlock(request);
				if (!outcome.IsSuccess()) {
					ThrowAwsError("DeletePublicAccessBlock", outcome);
				}
			}
		} catch (std::exception &restore_ex) {
			ErrorData restore_error(restore_ex);
			throw IOException("%s; bucket '%s' public-access-block configuration could not be restored (%s); "
			                  "policy blocks may remain disabled and existing public grants may be active",
			                  error.RawMessage(), name, restore_error.RawMessage());
		}
		throw IOException("%s; for AccessDenied, check s3:PutBucketPolicy permission and account- or "
		                  "organization-level Block Public Access, which this function cannot change",
		                  error.RawMessage());
	}
}

//===--------------------------------------------------------------------===//
// CORS: the duckdb-browser rule
//===--------------------------------------------------------------------===//

//! The one rule cors_origins manages, found again by this ID; other rules are carried over. S3 uses
//! the first rule matching the origin, method and requested headers, so ours goes last.
constexpr const char *CORS_RULE_ID = "duckdb-browser";

Aws::Vector<Aws::S3::Model::CORSRule> GetCorsRules(Aws::S3::S3Client &client, const string &name) {
	Aws::S3::Model::GetBucketCorsRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client.GetBucketCors(request);
	if (!outcome.IsSuccess()) {
		if (FromAws(outcome.GetError().GetExceptionName()) == "NoSuchCORSConfiguration") {
			return {};
		}
		ThrowAwsError("GetBucketCors", outcome);
	}
	return outcome.GetResult().GetCORSRules();
}

//! PutBucketCors replaces the whole configuration, and none is only expressible as a delete.
void PutCorsRules(Aws::S3::S3Client &client, const string &name, Aws::Vector<Aws::S3::Model::CORSRule> rules) {
	if (rules.empty()) {
		Aws::S3::Model::DeleteBucketCorsRequest request;
		request.SetBucket(name.c_str());
		auto outcome = client.DeleteBucketCors(request);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("DeleteBucketCors", outcome);
		}
		return;
	}
	Aws::S3::Model::CORSConfiguration configuration;
	configuration.SetCORSRules(std::move(rules));
	Aws::S3::Model::PutBucketCorsRequest request;
	request.SetBucket(name.c_str());
	request.SetCORSConfiguration(std::move(configuration));
	auto outcome = client.PutBucketCors(request);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("PutBucketCors", outcome);
	}
}

//! The rule a browser-hosted DuckDB needs: any request header (the SDK and httpfs send signing and
//! range headers), and the response headers range detection reads (duckdb-wasm#2228) plus the
//! request ids that make a failure traceable.
Aws::S3::Model::CORSRule BrowserCorsRule(const vector<string> &origins, const vector<string> &methods) {
	Aws::S3::Model::CORSRule rule;
	rule.SetID(CORS_RULE_ID);
	Aws::Vector<Aws::String> allowed_origins;
	for (auto &origin : origins) {
		allowed_origins.emplace_back(origin.c_str());
	}
	rule.SetAllowedOrigins(std::move(allowed_origins));
	Aws::Vector<Aws::String> allowed_methods;
	if (methods.empty()) {
		allowed_methods = {"GET", "HEAD"};
	} else {
		for (auto &method : methods) {
			allowed_methods.emplace_back(method.c_str());
		}
	}
	rule.SetAllowedMethods(std::move(allowed_methods));
	rule.SetAllowedHeaders(Aws::Vector<Aws::String> {"*"});
	rule.SetExposeHeaders(Aws::Vector<Aws::String> {"Accept-Ranges", "Content-Length", "Content-Range", "ETag",
	                                                "x-amz-request-id", "x-amz-id-2"});
	rule.SetMaxAgeSeconds(3000);
	return rule;
}

void SetBrowserCors(Aws::S3::S3Client &client, const string &name, const vector<string> &origins,
                    const vector<string> &methods) {
	Aws::Vector<Aws::S3::Model::CORSRule> rules;
	for (auto &rule : GetCorsRules(client, name)) {
		if (FromAws(rule.GetID()) != CORS_RULE_ID) {
			rules.push_back(rule);
		}
	}
	if (!origins.empty()) {
		rules.push_back(BrowserCorsRule(origins, methods));
	}
	PutCorsRules(client, name, std::move(rules));
}

//! The origins of the duckdb-browser rule as a VARCHAR[], NULL when the bucket has no such rule.
Value GetBrowserCorsOrigins(Aws::S3::S3Client &client, const string &name) {
	for (auto &rule : GetCorsRules(client, name)) {
		if (FromAws(rule.GetID()) == CORS_RULE_ID) {
			vector<Value> origins;
			for (auto &origin : rule.GetAllowedOrigins()) {
				origins.emplace_back(FromAws(origin));
			}
			return Value::LIST(LogicalType::VARCHAR, std::move(origins));
		}
	}
	return Value(LogicalType::LIST(LogicalType::VARCHAR));
}

Value OriginsValue(const vector<string> &origins) {
	if (origins.empty()) {
		return Value(LogicalType::LIST(LogicalType::VARCHAR));
	}
	vector<Value> values;
	for (auto &origin : origins) {
		values.emplace_back(origin);
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(values));
}

//! Every object version and delete marker, one page at a time. On an unversioned bucket this is
//! every object with version id "null", which DeleteObjects accepts, so one listing serves both
//! kinds of bucket. Each batch is at most 1000 entries, the DeleteObjects limit.
template <class FN>
void ForEachObjectBatch(ClientContext &context, Aws::S3::S3Client &client, const string &name, FN &&fn) {
	static constexpr idx_t BATCH_SIZE = 1000;
	Aws::S3::Model::ListObjectVersionsRequest request;
	request.SetBucket(name.c_str());
	request.SetMaxKeys(static_cast<int>(BATCH_SIZE));
	while (true) {
		context.InterruptCheck();
		auto outcome = client.ListObjectVersions(request);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("ListObjectVersions", outcome);
		}
		const auto &page = outcome.GetResult();
		Aws::Vector<Aws::S3::Model::ObjectIdentifier> batch;
		auto flush = [&]() {
			if (!batch.empty()) {
				fn(std::move(batch));
				batch.clear();
			}
		};
		for (const auto &version : page.GetVersions()) {
			Aws::S3::Model::ObjectIdentifier id;
			id.SetKey(version.GetKey());
			id.SetVersionId(version.GetVersionId());
			batch.push_back(std::move(id));
			if (batch.size() == BATCH_SIZE) {
				flush();
			}
		}
		for (const auto &marker : page.GetDeleteMarkers()) {
			Aws::S3::Model::ObjectIdentifier id;
			id.SetKey(marker.GetKey());
			id.SetVersionId(marker.GetVersionId());
			batch.push_back(std::move(id));
			if (batch.size() == BATCH_SIZE) {
				flush();
			}
		}
		flush();
		if (!page.GetIsTruncated()) {
			return;
		}
		if (page.GetNextKeyMarker() == request.GetKeyMarker() &&
		    page.GetNextVersionIdMarker() == request.GetVersionIdMarker()) {
			throw IOException("S3 ListObjectVersions returned a repeated continuation marker");
		}
		request.SetKeyMarker(page.GetNextKeyMarker());
		request.SetVersionIdMarker(page.GetNextVersionIdMarker());
	}
}

idx_t CountObjects(ClientContext &context, Aws::S3::S3Client &client, const string &name) {
	idx_t count = 0;
	ForEachObjectBatch(context, client, name,
	                   [&](Aws::Vector<Aws::S3::Model::ObjectIdentifier> &&batch) { count += batch.size(); });
	return count;
}

//! Delete everything in the bucket. Partial failures inside one batch are reported per object by
//! S3 rather than as a failed call, so they are checked explicitly; the first one is enough to
//! name, since the usual causes (Object Lock retention, MFA delete) apply to many objects at once.
idx_t EmptyBucket(ClientContext &context, Aws::S3::S3Client &client, const string &name) {
	idx_t deleted = 0;
	ForEachObjectBatch(context, client, name, [&](Aws::Vector<Aws::S3::Model::ObjectIdentifier> &&batch) {
		auto batch_size = batch.size();
		Aws::S3::Model::Delete to_delete;
		to_delete.SetObjects(std::move(batch));
		to_delete.SetQuiet(true);
		Aws::S3::Model::DeleteObjectsRequest request;
		request.SetBucket(name.c_str());
		request.SetDelete(std::move(to_delete));
		auto outcome = client.DeleteObjects(request);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("DeleteObjects", outcome);
		}
		const auto &errors = outcome.GetResult().GetErrors();
		if (!errors.empty()) {
			const auto &first = errors[0];
			throw IOException(
			    "S3 DeleteObjects failed for %llu of %llu objects after deleting %llu; first: '%s' %s - %s",
			    idx_t(errors.size()), idx_t(batch_size), deleted, FromAws(first.GetKey()), FromAws(first.GetCode()),
			    FromAws(first.GetMessage()));
		}
		deleted += batch_size;
	});
	return deleted;
}

//===--------------------------------------------------------------------===//
// s3_buckets([region :=, secret :=])
//
// ListBuckets, paginated. Pagination also makes ListBuckets return BucketRegion, avoiding a
// per-bucket lookup.
//===--------------------------------------------------------------------===//

struct S3BucketsBindData : public S3BindData {
	S3BucketsBindData() : S3BindData("s3_buckets", "listing S3 buckets") {
	}
	string region;
};

struct S3BucketsState : public GlobalTableFunctionState {
	unique_ptr<Aws::S3::S3Client> client;
	Aws::S3::Model::ListBucketsRequest request;
	Aws::S3::Model::ListBucketsResult page;
	idx_t cursor = 0;
	bool finished = false;
};

unique_ptr<FunctionData> S3BucketsBind(ClientContext &, TableFunctionBindInput &input,
                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<S3BucketsBindData>();
	result->region = StringOption(input, "region", result->fn_name);
	result->secret_name = StringOption(input, "secret", result->fn_name);

	AddColumn(return_types, names, "name", LogicalType::VARCHAR);
	AddColumn(return_types, names, "region", LogicalType::VARCHAR);
	AddColumn(return_types, names, "created_at", LogicalType::TIMESTAMP_TZ);
	return std::move(result);
}

unique_ptr<GlobalTableFunctionState> S3BucketsInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &data = input.bind_data->Cast<S3BucketsBindData>();
	CheckExternalAccess(context, data);
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto access = ResolveAccess(context, data.secret_name, data.region);

	auto result = make_uniq<S3BucketsState>();
	result->client = MakeClient(access, FromAws(access.config.region));
	result->request.SetMaxBuckets(1000);
	// A configured endpoint region must not silently restrict an account-wide listing.
	if (!data.region.empty()) {
		result->request.SetBucketRegion(data.region.c_str());
	}
	return std::move(result);
}

void S3BucketsFun(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &state = input.global_state->Cast<S3BucketsState>();

	while (state.cursor == state.page.GetBuckets().size()) {
		if (state.finished) {
			return;
		}
		context.InterruptCheck();
		auto outcome = state.client->ListBuckets(state.request);
		if (!outcome.IsSuccess()) {
			ThrowAwsError("ListBuckets", outcome);
		}
		state.page = outcome.GetResultWithOwnership();
		const auto &token = state.page.GetContinuationToken();
		state.finished = token.empty();
		if (!state.finished && token == state.request.GetContinuationToken()) {
			throw IOException("S3 ListBuckets returned a repeated continuation token");
		}
		state.request.SetContinuationToken(token);
		state.cursor = 0;
	}

	const auto &buckets = state.page.GetBuckets();
	auto count = MinValue<idx_t>(buckets.size() - state.cursor, STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < count; i++) {
		const auto &bucket = buckets[state.cursor + i];
		output.data[0].Append(bucket.NameHasBeenSet() ? Value(FromAws(bucket.GetName())) : Value());
		output.data[1].Append(bucket.BucketRegionHasBeenSet() ? Value(FromAws(bucket.GetBucketRegion())) : Value());
		output.data[2].Append(
		    bucket.CreationDateHasBeenSet()
		        ? Value::TIMESTAMPTZ(timestamp_tz_t(Timestamp::FromEpochMs(bucket.GetCreationDate().Millis())))
		        : Value());
	}
	output.CheckCardinality(count);
	state.cursor += count;
}

//===--------------------------------------------------------------------===//
// s3_create_bucket(name [, region :=, tags :=, versioning :=, block_public_access :=, public_read :=,
//                  cors_origins :=, cors_methods :=, secret :=, dry_run :=])
//
// CreateBucket, then the configuration S3 only accepts as separate calls. The `handle` column is
// the MAP every `name | handle` function takes in place of the name; it carries the region because
// an S3 bucket ARN, unlike a table bucket ARN, does not.
//===--------------------------------------------------------------------===//

struct CreateBucketBindData : public S3BindData {
	CreateBucketBindData() : S3BindData("s3_create_bucket", "creating S3 buckets") {
	}
	string name;
	string region;
	std::map<string, string> tags;
	BucketSettings settings;
	bool dry_run = false;
};

unique_ptr<FunctionData> CreateBucketBind(ClientContext &, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<CreateBucketBindData>();
	auto fn_name = result->fn_name;
	if (input.inputs[0].IsNull()) {
		throw InvalidInputException("%s: the bucket name must not be NULL", fn_name);
	}
	result->name = StringValue::Get(input.inputs[0]);
	if (result->name.empty()) {
		throw InvalidInputException("%s: the bucket name must not be empty", fn_name);
	}
	result->region = StringOption(input, "region", fn_name);
	result->secret_name = StringOption(input, "secret", fn_name);
	result->tags = TagsOption(input, fn_name, false).set;
	result->settings = SettingsOption(input, fn_name);
	result->dry_run = BoolOption(input, "dry_run", fn_name).value_or(false);

	AddColumn(return_types, names, "handle", LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	AddColumn(return_types, names, "name", LogicalType::VARCHAR);
	AddColumn(return_types, names, "region", LogicalType::VARCHAR);
	AddColumn(return_types, names, "arn", LogicalType::VARCHAR);
	return std::move(result);
}

void CreateBucketFun(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &data = input.bind_data->Cast<CreateBucketBindData>();
	auto &state = input.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}
	state.done = true;

	auto access = ResolveAccess(context, data.secret_name, data.region);
	// The SDK would quietly fall back to us-east-1; a bucket is too durable to place by accident.
	if (access.region.empty()) {
		throw InvalidInputException(
		    "%s: no region resolved; pass region :=, set REGION on the secret, or set s3_region / AWS_REGION",
		    data.fn_name);
	}
	const auto &region = access.region;

	if (data.dry_run) {
		// Nothing above this point mutates; stop here and leave handle and ARN NULL, since no
		// bucket exists to name (the same contract s3tables_create_table_bucket's dry_run has).
		output.data[0].Append(Value(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)));
		output.data[1].Append(Value(data.name));
		output.data[2].Append(Value(region));
		output.data[3].Append(Value());
		output.CheckCardinality(1);
		return;
	}

	auto client = MakeClient(access, region);
	// In us-east-1 CreateBucket answers 200 for a bucket the account already owns, where every other
	// region answers BucketAlreadyOwnedByYou. Taken at face value this call would reconfigure, and on
	// a later failure delete, a bucket it did not create. So the name is probed first there, and only
	// a clean NoSuchBucket proceeds. A creator racing between probe and create is not covered.
	if (region == "us-east-1") {
		Aws::S3::Model::HeadBucketRequest probe;
		probe.SetBucket(data.name.c_str());
		auto probe_outcome = client->HeadBucket(probe);
		if (probe_outcome.IsSuccess()) {
			throw IOException("S3 CreateBucket refused: bucket '%s' already exists", data.name);
		}
		auto code = static_cast<int>(probe_outcome.GetError().GetResponseCode());
		if (code != static_cast<int>(Aws::Http::HttpResponseCode::NOT_FOUND)) {
			throw IOException(
			    "S3 CreateBucket refused: bucket '%s' may already exist (HeadBucket answered HTTP %d, not "
			    "404) and us-east-1 would reuse it",
			    data.name, code);
		}
	}
	Aws::S3::Model::CreateBucketRequest request;
	request.SetBucket(data.name.c_str());
	// us-east-1 is the one region that must be asked for by omitting the LocationConstraint.
	if (region != "us-east-1") {
		Aws::S3::Model::CreateBucketConfiguration configuration;
		configuration.SetLocationConstraint(
		    Aws::S3::Model::BucketLocationConstraintMapper::GetBucketLocationConstraintForName(region.c_str()));
		request.SetCreateBucketConfiguration(std::move(configuration));
	}
	auto outcome = client->CreateBucket(request);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("CreateBucket", outcome);
	}

	// Provenance, so a bucket can say what made it long after this instance is gone; see the same
	// in s3tables_create_table_bucket. Caller-supplied tags win.
	auto tags = data.tags;
	tags.emplace("created-by", "duckdb");
	tags.emplace("duckdb-version", DuckDB::LibraryVersion());
	try {
		PutTags(*client, data.name, tags);
		if (data.settings.versioning.value_or(false)) {
			PutVersioning(*client, data.name, true);
		}
		if (data.settings.block_public_access) {
			PutPublicAccessBlock(*client, data.name, *data.settings.block_public_access);
		}
		if (data.settings.cors_origins && !data.settings.cors_origins->empty()) {
			SetBrowserCors(*client, data.name, *data.settings.cors_origins, data.settings.cors_methods);
		}
		// Keep the bucket private until the other configuration calls succeed.
		if (data.settings.public_read.value_or(false)) {
			SetPublicRead(*client, data.name, region, true);
		}
	} catch (std::exception &ex) {
		// A bucket that exists but is not what was asked for is worse than none, and this one is
		// empty and ours (see the us-east-1 probe above), so remove it: a retry after fixing the
		// cause then does not trip over BucketAlreadyOwnedByYou.
		Aws::S3::Model::DeleteBucketRequest cleanup;
		cleanup.SetBucket(data.name.c_str());
		auto cleanup_outcome = client->DeleteBucket(cleanup);
		if (!cleanup_outcome.IsSuccess()) {
			ErrorData error(ex);
			throw IOException("%s; bucket '%s' was created but could not be removed again (%s)", error.RawMessage(),
			                  data.name, FromAws(cleanup_outcome.GetError().GetExceptionName()));
		}
		throw;
	}

	output.data[0].Append(HandleFor(data.name, region));
	output.data[1].Append(Value(data.name));
	output.data[2].Append(Value(region));
	output.data[3].Append(Value(BucketArn(data.name, region)));
	output.CheckCardinality(1);
}

//===--------------------------------------------------------------------===//
// s3_get_bucket(name | handle [, region :=, secret :=])
//
// HeadBucket, then versioning, the public-access block, S3's public verdict on the policy and the
// browser CORS rule, so an s3_update_bucket change can be verified without the console (tags are
// in s3_bucket_tags).
//===--------------------------------------------------------------------===//

struct BucketBindData : public S3BindData {
	BucketBindData(const char *fn_name, const char *action) : S3BindData(fn_name, action) {
	}
	BucketRef bucket;
};

unique_ptr<FunctionData> GetBucketBind(ClientContext &, TableFunctionBindInput &input,
                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<BucketBindData>("s3_get_bucket", "reading S3 bucket configuration");
	result->bucket = BucketFromInput(input, result->fn_name);
	result->secret_name = StringOption(input, "secret", result->fn_name);

	AddColumn(return_types, names, "name", LogicalType::VARCHAR);
	AddColumn(return_types, names, "region", LogicalType::VARCHAR);
	AddColumn(return_types, names, "arn", LogicalType::VARCHAR);
	AddColumn(return_types, names, "versioning", LogicalType::VARCHAR);
	AddColumn(return_types, names, "block_public_access", LogicalType::BOOLEAN);
	AddColumn(return_types, names, "public", LogicalType::BOOLEAN);
	AddColumn(return_types, names, "cors_origins", LogicalType::LIST(LogicalType::VARCHAR));
	return std::move(result);
}

void GetBucketFun(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &data = input.bind_data->Cast<BucketBindData>();
	auto &state = input.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}
	state.done = true;

	auto access = ResolveAccess(context, data.secret_name, data.bucket.region);
	auto region = LocateBucket(access, data.bucket.name);
	auto client = MakeClient(access, region);

	output.data[0].Append(Value(data.bucket.name));
	output.data[1].Append(Value(region));
	output.data[2].Append(Value(BucketArn(data.bucket.name, region)));
	output.data[3].Append(GetVersioning(*client, data.bucket.name));
	output.data[4].Append(GetPublicAccessBlock(*client, data.bucket.name));
	output.data[5].Append(Value::BOOLEAN(GetPolicyIsPublic(*client, data.bucket.name)));
	output.data[6].Append(GetBrowserCorsOrigins(*client, data.bucket.name));
	output.CheckCardinality(1);
}

//===--------------------------------------------------------------------===//
// s3_bucket_tags(name | handle [, region :=, secret :=])
//
// GetBucketTagging as (key, value) rows.
//===--------------------------------------------------------------------===//

struct TagsState : public GlobalTableFunctionState {
	vector<std::pair<string, string>> rows;
	idx_t cursor = 0;
	bool ran = false;
};

unique_ptr<GlobalTableFunctionState> TagsInit(ClientContext &context, TableFunctionInitInput &input) {
	CheckExternalAccess(context, input.bind_data->Cast<S3BindData>());
	return make_uniq<TagsState>();
}

unique_ptr<FunctionData> BucketTagsBind(ClientContext &, TableFunctionBindInput &input,
                                        vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<BucketBindData>("s3_bucket_tags", "reading S3 bucket tags");
	result->bucket = BucketFromInput(input, result->fn_name);
	result->secret_name = StringOption(input, "secret", result->fn_name);

	AddColumn(return_types, names, "key", LogicalType::VARCHAR);
	AddColumn(return_types, names, "value", LogicalType::VARCHAR);
	return std::move(result);
}

void BucketTagsFun(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &data = input.bind_data->Cast<BucketBindData>();
	auto &state = input.global_state->Cast<TagsState>();

	if (!state.ran) {
		auto access = ResolveAccess(context, data.secret_name, data.bucket.region);
		auto region = LocateBucket(access, data.bucket.name);
		auto client = MakeClient(access, region);
		for (auto &tag : GetTags(*client, data.bucket.name)) {
			state.rows.emplace_back(tag.first, tag.second);
		}
		state.ran = true;
	}

	idx_t remaining = state.rows.size() - state.cursor;
	idx_t to_emit = MinValue<idx_t>(remaining, STANDARD_VECTOR_SIZE);
	for (idx_t i = 0; i < to_emit; i++) {
		auto &row = state.rows[state.cursor + i];
		output.data[0].Append(Value(row.first));
		output.data[1].Append(Value(row.second));
	}
	output.CheckCardinality(to_emit);
	state.cursor += to_emit;
}

//===--------------------------------------------------------------------===//
// s3_update_bucket(name | handle [, tags :=, versioning :=, block_public_access :=, public_read :=,
//                  cors_origins :=, cors_methods :=, region :=, secret :=, dry_run :=])
//
// S3 has no UpdateBucket; this is the Put calls behind the settings s3_create_bucket accepts, in
// the order tags, versioning, public-access block, CORS, public read. A failure stops there and
// leaves the earlier changes in place; the error names the call that failed. Tags merge into the
// existing set rather than replace it, so updating one tag does not silently drop the provenance
// tags; a NULL value removes a key. The CORS rule and the public-read statement likewise merge
// into what is there, by ID and Sid.
//===--------------------------------------------------------------------===//

struct UpdateBucketBindData : public BucketBindData {
	UpdateBucketBindData() : BucketBindData("s3_update_bucket", "updating S3 buckets") {
	}
	TagOption tags;
	BucketSettings settings;
	bool dry_run = false;
};

unique_ptr<FunctionData> UpdateBucketBind(ClientContext &, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<UpdateBucketBindData>();
	auto fn_name = result->fn_name;
	result->bucket = BucketFromInput(input, fn_name);
	result->secret_name = StringOption(input, "secret", fn_name);
	result->tags = TagsOption(input, fn_name, true);
	result->settings = SettingsOption(input, fn_name);
	result->dry_run = BoolOption(input, "dry_run", fn_name).value_or(false);

	if (result->tags.empty() && !result->settings.versioning && !result->settings.block_public_access &&
	    !result->settings.public_read && !result->settings.cors_origins) {
		throw InvalidInputException("%s: no change requested; pass a non-empty tags :=, versioning :=, "
		                            "block_public_access :=, public_read := or cors_origins :=",
		                            fn_name);
	}

	AddColumn(return_types, names, "status", LogicalType::VARCHAR);
	AddColumn(return_types, names, "name", LogicalType::VARCHAR);
	AddColumn(return_types, names, "region", LogicalType::VARCHAR);
	AddColumn(return_types, names, "tags", LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	AddColumn(return_types, names, "versioning", LogicalType::VARCHAR);
	AddColumn(return_types, names, "block_public_access", LogicalType::BOOLEAN);
	AddColumn(return_types, names, "public", LogicalType::BOOLEAN);
	AddColumn(return_types, names, "cors_origins", LogicalType::LIST(LogicalType::VARCHAR));
	return std::move(result);
}

void UpdateBucketFun(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &data = input.bind_data->Cast<UpdateBucketBindData>();
	auto &state = input.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}
	state.done = true;

	auto access = ResolveAccess(context, data.secret_name, data.bucket.region);
	auto region = LocateBucket(access, data.bucket.name);
	auto client = MakeClient(access, region);
	const auto &name = data.bucket.name;

	// Untouched settings come back NULL, so the row only states what this call decided.
	Value tags_out(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	Value versioning_out;
	Value block_public_access_out;
	Value public_out(LogicalType::BOOLEAN);
	Value cors_origins_out(LogicalType::LIST(LogicalType::VARCHAR));

	if (!data.tags.empty()) {
		auto tags = GetTags(*client, name);
		for (auto &tag : data.tags.set) {
			tags[tag.first] = tag.second;
		}
		for (auto &key : data.tags.unset) {
			tags.erase(key);
		}
		if (!data.dry_run) {
			PutTags(*client, name, tags);
		}
		tags_out = TagsValue(tags);
	}
	if (data.settings.versioning) {
		if (!data.dry_run) {
			PutVersioning(*client, name, *data.settings.versioning);
		}
		versioning_out = Value(*data.settings.versioning ? "Enabled" : "Suspended");
	}
	if (data.settings.block_public_access) {
		if (!data.dry_run) {
			PutPublicAccessBlock(*client, name, *data.settings.block_public_access);
		}
		block_public_access_out = Value::BOOLEAN(*data.settings.block_public_access);
	}
	if (data.settings.cors_origins) {
		if (!data.dry_run) {
			SetBrowserCors(*client, name, *data.settings.cors_origins, data.settings.cors_methods);
		}
		cors_origins_out = OriginsValue(*data.settings.cors_origins);
	}
	if (data.settings.public_read && !data.dry_run) {
		SetPublicRead(*client, name, region, *data.settings.public_read);
		// S3's verdict rather than the request: a foreign public statement keeps a bucket public
		// after public_read := false, and the row should say so.
		public_out = Value::BOOLEAN(GetPolicyIsPublic(*client, name));
	}

	output.data[0].Append(Value(data.dry_run ? "dry_run" : "updated"));
	output.data[1].Append(Value(name));
	output.data[2].Append(Value(region));
	output.data[3].Append(tags_out);
	output.data[4].Append(versioning_out);
	output.data[5].Append(block_public_access_out);
	output.data[6].Append(public_out);
	output.data[7].Append(cors_origins_out);
	output.CheckCardinality(1);
}

//===--------------------------------------------------------------------===//
// s3_delete_bucket(name | handle [, cascade :=, region :=, secret :=, dry_run :=])
//
// DeleteBucket only succeeds on an empty bucket and AWS offers no force flag, so emptying it is
// a client-side cascade: list every version and delete marker, DeleteObjects them in batches,
// then DeleteBucket. Unlike s3tables_delete_table_bucket there is no seal step: a Deny bucket
// policy would also lock out the owner if this process died mid-way, and overwriting an existing
// policy is not ours to do. A writer racing the cascade makes the final DeleteBucket fail with
// BucketNotEmpty; the objects already deleted are gone, which the error says.
//===--------------------------------------------------------------------===//

struct DeleteBucketBindData : public BucketBindData {
	DeleteBucketBindData() : BucketBindData("s3_delete_bucket", "deleting S3 buckets") {
	}
	bool cascade = false;
	bool dry_run = false;
};

unique_ptr<FunctionData> DeleteBucketBind(ClientContext &, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<DeleteBucketBindData>();
	auto fn_name = result->fn_name;
	result->bucket = BucketFromInput(input, fn_name);
	result->secret_name = StringOption(input, "secret", fn_name);
	result->cascade = BoolOption(input, "cascade", fn_name).value_or(false);
	result->dry_run = BoolOption(input, "dry_run", fn_name).value_or(false);

	AddColumn(return_types, names, "status", LogicalType::VARCHAR);
	AddColumn(return_types, names, "name", LogicalType::VARCHAR);
	AddColumn(return_types, names, "region", LogicalType::VARCHAR);
	AddColumn(return_types, names, "deleted_objects", LogicalType::BIGINT);
	AddColumn(return_types, names, "warning", LogicalType::VARCHAR);
	return std::move(result);
}

void DeleteBucketFun(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &data = input.bind_data->Cast<DeleteBucketBindData>();
	auto &state = input.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}
	state.done = true;

	auto access = ResolveAccess(context, data.secret_name, data.bucket.region);
	auto region = LocateBucket(access, data.bucket.name);
	auto client = MakeClient(access, region);
	const auto &name = data.bucket.name;

	idx_t deleted_objects = 0;
	string warning;

	if (data.dry_run) {
		deleted_objects = CountObjects(context, *client, name);
		if (!data.cascade && deleted_objects > 0) {
			warning = "bucket is not empty and cascade := false, so the delete would fail";
		}
		output.data[0].Append(Value("dry_run"));
		output.data[1].Append(Value(name));
		output.data[2].Append(Value(region));
		output.data[3].Append(Value::BIGINT(NumericCast<int64_t>(deleted_objects)));
		output.data[4].Append(warning.empty() ? Value() : Value(warning));
		output.CheckCardinality(1);
		return;
	}

	if (data.cascade) {
		deleted_objects = EmptyBucket(context, *client, name);
	}

	Aws::S3::Model::DeleteBucketRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client->DeleteBucket(request);
	if (!outcome.IsSuccess()) {
		if (deleted_objects > 0) {
			const auto &error = outcome.GetError();
			throw IOException("S3 DeleteBucket failed after %llu objects were deleted: %s - %s", deleted_objects,
			                  FromAws(error.GetExceptionName()), FromAws(error.GetMessage()));
		}
		ThrowAwsError("DeleteBucket", outcome);
	}

	output.data[0].Append(Value("deleted"));
	output.data[1].Append(Value(name));
	output.data[2].Append(Value(region));
	output.data[3].Append(Value::BIGINT(NumericCast<int64_t>(deleted_objects)));
	output.data[4].Append(Value());
	output.CheckCardinality(1);
}

TableFunctionSet BucketFunctionSet(const char *name, const std::function<void(TypedKwargs &)> &options,
                                   table_function_t function, table_function_bind_t bind,
                                   table_function_init_global_t init) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);
	TableFunctionSet set(name);
	set.AddFunction(TableFunction(
	    FunctionSignature().AddPositionalOnly("name", LogicalType::VARCHAR).WithTypedKwargs("options", options),
	    function, bind, init));
	set.AddFunction(
	    TableFunction(FunctionSignature().AddPositionalOnly("handle", map_vv).WithTypedKwargs("options", options),
	                  function, bind, init));
	return set;
}

} // namespace

//===--------------------------------------------------------------------===//
// Registration
//===--------------------------------------------------------------------===//

void S3Functions::Register(ExtensionLoader &loader) {
	auto map_vv = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);
	auto with_region_secret = [](TypedKwargs &options) {
		options.Add("region", LogicalType::VARCHAR).Add("secret", LogicalType::VARCHAR);
	};
	const string category = "s3";

	loader.RegisterFunction(Documented(
	    TableFunction("s3_buckets", FunctionSignature().WithTypedKwargs("options", with_region_secret), S3BucketsFun,
	                  S3BucketsBind, S3BucketsInit),
	    "Lists the general-purpose S3 buckets the account owns, with each bucket's region and creation time. "
	    "`region` filters to one region; without it every region in the partition is listed.",
	    "FROM s3_buckets(region := 'eu-central-1')", category));

	FunctionSignature create_signature;
	create_signature.AddParameter("name", LogicalType::VARCHAR).WithTypedKwargs("options", [&](TypedKwargs &options) {
		options.Add("region", LogicalType::VARCHAR)
		    .Add("tags", map_vv)
		    .Add("versioning", LogicalType::BOOLEAN)
		    .Add("block_public_access", LogicalType::BOOLEAN)
		    .Add("public_read", LogicalType::BOOLEAN)
		    .Add("cors_origins", LogicalType::LIST(LogicalType::VARCHAR))
		    .Add("cors_methods", LogicalType::LIST(LogicalType::VARCHAR))
		    .Add("secret", LogicalType::VARCHAR)
		    // Typed BOOLEAN rather than a string: a value that failed to parse would fall through to
		    // false and create a real bucket.
		    .Add("dry_run", LogicalType::BOOLEAN);
	});
	loader.RegisterFunction(Documented(
	    TableFunction("s3_create_bucket", std::move(create_signature), CreateBucketFun, CreateBucketBind, OnceInit),
	    "Creates a general-purpose S3 bucket in `region`, tags it with `created-by = duckdb` plus `tags`, and "
	    "optionally configures versioning, public-access blocks, anonymous object reads (`public_read`) and browser "
	    "CORS (`cors_origins`, `cors_methods`). Public reads grant GetObject, not bucket listing; other policies can "
	    "still allow listing or deny reads. Returns a handle MAP the other s3_* functions accept in place of the name. "
	    "`dry_run` resolves region and credentials and makes no S3 call.",
	    "FROM s3_create_bucket('my-bucket', region := 'eu-central-1', versioning := true, tags := MAP {'team': "
	    "'data'})",
	    category));

	loader.RegisterFunction(
	    Documented(BucketFunctionSet("s3_get_bucket", with_region_secret, GetBucketFun, GetBucketBind, OnceInit),
	               "Returns one row for a bucket given by name or handle: its region as S3 reports it, ARN, "
	               "versioning status, `block_public_access` (whether all four bucket blocks are enabled), "
	               "`public` (S3's policy verdict, not effective anonymous access) and `cors_origins` for the "
	               "managed browser rule. Fails with NoSuchBucket when the bucket does not exist.",
	               "FROM s3_get_bucket('my-bucket')", category));
	loader.RegisterFunction(
	    Documented(BucketFunctionSet("s3_bucket_tags", with_region_secret, BucketTagsFun, BucketTagsBind, TagsInit),
	               "Returns a bucket's tags as (key, value) rows; zero rows for an untagged bucket.",
	               "FROM s3_bucket_tags('my-bucket')", category));

	auto update_options = [map_vv](TypedKwargs &options) {
		options.Add("tags", map_vv)
		    .Add("versioning", LogicalType::BOOLEAN)
		    .Add("block_public_access", LogicalType::BOOLEAN)
		    .Add("public_read", LogicalType::BOOLEAN)
		    .Add("cors_origins", LogicalType::LIST(LogicalType::VARCHAR))
		    .Add("cors_methods", LogicalType::LIST(LogicalType::VARCHAR))
		    .Add("region", LogicalType::VARCHAR)
		    .Add("secret", LogicalType::VARCHAR)
		    .Add("dry_run", LogicalType::BOOLEAN);
	};
	loader.RegisterFunction(Documented(
	    BucketFunctionSet("s3_update_bucket", update_options, UpdateBucketFun, UpdateBucketBind, OnceInit),
	    "Changes a bucket's tags, versioning, public-access blocks, browser CORS and public-read statement, in "
	    "that order. `tags` merges into the existing set and a NULL value removes a key; `versioning := false` "
	    "suspends, since S3 cannot disable versioning. `cors_origins := []` removes the managed browser rule; "
	    "`public_read := false` removes the managed grant, not foreign public policies. Policy and CORS updates "
	    "preserve entries from the read snapshot; serialize configuration writers to avoid lost updates. Earlier "
	    "changes remain if a later call fails. `dry_run` reports requested changes without writing; `public` stays "
	    "NULL because S3's verdict on the proposed policy is unknown.",
	    "FROM s3_update_bucket('my-bucket', tags := MAP {'owner': NULL}, block_public_access := true)", category));

	auto delete_options = [](TypedKwargs &options) {
		options.Add("cascade", LogicalType::BOOLEAN)
		    .Add("region", LogicalType::VARCHAR)
		    .Add("secret", LogicalType::VARCHAR)
		    .Add("dry_run", LogicalType::BOOLEAN);
	};
	loader.RegisterFunction(Documented(
	    BucketFunctionSet("s3_delete_bucket", delete_options, DeleteBucketFun, DeleteBucketBind, OnceInit),
	    "Deletes a bucket given by name or handle. S3 only deletes an empty bucket; `cascade := true` first removes "
	    "every object version and delete marker, irreversibly. `dry_run` counts what a cascade would remove.",
	    "FROM s3_delete_bucket('my-bucket', cascade := true)", category));
}

} // namespace duckdb
