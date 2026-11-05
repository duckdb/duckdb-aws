#include "s3_functions.hpp"
#include "aws_client.hpp"
#include "aws_http_client.hpp"
#include "utils/utils.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/settings.hpp"

#include <aws/core/http/HttpResponse.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/BucketLocationConstraint.h>
#include <aws/s3/model/BucketVersioningStatus.h>
#include <aws/s3/model/CreateBucketConfiguration.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/Delete.h>
#include <aws/s3/model/DeleteBucketRequest.h>
#include <aws/s3/model/DeleteBucketTaggingRequest.h>
#include <aws/s3/model/DeleteObjectsRequest.h>
#include <aws/s3/model/GetBucketTaggingRequest.h>
#include <aws/s3/model/GetBucketVersioningRequest.h>
#include <aws/s3/model/GetPublicAccessBlockRequest.h>
#include <aws/s3/model/HeadBucketRequest.h>
#include <aws/s3/model/ListBucketsRequest.h>
#include <aws/s3/model/ListBucketsResult.h>
#include <aws/s3/model/ListObjectVersionsRequest.h>
#include <aws/s3/model/ObjectIdentifier.h>
#include <aws/s3/model/PublicAccessBlockConfiguration.h>
#include <aws/s3/model/PutBucketTaggingRequest.h>
#include <aws/s3/model/PutBucketVersioningRequest.h>
#include <aws/s3/model/PutPublicAccessBlockRequest.h>
#include <aws/s3/model/Tag.h>
#include <aws/s3/model/Tagging.h>
#include <aws/s3/model/VersioningConfiguration.h>

#include <functional>
#include <map>

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

//! Every function's bind data derives from this, so one init can enforce the external-access
//! guard and name the caller. The guard runs at init rather than bind so that it also stops
//! statements prepared before `enable_external_access` was switched off.
struct S3BindData : public TableFunctionData {
	S3BindData(const char *fn_name_p, const char *action_p) : fn_name(fn_name_p), action(action_p) {
	}
	const char *fn_name;
	const char *action;
	string secret_name;
};

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
	for (auto &np : input.named_parameters) {
		if (StringUtil::Lower(np.first.GetIdentifierName()) != key) {
			continue;
		}
		if (np.second.IsNull()) {
			throw InvalidInputException("%s: %s must not be NULL", fn_name, key);
		}
		auto value = StringValue::Get(np.second);
		if (value.empty()) {
			throw InvalidInputException("%s: %s must not be empty", fn_name, key);
		}
		return value;
	}
	return string();
}

//! A BOOLEAN option that distinguishes "not given" from false. Returns whether it was given.
bool TryBoolOption(TableFunctionBindInput &input, const char *key, const char *fn_name, bool &result) {
	for (auto &np : input.named_parameters) {
		if (StringUtil::Lower(np.first.GetIdentifierName()) != key) {
			continue;
		}
		if (np.second.IsNull()) {
			throw InvalidInputException("%s: %s must not be NULL", fn_name, key);
		}
		result = BooleanValue::Get(np.second);
		return true;
	}
	return false;
}

bool BoolOption(TableFunctionBindInput &input, const char *key, const char *fn_name) {
	bool result = false;
	TryBoolOption(input, key, fn_name, result);
	return result;
}

//! The `tags` MAP option. A NULL value means "remove this key", which only s3_update_bucket can
//! honour; `allow_unset` is false where there is nothing to remove from.
struct TagOption {
	bool given = false;
	std::map<string, string> set;
	vector<string> unset;
};

TagOption TagsOption(TableFunctionBindInput &input, const char *fn_name, bool allow_unset) {
	TagOption result;
	for (auto &np : input.named_parameters) {
		if (StringUtil::Lower(np.first.GetIdentifierName()) != "tags") {
			continue;
		}
		if (np.second.IsNull()) {
			throw InvalidInputException("%s: tags must not be NULL", fn_name);
		}
		result.given = true;
		for (auto &entry : MapValue::GetChildren(np.second)) {
			auto &kv = StructValue::GetChildren(entry);
			if (kv[0].IsNull()) {
				throw InvalidInputException("%s: tag keys must not be NULL", fn_name);
			}
			auto key = StringValue::Get(kv[0]);
			if (kv[1].IsNull()) {
				if (!allow_unset) {
					throw InvalidInputException("%s: tag '%s' has a NULL value; use '' for an empty value", fn_name,
					                            key);
				}
				result.unset.push_back(key);
			} else {
				result.set[key] = StringValue::Get(kv[1]);
			}
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

//! The identity and endpoint configuration one S3 call set shares. `region` is the caller's
//! choice after the usual resolution order (argument, secret, s3_region, environment, profile);
//! empty means nothing configured one and the SDK's own default stands.
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
//! right, otherwise in the x-amz-bucket-region header of the refusal. The header map is scanned
//! case-insensitively because the two HTTP transports do not agree on header case.
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
	for (const auto &header : error.GetResponseHeaders()) {
		if (StringUtil::Lower(FromAws(header.first)) == "x-amz-bucket-region" && !header.second.empty()) {
			return FromAws(header.second);
		}
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

//! All four public-access blocks are set together: a bucket is either sealed off from public
//! access or it is not, and a partial configuration is not a state this function produces.
void PutPublicAccessBlock(Aws::S3::S3Client &client, const string &name, bool blocked) {
	Aws::S3::Model::PublicAccessBlockConfiguration configuration;
	configuration.SetBlockPublicAcls(blocked);
	configuration.SetIgnorePublicAcls(blocked);
	configuration.SetBlockPublicPolicy(blocked);
	configuration.SetRestrictPublicBuckets(blocked);
	Aws::S3::Model::PutPublicAccessBlockRequest request;
	request.SetBucket(name.c_str());
	request.SetPublicAccessBlockConfiguration(std::move(configuration));
	auto outcome = client.PutPublicAccessBlock(request);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("PutPublicAccessBlock", outcome);
	}
}

//! True only when all four blocks are on; NULL when the bucket has no configuration of its own
//! (the account-level setting, if any, then applies).
Value GetPublicAccessBlock(Aws::S3::S3Client &client, const string &name) {
	Aws::S3::Model::GetPublicAccessBlockRequest request;
	request.SetBucket(name.c_str());
	auto outcome = client.GetPublicAccessBlock(request);
	if (!outcome.IsSuccess()) {
		if (FromAws(outcome.GetError().GetExceptionName()) == "NoSuchPublicAccessBlockConfiguration") {
			return Value();
		}
		ThrowAwsError("GetPublicAccessBlock", outcome);
	}
	const auto &configuration = outcome.GetResult().GetPublicAccessBlockConfiguration();
	return Value::BOOLEAN(configuration.GetBlockPublicAcls() && configuration.GetIgnorePublicAcls() &&
	                      configuration.GetBlockPublicPolicy() && configuration.GetRestrictPublicBuckets());
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
// s3_create_bucket(name [, region :=, tags :=, versioning :=, block_public_access :=, secret :=, dry_run :=])
//
// CreateBucket, then the configuration S3 only accepts as separate calls. The `handle` column is
// the MAP s3_update_bucket and s3_delete_bucket take in place of the name; it carries the region
// as well, because unlike a table bucket ARN an S3 bucket ARN does not.
//===--------------------------------------------------------------------===//

struct CreateBucketBindData : public S3BindData {
	CreateBucketBindData() : S3BindData("s3_create_bucket", "creating S3 buckets") {
	}
	string name;
	string region;
	std::map<string, string> tags;
	bool has_versioning = false;
	bool versioning = false;
	bool has_block_public_access = false;
	bool block_public_access = false;
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
	result->has_versioning = TryBoolOption(input, "versioning", fn_name, result->versioning);
	result->has_block_public_access = TryBoolOption(input, "block_public_access", fn_name, result->block_public_access);
	result->dry_run = BoolOption(input, "dry_run", fn_name);

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
		throw InvalidInputException("%s: no region: pass region := or set s3_region / AWS_REGION", data.fn_name);
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
	Aws::S3::Model::CreateBucketRequest request;
	request.SetBucket(data.name.c_str());
	// us-east-1 is the one region that must be asked for by omitting the LocationConstraint.
	if (region != "us-east-1") {
		auto constraint =
		    Aws::S3::Model::BucketLocationConstraintMapper::GetBucketLocationConstraintForName(region.c_str());
		// A region the SDK cannot serialize back would go out as an empty constraint, which is
		// us-east-1 again.
		if (FromAws(Aws::S3::Model::BucketLocationConstraintMapper::GetNameForBucketLocationConstraint(constraint)) !=
		    region) {
			throw InvalidInputException("%s: the AWS SDK does not know region '%s'", data.fn_name, region);
		}
		Aws::S3::Model::CreateBucketConfiguration configuration;
		configuration.SetLocationConstraint(constraint);
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
		if (data.has_versioning && data.versioning) {
			PutVersioning(*client, data.name, true);
		}
		if (data.has_block_public_access) {
			PutPublicAccessBlock(*client, data.name, data.block_public_access);
		}
	} catch (std::exception &ex) {
		// A bucket that exists but is not what was asked for is worse than none, and this one is
		// empty and ours, so remove it: a retry after fixing the cause then does not trip over
		// BucketAlreadyOwnedByYou.
		Aws::S3::Model::DeleteBucketRequest cleanup;
		cleanup.SetBucket(data.name.c_str());
		auto cleanup_outcome = client->DeleteBucket(cleanup);
		if (!cleanup_outcome.IsSuccess()) {
			throw IOException("%s; bucket '%s' was created but could not be removed again (%s)", ex.what(), data.name,
			                  FromAws(cleanup_outcome.GetError().GetExceptionName()));
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
// HeadBucket, then the two settings s3_update_bucket changes, so an update can be verified
// without the console.
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
// s3_update_bucket(name | handle [, tags :=, versioning :=, block_public_access :=, region :=, secret :=, dry_run :=])
//
// S3 has no UpdateBucket; this is the three Put calls behind the settings s3_create_bucket
// accepts, applied in that order. A failure stops there and leaves the earlier changes in place,
// which the error names. Tags merge into the existing set rather than replace it, so updating one
// tag does not silently drop the provenance tags; a NULL value removes a key.
//===--------------------------------------------------------------------===//

struct UpdateBucketBindData : public BucketBindData {
	UpdateBucketBindData() : BucketBindData("s3_update_bucket", "updating S3 buckets") {
	}
	TagOption tags;
	bool has_versioning = false;
	bool versioning = false;
	bool has_block_public_access = false;
	bool block_public_access = false;
	bool dry_run = false;
};

unique_ptr<FunctionData> UpdateBucketBind(ClientContext &, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<UpdateBucketBindData>();
	auto fn_name = result->fn_name;
	result->bucket = BucketFromInput(input, fn_name);
	result->secret_name = StringOption(input, "secret", fn_name);
	result->tags = TagsOption(input, fn_name, true);
	result->has_versioning = TryBoolOption(input, "versioning", fn_name, result->versioning);
	result->has_block_public_access = TryBoolOption(input, "block_public_access", fn_name, result->block_public_access);
	result->dry_run = BoolOption(input, "dry_run", fn_name);

	bool changes_tags = !result->tags.set.empty() || !result->tags.unset.empty();
	if (!changes_tags && !result->has_versioning && !result->has_block_public_access) {
		throw InvalidInputException("%s: nothing to change: pass tags :=, versioning := or block_public_access :=",
		                            fn_name);
	}

	AddColumn(return_types, names, "status", LogicalType::VARCHAR);
	AddColumn(return_types, names, "name", LogicalType::VARCHAR);
	AddColumn(return_types, names, "region", LogicalType::VARCHAR);
	AddColumn(return_types, names, "tags", LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR));
	AddColumn(return_types, names, "versioning", LogicalType::VARCHAR);
	AddColumn(return_types, names, "block_public_access", LogicalType::BOOLEAN);
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

	if (!data.tags.set.empty() || !data.tags.unset.empty()) {
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
	if (data.has_versioning) {
		if (!data.dry_run) {
			PutVersioning(*client, name, data.versioning);
		}
		versioning_out = Value(data.versioning ? "Enabled" : "Suspended");
	}
	if (data.has_block_public_access) {
		if (!data.dry_run) {
			PutPublicAccessBlock(*client, name, data.block_public_access);
		}
		block_public_access_out = Value::BOOLEAN(data.block_public_access);
	}

	output.data[0].Append(Value(data.dry_run ? "dry_run" : "updated"));
	output.data[1].Append(Value(name));
	output.data[2].Append(Value(region));
	output.data[3].Append(tags_out);
	output.data[4].Append(versioning_out);
	output.data[5].Append(block_public_access_out);
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
	result->cascade = BoolOption(input, "cascade", fn_name);
	result->dry_run = BoolOption(input, "dry_run", fn_name);

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
		// Count what a cascade would remove, touching nothing.
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

//! Two overloads for every function that acts on one bucket: the name, or the handle MAP that
//! s3_create_bucket returned.
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

	loader.RegisterFunction(TableFunction("s3_buckets",
	                                      FunctionSignature().WithTypedKwargs("options", with_region_secret),
	                                      S3BucketsFun, S3BucketsBind, S3BucketsInit));

	FunctionSignature create_signature;
	create_signature.AddParameter("name", LogicalType::VARCHAR).WithTypedKwargs("options", [&](TypedKwargs &options) {
		options.Add("region", LogicalType::VARCHAR)
		    .Add("tags", map_vv)
		    .Add("versioning", LogicalType::BOOLEAN)
		    .Add("block_public_access", LogicalType::BOOLEAN)
		    .Add("secret", LogicalType::VARCHAR)
		    // Typed BOOLEAN rather than a string: a value that failed to parse would fall through to
		    // false and create a real bucket.
		    .Add("dry_run", LogicalType::BOOLEAN);
	});
	loader.RegisterFunction(
	    TableFunction("s3_create_bucket", std::move(create_signature), CreateBucketFun, CreateBucketBind, OnceInit));

	loader.RegisterFunction(
	    BucketFunctionSet("s3_get_bucket", with_region_secret, GetBucketFun, GetBucketBind, OnceInit));
	loader.RegisterFunction(
	    BucketFunctionSet("s3_bucket_tags", with_region_secret, BucketTagsFun, BucketTagsBind, TagsInit));

	auto update_options = [map_vv](TypedKwargs &options) {
		options.Add("tags", map_vv)
		    .Add("versioning", LogicalType::BOOLEAN)
		    .Add("block_public_access", LogicalType::BOOLEAN)
		    .Add("region", LogicalType::VARCHAR)
		    .Add("secret", LogicalType::VARCHAR)
		    .Add("dry_run", LogicalType::BOOLEAN);
	};
	loader.RegisterFunction(
	    BucketFunctionSet("s3_update_bucket", update_options, UpdateBucketFun, UpdateBucketBind, OnceInit));

	auto delete_options = [](TypedKwargs &options) {
		options.Add("cascade", LogicalType::BOOLEAN)
		    .Add("region", LogicalType::VARCHAR)
		    .Add("secret", LogicalType::VARCHAR)
		    .Add("dry_run", LogicalType::BOOLEAN);
	};
	loader.RegisterFunction(
	    BucketFunctionSet("s3_delete_bucket", delete_options, DeleteBucketFun, DeleteBucketBind, OnceInit));
}

} // namespace duckdb
