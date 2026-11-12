#include "s3_metadata_functions.hpp"

#include "aws_client.hpp"
#include "aws_http_client.hpp"
#include "utils/utils.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <aws/s3/S3Client.h>
#include <aws/s3/model/CreateBucketMetadataConfigurationRequest.h>
#include <aws/s3/model/DeleteBucketMetadataConfigurationRequest.h>
#include <aws/s3/model/GetBucketMetadataConfigurationRequest.h>

namespace duckdb {

namespace {

string FromAws(const Aws::String &s) {
	return {s.data(), s.size()};
}

template <class OUTCOME>
[[noreturn]] void ThrowAwsError(const char *call, const OUTCOME &outcome) {
	const auto &err = outcome.GetError();
	throw IOException("S3 %s failed: %s - %s", call, FromAws(err.GetExceptionName()), FromAws(err.GetMessage()));
}

string StringParam(TableFunctionBindInput &input, const char *key) {
	for (auto &np : input.named_parameters) {
		if (StringUtil::Lower(np.first.GetIdentifierName()) == key && !np.second.IsNull()) {
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

int64_t IntParam(TableFunctionBindInput &input, const char *key, int64_t default_value) {
	for (auto &np : input.named_parameters) {
		if (StringUtil::Lower(np.first.GetIdentifierName()) == key && !np.second.IsNull()) {
			return np.second.GetValue<int64_t>();
		}
	}
	return default_value;
}

//! What every function here needs: the bucket, the region its client talks to, and the identity.
struct BucketBindData : public TableFunctionData {
	string bucket;
	string region;
	string secret_name;
	bool inventory = true;
	int64_t journal_expiration_days = 0;
};

struct OnceState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<GlobalTableFunctionState> OnceInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<OnceState>();
}

unique_ptr<BucketBindData> BindBucket(ClientContext &context, TableFunctionBindInput &input, const char *fn_name) {
	auto result = make_uniq<BucketBindData>();
	if (input.inputs[0].IsNull() || StringValue::Get(input.inputs[0]).empty()) {
		throw InvalidInputException("%s: the bucket must not be NULL or empty", fn_name);
	}
	result->bucket = StringValue::Get(input.inputs[0]);
	result->secret_name = StringParam(input, "secret");
	// The S3 Metadata configuration lives with the bucket, so the client has to be in the bucket's region.
	result->region = ResolveAwsRegion(context, StringParam(input, "region"), "");
	if (result->region.empty()) {
		throw InvalidInputException("%s: no region for bucket '%s': pass region := '<region>' or set s3_region, "
		                            "AWS_REGION or the profile's region",
		                            fn_name, result->bucket);
	}
	return result;
}

Aws::S3::S3Client MakeClient(ClientContext &context, const BucketBindData &data) {
	auto entry = FindAwsSecret(context, data.secret_name);
	auto provider = CredentialsProviderFromSecret(entry->secret->Cast<KeyValueSecret>(), "S3");
	Aws::S3::S3ClientConfiguration cfg(BuildClientConfigWithCa());
	cfg.region = data.region.c_str();
	return Aws::S3::S3Client(provider, nullptr, cfg);
}

void AddConfigurationColumns(vector<LogicalType> &return_types, vector<Identifier> &names) {
	for (auto &col : {"bucket", "region", "table_bucket_arn", "namespace", "journal_status", "journal_table_arn",
	                  "inventory_status", "inventory_table_arn"}) {
		names.emplace_back(col);
		return_types.emplace_back(LogicalType::VARCHAR);
	}
}

//! One row from GetBucketMetadataConfiguration; false when the bucket has no configuration.
bool EmitConfiguration(Aws::S3::S3Client &client, const BucketBindData &data, DataChunk &output) {
	Aws::S3::Model::GetBucketMetadataConfigurationRequest req;
	req.SetBucket(data.bucket.c_str());
	auto outcome = client.GetBucketMetadataConfiguration(req);
	if (!outcome.IsSuccess()) {
		if (outcome.GetError().GetExceptionName() == "MetadataConfigurationNotFound") {
			return false;
		}
		ThrowAwsError("GetBucketMetadataConfiguration", outcome);
	}
	const auto &res = outcome.GetResult().GetGetBucketMetadataConfigurationResult().GetMetadataConfigurationResult();
	const auto &journal = res.GetJournalTableConfigurationResult();
	const auto &inventory = res.GetInventoryTableConfigurationResult();
	auto nullable = [](const Aws::String &s) {
		return s.empty() ? Value(LogicalType::VARCHAR) : Value(FromAws(s));
	};
	output.data[0].SetValue(0, Value(data.bucket));
	output.data[1].SetValue(0, Value(data.region));
	output.data[2].SetValue(0, nullable(res.GetDestinationResult().GetTableBucketArn()));
	output.data[3].SetValue(0, nullable(res.GetDestinationResult().GetTableNamespace()));
	output.data[4].SetValue(0, nullable(journal.GetTableStatus()));
	output.data[5].SetValue(0, nullable(journal.GetTableArn()));
	// the inventory table is optional: its status is NULL when it was never enabled
	output.data[6].SetValue(0, nullable(inventory.GetTableStatus()));
	output.data[7].SetValue(0, nullable(inventory.GetTableArn()));
	output.SetCardinality(1);
	return true;
}

//===--------------------------------------------------------------------===//
// s3_bucket_metadata_configuration(bucket [, region := , secret := ])
//
// The S3 Metadata configuration of a general purpose bucket: the aws-s3 table bucket and namespace
// its tables land in, and the status of the journal and inventory tables (CREATING, ACTIVE,
// BACKFILLING, ...). No row when the bucket has no configuration.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> GetBind(ClientContext &context, TableFunctionBindInput &input,
                                 vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = BindBucket(context, input, "s3_bucket_metadata_configuration");
	AddConfigurationColumns(return_types, names);
	return std::move(result);
}

void GetFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &data = data_p.bind_data->Cast<BucketBindData>();
	auto &state = data_p.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}
	state.done = true;
	auto client = MakeClient(context, data);
	EmitConfiguration(client, data, output);
}

//===--------------------------------------------------------------------===//
// s3_create_bucket_metadata_configuration(bucket [, region := , inventory := true,
//                                         journal_expiration_days := 0, secret := ])
//
// CreateBucketMetadataConfiguration: a journal table always, an inventory table unless
// `inventory := false`, journal records kept forever unless `journal_expiration_days` is set. S3
// creates the aws-s3 table bucket of the region on the first configuration. Returns the
// configuration as s3_bucket_metadata_configuration does, right after creation, so the tables are
// typically still CREATING.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> CreateBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = BindBucket(context, input, "s3_create_bucket_metadata_configuration");
	result->inventory = BoolParam(input, "inventory", true);
	result->journal_expiration_days = IntParam(input, "journal_expiration_days", 0);
	if (result->journal_expiration_days < 0) {
		throw InvalidInputException("s3_create_bucket_metadata_configuration: journal_expiration_days must be >= 0");
	}
	AddConfigurationColumns(return_types, names);
	return std::move(result);
}

void CreateFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &data = data_p.bind_data->Cast<BucketBindData>();
	auto &state = data_p.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}
	state.done = true;
	auto client = MakeClient(context, data);

	Aws::S3::Model::RecordExpiration expiration;
	if (data.journal_expiration_days > 0) {
		expiration.SetExpiration(Aws::S3::Model::ExpirationState::ENABLED);
		expiration.SetDays(static_cast<int>(data.journal_expiration_days));
	} else {
		expiration.SetExpiration(Aws::S3::Model::ExpirationState::DISABLED);
	}
	Aws::S3::Model::JournalTableConfiguration journal;
	journal.SetRecordExpiration(expiration);
	Aws::S3::Model::MetadataConfiguration configuration;
	configuration.SetJournalTableConfiguration(journal);
	if (data.inventory) {
		Aws::S3::Model::InventoryTableConfiguration inventory;
		inventory.SetConfigurationState(Aws::S3::Model::InventoryConfigurationState::ENABLED);
		configuration.SetInventoryTableConfiguration(inventory);
	}
	Aws::S3::Model::CreateBucketMetadataConfigurationRequest req;
	req.SetBucket(data.bucket.c_str());
	req.SetMetadataConfiguration(configuration);
	auto outcome = client.CreateBucketMetadataConfiguration(req);
	if (!outcome.IsSuccess()) {
		ThrowAwsError("CreateBucketMetadataConfiguration", outcome);
	}
	if (!EmitConfiguration(client, data, output)) {
		throw IOException("s3_create_bucket_metadata_configuration: the configuration of bucket '%s' was created but "
		                  "cannot be read back",
		                  data.bucket);
	}
}

//===--------------------------------------------------------------------===//
// s3_delete_bucket_metadata_configuration(bucket [, region := , secret := ])
//
// DeleteBucketMetadataConfiguration. S3 deletes the bucket's journal and inventory tables with it:
// this is the "no system table for this bucket anymore" call, and it is not undoable.
//===--------------------------------------------------------------------===//

unique_ptr<FunctionData> DeleteBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = BindBucket(context, input, "s3_delete_bucket_metadata_configuration");
	names.emplace_back("status");
	return_types.emplace_back(LogicalType::VARCHAR);
	return std::move(result);
}

void DeleteFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));
	auto &data = data_p.bind_data->Cast<BucketBindData>();
	auto &state = data_p.global_state->Cast<OnceState>();
	if (state.done) {
		return;
	}
	state.done = true;
	auto client = MakeClient(context, data);
	Aws::S3::Model::DeleteBucketMetadataConfigurationRequest req;
	req.SetBucket(data.bucket.c_str());
	auto outcome = client.DeleteBucketMetadataConfiguration(req);
	if (!outcome.IsSuccess()) {
		if (outcome.GetError().GetExceptionName() == "MetadataConfigurationNotFound") {
			output.data[0].SetValue(0, Value("absent"));
			output.SetCardinality(1);
			return;
		}
		ThrowAwsError("DeleteBucketMetadataConfiguration", outcome);
	}
	output.data[0].SetValue(0, Value("deleted"));
	output.SetCardinality(1);
}

} // namespace

void S3MetadataFunctions::Register(ExtensionLoader &loader) {
	const string category = "system-tables";
	auto with_region_and_secret = [](TypedKwargs &options) {
		options.Add("region", LogicalType::VARCHAR).Add("secret", LogicalType::VARCHAR);
	};

	FunctionSignature get_signature;
	get_signature.AddParameter("bucket", LogicalType::VARCHAR).WithTypedKwargs("options", with_region_and_secret);
	loader.RegisterFunction(Documented(
	    TableFunction("s3_bucket_metadata_configuration", std::move(get_signature), GetFun, GetBind, OnceInit),
	    "Returns a bucket's S3 Metadata configuration as one row: the `aws-s3` table bucket and namespace its tables "
	    "live in, and the status and ARN of the journal and inventory tables. No row when the bucket has no "
	    "configuration.",
	    "FROM s3_bucket_metadata_configuration('my-bucket', region := 'us-east-1')", category));

	FunctionSignature create_signature;
	create_signature.AddParameter("bucket", LogicalType::VARCHAR).WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("region", LogicalType::VARCHAR)
		    .Add("secret", LogicalType::VARCHAR)
		    .Add("inventory", LogicalType::BOOLEAN)
		    .Add("journal_expiration_days", LogicalType::BIGINT);
	});
	loader.RegisterFunction(Documented(
	    TableFunction("s3_create_bucket_metadata_configuration", std::move(create_signature), CreateFun, CreateBind,
	                  OnceInit),
	    "Enables S3 Metadata for a bucket: a journal table always, an inventory table unless `inventory := false`, "
	    "journal records kept forever unless `journal_expiration_days` is set. S3 creates the region's `aws-s3` "
	    "table bucket on the first configuration. Returns the configuration as `s3_bucket_metadata_configuration` "
	    "does, so the tables are typically still CREATING.",
	    "FROM s3_create_bucket_metadata_configuration('my-bucket', region := 'us-east-1', inventory := true, "
	    "journal_expiration_days := 30)",
	    category));

	FunctionSignature delete_signature;
	delete_signature.AddParameter("bucket", LogicalType::VARCHAR).WithTypedKwargs("options", with_region_and_secret);
	loader.RegisterFunction(Documented(
	    TableFunction("s3_delete_bucket_metadata_configuration", std::move(delete_signature), DeleteFun, DeleteBind,
	                  OnceInit),
	    "Disables S3 Metadata for a bucket, which deletes its journal and inventory tables, irreversibly; the "
	    "bucket's objects are untouched. Returns `status = deleted`, or `absent` when there was no configuration.",
	    "FROM s3_delete_bucket_metadata_configuration('my-bucket', region := 'us-east-1')", category));
}

} // namespace duckdb
