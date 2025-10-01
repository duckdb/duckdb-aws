#include "aws_secret.hpp"
#include "aws_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/platform/Environment.h>

#include <iostream>

namespace duckdb {

//! Set the DuckDB AWS Credentials using the DefaultAWSCredentialsProviderChain
static AwsSetCredentialsResult TrySetAwsCredentials(DBConfig &config, const string &profile, bool set_region) {
	Aws::Auth::AWSCredentials credentials;

	if (!profile.empty()) {
		// The user has specified a specific profile they want to use instead of the current profile specified by the
		// system
		Aws::Auth::ProfileConfigFileAWSCredentialsProvider provider(profile.c_str());
		credentials = provider.GetAWSCredentials();
	} else {
		Aws::Auth::DefaultAWSCredentialsProviderChain provider;
		credentials = provider.GetAWSCredentials();
	}

	auto s3_config = Aws::Client::ClientConfiguration(profile.c_str());
	auto region = s3_config.region;

	// TODO: We would also like to get the endpoint here, but it's currently not supported by the AWS SDK:
	// 		 https://github.com/aws/aws-sdk-cpp/issues/2587

	AwsSetCredentialsResult ret;
	if (!credentials.IsExpiredOrEmpty()) {
		config.SetOption("s3_access_key_id", Value(credentials.GetAWSAccessKeyId()));
		config.SetOption("s3_secret_access_key", Value(credentials.GetAWSSecretKey()));
		config.SetOption("s3_session_token", Value(credentials.GetSessionToken()));
		ret.set_access_key_id = credentials.GetAWSAccessKeyId();
		ret.set_secret_access_key = credentials.GetAWSSecretKey();
		ret.set_session_token = credentials.GetSessionToken();
	}

	if (!region.empty() && set_region) {
		config.SetOption("s3_region", Value(region));
		ret.set_region = region;
	}

	return ret;
}

struct SetAWSCredentialsFunctionData : public TableFunctionData {
	string profile_name;
	bool finished = false;
	bool set_region = true;
	bool redact_secret = true;
};

static unique_ptr<FunctionData> LoadAWSCredentialsBind(ClientContext &context, TableFunctionBindInput &input,
                                                       vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<SetAWSCredentialsFunctionData>();

	for (const auto &option : input.named_parameters) {
		if (option.first == "set_region") {
			result->set_region = BooleanValue::Get(option.second);
		} else if (option.first == "redact_secret") {
			result->redact_secret = BooleanValue::Get(option.second);
		}
	}

	if (input.inputs.size() >= 1) {
		result->profile_name = input.inputs[0].ToString();
	}

	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("loaded_access_key_id");

	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("loaded_secret_access_key");

	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("loaded_session_token");

	return_types.emplace_back(LogicalType::VARCHAR);
	names.emplace_back("loaded_region");

	return std::move(result);
}

static void LoadAWSCredentialsFun(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &data = (SetAWSCredentialsFunctionData &)*data_p.bind_data;
	if (data.finished) {
		return;
	}

	if (!Catalog::TryAutoLoad(context, "httpfs")) {
		throw MissingExtensionException("httpfs extension is required for load_aws_credentials");
	}

	auto load_result = TrySetAwsCredentials(DBConfig::GetConfig(context), data.profile_name, data.set_region);

	// Set return values for all modified params
	output.SetValue(0, 0, load_result.set_access_key_id.empty() ? Value(nullptr) : load_result.set_access_key_id);
	if (data.redact_secret && !load_result.set_secret_access_key.empty()) {
		output.SetValue(1, 0, "<redacted>");
	} else {
		output.SetValue(1, 0,
		                load_result.set_secret_access_key.empty() ? Value(nullptr) : load_result.set_secret_access_key);
	}
	output.SetValue(2, 0, load_result.set_session_token.empty() ? Value(nullptr) : load_result.set_session_token);
	output.SetValue(3, 0, load_result.set_region.empty() ? Value(nullptr) : load_result.set_region);

	output.SetCardinality(1);

	data.finished = true;
}
static void LoadInternal(ExtensionLoader &loader) {
	Aws::SDKOptions options;
	Aws::InitAPI(options);

	{
		// What the process env says:
		std::cout << "ENV AWS_SHARED_CREDENTIALS_FILE=" << Aws::Environment::GetEnv("AWS_SHARED_CREDENTIALS_FILE")
		          << "\n";
		std::cout << "ENV AWS_CONFIG_FILE=" << Aws::Environment::GetEnv("AWS_CONFIG_FILE") << "\n";

		// What the SDK resolved to (post-init):
		std::cout << "SDK credentials file path="
		          << Aws::Auth::ProfileConfigFileAWSCredentialsProvider::GetCredentialsProfileFilename() << "\n";
		std::cout << "SDK config file path=" << Aws::Auth::GetConfigProfileFilename() << "\n";
	}

	CreateAwsSecretFunctions::InitializeCurlCertificates(loader.GetDatabaseInstance());

	TableFunctionSet function_set("load_aws_credentials");
	auto base_fun = TableFunction("load_aws_credentials", {}, LoadAWSCredentialsFun, LoadAWSCredentialsBind);
	auto profile_fun =
	    TableFunction("load_aws_credentials", {LogicalTypeId::VARCHAR}, LoadAWSCredentialsFun, LoadAWSCredentialsBind);

	base_fun.named_parameters["set_region"] = LogicalTypeId::BOOLEAN;
	base_fun.named_parameters["redact_secret"] = LogicalTypeId::BOOLEAN;
	profile_fun.named_parameters["set_region"] = LogicalTypeId::BOOLEAN;
	profile_fun.named_parameters["redact_secret"] = LogicalTypeId::BOOLEAN;

	function_set.AddFunction(base_fun);
	function_set.AddFunction(profile_fun);

	loader.RegisterFunction(function_set);

	CreateAwsSecretFunctions::Register(loader);
}

void AwsExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string AwsExtension::Name() {
	return "aws";
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(aws, loader) {
	duckdb::LoadInternal(loader);
}
}
