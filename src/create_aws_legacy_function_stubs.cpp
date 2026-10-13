#include "create_aws_legacy_function_stubs.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

namespace {

static constexpr const char *REMOVED_MESSAGE = "load_aws_credentials is no longer supported. Configure AWS credentials "
                                               "with "
                                               "`CREATE SECRET cfg (TYPE S3, PROVIDER credential_chain)`. "
                                               "To use a named profile, add `CHAIN 'config', PROFILE 'profile_name'`. "
                                               "See https://duckdb.org/docs/current/core_extensions/aws.";

static unique_ptr<FunctionData> LoadAWSCredentialsBind(ClientContext &, TableFunctionBindInput &, vector<LogicalType> &,
                                                       vector<Identifier> &) {
	throw InvalidInputException(REMOVED_MESSAGE);
}

static void LoadAWSCredentialsFunction(ClientContext &, TableFunctionInput &, DataChunk &) {
	throw InvalidInputException(REMOVED_MESSAGE);
}

} // namespace

void CreateAwsLegacyFunctionStubs::Register(ExtensionLoader &loader) {
	TableFunctionSet function_set("load_aws_credentials");
	FunctionSignature base_signature;
	base_signature.WithTypedKwargs("options", [&](TypedKwargs &options) {
		options.Add("set_region", LogicalTypeId::BOOLEAN).Add("redact_secret", LogicalTypeId::BOOLEAN);
	});
	auto base_fun = TableFunction("load_aws_credentials", std::move(base_signature), LoadAWSCredentialsFunction,
	                              LoadAWSCredentialsBind);

	FunctionSignature profile_signature;
	profile_signature.AddParameter("profile", LogicalTypeId::VARCHAR)
	    .WithTypedKwargs("options", [&](TypedKwargs &options) {
		    options.Add("set_region", LogicalTypeId::BOOLEAN).Add("redact_secret", LogicalTypeId::BOOLEAN);
	    });
	auto profile_fun = TableFunction("load_aws_credentials", std::move(profile_signature), LoadAWSCredentialsFunction,
	                                 LoadAWSCredentialsBind);

	function_set.AddFunction(base_fun);
	function_set.AddFunction(profile_fun);

	loader.RegisterFunction(function_set);
}

} // namespace duckdb
