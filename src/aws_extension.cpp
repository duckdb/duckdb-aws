#include "arn_storage.hpp"
#include "aws_secret.hpp"
#include "aws_extension.hpp"
#include "aws_http_client.hpp"
#include "cloudformation_functions.hpp"
#include "rds/rds_utils.hpp"
#include "quack_on_ec2_resource.hpp"
#include "redshift/redshift_utils.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/client/ClientConfiguration.h>

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	Aws::SDKOptions options;
	Aws::InitAPI(options);

	// Ignored under wasm, where the bridge is the only path. Registered as GLOBAL: the client
	// factory reads this off the DatabaseInstance, which never sees a session-scoped value, so
	// the default SESSION scope would make a plain SET silently do nothing.
	DBConfig::GetConfig(loader.GetDatabaseInstance())
	    .AddExtensionOption("aws_network_calls_via_duckdb",
	                        "Route all AWS SDK network calls through DuckDB's HTTP layer (httpfs transport) "
	                        "instead of the AWS SDK's own HTTP client. Required under WebAssembly; on native it "
	                        "avoids statically linking libcurl and patching its CA-certificate path. Default true.",
	                        LogicalType::BOOLEAN, Value::BOOLEAN(true), nullptr, SetScope::GLOBAL);

	// Must run before any AWS client is constructed. The factory reads the setting per
	// client, so the toggle stays live.
	RegisterDuckDBAwsHttpClientFactory(loader.GetDatabaseInstance());

	CreateAwsSecretFunctions::InitializeCurlCertificates(loader.GetDatabaseInstance());
	CreateAwsSecretFunctions::Register(loader);

	// Makes `ATTACH '<cluster-id>' (TYPE redshift, ...)` resolve to the redshift storage extension.
	Redshift::RegisterStorageExtension(loader);

	// RDS is both a direct storage type and an internal ARN delegation target.
	Rds::RegisterStorageExtension(loader);

	// Makes `ATTACH 'arn:aws:...'` dispatch to the backend serving the ARN's service.
	ArnStorage::RegisterStorageExtension(loader);

	CloudFormationFunctions::Register(loader);
	QuackOnEc2Resource::Register(loader);
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
