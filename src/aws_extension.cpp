#include "aws_secret.hpp"
#include "aws_extension.hpp"
#include "cloudformation_functions.hpp"
#include "quack_on_ec2_resource.hpp"
#include "redshift/redshift_utils.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/settings.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/client/ClientConfiguration.h>

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	Aws::SDKOptions options;
	Aws::InitAPI(options);

	CreateAwsSecretFunctions::InitializeCurlCertificates(loader.GetDatabaseInstance());
	CreateAwsSecretFunctions::Register(loader);

	// Makes `ATTACH '<cluster-id>' (TYPE redshift, ...)` resolve to the redshift storage extension.
	Redshift::RegisterStorageExtension(loader);

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
