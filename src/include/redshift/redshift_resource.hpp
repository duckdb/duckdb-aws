#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ExtensionLoader;

//! The `aws.redshift.cluster` and `aws.redshift-serverless.workgroup` external-resource types: the
//! account's clusters and Serverless workgroups, listed and attached by ARN.
struct RedshiftResource {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
