#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ExtensionLoader;

//! Listing over the Redshift and Redshift Serverless control planes: `redshift_clusters()` (DescribeClusters) and
//! `redshift_serverless_workgroups()` (ListWorkgroups). They only read, and the external-resource types in
//! redshift_resource.cpp are built on them.
struct RedshiftFunctions {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
