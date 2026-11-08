#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ExtensionLoader;

//! The AWS system tables: Iceberg tables that AWS services write into the AWS-managed `aws-*`
//! table buckets of an account (S3 Metadata in aws-s3, the Glue Data Catalog export in
//! aws-catalog, Athena usage in aws-athena, Redshift sys_* views in aws-redshift, ...).
//! `aws_system_tables()` lists them, `aws_system_table()` scans one; both are plain SQL over the
//! s3tables_* functions, so other extensions consume them by name.
struct SystemTablesFunctions {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
