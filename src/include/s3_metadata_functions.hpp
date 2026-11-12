#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ExtensionLoader;

//! S3 Metadata: the per-bucket configuration that makes S3 write a bucket's object journal and
//! inventory as Iceberg tables into the account's AWS-managed `aws-s3` table bucket. Get, create
//! and delete of that configuration; the `aws:system-table` type's create/status/destroy for the
//! `aws:s3:bucket` family run on these.
struct S3MetadataFunctions {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
