#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ExtensionLoader;

//! The `aws:s3tables:table-bucket` external-resource type: an S3 Tables table bucket, which is the
//! one level of S3 Tables that maps one-to-one onto an attachable DuckDB catalog.
struct S3TablesResource {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
