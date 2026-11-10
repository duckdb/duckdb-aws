#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ExtensionLoader;

//! The `aws:s3:bucket` external-resource type: a general-purpose S3 bucket, provisioned and torn
//! down through the s3_* functions. Its kind is 'storage': it is created, listed and destroyed,
//! not attached, since a bucket is not a catalog.
struct S3Resource {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
