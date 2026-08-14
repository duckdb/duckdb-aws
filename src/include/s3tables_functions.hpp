#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ExtensionLoader;

//! Table functions over the S3 Tables control plane: the three listing levels
//! (table buckets / namespaces / tables) plus the lifecycle calls a
//! DuckDB-managed table bucket needs (create, and a sealing cascade delete).
struct S3TablesFunctions {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
