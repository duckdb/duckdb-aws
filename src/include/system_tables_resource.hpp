#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ExtensionLoader;

//! The `aws:system-table` external-resource type: one AWS system table, a table in an `aws-*`
//! table bucket, named by its path (`aws-catalog/glue/tables`), handled by its table ARN, attached
//! as its bucket with the namespace as the default schema.
struct SystemTablesResource {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
