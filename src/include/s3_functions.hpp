#pragma once

namespace duckdb {

class ExtensionLoader;

struct S3Functions {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
