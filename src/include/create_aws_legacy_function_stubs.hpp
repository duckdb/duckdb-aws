#pragma once

namespace duckdb {

class ExtensionLoader;

struct CreateAwsLegacyFunctionStubs {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
