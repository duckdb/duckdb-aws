#pragma once

namespace duckdb {

class ExtensionLoader;

struct CloudFormationFunctions {
	//! Register the generic CloudFormation table functions (cloudformation_*).
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
