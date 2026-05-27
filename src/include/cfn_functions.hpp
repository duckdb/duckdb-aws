#pragma once

namespace duckdb {

class ExtensionLoader;

struct CfnFunctions {
	//! Register the generic CloudFormation table functions (cfn_*).
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
