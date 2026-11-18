#pragma once

namespace duckdb {

class ExtensionLoader;

//! Registers the `aws.cloudformation.stack` external resource type and its native create/status/destroy/list/
//! resolve callbacks (thin adapters over the generic cloudformation_* table functions). Called from the aws
//! extension's Load so that `LOAD aws;` makes the type available with no user-authored SQL.
struct CloudFormationStackResource {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
