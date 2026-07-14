#pragma once

namespace duckdb {

class ExtensionLoader;

//! Registers the `aws:cloudformation:quack-on-ec2` external resource type and its native create/status/
//! destroy callbacks (thin adapters over the generic cloudformation_* table functions). Called from the
//! aws extension's Load so that `LOAD aws;` makes the type available with no user-authored SQL.
struct QuackOnEc2Resource {
	static void Register(ExtensionLoader &loader);
};

} // namespace duckdb
