#pragma once

namespace duckdb {

class ExtensionLoader;

struct ArnStorage {
	//! Register the 'aws' storage extension, dispatching `ATTACH 'arn:aws:...'`
	//! to the storage backend serving the ARN's service.
	static void RegisterStorageExtension(ExtensionLoader &loader);
};

} // namespace duckdb
