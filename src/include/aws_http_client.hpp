#pragma once

#include "duckdb/common/shared_ptr.hpp"

namespace duckdb {
class DatabaseInstance;

//! Default of the aws_network_calls_via_duckdb setting. Opt-in on native, where the AWS
//! SDK's own HTTP client stays the default. Under wasm the bridge is the only transport,
//! so the setting defaults to (and is effectively pinned at) true.
#if defined(__EMSCRIPTEN__)
static constexpr bool AWS_NETWORK_VIA_DUCKDB_DEFAULT = true;
#else
static constexpr bool AWS_NETWORK_VIA_DUCKDB_DEFAULT = false;
#endif

//! Install an AWS SDK HttpClientFactory routing all AWS SDK HTTP through DuckDB's
//! HTTPUtil, whichever transport the DatabaseInstance has registered (httpfs curl on
//! native, browser fetch under wasm). Lets the extension build for wasm without
//! libcurl, and unifies proxy, CA certs and logging everywhere. Call once at
//! extension load, BEFORE any AWS client is constructed.
void RegisterDuckDBAwsHttpClientFactory(DatabaseInstance &db);

//! Binds AWS SDK client construction on the current thread to a DatabaseInstance.
//!
//! Aws::Http::SetHttpClientFactory is process-global and CreateHttpClient() is handed
//! nothing but a ClientConfiguration, so the factory cannot tell which instance an AWS
//! client belongs to. Without a binding it falls back to whichever instance most
//! recently loaded the extension, which means that with several DatabaseInstances in
//! one process every instance's AWS traffic follows the last-loaded one's transport and
//! settings -- and breaks outright once that instance is closed.
//!
//! Hold one of these across the construction of any AWS SDK client (or across a whole
//! operation, so clients built underneath it, credential providers included, inherit
//! it). The binding is thread-local and does NOT propagate to scheduler tasks: a task
//! that builds its own AWS client has to establish its own.
class AwsInstanceBinding {
public:
	explicit AwsInstanceBinding(DatabaseInstance &db);
	~AwsInstanceBinding();
	AwsInstanceBinding(const AwsInstanceBinding &) = delete;
	AwsInstanceBinding &operator=(const AwsInstanceBinding &) = delete;

private:
	weak_ptr<DatabaseInstance> previous;
};

} // namespace duckdb
