#pragma once

namespace duckdb {
class DatabaseInstance;

//! Install an AWS SDK HttpClientFactory routing all AWS SDK HTTP through DuckDB's
//! HTTPUtil, whichever transport the DatabaseInstance has registered (httpfs curl on
//! native, browser fetch under wasm). Lets the extension build for wasm without
//! libcurl, and unifies proxy, CA certs and logging everywhere. Call once at
//! extension load, BEFORE any AWS client is constructed.
void RegisterDuckDBAwsHttpClientFactory(DatabaseInstance &db);

} // namespace duckdb
