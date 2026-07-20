#pragma once

namespace duckdb {
class DatabaseInstance;

//! Install an AWS SDK HttpClientFactory that routes ALL AWS SDK HTTP through
//! DuckDB's HTTPUtil (obtained from the DatabaseInstance). The concrete transport
//! is whatever is registered on the instance: httpfs's curl-backed HTTPFSUtil on
//! native, the browser-fetch HTTP layer under duckdb-wasm. This is what lets the
//! extension build for wasm (no libcurl dependency) and unifies HTTP handling
//! (proxy, CA certs, logging) on every platform. Call once at extension load,
//! BEFORE any AWS client is constructed (i.e. right after Aws::InitAPI).
void RegisterDuckDBAwsHttpClientFactory(DatabaseInstance &db);

} // namespace duckdb
