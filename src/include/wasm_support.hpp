#pragma once

namespace duckdb {

//! Installs the hash implementations aws-c-cal lacks on wasm (built with BYO_CRYPTO); call before Aws::InitAPI.
void RegisterWasmSupport();

} // namespace duckdb
