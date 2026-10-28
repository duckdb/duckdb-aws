# vcpkg overlay ports for WebAssembly builds

This directory contains vcpkg overlay ports needed to build this extension for
the DuckDB-Wasm platforms (`wasm_mvp`, `wasm_eh`, `wasm_threads`).

## aws-c-io

Upstream `aws-c-io` (the AWS CRT I/O layer) refuses to configure for
`wasm32-emscripten` with `"Event Loop is not setup on the platform."`, because it
only knows the Windows (IOCP), Linux (epoll), Apple (dispatch queue) and BSD
(kqueue) event loops.

The `emscripten-support.patch` overlay adds an Emscripten platform branch that:

- compiles the POSIX sources (sockets, pipes, DNS, shared-library stubs), which
  build cleanly against Emscripten's musl libc;
- ships **no** event loop implementation — `aws_event_loop_new*` fails
  gracefully at runtime with `AWS_ERROR_PLATFORM_NOT_SUPPORTED` instead of
  failing the build. The extension only uses the SDK's curl-style code paths,
  so no event loop is ever required for the supported flows.

Everything else in the dependency tree (openssl, curl, s2n, the remaining
`aws-c-*` libraries, `aws-crt-cpp`, and `aws-sdk-cpp` itself) builds for
`wasm32-emscripten` without modification.

## Local usage

```sh
export VCPKG_OVERLAY_PORTS=$PWD/vcpkg-overlay-ports
make wasm_eh
```

## CI usage

The extension distribution CI (`_extension_distribution.yml` in
duckdb/extension-ci-tools) sets `VCPKG_OVERLAY_PORTS` to
`extension-ci-tools/vcpkg_ports`, so for CI wasm builds this port needs to land
in that repository (or the CI needs to also honor a per-extension overlay dir).
