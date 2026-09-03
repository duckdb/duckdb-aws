# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
if (EMSCRIPTEN)
    # For WebAssembly builds the loadable extension is produced by a plain
    # `emcc <archive> -o <ext>.wasm -sSIDE_MODULE=2 ${LINKED_LIBS}` re-link
    # (see build_loadable_extension_directory in duckdb), so the AWS SDK static
    # libraries from vcpkg must be passed explicitly via LINKED_LIBS: they are
    # NOT pulled in through target_link_libraries for that step.
    # Paths are relative to build/<platform>/extension/aws/, where the
    # POST_BUILD emcc command runs.
    set(VCPKG_WASM_LIB_DIR "../../vcpkg_installed/wasm32-emscripten/lib")
    string(JOIN " " AWS_WASM_LINKED_LIBS
        "${VCPKG_WASM_LIB_DIR}/libaws-cpp-sdk-cloudformation.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-cpp-sdk-rds.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-cpp-sdk-redshift.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-cpp-sdk-identity-management.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-cpp-sdk-cognito-identity.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-cpp-sdk-sso.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-cpp-sdk-sts.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-cpp-sdk-core.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-crt-cpp.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-s3.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-auth.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-mqtt.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-event-stream.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-http.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-compression.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-io.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-cal.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-sdkutils.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-checksums.a"
        "${VCPKG_WASM_LIB_DIR}/libaws-c-common.a"
        "${VCPKG_WASM_LIB_DIR}/libs2n.a"
        "${VCPKG_WASM_LIB_DIR}/libcurl.a"
        "${VCPKG_WASM_LIB_DIR}/libssl.a"
        "${VCPKG_WASM_LIB_DIR}/libcrypto.a"
        "${VCPKG_WASM_LIB_DIR}/libz.a"
    )
    duckdb_extension_load(aws
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
        LOAD_TESTS
        LINKED_LIBS "${AWS_WASM_LINKED_LIBS}"
    )
else()
    duckdb_extension_load(aws
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
        LOAD_TESTS
    )
endif()

duckdb_extension_load(icu)

# Build the postgres scanner for the redshift action (e.g. redshift attach).
# Currently Disabled since this will not build on CI. To get CI working you (most likely)
# need to copy the vcpkg_ports/libpq in the duckdb/duckdb-postgres repo. 
# For now commented out so unblock development
#duckdb_extension_load(postgres_scanner
#    DONT_LINK
#    GIT_URL https://github.com/duckdb/duckdb-postgres
#    GIT_TAG a4e03aad76a002e913e676cce1fc2600f64a614f
#    SUBMODULES database-connector
#)
