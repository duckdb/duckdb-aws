# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(aws
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)

duckdb_extension_load(httpfs
        GIT_URL https://github.com/duckdb/duckdb-httpfs
        GIT_TAG 4cf8a592cda330a9acc4c39756434f0e08ed1512
        INCLUDE_DIR extension/httpfs/include
)
