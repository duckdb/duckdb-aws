# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(aws
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)

duckdb_extension_load(httpfs
        GIT_URL https://github.com/duckdb/duckdb-httpfs
        GIT_TAG cb5b2825eff68fc91f47e917ba88bf2ed84c2dd3 
        INCLUDE_DIR extension/httpfs/include
	APPLY_PATCHES
)
