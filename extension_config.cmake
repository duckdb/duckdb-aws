# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(aws
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)

# Build the postgres scanner for the redshift action (e.g. redshift attach).
# Currently Disabled since this will not build on CI. To get CI working you (most likely)
# need to copy the vcpkg_ports/libpq in the duckdb/duckdb-postgres repo. 
# For now commented out so unblock development
# duckdb_extension_load(postgres_scanner
#    DONT_LINK
#    GIT_URL https://github.com/duckdb/duckdb-postgres
#    GIT_TAG f77b0cb511748fd70fb8a4eb265e2990599d286c
#    SUBMODULES database-connector
#    APPLY_PATCHES
#)
