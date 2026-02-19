PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=aws
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Core extensions that we need for crucial testing
DEFAULT_TEST_EXTENSION_DEPS=httpfs;tpch;json;
# For cloud testing we also need these extensions
FULL_TEST_EXTENSION_DEPS=


# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile
