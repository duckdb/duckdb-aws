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

.PHONY: quack-redshift-setup quack-redshift-check quack-redshift-cleanup quack-redshift-manual-test
quack-redshift-setup:
	python3 "$(PROJ_DIR)scripts/quack_redshift.py" setup $(if $(filter 1,$(FORCE)),--force,)

quack-redshift-check:
	python3 "$(PROJ_DIR)scripts/quack_redshift.py" check $(if $(filter 1,$(FORCE)),--force,)

quack-redshift-cleanup:
	python3 "$(PROJ_DIR)scripts/quack_redshift.py" cleanup $(if $(filter 1,$(FORCE)),--force,)

quack-redshift-manual-test:
	python3 "$(PROJ_DIR)scripts/generate_manual_test_with_secrets.py" $(if $(filter 1,$(FORCE)),--force,)
