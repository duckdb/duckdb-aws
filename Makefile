PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=aws
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Core extensions that we need for crucial testing
DEFAULT_TEST_EXTENSION_DEPS=httpfs;tpch;json;
# For cloud testing we also need these extensions
FULL_TEST_EXTENSION_DEPS=


# Only run this repository's tests. extension-ci-tools' build workflow sets the test selection to
# "complete", which turns the pattern into "*" and also picks up the test suites of the test
# dependency extensions (httpfs, ...) via their absolute paths under build/<type>/_deps/. Those
# paths exceed MAX_PATH on the Windows runners once a test creates its temp directory. Same
# approach as duckdb-httpfs; `make test T=...` still overrides this.
T ?= "test/*"

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

.PHONY: sql-aws-session-token
sql-aws-session-token:
	@python3 "$(PROJ_DIR)scripts/generate_aws_secret.py" $(if $(filter 1,$(FORCE)),--force,)

.PHONY: docs docs-check
docs:
	python3 "$(PROJ_DIR)scripts/generate_function_docs.py" --build-dir "$(PROJ_DIR)build/release"

docs-check:
	python3 "$(PROJ_DIR)scripts/generate_function_docs.py" --build-dir "$(PROJ_DIR)build/release" --check
