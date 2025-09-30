#!/usr/bin/env bash

##
# NOTE: several assumptions baked in, named here, checked below
# PWD=.../duckdb-aws/ -> assert -d ./duckdb ./build/release/
# setup scripts in build/release/...httpfs.../scripts
#

# must be relative path
#DUCKDB_PATH=./build/release/duckdb # needed by generate_presigned_url
SCRIPTS_PATH=./build/release/_deps/httpfs_extension_fc-src/scripts

[[ $(basename $PWD) = "duckdb-aws" && -d "./duckdb" ]] || {
	echo "$0: assert failed -- expect to be in .../duckdb-aws (in $PWD)" >&2
	exit 1
}

[[ -d "$SCRIPTS_PATH" ]] || {
	echo "$0: assert failed -- no such directory: SCRIPTS_PATH=$SCRIPTS_PATH" >&2
	exit 1
}

# generate_presigned_url expects duckdb/build which we don't have, but accepts duckdb/duckdb which we link
source "${SCRIPTS_PATH}/generate_presigned_url.sh"
cd duckdb
( # instead of mod'ing httpfs scripts, bridge the gap
	cd test
	ln -sf ../../test/test_data
)
sudo "../${SCRIPTS_PATH}/install_s3_test_server.sh"
source "../${SCRIPTS_PATH}/run_s3_test_server.sh"
sleep 30
