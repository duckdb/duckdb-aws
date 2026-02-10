#!/usr/bin/env bash

[[ $(basename $PWD) = "duckdb-aws" && -d "./duckdb" ]] || {
	echo "$0: assert failed -- expect to be in .../duckdb-aws (in $PWD)" >&2
	exit 1
}

set -xv
mkdir -p test/test_data
touch test/test_data/attach.db
sudo ./scripts/install_s3_test_server.sh
source ./scripts/run_s3_test_server.sh
sleep 30
