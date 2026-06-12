#!/usr/bin/env bash
set -euo pipefail

# Determine repo root regardless of cwd
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -d "$REPO_ROOT/duckdb" ]]; then
	echo "$0: error -- expected '$REPO_ROOT/duckdb' to exist (is this the duckdb-aws repo?)" >&2
	exit 1
fi

cd "$REPO_ROOT"

mkdir -p test/test_data
touch test/test_data/attach.db

if [[ ! -x ./scripts/install_s3_test_server.sh ]]; then
	echo "$0: error -- ./scripts/install_s3_test_server.sh not found or not executable" >&2
	exit 1
fi
sudo ./scripts/install_s3_test_server.sh

if [[ ! -f ./scripts/run_s3_test_server.sh ]]; then
	echo "$0: error -- ./scripts/run_s3_test_server.sh not found" >&2
	exit 1
fi
# shellcheck disable=SC1091
source ./scripts/run_s3_test_server.sh

# Wait for the server to become ready instead of a fixed sleep
HOST="${S3TEST_SERVER_HOST:-localhost}"
PORT="${S3TEST_SERVER_PORT:-9000}"
for i in $(seq 1 30); do
	if curl -s -o /dev/null "http://$HOST:$PORT"; then
		echo "S3 test server is up after ${i}s"
		break
	fi
	sleep 1
done