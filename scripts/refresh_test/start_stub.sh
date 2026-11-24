#!/usr/bin/env bash
# Launches the offline expiring-credential stub for test/sql/env/aws_secret_refresh_offline.test
# and prints the environment the test needs. Typical use:
#
#   eval "$(scripts/refresh_test/start_stub.sh)"
#   build/release/test/unittest test/sql/env/aws_secret_refresh_offline.test
#   kill "$AWS_REFRESH_STUB_PID"
#
# Everything is local and deterministic: credentials come from a credential_process
# that mints a new key per invocation, and the stub S3 server rejects keys the test
# has revoked (by writing to $AWS_REFRESH_STUB_STATE/min_valid.txt) with the same
# 400 ExpiredToken document real S3 sends. No AWS endpoint is ever contacted.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${1:-$(mktemp -d /tmp/duckdb_aws_refresh_stub.XXXXXX)}"
PYTHON="${PYTHON:-python3}"

mkdir -p "$STATE_DIR/objects/test-bucket"
printf 'answer\n42\n' > "$STATE_DIR/objects/test-bucket/data.csv"
printf 'answer\n42\n' > "$STATE_DIR/objects/test-bucket/data2.csv"

# The config file routes CHAIN 'process' to our credential process; the static
# profile exercises the config chain with keys that never expire.
cat > "$STATE_DIR/aws_config" <<EOF
[default]
region = eu-west-1
credential_process = $PYTHON -I $SCRIPT_DIR/credential_process.py $STATE_DIR

[profile staticprof]
region = eu-west-1
EOF
cat > "$STATE_DIR/aws_credentials" <<EOF
[staticprof]
aws_access_key_id = refresh_key_999999999
aws_secret_access_key = static_secret
EOF

"$PYTHON" -I "$SCRIPT_DIR/stub_s3_server.py" "$STATE_DIR" > "$STATE_DIR/server.out" 2> "$STATE_DIR/server.err" &
SERVER_PID=$!

PORT=""
for _ in $(seq 1 50); do
    PORT="$(sed -n 's/^LISTENING //p' "$STATE_DIR/server.out" 2>/dev/null | head -n1)"
    [ -n "$PORT" ] && break
    sleep 0.1
done
if [ -z "$PORT" ]; then
    echo "echo 'stub S3 server failed to start; see $STATE_DIR/server.err' >&2; false"
    exit 1
fi

echo "export AWS_REFRESH_STUB_ENDPOINT=127.0.0.1:$PORT"
echo "export AWS_REFRESH_STUB_STATE=$STATE_DIR"
echo "export AWS_REFRESH_STUB_PID=$SERVER_PID"
echo "export AWS_CONFIG_FILE=$STATE_DIR/aws_config"
echo "export AWS_SHARED_CREDENTIALS_FILE=$STATE_DIR/aws_credentials"
