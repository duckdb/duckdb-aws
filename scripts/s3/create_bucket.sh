#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/fixture.sh"

usage() {
	cat <<EOF
Usage: $(basename "$0") [--force]

Print the setup plan, or create/reuse a private S3 test bucket with --force.
Uploads a three-row fixture and the Dutch railway CSV archive.

Environment:
  AWS_PROFILE, AWS_REGION          AWS profile and region (default: eu-central-1).
  PREFIX                          Resource prefix (default: local username).
  S3_BUCKET_NAME                  Exact bucket name; default includes prefix/account/region.
  S3_DATA_URL, S3_OBJECT_KEY       Railway source URL and destination key.
  S3_CORS_ALLOWED_ORIGINS         Space-separated origins; defaults to local ports and shell.duckdb.org.
  S3_ENV_FILE                     Generated config (default: test/sql/s3/s3.env).
EOF
}

cors_configuration() {
	local origins="${S3_CORS_ALLOWED_ORIGINS:-${S3_CORS_ALLOWED_ORIGIN:-http://127.0.0.1:* http://localhost:*} https://shell.duckdb.org}"
	local origin
	local -a values=() expanded=()
	read -r -a values <<<"$origins"
	((${#values[@]} > 0)) || { echo "At least one CORS origin is required" >&2; return 1; }
	for origin in "${values[@]}"; do
		if [[ ! "$origin" =~ ^https?://[a-zA-Z0-9.-]+(:([0-9]{1,5}|\*))?$ ]]; then
			echo "Invalid CORS origin: expected HTTP(S) host with optional port, no path" >&2
			return 1
		fi
		if [[ "$origin" == *':*' ]]; then expanded+=("${origin%:*}"); fi
		expanded+=("$origin")
	done
	printf '%s\n' "${expanded[@]}" | jq -Rs '{CORSRules: [{ID: "BrowserRead",
		AllowedOrigins: (split("\n") | map(select(length > 0))),
		AllowedMethods: ["GET", "HEAD"],
		AllowedHeaders: ["Authorization", "Content-Type", "Range", "amz-sdk-*", "x-amz-*", "x-host-override"],
		ExposeHeaders: ["Accept-Ranges", "Content-Length", "Content-Range", "ETag", "x-amz-id-2", "x-amz-request-id"],
		MaxAgeSeconds: 3000}]}'
}

create_bucket() {
	local status
	if bucket_exists; then
		assert_managed_bucket
		echo "Reusing managed bucket $BUCKET"
	else
		status=$?
		[[ "$status" == 1 ]] || return "$status"
		local -a args=(--bucket "$BUCKET" --object-ownership BucketOwnerEnforced)
		if [[ "$AWS_REGION" != us-east-1 ]]; then
			args+=(--create-bucket-configuration "LocationConstraint=$AWS_REGION")
		fi
		s3api create-bucket "${args[@]}" >/dev/null
		s3api put-bucket-tagging --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" \
			--tagging "TagSet=[{Key=ManagedBy,Value=$MANAGED_BY},{Key=Project,Value=duckdb-aws}]"
	fi
}

configure_bucket() {
	s3api put-bucket-ownership-controls --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" \
		--ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
	s3api put-public-access-block --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" \
		--public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
	s3api put-bucket-encryption --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" \
		--server-side-encryption-configuration 'Rules=[{ApplyServerSideEncryptionByDefault={SSEAlgorithm=AES256}}]'
	s3api put-bucket-cors --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" --cors-configuration "$CORS"
}

upload_data() {
	local result status
	gzip -n -c "$PROJECT_ROOT/test/sql/s3/data.csv" >"$TEMP_DIR/data.csv.gz"
	s3api put-object --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" --key "$FIXTURE_KEY" \
		--body "$TEMP_DIR/data.csv.gz" --content-type application/gzip --server-side-encryption AES256 >/dev/null
	if result=$(s3api head-object --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" --key "$OBJECT_KEY" 2>&1); then
		echo "Railway object already exists; leaving it unchanged"
		return
	else
		status=$?
		if [[ "$result" != *'(404)'* && "$result" != *'(NoSuchKey)'* && "$result" != *'(NotFound)'* ]]; then
			echo "$result" >&2
			return "$status"
		fi
	fi
	# Download completely before uploading so a failed download cannot publish a truncated object.
	curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' "$DATA_URL" -o "$TEMP_DIR/railway.csv.gz"
	gzip -t "$TEMP_DIR/railway.csv.gz"
	s3api put-object --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" --key "$OBJECT_KEY" \
		--body "$TEMP_DIR/railway.csv.gz" --content-type application/gzip --server-side-encryption AES256 >/dev/null
}

main() {
	parse_args "$@"
	validate_configuration
	command -v jq >/dev/null || { echo "jq is required" >&2; return 1; }
	CORS=$(cors_configuration)
	if [[ "$FORCE" != true ]]; then
		echo "Create/reuse private S3 bucket: ${BUCKET:-$PREFIX-duckdb-aws-<account>-$AWS_REGION}"
		echo "Upload: $FIXTURE_KEY and $OBJECT_KEY from $DATA_URL"
		echo "CORS: $CORS"
		echo "Write non-secret test config: $ENV_FILE"
		echo "Run with --force to modify AWS resources."
		return
	fi
	command -v curl >/dev/null
	command -v gzip >/dev/null
	resolve_identity
	create_bucket
	configure_bucket
	TEMP_DIR=$(mktemp -d)
	trap 'rm -rf -- "$TEMP_DIR"' EXIT
	upload_data
	write_environment
	echo "Ready: s3://$BUCKET/$FIXTURE_KEY"
	echo "Railway example: s3://$BUCKET/$OBJECT_KEY"
	echo "Run: source $ENV_FILE"
}

main "$@"
