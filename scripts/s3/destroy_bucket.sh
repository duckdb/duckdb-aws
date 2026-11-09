#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/fixture.sh"

usage() {
	cat <<EOF
Usage: $(basename "$0") [--force]

Print the cleanup plan, or delete the fixture with --force.
Uses AWS_PROFILE, AWS_REGION, PREFIX, S3_BUCKET_NAME, S3_OBJECT_KEY and S3_ENV_FILE.
Refuses untagged, wrong-owner, wrong-region or versioned buckets and unrelated objects.
EOF
}

main() {
	parse_args "$@"
	validate_configuration
	if [[ "$FORCE" != true ]]; then
		echo "Delete only $FIXTURE_KEY and $OBJECT_KEY, then managed bucket: ${BUCKET:-$PREFIX-duckdb-aws-<account>-$AWS_REGION}"
		echo "Run with --force to modify AWS resources."
		return
	fi
	resolve_identity
	local status
	if bucket_exists; then
		assert_managed_bucket
		assert_only_fixture_objects
	else
		status=$?
		[[ "$status" == 1 ]] || return "$status"
		disable_environment
		echo "Bucket already absent"
		return
	fi
	s3api delete-object --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" --key "$FIXTURE_KEY" >/dev/null
	disable_environment
	s3api delete-object --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID" --key "$OBJECT_KEY" >/dev/null
	s3api delete-bucket --bucket "$BUCKET" --expected-bucket-owner "$AWS_ACCOUNT_ID"
	echo "Deleted managed bucket $BUCKET"
}

main "$@"
