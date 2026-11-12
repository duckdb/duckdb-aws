#!/usr/bin/env bash
# Removes resources created by create_s3tables_test_fixture.sh.
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/fixture.sh"

TOTAL_STEPS=4
TABLE_BUCKET_EXISTS=false

usage() {
	cat <<EOF
Usage: $(basename "$0") [--force]

Without --force, this script only lists the exact Amazon S3 Tables fixture
resources it would destroy. With --force, it verifies fixture management tags
and deletes the managed table, fixture namespace, and managed table bucket in
dependency order. It never deletes other tables or namespaces.

Environment:
  PREFIX="username"                  Select resources by prefix.
  AWS_REGION="desired_region"        Select an S3 Tables region.
  S3TABLES_TABLE_BUCKET_NAME="name"  Override the complete table bucket name.
  S3TABLES_NAMESPACE="test"          Override the namespace.
  S3TABLES_TABLE="daily_sales"       Override the table name.
  S3TABLES_ENV_FILE="path"           Override the generated environment file.

Options:
  --force                            Destroy the managed fixture resources.
  -h, --help                         Show this help.
EOF
}

print_plan() {
	echo "The following Amazon S3 Tables test fixture will be destroyed after tag verification:"
	echo "  Managed table: $NAMESPACE.$TABLE_NAME"
	echo "  Fixture namespace: $NAMESPACE"
	echo "  Managed table bucket: $TABLE_BUCKET_NAME"
	echo "  Environment file disabled after the managed table is absent: $ENV_FILE"
	echo "  Resource prefix: $PREFIX"
	echo "  AWS region: $AWS_REGION"
	echo
	echo "Unrelated tables or namespaces will not be deleted; their presence stops cleanup."
	echo "Run $(basename "$0") --force to destroy the fixture."
}

resolve_identity() {
	step 1 "Resolve and verify the exact managed table bucket"

	local bucket_json
	local lookup_status
	resolve_table_bucket_arn || return 2
	if bucket_json=$(get_table_bucket_json); then
		if ! jq -e --arg arn "$TABLE_BUCKET_ARN" --arg name "$TABLE_BUCKET_NAME" \
			'.arn == $arn and .name == $name and .type == "customer"' >/dev/null <<<"$bucket_json"; then
			echo "The existing table bucket does not match the expected fixture identity" >&2
			return 2
		fi
		if ! assert_managed_tags "$TABLE_BUCKET_ARN" "$TABLE_BUCKET_NAME" "Table bucket"; then
			return 1
		fi
		TABLE_BUCKET_EXISTS=true
		echo "Verified managed table bucket $TABLE_BUCKET_ARN"
	else
		lookup_status=$?
		if [[ $lookup_status -eq 1 ]]; then
			echo "Managed table bucket is already absent"
			return
		fi
		return "$lookup_status"
	fi
}

delete_managed_table() {
	step 2 "Delete the exact managed table"

	local table_json
	local table_arn
	local version_token
	local lookup_status
	if table_json=$(get_table_json); then
		table_arn=$(jq -r '.tableARN' <<<"$table_json")
		version_token=$(jq -r '.versionToken' <<<"$table_json")
		if ! jq -e --arg name "$TABLE_NAME" --arg namespace "$NAMESPACE" \
			'.name == $name and .namespace == [$namespace] and .type == "customer" and .format == "ICEBERG"' \
			>/dev/null <<<"$table_json"; then
			echo "The existing table does not match the expected fixture identity" >&2
			return 1
		fi
		if ! assert_managed_tags "$table_arn" "$TABLE_NAME" "Table"; then
			return 1
		fi
		aws_s3tables delete-table --table-bucket-arn "$TABLE_BUCKET_ARN" \
			--namespace "$NAMESPACE" --name "$TABLE_NAME" --version-token "$version_token"
		echo "Deleted managed table $NAMESPACE.$TABLE_NAME"
	else
		lookup_status=$?
		if [[ $lookup_status -eq 1 ]]; then
			echo "Managed table is already absent"
			disable_environment_file
			return
		fi
		return "$lookup_status"
	fi
	disable_environment_file
}

delete_fixture_namespace() {
	step 3 "Delete the fixture namespace if it contains no other tables"

	local namespace_json
	local tables_json
	local table_count
	local lookup_status
	if namespace_json=$(get_namespace_json); then
		if ! jq -e --arg namespace "$NAMESPACE" '.namespace == [$namespace]' >/dev/null <<<"$namespace_json"; then
			echo "The existing namespace does not match the expected fixture identity" >&2
			return 1
		fi
	else
		lookup_status=$?
		if [[ $lookup_status -eq 1 ]]; then
			echo "Fixture namespace is already absent"
			return
		fi
		return "$lookup_status"
	fi

	tables_json=$(aws_s3tables list-tables --table-bucket-arn "$TABLE_BUCKET_ARN" \
		--namespace "$NAMESPACE" --output json)
	table_count=$(jq '.tables | length' <<<"$tables_json")
	if [[ "$table_count" -ne 0 ]]; then
		echo "Namespace $NAMESPACE still contains $table_count unrelated table(s); refusing to delete it" >&2
		jq -r '.tables[] | "  \(.namespace | join(".")).\(.name)"' <<<"$tables_json" >&2
		return 1
	fi

	aws_s3tables delete-namespace --table-bucket-arn "$TABLE_BUCKET_ARN" --namespace "$NAMESPACE"
	echo "Deleted namespace $NAMESPACE"
}

disable_environment_file() {
	local quoted_arn
	local quoted_namespace
	local quoted_table
	if [[ ! -f "$ENV_FILE" ]]; then
		echo "Environment file is already absent"
		return
	fi
	printf -v quoted_arn "%q" "$TABLE_BUCKET_ARN"
	printf -v quoted_namespace "%q" "$NAMESPACE"
	printf -v quoted_table "%q" "$TABLE_NAME"
	if grep -Fqx "# Generated by scripts/s3tables/create_s3tables_test_fixture.sh; contains no AWS secrets." "$ENV_FILE" &&
		grep -Fqx "export AWS_S3TABLES_TABLE_BUCKET_ARN=$quoted_arn" "$ENV_FILE" &&
		grep -Fqx "export AWS_S3TABLES_NAMESPACE=$quoted_namespace" "$ENV_FILE" &&
		grep -Fqx "export AWS_S3TABLES_TABLE=$quoted_table" "$ENV_FILE"; then
		rm -f -- "$ENV_FILE"
		echo "Removed generated environment file $ENV_FILE; unset S3TABLES_TEST_AVAILABLE in shells that already sourced it"
	else
		echo "Environment file $ENV_FILE was not generated by this fixture; leaving it unchanged" >&2
	fi
}

delete_managed_table_bucket() {
	step 4 "Delete the managed table bucket"

	local namespaces_json
	local namespace_count
	namespaces_json=$(aws_s3tables list-namespaces --table-bucket-arn "$TABLE_BUCKET_ARN" --output json)
	namespace_count=$(jq '.namespaces | length' <<<"$namespaces_json")
	if [[ "$namespace_count" -ne 0 ]]; then
		echo "Table bucket $TABLE_BUCKET_NAME still contains $namespace_count unrelated namespace(s); refusing to delete it" >&2
		jq -r '.namespaces[] | "  \(.namespace | join("."))"' <<<"$namespaces_json" >&2
		return 1
	fi

	aws_s3tables delete-table-bucket --table-bucket-arn "$TABLE_BUCKET_ARN"
	echo
	echo "Amazon S3 Tables test fixture removed successfully."
	echo "Table bucket: $TABLE_BUCKET_NAME"
	echo "Namespace: $NAMESPACE"
	echo "Table: $TABLE_NAME"
}

main() {
	parse_args "$@"
	validate_configuration
	if [[ "$FORCE" != true ]]; then
		print_plan
		return
	fi

	fixture_credentials
	validate_tools
	resolve_identity
	if [[ "$TABLE_BUCKET_EXISTS" != true ]]; then
		disable_environment_file
		echo "Fixture resources are already absent."
		return
	fi
	delete_managed_table
	delete_fixture_namespace
	delete_managed_table_bucket
}

main "$@"
