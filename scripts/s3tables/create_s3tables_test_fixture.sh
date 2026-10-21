#!/usr/bin/env bash
# Creates the Amazon S3 Tables fixture used by test/sql/s3tables/s3tables.test.
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/fixture.sh"

CREDENTIAL_CHAIN="${S3TABLES_AWS_CREDENTIAL_CHAIN:-env}"
DUCKDB_BIN="${DUCKDB_BIN:-$PROJECT_ROOT/build/release/duckdb}"
TOTAL_STEPS=5
TABLE_ARN=""

usage() {
	cat <<EOF
Usage: $(basename "$0") [--force]

Without --force, this script only lists the Amazon S3 Tables resources it
would create. With --force, it creates or safely reuses the tagged fixture
table bucket, namespace, and table, replaces the table contents with the
deterministic test rows, and writes a non-secret environment file.

Environment:
  PREFIX="username"                       Prefix the table bucket name.
  AWS_REGION="desired_region"             Select an S3 Tables region.
  S3TABLES_TABLE_BUCKET_NAME="name"       Override the complete table bucket name.
  S3TABLES_NAMESPACE="test"               Override the namespace.
  S3TABLES_TABLE="daily_sales"            Override the table name.
  S3TABLES_AWS_CREDENTIAL_CHAIN="env"     DuckDB chain (default: credentials exported by the AWS CLI).
  S3TABLES_ENV_FILE="path"                Override the generated environment file.
  DUCKDB_BIN="path"                       DuckDB executable used to load and verify data.

Options:
  --force                                 Create and populate the resources.
  -h, --help                              Show this help.
EOF
}

validate_credential_chain() {
	if [[ -n "$CREDENTIAL_CHAIN" &&
		! "$CREDENTIAL_CHAIN" =~ ^(config|container|env|instance|process|sso|web_identity)(;(config|container|env|instance|process|sso|web_identity))*$ ]]; then
		echo "S3TABLES_AWS_CREDENTIAL_CHAIN must be a semicolon-separated DuckDB AWS credential chain" >&2
		return 1
	fi
}

validate_duckdb_extensions() {
	if ! "$DUCKDB_BIN" -unsigned -c \
		"LOAD httpfs; LOAD aws; LOAD iceberg; LOAD parquet; LOAD avro; LOAD json;" >/dev/null; then
		echo "DUCKDB_BIN must load the aws, httpfs, iceberg, parquet, avro, and json extensions" >&2
		return 1
	fi
}

print_plan() {
	echo "The following Amazon S3 Tables test fixture will be created or reconciled:"
	echo "  Table bucket: $TABLE_BUCKET_NAME"
	echo "  Namespace: $NAMESPACE"
	echo "  Table: $TABLE_NAME"
	echo "  Rows: 3 deterministic daily-sales rows (existing rows will be replaced)"
	echo "  Environment file: $ENV_FILE"
	echo "  Resource prefix: $PREFIX"
	echo "  AWS region: $AWS_REGION"
	echo
	echo "Only a table bucket and table carrying the exact fixture management tags will be reused."
	echo "Run $(basename "$0") --force to create the fixture."
}

resolve_identity() {
	step 1 "Resolve the AWS account and exact table-bucket ARN"
	resolve_table_bucket_arn
	echo "Fixture table bucket ARN: $TABLE_BUCKET_ARN"
}

create_or_reuse_table_bucket() {
	step 2 "Create or verify the dedicated table bucket"

	local bucket_json
	local lookup_status
	if bucket_json=$(get_table_bucket_json); then
		if ! jq -e --arg arn "$TABLE_BUCKET_ARN" --arg name "$TABLE_BUCKET_NAME" \
			'.arn == $arn and .name == $name and .type == "customer"' >/dev/null <<<"$bucket_json"; then
			echo "The existing table bucket does not match the expected fixture identity" >&2
			return 1
		fi
		if ! assert_managed_tags "$TABLE_BUCKET_ARN" "$TABLE_BUCKET_NAME" "Table bucket"; then
			return 1
		fi
		echo "Using existing managed table bucket $TABLE_BUCKET_NAME"
	else
		lookup_status=$?
		if [[ $lookup_status -ne 1 ]]; then
			return "$lookup_status"
		fi
		aws_s3tables create-table-bucket \
			--name "$TABLE_BUCKET_NAME" \
			--tags "ManagedBy=$MANAGED_BY,FixtureId=$FIXTURE_ID,Prefix=$PREFIX,Region=$AWS_REGION,ResourceName=$TABLE_BUCKET_NAME" \
			>/dev/null
		echo "Created table bucket $TABLE_BUCKET_NAME"
		bucket_json=$(get_table_bucket_json)
		if ! assert_managed_tags "$TABLE_BUCKET_ARN" "$TABLE_BUCKET_NAME" "Table bucket"; then
			return 1
		fi
	fi
}

create_or_reuse_namespace() {
	step 3 "Create or verify namespace $NAMESPACE"

	local namespace_json
	local lookup_status
	if namespace_json=$(get_namespace_json); then
		if ! jq -e --arg namespace "$NAMESPACE" '.namespace == [$namespace]' >/dev/null <<<"$namespace_json"; then
			echo "The existing namespace does not match the expected fixture identity" >&2
			return 1
		fi
		echo "Using existing namespace $NAMESPACE in the managed table bucket"
	else
		lookup_status=$?
		if [[ $lookup_status -ne 1 ]]; then
			return "$lookup_status"
		fi
		aws_s3tables create-namespace --table-bucket-arn "$TABLE_BUCKET_ARN" \
			--namespace "$NAMESPACE" >/dev/null
		echo "Created namespace $NAMESPACE"
	fi
}

create_or_reuse_table() {
	step 4 "Create or verify Iceberg table $NAMESPACE.$TABLE_NAME"

	local table_json
	local lookup_status
	local metadata
	metadata='{"iceberg":{"schema":{"fields":[{"id":1,"name":"sale_date","type":"date","required":true},{"id":2,"name":"product","type":"string","required":true},{"id":3,"name":"quantity","type":"int","required":true}]}}}'

	if table_json=$(get_table_json); then
		TABLE_ARN=$(jq -r '.tableARN' <<<"$table_json")
		if ! jq -e --arg name "$TABLE_NAME" --arg namespace "$NAMESPACE" \
			'.name == $name and .namespace == [$namespace] and .type == "customer" and .format == "ICEBERG"' \
			>/dev/null <<<"$table_json"; then
			echo "The existing table does not match the expected fixture identity" >&2
			return 1
		fi
		if ! assert_managed_tags "$TABLE_ARN" "$TABLE_NAME" "Table"; then
			return 1
		fi
		echo "Using existing managed table $NAMESPACE.$TABLE_NAME"
	else
		lookup_status=$?
		if [[ $lookup_status -ne 1 ]]; then
			return "$lookup_status"
		fi
		table_json=$(aws_s3tables create-table \
			--table-bucket-arn "$TABLE_BUCKET_ARN" \
			--namespace "$NAMESPACE" \
			--name "$TABLE_NAME" \
			--format ICEBERG \
			--metadata "$metadata" \
			--tags "ManagedBy=$MANAGED_BY,FixtureId=$FIXTURE_ID,Prefix=$PREFIX,Region=$AWS_REGION,ResourceName=$TABLE_NAME,TableBucket=$TABLE_BUCKET_NAME,Namespace=$NAMESPACE" \
			--output json)
		TABLE_ARN=$(jq -r '.tableARN' <<<"$table_json")
		echo "Created table $NAMESPACE.$TABLE_NAME"
		if ! assert_managed_tags "$TABLE_ARN" "$TABLE_NAME" "Table"; then
			return 1
		fi
	fi
}

populate_table() {
	echo "Replacing the table contents with the deterministic DuckDB fixture"
	"$DUCKDB_BIN" -unsigned -batch -bail -no-init -c "
		LOAD httpfs;
		LOAD aws;
		LOAD iceberg;
		LOAD parquet;
		LOAD avro;
		LOAD json;
		SET allow_persistent_secrets=false;
		CREATE SECRET s3tables_fixture_credentials (
			TYPE s3,
			PROVIDER credential_chain,
			CHAIN '$CREDENTIAL_CHAIN',
			REGION '$AWS_REGION'
		);
		ATTACH '$TABLE_BUCKET_ARN' AS s3tables_fixture (
			SECRET s3tables_fixture_credentials
		);
		SELECT CASE
			WHEN count(*) = 3
			 AND count(*) FILTER (
				WHERE column_index = 1 AND column_name = 'sale_date'
				  AND data_type = 'DATE' AND NOT is_nullable
			 ) = 1
			 AND count(*) FILTER (
				WHERE column_index = 2 AND column_name = 'product'
				  AND data_type = 'VARCHAR' AND NOT is_nullable
			 ) = 1
			 AND count(*) FILTER (
				WHERE column_index = 3 AND column_name = 'quantity'
				  AND data_type = 'INTEGER' AND NOT is_nullable
			 ) = 1
			THEN true
			ELSE error('Unexpected schema for the managed S3 Tables fixture')
		END
		FROM duckdb_columns()
		WHERE database_name = 's3tables_fixture'
		  AND schema_name = '$NAMESPACE'
		  AND table_name = '$TABLE_NAME';
		DELETE FROM s3tables_fixture.\"$NAMESPACE\".\"$TABLE_NAME\";
		INSERT INTO s3tables_fixture.\"$NAMESPACE\".\"$TABLE_NAME\" VALUES
			(DATE '2020-07-21', 'SHOES', 21),
			(DATE '2020-07-22', 'JACKET', 3),
			(DATE '2020-07-24', 'SOCKS', 87);
		SELECT CASE
			WHEN list((sale_date, product, quantity) ORDER BY sale_date, product, quantity) = [
				(DATE '2020-07-21', 'SHOES', 21),
				(DATE '2020-07-22', 'JACKET', 3),
				(DATE '2020-07-24', 'SOCKS', 87)
			]
			THEN true
			ELSE error('Unexpected rows in the managed S3 Tables fixture')
		END
		FROM s3tables_fixture.\"$NAMESPACE\".\"$TABLE_NAME\";
		DETACH s3tables_fixture;
		DROP SECRET s3tables_fixture_credentials;
	" >/dev/null
	echo "Table contents verified: exactly 3 expected rows"
}

write_environment_file() {
	local environment_directory
	environment_directory=$(dirname -- "$ENV_FILE")
	mkdir -p -- "$environment_directory"

	(umask 077; {
		echo "# Generated by scripts/s3tables/create_s3tables_test_fixture.sh; contains no AWS secrets."
		printf "unset S3TABLES_TEST_AVAILABLE\n"
		printf 'export PREFIX=%q\n' "$PREFIX"
		printf 'export S3TABLES_ENV_FILE=%q\n' "$ENV_FILE"
		printf 'export AWS_REGION=%q\n' "$AWS_REGION"
		printf 'export S3TABLES_TABLE_BUCKET_NAME=%q\n' "$TABLE_BUCKET_NAME"
		printf 'export S3TABLES_NAMESPACE=%q\n' "$NAMESPACE"
		printf 'export S3TABLES_TABLE=%q\n' "$TABLE_NAME"
		printf 'export AWS_S3TABLES_REGION=%q\n' "$AWS_REGION"
		printf 'export AWS_S3TABLES_TABLE_BUCKET_ARN=%q\n' "$TABLE_BUCKET_ARN"
		printf 'export AWS_S3TABLES_NAMESPACE=%q\n' "$NAMESPACE"
		printf 'export AWS_S3TABLES_TABLE=%q\n' "$TABLE_NAME"
		printf 'export S3TABLES_AWS_CREDENTIAL_CHAIN=%q\n' "$CREDENTIAL_CHAIN"
		fixture_write_credentials
		printf "export S3TABLES_TEST_AVAILABLE=1\n"
	} >"$ENV_FILE")
	chmod 600 "$ENV_FILE"
}

print_result() {
	step 5 "Write the guarded SQL-test environment"

	write_environment_file
	echo
	echo "Amazon S3 Tables test fixture is ready."
	echo "Table bucket ARN: $TABLE_BUCKET_ARN"
	echo "Table: $NAMESPACE.$TABLE_NAME"
	echo "Environment file: $ENV_FILE"
	printf 'Run: source %q\n' "$ENV_FILE"
}

main() {
	parse_args "$@"
	validate_configuration
	validate_credential_chain
	if [[ "$FORCE" != true ]]; then
		print_plan
		return
	fi

	fixture_credentials
	validate_tools "$DUCKDB_BIN"
	validate_duckdb_extensions
	resolve_identity
	create_or_reuse_table_bucket
	create_or_reuse_namespace
	create_or_reuse_table
	populate_table
	print_result
}

main "$@"
