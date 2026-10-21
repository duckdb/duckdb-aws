#!/usr/bin/env bash

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$PROJECT_ROOT/scripts/test_aws_credentials.sh"

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"
PREFIX="${PREFIX:-$(id -un)}"
TABLE_BUCKET_NAME="${S3TABLES_TABLE_BUCKET_NAME:-$PREFIX-duckdb-s3tables-test-$AWS_REGION}"
NAMESPACE="${S3TABLES_NAMESPACE:-test}"
TABLE_NAME="${S3TABLES_TABLE:-daily_sales}"
ENV_FILE="${S3TABLES_ENV_FILE:-$PROJECT_ROOT/test/sql/s3tables/s3tables.env}"
MANAGED_BY="duckdb-aws-s3tables-test"
FIXTURE_ID="s3tables-sql-fixture-v1"
FORCE=false
TABLE_BUCKET_ARN=""

parse_args() {
	while (($#)); do
		case "$1" in
			--force)
				FORCE=true
				;;
			-h | --help)
				usage
				exit 0
				;;
			*)
				echo "Unknown argument: $1" >&2
				usage >&2
				exit 2
				;;
		esac
		shift
	done
}

validate_configuration() {
	if [[ ! "$PREFIX" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
		echo "PREFIX must start with a lowercase letter or digit and contain only lowercase letters, digits, and hyphens" >&2
		return 1
	fi
	if [[ ! "$AWS_REGION" =~ ^[a-z0-9-]+$ ]]; then
		echo "AWS_REGION must contain only lowercase letters, digits, and hyphens" >&2
		return 1
	fi
	if [[ ! "$TABLE_BUCKET_NAME" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]]; then
		echo "S3TABLES_TABLE_BUCKET_NAME must be 3-63 lowercase letters, digits, or hyphens and start/end with a letter or digit" >&2
		return 1
	fi
	case "$TABLE_BUCKET_NAME" in
		xn--*|sthree-*|amzn-s3-demo-*|aws*|*-s3alias|*--ol-s3|*--x-s3|*--table-s3)
			echo "S3TABLES_TABLE_BUCKET_NAME uses a reserved prefix or suffix" >&2; return 1 ;;
	esac
	if [[ ! "$NAMESPACE" =~ ^[a-z0-9][a-z0-9_]{0,254}$ || "$NAMESPACE" == aws* ]]; then
		echo "S3TABLES_NAMESPACE must be 1-255 lowercase letters, digits or underscores, start with a letter or digit and not start with aws" >&2
		return 1
	fi
	if [[ ! "$TABLE_NAME" =~ ^[a-z0-9][a-z0-9_]{0,254}$ ]]; then
		echo "S3TABLES_TABLE must be 1-255 lowercase letters, digits or underscores and start with a letter or digit" >&2
		return 1
	fi
}

command_exists() {
	local command_name=$1
	if [[ "$command_name" == */* ]]; then
		[[ -x "$command_name" ]]
	else
		command -v "$command_name" >/dev/null 2>&1
	fi
}

validate_tools() {
	local command_name
	for command_name in aws jq "$@"; do
		if ! command_exists "$command_name"; then
			echo "Required command not found or not executable: $command_name" >&2
			return 1
		fi
	done

	if ! aws s3tables help >/dev/null 2>&1; then
		echo "The installed AWS CLI does not provide the s3tables commands; install a current AWS CLI v2" >&2
		return 1
	fi
}

step() {
	echo
	echo "[$1/$TOTAL_STEPS] $2"
}

aws_s3tables() {
	aws --region "$AWS_REGION" --no-cli-pager s3tables "$@"
}

is_not_found_error() {
	local message=$1
	[[ "$message" == *"NotFoundException"* || "$message" == *"ResourceNotFoundException"* ]]
}

get_table_bucket_json() {
	local result
	if result=$(aws_s3tables get-table-bucket --table-bucket-arn "$TABLE_BUCKET_ARN" --output json 2>&1); then
		printf '%s\n' "$result"
	elif is_not_found_error "$result"; then
		return 1
	else
		echo "$result" >&2
		return 2
	fi
}

get_namespace_json() {
	local result
	if result=$(aws_s3tables get-namespace --table-bucket-arn "$TABLE_BUCKET_ARN" \
		--namespace "$NAMESPACE" --output json 2>&1); then
		printf '%s\n' "$result"
	elif is_not_found_error "$result"; then
		return 1
	else
		echo "$result" >&2
		return 2
	fi
}

get_table_json() {
	local result
	if result=$(aws_s3tables get-table --table-bucket-arn "$TABLE_BUCKET_ARN" \
		--namespace "$NAMESPACE" --name "$TABLE_NAME" --output json 2>&1); then
		printf '%s\n' "$result"
	elif is_not_found_error "$result"; then
		return 1
	else
		echo "$result" >&2
		return 2
	fi
}

assert_managed_tags() {
	local resource_arn=$1
	local resource_name=$2
	local resource_kind=$3
	local tags_json
	local tag_filter

	tag_filter='.tags.ManagedBy == $managed_by
		and .tags.FixtureId == $fixture_id
		and .tags.Prefix == $prefix
		and .tags.Region == $region
		and .tags.ResourceName == $resource_name'
	if [[ "$resource_kind" == "Table" ]]; then
		tag_filter="$tag_filter
			and .tags.TableBucket == \$table_bucket
			and .tags.Namespace == \$namespace"
	fi

	tags_json=$(aws_s3tables list-tags-for-resource --resource-arn "$resource_arn" --output json) || return
	if ! jq -e \
		--arg managed_by "$MANAGED_BY" \
		--arg fixture_id "$FIXTURE_ID" \
		--arg prefix "$PREFIX" \
		--arg region "$AWS_REGION" \
		--arg resource_name "$resource_name" \
		--arg table_bucket "$TABLE_BUCKET_NAME" \
		--arg namespace "$NAMESPACE" \
		"$tag_filter" \
		>/dev/null <<<"$tags_json"; then
		echo "$resource_kind $resource_arn is not managed by this exact fixture; refusing to modify it" >&2
		return 1
	fi
}

resolve_table_bucket_arn() {
	local caller_identity
	local caller_arn
	local account_id
	local partition
	caller_identity=$(aws --region "$AWS_REGION" sts get-caller-identity --output json) || return
	caller_arn=$(jq -r '.Arn' <<<"$caller_identity") || return
	account_id=$(jq -r '.Account' <<<"$caller_identity") || return
	partition="${caller_arn#arn:}"
	partition="${partition%%:*}"
	if [[ ! "$account_id" =~ ^[0-9]{12}$ || ! "$partition" =~ ^aws[a-z0-9-]*$ ]]; then
		echo "Could not derive a valid AWS account and partition from sts:GetCallerIdentity" >&2
		return 1
	fi
	TABLE_BUCKET_ARN="arn:$partition:s3tables:$AWS_REGION:$account_id:bucket/$TABLE_BUCKET_NAME"
}
