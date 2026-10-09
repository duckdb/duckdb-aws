#!/usr/bin/env bash
# Creates a Redshift Serverless namespace and workgroup with a minimal test fixture.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"
PREFIX="${PREFIX:-$(id -un)}"
NAMESPACE="$PREFIX-redshift-serverless-$AWS_REGION"
WORKGROUP="$NAMESPACE"
UNASSOCIATED_NAMESPACE="${REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE:-$PREFIX-redshift-unassociated-$AWS_REGION}"
UNASSOCIATED_DATABASE="${REDSHIFT_SERVERLESS_UNASSOCIATED_DATABASE:-duckdb_unassociated_db}"
SECURITY_GROUP="$WORKGROUP-client"
MANAGED_BY="duckdb-redshift-serverless-test"
FIRST_DATABASE="${FIRST_DATABASE:-duckdb_first_db}"
SECOND_DATABASE="${SECOND_DATABASE:-duckdb_second_db}"
FIXTURE_TABLE="public.duckdb_database_fixture"
DATABASE_ALIAS="${REDSHIFT_DATABASE_ALIAS:-redshift_serverless_db}"
BASE_CAPACITY="${REDSHIFT_SERVERLESS_BASE_CAPACITY:-8}"
MAX_CAPACITY="${REDSHIFT_SERVERLESS_MAX_CAPACITY:-8}"
ENV_FILE="${REDSHIFT_SERVERLESS_ENV_FILE:-$PROJECT_ROOT/test/sql/redshift/serverless/redshift-serverless.env}"
TOTAL_STEPS=6
SUBNET_IDS=()
DATA_API_ARGS=(--workgroup-name "$WORKGROUP" --database "$FIRST_DATABASE")
FORCE=false

configure_aws_environment() {
	local aws_directory="${HOME:+$HOME/.aws}"
	local configured_profile="${AWS_PROFILE:-${AWS_DEFAULT_PROFILE:-}}"
	local profiles

	if [[ -z "$aws_directory" && (-z "${AWS_CONFIG_FILE:-}" || -z "${AWS_SHARED_CREDENTIALS_FILE:-}") ]]; then
		echo "HOME is not set; set AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE explicitly" >&2
		return 1
	fi

	if ! command -v aws >/dev/null 2>&1; then
		echo "The AWS CLI is required to detect configured profiles" >&2
		return 1
	fi

	export AWS_CONFIG_FILE="${AWS_CONFIG_FILE:-$aws_directory/config}"
	export AWS_SHARED_CREDENTIALS_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$aws_directory/credentials}"

	if [[ ! -r "$AWS_CONFIG_FILE" && ! -r "$AWS_SHARED_CREDENTIALS_FILE" ]]; then
		echo "No readable AWS config files found" >&2
		echo "Checked AWS_CONFIG_FILE=$AWS_CONFIG_FILE" >&2
		echo "Checked AWS_SHARED_CREDENTIALS_FILE=$AWS_SHARED_CREDENTIALS_FILE" >&2
		return 1
	fi

	if ! profiles=$(aws configure list-profiles) || [[ -z "$profiles" ]]; then
		echo "Could not read AWS profiles from $AWS_CONFIG_FILE and $AWS_SHARED_CREDENTIALS_FILE" >&2
		return 1
	fi

	if [[ -z "$configured_profile" ]] && grep -Fxq default <<<"$profiles"; then
		configured_profile=default
	elif [[ -z "$configured_profile" && "$profiles" != *$'\n'* ]]; then
		configured_profile="$profiles"
	fi

	if [[ -z "$configured_profile" ]]; then
		echo "Multiple AWS profiles found and none is named default; set AWS_PROFILE explicitly" >&2
		echo "Available profiles: ${profiles//$'\n'/ }" >&2
		return 1
	fi

	if ! grep -Fxq -- "$configured_profile" <<<"$profiles"; then
		echo "AWS profile '$configured_profile' was not found in $AWS_CONFIG_FILE or $AWS_SHARED_CREDENTIALS_FILE" >&2
		return 1
	fi

	export AWS_PROFILE="$configured_profile"
}

usage() {
	cat <<EOF
Usage: $(basename "$0") [--force]

Without --force, this script only lists the Redshift Serverless test resources it would create. With --force, it creates an associated namespace and workgroup, an unassociated namespace, a client security group, test databases, fixtures, and an environment file.

Environment:
  PREFIX="username"                 Prefix resource names (default: local username).
  AWS_REGION="desired_region"       Select the AWS region (default: eu-central-1).
  AWS_CONFIG_FILE="path"            AWS config file (default: ~/.aws/config).
  AWS_SHARED_CREDENTIALS_FILE="path"
                                    AWS credentials file (default: ~/.aws/credentials).
  AWS_PROFILE="profile_name"        AWS profile. Defaults to the default profile, or the only profile found.
  REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE="name"
                                    Override the namespace created without a workgroup.
  REDSHIFT_SERVERLESS_UNASSOCIATED_DATABASE="database"
                                    Override its initial database name.

Options:
  --force                           Create the resources.
  -h, --help                        Show this help.
EOF
}

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
	if [[ "$UNASSOCIATED_NAMESPACE" == "$NAMESPACE" ]]; then
		echo "REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE must differ from the associated namespace" >&2
		return 1
	fi
	if [[ ! "$SECOND_DATABASE" =~ ^[a-z_][a-z0-9_]*$ ]]; then
		echo "SECOND_DATABASE must contain only lowercase letters, digits, and underscores" >&2
		return 1
	fi
	if [[ "$SECOND_DATABASE" == "$FIRST_DATABASE" ]]; then
		echo "SECOND_DATABASE must differ from FIRST_DATABASE" >&2
		return 1
	fi
}

print_plan() {
	echo "The following Redshift Serverless test resources will be created:"
	echo "  Associated namespace: $NAMESPACE"
	echo "  Associated workgroup: $WORKGROUP"
	echo "  Unassociated namespace: $UNASSOCIATED_NAMESPACE"
	echo "  Security group: $SECURITY_GROUP"
	echo "  First database: $FIRST_DATABASE"
	echo "  Second database: $SECOND_DATABASE"
	echo "  Fixture table: $FIXTURE_TABLE in both databases"
	echo "  Environment file: $ENV_FILE"
	echo "  Resource prefix: $PREFIX"
	echo "  AWS region: $AWS_REGION"
	echo "  AWS config file: $AWS_CONFIG_FILE"
	echo "  AWS credentials file: $AWS_SHARED_CREDENTIALS_FILE"
	echo "  AWS profile: $AWS_PROFILE"
	echo
	echo "Run $(basename "$0") --force to create them."
}

step() {
	echo
	echo "[$1/$TOTAL_STEPS] $2"
}

find_vpc() {
	if [[ -n "${REDSHIFT_VPC_ID:-}" ]]; then
		VPC_ID="$REDSHIFT_VPC_ID"
		return
	fi

	VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
		--query 'Vpcs[0].VpcId' --output text)
	if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
		echo "No default VPC found; set REDSHIFT_VPC_ID and REDSHIFT_SUBNET_IDS" >&2
		return 1
	fi
}

select_subnets() {
	step 1 "Select Redshift Serverless subnets in three Availability Zones"

	find_vpc
	if [[ -n "${REDSHIFT_SUBNET_IDS:-}" ]]; then
		read -r -a SUBNET_IDS <<< "$REDSHIFT_SUBNET_IDS"
	else
		local subnet_id availability_zone
		local availability_zones=" "
		while read -r subnet_id availability_zone; do
			if [[ "$availability_zones" != *" $availability_zone "* ]]; then
				SUBNET_IDS+=("$subnet_id")
				availability_zones+="$availability_zone "
			fi
			[[ ${#SUBNET_IDS[@]} -eq 3 ]] && break
		done < <(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC_ID" \
			--query 'sort_by(Subnets, &AvailabilityZone)[].[SubnetId,AvailabilityZone]' --output text)
	fi

	validate_subnets
	echo "Using VPC $VPC_ID and subnets: ${SUBNET_IDS[*]}"
}

validate_subnets() {
	if [[ ${#SUBNET_IDS[@]} -lt 3 ]]; then
		echo "Redshift Serverless requires subnets in three distinct Availability Zones; set REDSHIFT_SUBNET_IDS" >&2
		return 1
	fi

	local subnet_id availability_zone subnet_vpc
	local described_subnet_count=0
	local availability_zone_count=0
	local availability_zones=" "
	while read -r subnet_id availability_zone subnet_vpc; do
		described_subnet_count=$((described_subnet_count + 1))
		if [[ "$subnet_vpc" != "$VPC_ID" ]]; then
			echo "Subnet $subnet_id belongs to $subnet_vpc, not $VPC_ID" >&2
			return 1
		fi
		if [[ "$availability_zones" != *" $availability_zone "* ]]; then
			availability_zones+="$availability_zone "
			availability_zone_count=$((availability_zone_count + 1))
		fi
	done < <(aws ec2 describe-subnets --subnet-ids "${SUBNET_IDS[@]}" \
		--query 'Subnets[].[SubnetId,AvailabilityZone,VpcId]' --output text)

	if [[ $described_subnet_count -ne ${#SUBNET_IDS[@]} || $availability_zone_count -lt 3 ]]; then
		echo "REDSHIFT_SUBNET_IDS must contain existing subnets in three distinct Availability Zones" >&2
		return 1
	fi
}

is_managed_security_group() {
	local security_group_id=$1
	local managed_group_id

	managed_group_id=$(aws ec2 describe-tags \
		--filters Name=resource-id,Values="$security_group_id" Name=key,Values=ManagedBy Name=value,Values="$MANAGED_BY" \
		--query 'Tags[0].ResourceId' --output text)
	[[ "$managed_group_id" == "$security_group_id" ]]
}

has_client_ingress() {
	local security_group_id=$1
	local client_cidr=$2
	local cidr

	for cidr in $(aws ec2 describe-security-groups --group-ids "$security_group_id" \
		--query 'SecurityGroups[0].IpPermissions[?IpProtocol==`tcp` && FromPort==`5439` && ToPort==`5439`].IpRanges[].CidrIp' \
		--output text); do
		[[ "$cidr" == "$client_cidr" ]] && return 0
	done
	return 1
}

configure_security_group() {
	step 2 "Create a dedicated security group for Serverless client access"

	SECURITY_GROUP_ID=$(aws ec2 describe-security-groups \
		--filters Name=group-name,Values="$SECURITY_GROUP" Name=vpc-id,Values="$VPC_ID" \
		--query 'SecurityGroups[0].GroupId' --output text)

	if [[ -z "$SECURITY_GROUP_ID" || "$SECURITY_GROUP_ID" == "None" ]]; then
		SECURITY_GROUP_ID=$(aws ec2 create-security-group \
			--group-name "$SECURITY_GROUP" \
			--description "DuckDB Redshift Serverless test client access for $WORKGROUP" \
			--vpc-id "$VPC_ID" \
			--tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=$SECURITY_GROUP},{Key=ManagedBy,Value=$MANAGED_BY},{Key=Workgroup,Value=$WORKGROUP}]" \
			--query GroupId --output text)
		echo "Created security group $SECURITY_GROUP_ID in $VPC_ID"
	elif is_managed_security_group "$SECURITY_GROUP_ID"; then
		echo "Using existing dedicated security group $SECURITY_GROUP_ID"
	else
		echo "Security group $SECURITY_GROUP already exists in $VPC_ID but is not managed by this script" >&2
		return 1
	fi

	local client_cidr
	client_cidr="$(curl -fsS https://checkip.amazonaws.com)/32"
	if has_client_ingress "$SECURITY_GROUP_ID" "$client_cidr"; then
		echo "Ingress rule for $client_cidr on port 5439 already exists"
		return
	fi

	aws ec2 authorize-security-group-ingress --group-id "$SECURITY_GROUP_ID" \
		--protocol tcp --port 5439 --cidr "$client_cidr" >/dev/null
	echo "Authorized $client_cidr to connect on port 5439"
}

serverless_status() {
	local resource=$1
	local name=$2
	aws redshift-serverless "get-$resource" "--$resource-name" "$name" \
		--query "$resource.status" --output text
}

wait_until_available() {
	local resource=$1
	local name=$2
	local status

	while true; do
		status=$(serverless_status "$resource" "$name")
		case "$status" in
		AVAILABLE)
			echo "$resource is available"
			return
			;;
		CREATING | MODIFYING)
			echo "$resource status: $status"
			sleep 5
			;;
		*)
			echo "$resource entered unexpected status: $status" >&2
			return 1
			;;
		esac
	done
}

create_namespace() {
	local namespace_name=$1
	local database_name=$2
	local fixture_role=$3

	local status
	if status=$(serverless_status namespace "$namespace_name" 2>/dev/null); then
		local existing_database
		existing_database=$(aws redshift-serverless get-namespace --namespace-name "$namespace_name" \
			--query 'namespace.dbName' --output text)
		if [[ "$existing_database" != "$database_name" ]]; then
			echo "Existing namespace $namespace_name uses first database '$existing_database', expected '$database_name'." >&2
			echo "Destroy and recreate it, or configure the expected database as '$existing_database'." >&2
			return 1
		fi
		echo "Using existing namespace $namespace_name (status: $status)"
		return
	fi

	local -a tags=(
		"key=ManagedBy,value=$MANAGED_BY"
		"key=FixtureRole,value=$fixture_role"
	)
	if [[ "$fixture_role" == associated ]]; then
		tags+=("key=Workgroup,value=$WORKGROUP")
	fi
	aws redshift-serverless create-namespace \
		--namespace-name "$namespace_name" \
		--db-name "$database_name" \
		--tags "${tags[@]}" >/dev/null
	echo "Namespace creation requested for $namespace_name"
}

create_namespaces() {
	step 3 "Create associated and unassociated Redshift Serverless namespaces"

	create_namespace "$NAMESPACE" "$FIRST_DATABASE" associated
	create_namespace "$UNASSOCIATED_NAMESPACE" "$UNASSOCIATED_DATABASE" unassociated
}

create_workgroup() {
	step 4 "Create Redshift Serverless workgroup $WORKGROUP"

	local status
	if status=$(serverless_status workgroup "$WORKGROUP" 2>/dev/null); then
		echo "Using existing workgroup (status: $status)"
		return
	fi

	local -a args=(
		--workgroup-name "$WORKGROUP"
		--namespace-name "$NAMESPACE"
		--publicly-accessible
		--security-group-ids "$SECURITY_GROUP_ID"
		--subnet-ids "${SUBNET_IDS[@]}"
		--base-capacity "$BASE_CAPACITY"
		--max-capacity "$MAX_CAPACITY"
		--tags key=ManagedBy,value="$MANAGED_BY" key=Namespace,value="$NAMESPACE"
	)
	aws redshift-serverless create-workgroup "${args[@]}" >/dev/null
	echo "Workgroup creation requested"
}

validate_unassociated_namespace() {
	local associated_workgroups
	associated_workgroups=$(aws redshift-serverless list-workgroups \
		--query "workgroups[?namespaceName=='$UNASSOCIATED_NAMESPACE'].workgroupName" --output text)
	if [[ -n "$associated_workgroups" && "$associated_workgroups" != "None" ]]; then
		echo "Namespace $UNASSOCIATED_NAMESPACE must remain unassociated, but it is used by: $associated_workgroups" >&2
		echo "Remove that workgroup or choose another REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE." >&2
		return 1
	fi
}

wait_for_statement() {
	local statement_id=$1
	local description=$2
	local status

	while true; do
		status=$(aws redshift-data describe-statement --id "$statement_id" --query Status --output text)
		case "$status" in
		FINISHED)
			return
			;;
		FAILED | ABORTED)
			aws redshift-data describe-statement --id "$statement_id" --query '[Status, Error]' --output text >&2
			return 1
			;;
		*)
			echo "$description status: $status"
			sleep 5
			;;
		esac
	done
}

create_database_fixture() {
	local database=$1
	local first_value=$2
	local second_value=$3
	local -a statements=(
		"create table if not exists $FIXTURE_TABLE(id integer not null, test_value varchar(64) not null)"
		"delete from $FIXTURE_TABLE"
		"insert into $FIXTURE_TABLE values (1, '$first_value'), (2, '$second_value')"
		"grant select on table $FIXTURE_TABLE to public"
	)
	local statement_id
	statement_id=$(aws redshift-data batch-execute-statement --workgroup-name "$WORKGROUP" --database "$database" \
		--query Id --output text --sqls "${statements[@]}")

	echo "Submitted test fixture batch for $database: $statement_id"
	wait_for_statement "$statement_id" "Test fixture in $database"
}

create_second_database() {
	local existing_database
	existing_database=$(aws redshift-data list-databases "${DATA_API_ARGS[@]}" \
		--query "Databases[?@=='$SECOND_DATABASE'] | [0]" --output text)
	if [[ "$existing_database" == "$SECOND_DATABASE" ]]; then
		echo "Using existing second database $SECOND_DATABASE"
		return
	fi

	local statement_id
	statement_id=$(aws redshift-data execute-statement "${DATA_API_ARGS[@]}" \
		--query Id --output text --sql "create database $SECOND_DATABASE")
	echo "Submitted second database creation: $statement_id"
	wait_for_statement "$statement_id" "Second database creation"
}

create_test_fixture() {
	step 5 "Wait for the namespaces and workgroup, then create the test databases"

	wait_until_available namespace "$NAMESPACE"
	wait_until_available namespace "$UNASSOCIATED_NAMESPACE"
	wait_until_available workgroup "$WORKGROUP"
	validate_unassociated_namespace

	create_second_database
	create_database_fixture "$FIRST_DATABASE" "redshift-serverless-first-db" "duckdb-first-db"
	create_database_fixture "$SECOND_DATABASE" "redshift-serverless-second-db" "duckdb-second-db"
	echo "Test fixtures created successfully"
}

print_env() {
	printf "export AWS_REGION='%s'\n" "$AWS_REGION"
	printf "export AWS_CONFIG_FILE='%s'\n" "$AWS_CONFIG_FILE"
	printf "export AWS_SHARED_CREDENTIALS_FILE='%s'\n" "$AWS_SHARED_CREDENTIALS_FILE"
	printf "export AWS_PROFILE='%s'\n" "$AWS_PROFILE"
	printf "export ACCOUNT_ID='%s'\n" "$ACCOUNT_ID"
	printf "export NAMESPACE_ID='%s'\n" "$NAMESPACE_ID"
	printf "export WORKGROUP_ID='%s'\n" "$WORKGROUP_ID"
	printf "export UNASSOCIATED_NAMESPACE_ID='%s'\n" "$UNASSOCIATED_NAMESPACE_ID"
	printf "export AWS_REDSHIFT_SERVERLESS_NAMESPACE_ARN='%s'\n" "$AWS_REDSHIFT_SERVERLESS_NAMESPACE_ARN"
	printf "export AWS_REDSHIFT_SERVERLESS_WORKGROUP_ARN='%s'\n" "$AWS_REDSHIFT_SERVERLESS_WORKGROUP_ARN"
	printf "export AWS_REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE_ARN='%s'\n" \
		"$AWS_REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE_ARN"
	printf "export FIRST_DATABASE='%s'\n" "$FIRST_DATABASE"
	printf "export SECOND_DATABASE='%s'\n" "$SECOND_DATABASE"
}

print_result() {
	step 6 "Read the Serverless ARNs and print the test environment"

	local namespace_info workgroup_info unassociated_namespace_info
	ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
	namespace_info=$(aws redshift-serverless get-namespace --namespace-name "$NAMESPACE" \
		--query '[namespace.namespaceId, namespace.namespaceArn]' --output text)
	read -r NAMESPACE_ID AWS_REDSHIFT_SERVERLESS_NAMESPACE_ARN <<< "$namespace_info"
	workgroup_info=$(aws redshift-serverless get-workgroup --workgroup-name "$WORKGROUP" \
		--query '[workgroup.workgroupId, workgroup.workgroupArn]' --output text)
	read -r WORKGROUP_ID AWS_REDSHIFT_SERVERLESS_WORKGROUP_ARN <<< "$workgroup_info"
	unassociated_namespace_info=$(aws redshift-serverless get-namespace --namespace-name "$UNASSOCIATED_NAMESPACE" \
		--query '[namespace.namespaceId, namespace.namespaceArn]' --output text)
	read -r UNASSOCIATED_NAMESPACE_ID AWS_REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE_ARN \
		<<< "$unassociated_namespace_info"
	if [[ -z "$ACCOUNT_ID" || "$ACCOUNT_ID" == "None" ]]; then
		echo "Could not read the AWS account ID" >&2
		return 1
	fi
	if [[ -z "$NAMESPACE_ID" || "$NAMESPACE_ID" == "None" ]]; then
		echo "Could not read the namespace ID for $NAMESPACE" >&2
		return 1
	fi
	if [[ -z "$WORKGROUP_ID" || "$WORKGROUP_ID" == "None" ]]; then
		echo "Could not read the workgroup ID for $WORKGROUP" >&2
		return 1
	fi
	if [[ -z "$UNASSOCIATED_NAMESPACE_ID" || "$UNASSOCIATED_NAMESPACE_ID" == "None" ]]; then
		echo "Could not read the namespace ID for $UNASSOCIATED_NAMESPACE" >&2
		return 1
	fi
	if [[ -z "$AWS_REDSHIFT_SERVERLESS_NAMESPACE_ARN" || "$AWS_REDSHIFT_SERVERLESS_NAMESPACE_ARN" == "None" ]]; then
		echo "Could not read the namespace ARN for $NAMESPACE" >&2
		return 1
	fi
	if [[ -z "$AWS_REDSHIFT_SERVERLESS_WORKGROUP_ARN" || "$AWS_REDSHIFT_SERVERLESS_WORKGROUP_ARN" == "None" ]]; then
		echo "Could not read the workgroup ARN for $WORKGROUP" >&2
		return 1
	fi
	if [[ -z "$AWS_REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE_ARN" ||
		"$AWS_REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE_ARN" == "None" ]]; then
		echo "Could not read the namespace ARN for $UNASSOCIATED_NAMESPACE" >&2
		return 1
	fi

	echo
	echo "Redshift Serverless test environment created successfully."
	echo "AWS account: $ACCOUNT_ID"
	echo "Associated namespace: $NAMESPACE ($NAMESPACE_ID)"
	echo "Associated workgroup: $WORKGROUP ($WORKGROUP_ID)"
	echo "Unassociated namespace: $UNASSOCIATED_NAMESPACE ($UNASSOCIATED_NAMESPACE_ID)"
	echo "Security group: $SECURITY_GROUP ($SECURITY_GROUP_ID)"
	echo "First database: $FIRST_DATABASE"
	echo "Second database: $SECOND_DATABASE"
	print_env
	printf "ATTACH '%s' AS %s;\n" "$AWS_REDSHIFT_SERVERLESS_NAMESPACE_ARN" "$DATABASE_ALIAS"

	print_env > "$ENV_FILE"
	echo
	echo "Wrote env vars to $ENV_FILE (run: source $ENV_FILE)"
}

main() {
	parse_args "$@"
	configure_aws_environment
	validate_configuration
	if [[ "$FORCE" != true ]]; then
		print_plan
		return
	fi

	select_subnets
	configure_security_group
	create_namespaces
	create_workgroup
	create_test_fixture
	print_result
}

main "$@"
