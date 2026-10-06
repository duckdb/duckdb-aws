#!/usr/bin/env bash
# Creates the Redshift cluster with TICKIT sample data used by test/sql/redshift/*.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-eu-central-1}"
# PREFIX keeps resource names unique in a shared account.
PREFIX="${PREFIX:-$(id -un)}"
CLUSTER="$PREFIX-redshift-$AWS_DEFAULT_REGION"
ROLE="$CLUSTER-tickit-loader"
SECURITY_GROUP="$CLUSTER-client"
MANAGED_BY="duckdb-redshift-test"
AWS_REDSHIFT_DATABASE="${AWS_REDSHIFT_DATABASE:-dev}"
VPC_ID="${REDSHIFT_VPC_ID:-}"
TOTAL_STEPS=6

step() {
	echo
	echo "[$1/$TOTAL_STEPS] $2"
}

configure_loader_role() {
	step 1 "Configure the IAM role used to load TICKIT data from S3"

	if ROLE_ARN=$(aws iam get-role --role-name "$ROLE" --query Role.Arn --output text 2>/dev/null); then
		echo "Using existing IAM role: $ROLE"
	else
		echo "Creating IAM role: $ROLE"
		ROLE_ARN=$(aws iam create-role --role-name "$ROLE" --query Role.Arn --output text \
			--assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"redshift.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
	fi

	echo "Granting the role read access to s3://redshift-downloads"
	aws iam put-role-policy --role-name "$ROLE" --policy-name tickit-read \
		--policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::redshift-downloads","arn:aws:s3:::redshift-downloads/*"]}]}'
}

find_default_vpc() {
	if [[ -n "$VPC_ID" ]]; then
		return
	fi

	VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
		--query 'Vpcs[0].VpcId' --output text)
	if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
		echo "No default VPC found; set REDSHIFT_VPC_ID to the VPC used by the Redshift subnet group" >&2
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
	local allowed_cidrs
	local cidr

	allowed_cidrs=$(aws ec2 describe-security-groups --group-ids "$security_group_id" \
		--query 'SecurityGroups[0].IpPermissions[?IpProtocol==`tcp` && FromPort==`5439` && ToPort==`5439`].IpRanges[].CidrIp' \
		--output text)
	for cidr in $allowed_cidrs; do
		[[ "$cidr" == "$client_cidr" ]] && return 0
	done
	return 1
}

configure_security_group() {
	step 2 "Create a dedicated security group for Redshift client access"

	find_default_vpc
	SECURITY_GROUP_ID=$(aws ec2 describe-security-groups \
		--filters Name=group-name,Values="$SECURITY_GROUP" Name=vpc-id,Values="$VPC_ID" \
		--query 'SecurityGroups[0].GroupId' --output text)

	if [[ -z "$SECURITY_GROUP_ID" || "$SECURITY_GROUP_ID" == "None" ]]; then
		SECURITY_GROUP_ID=$(aws ec2 create-security-group \
			--group-name "$SECURITY_GROUP" \
			--description "DuckDB Redshift test client access for $CLUSTER" \
			--vpc-id "$VPC_ID" \
			--tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=$SECURITY_GROUP},{Key=ManagedBy,Value=$MANAGED_BY},{Key=Cluster,Value=$CLUSTER}]" \
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

create_cluster() {
	step 3 "Create Redshift cluster $CLUSTER in $AWS_DEFAULT_REGION"

	local cluster_status
	if cluster_status=$(aws redshift describe-clusters --cluster-identifier "$CLUSTER" \
		--query 'Clusters[0].ClusterStatus' --output text 2>/dev/null); then
		echo "Using existing cluster (status: $cluster_status)"
		return
	fi

	aws redshift create-cluster --cluster-identifier "$CLUSTER" --node-type rg.large --cluster-type single-node \
		--db-name "$AWS_REDSHIFT_DATABASE" --master-username awsuser --manage-master-password --publicly-accessible \
		--iam-roles "$ROLE_ARN" --default-iam-role-arn "$ROLE_ARN" \
		--vpc-security-group-ids "$SECURITY_GROUP_ID" >/dev/null
	echo "Cluster creation requested"
}

wait_for_cluster() {
	step 4 "Wait for the Redshift cluster to become available"

	aws redshift wait cluster-available --cluster-identifier "$CLUSTER"
	echo "Cluster is available"
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

wait_for_data_load() {
	local statement_id=$1

	wait_for_statement "$statement_id" "Data load"
	echo "TICKIT schema and data loaded successfully"
}

tickit_tables_exist() {
	local statement_id
	local table_count

	statement_id=$(aws redshift-data execute-statement \
		--cluster-identifier "$CLUSTER" \
		--database "$AWS_REDSHIFT_DATABASE" \
		--db-user awsuser \
		--query Id \
		--output text \
		--sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('users', 'venue', 'category', 'date', 'event', 'listing', 'sales')")
	echo "Submitted TICKIT table check: $statement_id"
	wait_for_statement "$statement_id" "Table check"

	table_count=$(aws redshift-data get-statement-result --id "$statement_id" \
		--query 'Records[0][0].longValue' --output text)
	[[ "$table_count" == "7" ]]
}

load_tickit_data() {
	step 5 "Create the TICKIT schema and load its sample data"

	if tickit_tables_exist; then
		echo "TICKIT tables already exist; skipping data load"
		return
	fi

	local copy_credentials="iam_role default region 'us-east-1'"
	local source="s3://redshift-downloads/tickit"
	local -a statements=(
		"create table if not exists users(userid integer not null distkey sortkey, username char(8), firstname varchar(30), lastname varchar(30), city varchar(30), state char(2), email varchar(100), phone char(14), likesports boolean, liketheatre boolean, likeconcerts boolean, likejazz boolean, likeclassical boolean, likeopera boolean, likerock boolean, likevegas boolean, likebroadway boolean, likemusicals boolean)"
		"create table if not exists venue(venueid smallint not null distkey sortkey, venuename varchar(100), venuecity varchar(30), venuestate char(2), venueseats integer)"
		"create table if not exists category(catid smallint not null distkey sortkey, catgroup varchar(10), catname varchar(10), catdesc varchar(50))"
		"create table if not exists date(dateid smallint not null distkey sortkey, caldate date not null, day character(3) not null, week smallint not null, month character(5) not null, qtr character(5) not null, year smallint not null, holiday boolean default('N'))"
		"create table if not exists event(eventid integer not null distkey, venueid smallint not null, catid smallint not null, dateid smallint not null sortkey, eventname varchar(200), starttime timestamp)"
		"create table if not exists listing(listid integer not null distkey, sellerid integer not null, eventid integer not null, dateid smallint not null sortkey, numtickets smallint not null, priceperticket decimal(8,2), totalprice decimal(8,2), listtime timestamp)"
		"create table if not exists sales(salesid integer not null, listid integer not null distkey, sellerid integer not null, buyerid integer not null, eventid integer not null, dateid smallint not null sortkey, qtysold smallint not null, pricepaid decimal(8,2), commission decimal(8,2), saletime timestamp)"
		"copy users from '$source/allusers_pipe.txt' $copy_credentials delimiter '|'"
		"copy venue from '$source/venue_pipe.txt' $copy_credentials delimiter '|'"
		"copy category from '$source/category_pipe.txt' $copy_credentials delimiter '|'"
		"copy date from '$source/date2008_pipe.txt' $copy_credentials delimiter '|'"
		"copy event from '$source/allevents_pipe.txt' $copy_credentials delimiter '|' timeformat 'YYYY-MM-DD HH:MI:SS'"
		"copy listing from '$source/listings_pipe.txt' $copy_credentials delimiter '|'"
		"copy sales from '$source/sales_tab.txt' $copy_credentials delimiter '\\t' timeformat 'MM/DD/YYYY HH:MI:SS'"
		"grant select on all tables in schema public to public"
	)
	local statement_id
	statement_id=$(aws redshift-data batch-execute-statement \
		--cluster-identifier "$CLUSTER" \
		--database "$AWS_REDSHIFT_DATABASE" \
		--db-user awsuser \
		--query Id \
		--output text \
		--sqls "${statements[@]}")

	echo "Submitted Redshift Data API batch: $statement_id"
	wait_for_data_load "$statement_id"
}

print_result() {
	step 6 "Read the cluster namespace ARN and print the test environment"

	AWS_REDSHIFT_ARN=$(aws redshift describe-clusters --cluster-identifier "$CLUSTER" \
		--query 'Clusters[0].ClusterNamespaceArn' --output text)
	if [[ -z "$AWS_REDSHIFT_ARN" || "$AWS_REDSHIFT_ARN" == "None" ]]; then
		echo "Could not read the namespace ARN for $CLUSTER" >&2
		return 1
	fi

	AWS_REDSHIFT_HOST=$(aws redshift describe-clusters --cluster-identifier "$CLUSTER" \
		--query 'Clusters[0].Endpoint.Address' --output text)
	if [[ -z "$AWS_REDSHIFT_HOST" || "$AWS_REDSHIFT_HOST" == "None" ]]; then
		echo "Could not read the endpoint host for $CLUSTER" >&2
		return 1
	fi

	echo
	echo "Redshift cluster created successfully."
	echo "Cluster identifier: $CLUSTER"
	echo "Security group: $SECURITY_GROUP ($SECURITY_GROUP_ID)"
	echo "Database: $AWS_REDSHIFT_DATABASE"
	printf "export AWS_REDSHIFT_CLUSTER_NAME='%s'\n" "$CLUSTER"
	printf "export AWS_REDSHIFT_ARN='%s'\n" "$AWS_REDSHIFT_ARN"
	printf "export AWS_REDSHIFT_HOST='%s'\n" "$AWS_REDSHIFT_HOST"
	printf "export AWS_REDSHIFT_DATABASE='%s'\n" "$AWS_REDSHIFT_DATABASE"

	local env_file="${REDSHIFT_ENV_FILE:-$PROJECT_ROOT/test/sql/redshift/redshift.env}"
	{
		printf "export AWS_REDSHIFT_CLUSTER_NAME='%s'\n" "$CLUSTER"
		printf "export AWS_REDSHIFT_ARN='%s'\n" "$AWS_REDSHIFT_ARN"
		printf "export AWS_REDSHIFT_HOST='%s'\n" "$AWS_REDSHIFT_HOST"
		printf "export AWS_REDSHIFT_DATABASE='%s'\n" "$AWS_REDSHIFT_DATABASE"
	} > "$env_file"
	echo
	echo "Wrote env vars to $env_file (run: source $env_file)"
}

main() {
	configure_loader_role
	configure_security_group
	create_cluster
	wait_for_cluster
	load_tickit_data
	print_result
}

main "$@"
