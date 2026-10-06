#!/usr/bin/env bash
# Removes the Redshift cluster and supporting resources created by create_redshift_test_cluster.sh.
set -euo pipefail

export AWS_REGION="${AWS_REGION:-eu-central-1}"
# PREFIX keeps resource names unique in a shared account.
PREFIX="${PREFIX:-$(id -un)}"
CLUSTER="$PREFIX-redshift-$AWS_REGION"
ROLE="$CLUSTER-tickit-loader"
SECURITY_GROUP="$CLUSTER-client"
MANAGED_BY="duckdb-redshift-test"
TOTAL_STEPS=4
FORCE=false

usage() {
	cat <<EOF
Usage: $(basename "$0") [--force]

Without --force, this script only lists the Redshift test resources it would destroy. With --force, it permanently deletes the cluster without creating a final snapshot and removes its supporting IAM role and security group.

Environment:
  PREFIX="resource_prefix"         Select resources with this name prefix (default: local username).
  AWS_REGION="desired_region"      Select resources in a specific AWS region (default: eu-central-1).

Options:
  --force                          Destroy the resources.
  -h, --help                       Show this help.
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

print_plan() {
	echo "The following Redshift test resources will be destroyed:"
	echo "  Redshift cluster: $CLUSTER (without creating a final snapshot)"
	echo "  IAM loader role: $ROLE (including inline policy tickit-read)"
	echo "  Security group: $SECURITY_GROUP"
	echo "  Resource prefix: $PREFIX"
	echo "  AWS region: $AWS_REGION"
	echo
	echo "Run $(basename "$0") --force to destroy them."
}

step() {
	echo
	echo "[$1/$TOTAL_STEPS] $2"
}

delete_cluster() {
	step 1 "Delete Redshift cluster $CLUSTER"

	if ! aws redshift describe-clusters --cluster-identifier "$CLUSTER" >/dev/null 2>&1; then
		echo "Cluster is already absent"
		return
	fi

	aws redshift delete-cluster --cluster-identifier "$CLUSTER" --skip-final-cluster-snapshot >/dev/null
	echo "Cluster deletion requested; waiting for it to finish"
	aws redshift wait cluster-deleted --cluster-identifier "$CLUSTER"
	echo "Cluster deleted"
}

delete_loader_role() {
	step 2 "Delete IAM loader role $ROLE"

	if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
		echo "IAM role is already absent"
		return
	fi

	if aws iam get-role-policy --role-name "$ROLE" --policy-name tickit-read >/dev/null 2>&1; then
		aws iam delete-role-policy --role-name "$ROLE" --policy-name tickit-read
		echo "Deleted inline policy tickit-read"
	else
		echo "Inline policy tickit-read is already absent"
	fi

	aws iam delete-role --role-name "$ROLE"
	echo "IAM role deleted"
}

delete_security_group() {
	step 3 "Delete dedicated security group $SECURITY_GROUP"

	local security_group_id
	security_group_id=$(aws ec2 describe-security-groups \
		--filters Name=group-name,Values="$SECURITY_GROUP" Name=tag:ManagedBy,Values="$MANAGED_BY" Name=tag:Cluster,Values="$CLUSTER" \
		--query 'SecurityGroups[0].GroupId' --output text)

	if [[ -z "$security_group_id" || "$security_group_id" == "None" ]]; then
		echo "Dedicated security group is already absent"
		return
	fi

	aws ec2 delete-security-group --group-id "$security_group_id"
	echo "Deleted security group $security_group_id"
}

print_result() {
	step 4 "Report cleanup result"

	echo
	echo "Redshift test resources removed successfully."
	echo "Cluster identifier: $CLUSTER"
	echo "IAM role: $ROLE"
	echo "Security group: $SECURITY_GROUP"
}

main() {
	parse_args "$@"
	if [[ "$FORCE" != true ]]; then
		print_plan
		return
	fi

	delete_cluster
	delete_loader_role
	delete_security_group
	print_result
}

main "$@"
