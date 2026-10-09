#!/usr/bin/env bash
# Removes resources created by the companion create_redshift_serverless_test.sh script.
set -euo pipefail

export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"
PREFIX="${PREFIX:-$(id -un)}"
NAMESPACE="$PREFIX-redshift-serverless-$AWS_REGION"
WORKGROUP="$NAMESPACE"
UNASSOCIATED_NAMESPACE="${REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE:-$PREFIX-redshift-unassociated-$AWS_REGION}"
SECURITY_GROUP="$WORKGROUP-client"
MANAGED_BY="duckdb-redshift-serverless-test"
TOTAL_STEPS=4
FORCE=false

usage() {
	cat <<EOF
Usage: $(basename "$0") [--force]

Without --force, this script only lists the Redshift Serverless test resources it would destroy. With --force, it deletes the workgroup, its associated namespace, the unassociated namespace, and the client security group.

Environment:
  PREFIX="username"                 Select resources by prefix (default: local username).
  AWS_REGION="desired_region"       Select the AWS region (default: eu-central-1).
  REDSHIFT_SERVERLESS_UNASSOCIATED_NAMESPACE="name"
                                    Override the namespace created without a workgroup.

Options:
  --force                           Destroy the resources.
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

print_plan() {
	echo "The following Redshift Serverless test resources will be destroyed:"
	echo "  Workgroup: $WORKGROUP"
	echo "  Associated namespace: $NAMESPACE (including its test databases)"
	echo "  Unassociated namespace: $UNASSOCIATED_NAMESPACE"
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

delete_workgroup() {
	step 1 "Delete Redshift Serverless workgroup $WORKGROUP"

	if ! aws redshift-serverless get-workgroup --workgroup-name "$WORKGROUP" >/dev/null 2>&1; then
		echo "Workgroup is already absent"
		return
	fi

	aws redshift-serverless delete-workgroup --workgroup-name "$WORKGROUP" >/dev/null
	echo "Workgroup deletion requested"
	while aws redshift-serverless get-workgroup --workgroup-name "$WORKGROUP" >/dev/null 2>&1; do
		local status
		status=$(aws redshift-serverless get-workgroup --workgroup-name "$WORKGROUP" \
			--query 'workgroup.status' --output text)
		echo "Workgroup status: $status"
		sleep 5
	done
	echo "Workgroup deleted"
}

delete_namespace() {
	local namespace_name=$1

	if ! aws redshift-serverless get-namespace --namespace-name "$namespace_name" >/dev/null 2>&1; then
		echo "Namespace $namespace_name is already absent"
		return
	fi

	aws redshift-serverless delete-namespace --namespace-name "$namespace_name" >/dev/null
	echo "Namespace deletion requested for $namespace_name"
	while aws redshift-serverless get-namespace --namespace-name "$namespace_name" >/dev/null 2>&1; do
		local status
		status=$(aws redshift-serverless get-namespace --namespace-name "$namespace_name" \
			--query 'namespace.status' --output text)
		echo "Namespace $namespace_name status: $status"
		sleep 5
	done
	echo "Namespace $namespace_name deleted"
}

delete_namespaces() {
	step 2 "Delete Redshift Serverless namespaces"

	delete_namespace "$NAMESPACE"
	delete_namespace "$UNASSOCIATED_NAMESPACE"
}

delete_security_group() {
	step 3 "Delete dedicated security group $SECURITY_GROUP"

	local security_group_id
	security_group_id=$(aws ec2 describe-security-groups \
		--filters Name=group-name,Values="$SECURITY_GROUP" Name=tag:ManagedBy,Values="$MANAGED_BY" Name=tag:Workgroup,Values="$WORKGROUP" \
		--query 'SecurityGroups[0].GroupId' --output text)

	if [[ -z "$security_group_id" || "$security_group_id" == "None" ]]; then
		echo "Dedicated security group is already absent"
		return
	fi

	local attempt
	local delete_error
	local max_attempts=24
	for ((attempt = 1; attempt <= max_attempts; attempt++)); do
		if delete_error=$(aws ec2 delete-security-group --group-id "$security_group_id" 2>&1); then
			echo "Deleted security group $security_group_id"
			return
		fi
		if [[ "$delete_error" != *"DependencyViolation"* ]]; then
			echo "$delete_error" >&2
			return 1
		fi
		if [[ $attempt -eq $max_attempts ]]; then
			echo "$delete_error" >&2
			echo "Security group $security_group_id still has dependent objects after two minutes" >&2
			return 1
		fi
		echo "Security group $security_group_id still has a dependent object; retrying in 5 seconds"
		sleep 5
	done
}

print_result() {
	step 4 "Report cleanup result"

	echo
	echo "Redshift Serverless test resources removed successfully."
	echo "Associated namespace: $NAMESPACE"
	echo "Unassociated namespace: $UNASSOCIATED_NAMESPACE"
	echo "Workgroup: $WORKGROUP"
	echo "Security group: $SECURITY_GROUP"
}

main() {
	parse_args "$@"
	if [[ "$FORCE" != true ]]; then
		print_plan
		return
	fi

	delete_workgroup
	delete_namespaces
	delete_security_group
	print_result
}

main "$@"
