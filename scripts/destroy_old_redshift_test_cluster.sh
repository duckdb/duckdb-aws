#!/usr/bin/env bash
# Removes resources made by the create script before names got a prefix and region. Skips what is already gone.
set -euo pipefail
export AWS_REGION="${AWS_REGION:-eu-central-1}"
CLUSTER=redshift-cluster-1
ROLE="$CLUSTER-copy"

if aws redshift describe-clusters --cluster-identifier "$CLUSTER" >/dev/null 2>&1; then
	aws redshift delete-cluster --cluster-identifier "$CLUSTER" --skip-final-cluster-snapshot >/dev/null
	aws redshift wait cluster-deleted --cluster-identifier "$CLUSTER"
fi
if aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
	aws iam delete-role-policy --role-name "$ROLE" --policy-name tickit-read 2>/dev/null || true
	aws iam delete-role --role-name "$ROLE"
fi
RULE_IDS=($(aws ec2 describe-security-group-rules --filters Name=tag:Name,Values="$CLUSTER" \
	--query 'SecurityGroupRules[].SecurityGroupRuleId' --output text)) || true
[[ ${#RULE_IDS[@]} -eq 0 ]] || aws ec2 revoke-security-group-ingress --group-name default --security-group-rule-ids "${RULE_IDS[@]}" >/dev/null
