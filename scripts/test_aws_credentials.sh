#!/usr/bin/env bash

fixture_credentials() {
	local profile="${AWS_PROFILE:-${AWS_DEFAULT_PROFILE:-}}"
	local profiles credentials
	command -v aws >/dev/null || { echo "AWS CLI v2 is required" >&2; return 1; }
	command -v jq >/dev/null || { echo "jq is required" >&2; return 1; }
	export AWS_PAGER=""
	export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"

	if [[ -z "$profile" && -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
		fixture_validate_credentials
		return $?
	fi
	if [[ -z "$profile" ]]; then
		profiles=$(aws configure list-profiles) || return 1
		if grep -Fxq default <<<"$profiles"; then
			profile=default
		elif [[ -n "$profiles" && "$profiles" != *$'\n'* ]]; then
			profile="$profiles"
		else
			echo "Set AWS_PROFILE to an authenticated profile, or export AWS credentials" >&2
			return 1
		fi
	fi
	export AWS_PROFILE="$profile"
	# An explicit profile must not silently reuse expired environment credentials.
	unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CREDENTIAL_EXPIRATION
	credentials=$(aws configure export-credentials --profile "$profile" --format process) || return 1
	if ! jq -e 'all([.AccessKeyId, .SecretAccessKey, (.SessionToken // "") ][];
		type == "string" and (test("[\\r\\n]") | not))' >/dev/null <<<"$credentials"; then
		echo "AWS CLI returned invalid credentials or credentials containing line breaks" >&2
		return 1
	fi
	AWS_ACCESS_KEY_ID=$(jq -er '.AccessKeyId | strings | select(length > 0)' <<<"$credentials") || return 1
	AWS_SECRET_ACCESS_KEY=$(jq -er '.SecretAccessKey | strings | select(length > 0)' <<<"$credentials") || return 1
	AWS_SESSION_TOKEN=$(jq -r '.SessionToken // ""' <<<"$credentials") || return 1
	AWS_CREDENTIAL_EXPIRATION=$(jq -r '.Expiration // ""' <<<"$credentials") || return 1
	export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CREDENTIAL_EXPIRATION
	fixture_validate_credentials
}

fixture_validate_credentials() {
	local value
	for value in "${AWS_ACCESS_KEY_ID:-}" "${AWS_SECRET_ACCESS_KEY:-}" "${AWS_SESSION_TOKEN:-}"; do
		if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
			echo "AWS credentials contain a line break; refresh without copying terminal-wrapped values" >&2
			return 1
		fi
	done
}

fixture_write_credentials() {
	local name
	for name in AWS_PROFILE AWS_DEFAULT_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE; do
		if [[ -n "${!name:-}" ]]; then
			printf 'export %s=%q\n' "$name" "${!name}"
		else
			printf 'unset %s\n' "$name"
		fi
	done
	printf 'source %q || return 1\n' "$PROJECT_ROOT/scripts/test_aws_credentials.sh"
	printf 'fixture_credentials || return 1\n'
}
