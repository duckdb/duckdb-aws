#!/usr/bin/env bash
# duckdb-oidc-test.sh
#
# Sets up an OIDC test harness for duckdb-aws PR #136 (web_identity chain).
# Uses Cognito as the OIDC provider; everything fits within the AWS Free Tier.
#
# Usage:
#   ./duckdb-oidc-test.sh setup     # create resources, mint token, print env
#   ./duckdb-oidc-test.sh token     # mint a fresh token (Cognito IDs last ~1h)
#   ./duckdb-oidc-test.sh verify    # call sts:AssumeRoleWithWebIdentity
#   ./duckdb-oidc-test.sh env       # print export lines (for `eval`)
#   ./duckdb-oidc-test.sh status    # show current state
#   ./duckdb-oidc-test.sh cleanup   # tear down all resources

set -euo pipefail

STATE_FILE="${STATE_FILE:-$HOME/.duckdb-oidc-test.state}"
TOKEN_FILE="${TOKEN_FILE:-/tmp/duckdb-oidc-test-token}"
TRUST_POLICY_FILE="/tmp/duckdb-oidc-test-trust.json"

AWS_REGION="${AWS_REGION:-us-east-1}"
POOL_NAME="${POOL_NAME:-duckdb-irsa-test}"
CLIENT_NAME="${CLIENT_NAME:-duckdb-irsa-test-client}"
USERNAME="${USERNAME:-tester}"
PASSWORD="${PASSWORD:-TestPassword123!}"
ROLE_NAME="${ROLE_NAME:-duckdb-irsa-test-role}"

log()  { printf '\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1"; }

load_state() {
    [[ -f "$STATE_FILE" ]] || fail "no state at $STATE_FILE — run '$0 setup' first"
    # shellcheck source=/dev/null
    source "$STATE_FILE"
}

save_state() {
    umask 077
    cat > "$STATE_FILE" <<EOF
USER_POOL_ID="$USER_POOL_ID"
CLIENT_ID="$CLIENT_ID"
OIDC_PROVIDER_ARN="$OIDC_PROVIDER_ARN"
ROLE_ARN="$ROLE_ARN"
ROLE_NAME="$ROLE_NAME"
AWS_REGION="$AWS_REGION"
ISSUER_HOST="$ISSUER_HOST"
USERNAME="$USERNAME"
PASSWORD="$PASSWORD"
EOF
}

mint_token() {
    local id_token
    id_token=$(aws cognito-idp admin-initiate-auth \
        --region "$AWS_REGION" \
        --user-pool-id "$USER_POOL_ID" \
        --client-id "$CLIENT_ID" \
        --auth-flow ADMIN_USER_PASSWORD_AUTH \
        --auth-parameters "USERNAME=$USERNAME,PASSWORD=$PASSWORD" \
        --query 'AuthenticationResult.IdToken' --output text)

    umask 077
    printf '%s' "$id_token" > "$TOKEN_FILE"
}

cmd_setup() {
    require aws
    require openssl

    if [[ -f "$STATE_FILE" ]]; then
        fail "state file already exists at $STATE_FILE — run '$0 cleanup' first"
    fi

    log "checking AWS credentials"
    aws sts get-caller-identity >/dev/null \
        || fail "AWS CLI not authenticated — run 'aws configure' first"

    ISSUER_HOST="cognito-idp.${AWS_REGION}.amazonaws.com"

    log "creating Cognito user pool ($POOL_NAME)"
    USER_POOL_ID=$(aws cognito-idp create-user-pool \
        --region "$AWS_REGION" \
        --pool-name "$POOL_NAME" \
        --policies '{"PasswordPolicy":{"MinimumLength":8,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":true}}' \
        --query 'UserPool.Id' --output text)
    log "  USER_POOL_ID=$USER_POOL_ID"

    log "creating Cognito app client"
    CLIENT_ID=$(aws cognito-idp create-user-pool-client \
        --region "$AWS_REGION" \
        --user-pool-id "$USER_POOL_ID" \
        --client-name "$CLIENT_NAME" \
        --no-generate-secret \
        --explicit-auth-flows ALLOW_ADMIN_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
        --query 'UserPoolClient.ClientId' --output text)
    log "  CLIENT_ID=$CLIENT_ID"

    log "creating user $USERNAME"
    aws cognito-idp admin-create-user \
        --region "$AWS_REGION" \
        --user-pool-id "$USER_POOL_ID" \
        --username "$USERNAME" \
        --message-action SUPPRESS >/dev/null

    aws cognito-idp admin-set-user-password \
        --region "$AWS_REGION" \
        --user-pool-id "$USER_POOL_ID" \
        --username "$USERNAME" \
        --password "$PASSWORD" \
        --permanent

    log "fetching issuer TLS thumbprint"
    THUMBPRINT=$(
        echo | openssl s_client -servername "$ISSUER_HOST" \
            -showcerts -connect "${ISSUER_HOST}:443" </dev/null 2>/dev/null \
        | openssl x509 -fingerprint -sha1 -noout 2>/dev/null \
        | awk -F'=' '{gsub(/[: \t\r\n]/, "", $2); print tolower($2)}'
    )
    if ! [[ "$THUMBPRINT" =~ ^[0-9a-f]{40}$ ]]; then
        warn "thumbprint extraction produced '$THUMBPRINT' (length ${#THUMBPRINT})"
        warn "falling back to Starfield Class 2 root CA thumbprint"
        warn "(AWS auto-validates Cognito OIDC certs, the value is effectively a placeholder)"
        THUMBPRINT="afe5d244a8d1194230ff479fe2f897bbcd7a8cb4"
    fi
    log "  thumbprint: $THUMBPRINT"

    log "registering IAM OIDC identity provider"
    OIDC_PROVIDER_ARN=$(aws iam create-open-id-connect-provider \
        --url "https://${ISSUER_HOST}/${USER_POOL_ID}" \
        --client-id-list "$CLIENT_ID" \
        --thumbprint-list "$THUMBPRINT" \
        --query 'OpenIDConnectProviderArn' --output text)
    log "  OIDC_PROVIDER_ARN=$OIDC_PROVIDER_ARN"

    log "creating IAM role $ROLE_NAME"
    cat > "$TRUST_POLICY_FILE" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "$OIDC_PROVIDER_ARN" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${ISSUER_HOST}/${USER_POOL_ID}:aud": "$CLIENT_ID"
      }
    }
  }]
}
EOF
    ROLE_ARN=$(aws iam create-role \
        --role-name "$ROLE_NAME" \
        --assume-role-policy-document "file://$TRUST_POLICY_FILE" \
        --query 'Role.Arn' --output text)
    log "  ROLE_ARN=$ROLE_ARN"

    save_state

    log "waiting 10s for IAM consistency"
    sleep 10

    log "minting initial OIDC token"
    mint_token
    log "  token written to $TOKEN_FILE ($(wc -c < "$TOKEN_FILE") bytes, valid ~1h)"

    log "verifying trust chain via sts:AssumeRoleWithWebIdentity"
    if aws sts assume-role-with-web-identity \
        --role-arn "$ROLE_ARN" \
        --role-session-name duckdb-irsa-test \
        --web-identity-token "$(cat "$TOKEN_FILE")" \
        --query 'Credentials.{AccessKeyId:AccessKeyId,Expiration:Expiration}' \
        --output table >/dev/null 2>&1; then
        log "trust chain OK"
    else
        warn "STS verify failed — IAM may still be propagating; rerun '$0 verify' in a moment"
    fi

    echo
    echo "Setup complete. To use these credentials with duckdb:"
    echo
    echo "  eval \"\$($0 env)\""
    echo
    echo "Then run your duckdb-aws test. When done:"
    echo
    echo "  $0 cleanup"
}

cmd_token() {
    require aws
    load_state
    log "minting fresh OIDC token"
    mint_token
    log "  token written to $TOKEN_FILE ($(wc -c < "$TOKEN_FILE") bytes, valid ~1h)"
}

cmd_verify() {
    require aws
    load_state
    [[ -f "$TOKEN_FILE" ]] || fail "no token at $TOKEN_FILE — run '$0 token' first"

    log "calling sts:AssumeRoleWithWebIdentity"
    aws sts assume-role-with-web-identity \
        --role-arn "$ROLE_ARN" \
        --role-session-name duckdb-irsa-test \
        --web-identity-token "$(cat "$TOKEN_FILE")" \
        --query 'Credentials.{AccessKeyId:AccessKeyId,Expiration:Expiration}' \
        --output table
    log "credentials minted successfully"
}

cmd_env() {
    load_state
    [[ -f "$TOKEN_FILE" ]] || fail "no token at $TOKEN_FILE — run '$0 token' first"
    cat <<EOF
export AWS_ROLE_ARN="$ROLE_ARN"
export AWS_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
export AWS_ROLE_SESSION_NAME=duckdb-irsa-test
export AWS_DEFAULT_REGION="$AWS_REGION"
EOF
}

cmd_status() {
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "not set up (no state file at $STATE_FILE)"
        return
    fi
    load_state
    echo "USER_POOL_ID=$USER_POOL_ID"
    echo "CLIENT_ID=$CLIENT_ID"
    echo "OIDC_PROVIDER_ARN=$OIDC_PROVIDER_ARN"
    echo "ROLE_ARN=$ROLE_ARN"
    echo "TOKEN_FILE=$TOKEN_FILE ($([[ -f $TOKEN_FILE ]] && echo present || echo missing))"
}

cmd_cleanup() {
    require aws
    if [[ ! -f "$STATE_FILE" ]]; then
        log "no state at $STATE_FILE — nothing to clean up"
        return 0
    fi
    load_state

    # cleanup is tolerant of partial state (already-deleted resources, etc.)
    set +e
    set +o pipefail

    log "detaching any role policies"
    local attached
    attached=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
        --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
    for arn in $attached; do
        log "  detaching $arn"
        aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$arn"
    done

    log "deleting IAM role $ROLE_NAME"
    aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null

    log "deleting IAM OIDC provider"
    aws iam delete-open-id-connect-provider \
        --open-id-connect-provider-arn "$OIDC_PROVIDER_ARN" 2>/dev/null

    log "deleting Cognito user pool $USER_POOL_ID"
    aws cognito-idp delete-user-pool \
        --region "$AWS_REGION" \
        --user-pool-id "$USER_POOL_ID" 2>/dev/null

    rm -f "$TOKEN_FILE" "$TRUST_POLICY_FILE" "$STATE_FILE"
    log "cleanup complete"
}

case "${1:-}" in
    setup)   cmd_setup ;;
    token)   cmd_token ;;
    verify)  cmd_verify ;;
    env)     cmd_env ;;
    status)  cmd_status ;;
    cleanup) cmd_cleanup ;;
    *)
        cat <<USAGE
duckdb-oidc-test.sh — OIDC test harness for duckdb-aws PR #136

USAGE: $0 <command>

  setup    Create Cognito + IAM OIDC + IAM role, mint token, verify
  token    Mint a fresh OIDC ID token (Cognito tokens expire after ~1h)
  verify   Call sts:AssumeRoleWithWebIdentity to confirm trust chain
  env      Print export lines for AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE
  status   Show current state
  cleanup  Tear down all AWS resources and remove state

ENV (defaults shown):
  AWS_REGION=us-east-1
  POOL_NAME=duckdb-irsa-test
  USERNAME=tester
  PASSWORD=TestPassword123!
  ROLE_NAME=duckdb-irsa-test-role
  TOKEN_FILE=/tmp/duckdb-oidc-test-token
  STATE_FILE=~/.duckdb-oidc-test.state

TYPICAL FLOW:
  $0 setup
  eval "\$($0 env)"
  # ... run duckdb-aws web_identity test ...
  $0 cleanup
USAGE
        exit 1
        ;;
esac
