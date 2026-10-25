#!/usr/bin/env bash
# aws/run_as_agent.sh <agent> <user>: one agent run for one signed-in user (GUIDED-BUILD.md, step B1).
#   1. signs the user in to Cognito and reads `sub` from the token (the human, from a validated sign-in)
#   2. assumes the agent's own role with SourceIdentity = user-<sub>, for 15 minutes
#   3. as that role, asks AgentCore Identity for a workload access token for the agent's own workload identity
#   4. writes one line to aws/out/app-log.jsonl: what the launcher believed (run id, agent, JWT sub)
# Needs: AWS CLI v2, Python 3, and POOL_CLIENT + PW_LAB + ACCOUNT exported (GUIDED-BUILD.md, A1).
set -euo pipefail
agent="$1"; user="$2"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/out"
jwt=$(aws cognito-idp initiate-auth --client-id "$POOL_CLIENT" --auth-flow USER_PASSWORD_AUTH \
      --auth-parameters USERNAME="$user",PASSWORD="$PW_LAB" --query AuthenticationResult.AccessToken --output text)
read -r sub iss < <(python3 -c 'import base64,json,sys; p=sys.argv[1].split(".")[1]; c=json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))); print(c["sub"], c["iss"])' "$jwt")
run="$agent-run-$(date +%H%M%S)"
creds=$(aws sts assume-role --role-arn "arn:aws:iam::$ACCOUNT:role/tsg-agent-$agent" --role-session-name "$run" \
        --source-identity "user-$sub" --duration-seconds 900 \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
read -r AK SK ST <<<"$creds"
AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$ST" \
  aws bedrock-agentcore get-workload-access-token-for-jwt --workload-name "tsg-$agent" --user-token "$jwt" \
  --query 'length(workloadAccessToken)' --output text | sed 's/^/workload access token received, length /'
printf '{"ts": "%s", "run_id": "%s", "agent": "%s", "jwt_iss": "%s", "jwt_sub": "%s", "source_identity": "user-%s"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run" "$agent" "$iss" "$sub" "$sub" >> "$here/out/app-log.jsonl"
echo "run $run: agent $agent acted for $user (sub $sub)"
