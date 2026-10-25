#!/usr/bin/env bash
# Runs ON the jump VM via `az vm run-command invoke` (cloud.sh fills in the three __PLACEHOLDERS__).
# No internet needed: DNS goes to Azure DNS inside the VNet, the token comes from the VM's own metadata endpoint.
NAME="__NAME__"; CLIENT_ID="__CLIENT_ID__"; DEP="__DEPLOYMENT__"
for h in "$NAME.openai.azure.com" "$NAME.cognitiveservices.azure.com" "$NAME.services.ai.azure.com"; do
  echo "$h -> $(getent hosts "$h" | awk '{print $1}')   (expect 10.20.2.x: the private endpoint)"
done
TOKEN=""
for aud in "https://ai.azure.com" "https://cognitiveservices.azure.com"; do
  TOKEN=$(curl -s -H Metadata:true \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$aud&client_id=$CLIENT_ID" \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
  [ -n "$TOKEN" ] && { echo "token for audience $aud: obtained (not printed)"; break; }
done
code=$(curl -s -o /tmp/probe.json -w "%{http_code}" "https://$NAME.openai.azure.com/openai/v1/responses" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"model\":\"$DEP\",\"input\":\"Reply with OK\",\"max_output_tokens\":1000}")
echo "POST /openai/v1/responses from inside the VNet -> HTTP $code (expect 200)"
head -c 300 /tmp/probe.json; echo
