#!/usr/bin/env bash
# AZ11 cloud path (OPTIONAL): the hardened TSG Helpdesk build in YOUR OWN subscription.
# Needs: Azure CLI (az login), Terraform 1.6+ or OpenTofu (set TF=tofu), Python 3.11+.
# Usage: ./cloud.sh cost | up | policy | probe-outside | probe-inside | logs | evidence | down
# Read README Step 8 first. Not run by the course team (no Azure subscription in the build): treat output as yours to verify.
set -euo pipefail
cd "$(dirname "$0")"
TF="${TF:-terraform}"
: "${AZ11_NAME:?set AZ11_NAME, e.g. export AZ11_NAME=az11-ab1234 (globally unique, 3-21 lowercase characters)}"
RG="rg-$AZ11_NAME"
DIR="../terraform"
tfout() { "$TF" -chdir="$DIR" output -raw "$1"; }

case "${1:-}" in
  cost)
    cat <<'TXT'
What this build bills while it exists (look each one up for your region in the Azure pricing calculator):
  - 1 private endpoint (per hour, plus a small per-GB charge for data through it)
  - 1 small Linux VM (Standard_B1s by default) and its Standard_LRS OS disk (per hour)
  - Log Analytics ingestion (per GB; this lab writes a few MB) and Key Vault key operations (per 10,000)
  - model tokens: probe-inside sends ONE tiny request (a few dozen tokens)
  - 3 private DNS zones (billed per zone per month, so a few hours costs a fraction of that)
No charge for Azure Policy on Azure resources. The Foundry resource has no hourly charge here: the deployment is
pay-per-token. Plan for a 2-hour session, then run ./cloud.sh down. Set a budget alert first (lab AZ10, budget.bicep).
TXT
    ;;
  up)
    : "${MY_IP:?set MY_IP to the public IPv4 address of your laptop (only it may create the key in Key Vault)}"
    "$TF" -chdir="$DIR" init -input=false
    "$TF" -chdir="$DIR" plan -input=false -out=tfplan -var "name=$AZ11_NAME" -var "my_ip=$MY_IP"
    "$TF" -chdir="$DIR" show -json tfplan > ../cloud-plan.json
    echo; echo "=== the same checker, on YOUR plan, before anything exists ==="
    (cd .. && python3 checker.py --plan cloud-plan.json)
    read -r -p "Apply this plan in subscription $(az account show --query name -o tsv)? Type yes: " ok
    [ "$ok" = "yes" ] || { echo "Not applied."; exit 1; }
    "$TF" -chdir="$DIR" apply -input=false tfplan
    echo "If apply failed with 403 on the key or on CMK, RBAC was still propagating: run ./cloud.sh up again."
    ;;
  policy)   # the guardrails from fixes/policy-assignments.json, including YOUR challenge-1 policy
    SCOPE="$(az group show -n "$RG" --query id -o tsv)"
    python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["properties"]["policyRule"]))' \
      ../fixes/policies/deny-global-deployments.json > .rule.json
    az policy definition create --name "contoso-az11-deployment-types" --mode All --rules .rule.json \
      --display-name "Contoso: Foundry deployments must use an approved deployment type" -o none
    az policy assignment create --name az11-deployment-types --scope "$SCOPE" --policy contoso-az11-deployment-types -o none
    az policy assignment create --name az11-network --scope "$SCOPE" --policy 037eea7a-bd0a-46c5-9a66-03aea78705d3 \
      --params '{"effect":{"value":"Deny"}}' -o none
    az policy assignment create --name az11-keys --scope "$SCOPE" --policy 71ef260a-8f18-47b7-abcb-62d0673d94dc \
      --params '{"effect":{"value":"Deny"}}' -o none
    az policy assignment create --name az11-diag --scope "$SCOPE" --policy 1b4d1c4e-934c-4703-944c-27c82c06bebb -o none
    rm -f .rule.json
    echo "Assigned. Wait at least 15 minutes, then try: az cognitiveservices account deployment create -g $RG -n $AZ11_NAME \\"
    echo "  --deployment-name test-global --model-name gpt-4.1-mini --model-version 2025-04-14 --model-format OpenAI \\"
    echo "  --sku-name GlobalStandard --sku-capacity 1     # expect: refused by policy"
    ;;
  probe-outside)   # from your laptop: public DNS answer, and the network refuses before identity matters
    for h in $("$TF" -chdir="$DIR" output -json hostnames | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)))'); do
      echo "$h -> $(python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "$h")"
    done
    TOKEN="$(az account get-access-token --scope https://ai.azure.com/.default --query accessToken -o tsv)"
    code=$(curl -s -o .probe.json -w "%{http_code}" "https://$AZ11_NAME.openai.azure.com/openai/v1/responses" \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d "{\"model\":\"$(tfout deployment_name)\",\"input\":\"Reply with OK\",\"max_output_tokens\":16}")
    echo "POST /openai/v1/responses from your laptop -> HTTP $code (expect a refusal: public network access is Disabled)"
    head -c 400 .probe.json; echo; rm -f .probe.json
    ;;
  probe-inside)    # from the VM in snet-jump: private DNS answers and one tiny model call with the VM's identity
    CLIENT_ID="$(tfout jump_identity_client_id)"; DEP="$(tfout deployment_name)"
    sed -e "s/__NAME__/$AZ11_NAME/g" -e "s/__CLIENT_ID__/$CLIENT_ID/g" -e "s/__DEPLOYMENT__/$DEP/g" probe-inside.sh > .probe-filled.sh
    az vm run-command invoke -g "$RG" -n "$(tfout jump_vm_name)" --command-id RunShellScript --scripts @.probe-filled.sh -o json \
      | python3 -c 'import json,sys; [print(v.get("message", "")) for v in json.load(sys.stdin).get("value", [])]'
    rm -f .probe-filled.sh
    ;;
  logs)            # resource logs can take several minutes to arrive after probe-inside (the CLI may offer to install its log-analytics extension)
    az monitor log-analytics query -w "$(tfout log_analytics_workspace_id)" --analytics-query \
      "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.COGNITIVESERVICES' | summarize count() by Category, OperationName" -o table
    ;;
  evidence)        # the settings an auditor asks for, read back from Azure
    az cognitiveservices account show -n "$AZ11_NAME" -g "$RG" --query "{publicNetworkAccess:properties.publicNetworkAccess, \
disableLocalAuth:properties.disableLocalAuth, keySource:properties.encryption.keySource, \
keyVaultUri:properties.encryption.keyVaultProperties.keyVaultUri}" -o table
    az cognitiveservices account deployment list -n "$AZ11_NAME" -g "$RG" --query "[].{name:name, type:sku.name}" -o table
    az monitor diagnostic-settings list --resource "$(az cognitiveservices account show -n "$AZ11_NAME" -g "$RG" --query id -o tsv)" \
      --query "[].{name:name, logs:logs[?enabled].category}" -o json
    az keyvault show -n "$(tfout key_vault_name)" --query "{purgeProtection:properties.enablePurgeProtection, \
softDeleteDays:properties.softDeleteRetentionInDays, rbac:properties.enableRbacAuthorization}" -o table
    ;;
  down)
    for a in az11-deployment-types az11-network az11-keys az11-diag; do
      az policy assignment delete --name "$a" --scope "$(az group show -n "$RG" --query id -o tsv 2>/dev/null || echo /)" 2>/dev/null || true
    done
    az policy definition delete --name contoso-az11-deployment-types 2>/dev/null || true
    "$TF" -chdir="$DIR" destroy -input=false -auto-approve -var "name=$AZ11_NAME" -var "my_ip=${MY_IP:-203.0.113.10}"
    rm -f ../cloud-plan.json "$DIR/tfplan"
    echo "Done. The Key Vault kv-$AZ11_NAME stays soft-deleted for 7 days (purge protection), and its name can't be reused until then."
    echo "Check: az keyvault list-deleted -o table ; and Cost Management tomorrow."
    ;;
  *) echo "usage: $0 cost | up | policy | probe-outside | probe-inside | logs | evidence | down"; exit 2 ;;
esac
