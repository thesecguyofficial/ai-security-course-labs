#!/usr/bin/env bash
# AZ10 Azure twin (OPTIONAL). Needs the Azure CLI (az), Bicep (az bicep install) and YOUR OWN subscription.
# Usage:  ./twin.sh up | key-test | policy-test | lock | wait-401 | activity | down
# Expected cost: $0 (no model calls, no hourly resources). Read README Step 8 before running.
set -euo pipefail
: "${AZ10_NAME:?set AZ10_NAME, e.g. export AZ10_NAME=az10-twin-ab1234 (globally unique)}"
RG="${AZ10_RG:-rg-az10-twin}"
LOC="${AZ10_LOCATION:-swedencentral}"
SUB="$(az account show --query id -o tsv)"
SCOPE="/subscriptions/$SUB/resourceGroups/$RG"
ENDPOINT="https://$AZ10_NAME.openai.azure.com"
APPROVED_DEF="aafe3651-cb78-4f68-9f81-e7e41509110f"   # Foundry model deployments should only use approved models
NOKEYS_DEF="71ef260a-8f18-47b7-abcb-62d0673d94dc"     # Azure AI Services resources should have key access disabled
cd "$(dirname "$0")"

case "${1:-}" in
  up)
    az group create -n "$RG" -l "$LOC" -o none
    az deployment group create -g "$RG" -f main.bicep -p name="$AZ10_NAME" disableLocalAuth=false -o none
    if [ -n "${AZ10_EMAIL:-}" ]; then
      az deployment group create -g "$RG" -f budget.bicep -p email="$AZ10_EMAIL" startDate="$(date -u +%Y-%m-01)" -o none
    fi
    az policy assignment create --name az10-approved-models --scope "$SCOPE" --policy "$APPROVED_DEF" \
      --params @approved-models.params.json -o none
    az policy assignment create --name az10-audit-key-access --scope "$SCOPE" --policy "$NOKEYS_DEF" \
      --params '{"effect":{"value":"Audit"}}' -o none
    echo "Up. Wait at least 15 minutes before policy-test (new policy assignments are not instant)."
    ;;
  key-test)   # a free data-plane call (lists models, no tokens) with the resource KEY; keeps the key like a thief would
    az cognitiveservices account keys list -n "$AZ10_NAME" -g "$RG" --query key1 -o tsv > .twin-key
    chmod 600 .twin-key; KEY="$(cat .twin-key)"
    curl -s -o /dev/null -w "GET /openai/models with the key -> HTTP %{http_code}\n" \
      "$ENDPOINT/openai/models?api-version=2024-10-21" -H "api-key: $KEY"
    ;;
  policy-test)
    echo "1) An UNAPPROVED model (expect: refused by policy). Change the model if it isn't offered in your region:"
    az cognitiveservices account deployment create -g "$RG" -n "$AZ10_NAME" --deployment-name not-approved \
      --model-name "${AZ10_BLOCKED_MODEL:-gpt-4.1-nano}" --model-version "${AZ10_BLOCKED_VERSION:-2025-04-14}" \
      --model-format OpenAI --sku-name GlobalStandard --sku-capacity 1 -o none \
      && { echo "   NOT refused: the policy assignment isn't active yet. Deleting it; wait and run policy-test again.";
           az cognitiveservices account deployment delete -g "$RG" -n "$AZ10_NAME" --deployment-name not-approved; } \
      || echo "   refused (expected)"
    echo "2) The APPROVED model (expect: created; no calls are made, so no tokens are billed):"
    az cognitiveservices account deployment create -g "$RG" -n "$AZ10_NAME" --deployment-name approved \
      --model-name gpt-4.1-mini --model-version 2025-04-14 --model-format OpenAI --sku-name GlobalStandard --sku-capacity 1 -o none
    az cognitiveservices account deployment delete -g "$RG" -n "$AZ10_NAME" --deployment-name approved
    ;;
  lock)       # the fix: Microsoft Entra ID only
    az deployment group create -g "$RG" -f main.bicep -p name="$AZ10_NAME" disableLocalAuth=true -o none
    az resource show --ids "$SCOPE/providers/Microsoft.CognitiveServices/accounts/$AZ10_NAME" --query properties.disableLocalAuth
    ;;
  wait-401)   # the OLD key keeps working until the gateway cache refreshes: minutes, up to several hours
    KEY="$(cat .twin-key)"
    for i in $(seq 1 30); do
      code=$(curl -s -o /dev/null -w "%{http_code}" "$ENDPOINT/openai/models?api-version=2024-10-21" -H "api-key: $KEY")
      echo "$(date -u +%H:%M:%S) old key -> HTTP $code"; [ "$code" = "401" ] && exit 0; sleep 60
    done
    echo "Still not 401 after 30 minutes. That's within Microsoft's documented delay: run wait-401 again later."
    ;;
  activity)   # what the control plane recorded (free, 90 days)
    az monitor activity-log list -g "$RG" --offset 6h \
      --query "[].{time:eventTimestamp, op:operationName.value, status:status.value, caller:caller}" -o table
    ;;
  down)
    az policy assignment delete --name az10-approved-models --scope "$SCOPE" || true
    az policy assignment delete --name az10-audit-key-access --scope "$SCOPE" || true
    az consumption budget delete --budget-name az10-twin-budget --resource-group "$RG" 2>/dev/null || true
    az group delete -n "$RG" --yes
    rm -f .twin-key
    echo "Deleted. The Foundry name stays reserved for 48 hours unless you purge it (README Step 8)."
    ;;
  *) echo "usage: $0 up | key-test | policy-test | lock | wait-401 | activity | down"; exit 1 ;;
esac
