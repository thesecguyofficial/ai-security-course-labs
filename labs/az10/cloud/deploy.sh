#!/usr/bin/env bash
# AZ10 in one go: the LOCKED-DOWN Foundry estate from the guided build (lesson 10.5), its proof, and its teardown.
#
#   bash deploy.sh up      # build the secure end state (about 10 minutes, most of it Azure)
#   bash deploy.sh test    # prove it: 5 checks, each prints PASS or WAIT or FAIL
#   bash deploy.sh down    # delete everything this script made (do it today). Also works for the Terraform build:
#                          # AZ10_NAME=<your name> bash deploy.sh down
#
# Runs in Azure Cloud Shell (Bash) or any shell with the Azure CLI signed in (az login). One file, no other files
# needed. Your names are saved in ~/.az10.env so test and down find the same estate.
#
# Optional settings, before `up`:
#   export AZ10_NAME=az10-ab1234        # globally unique, lowercase letters, digits, hyphens (default: random)
#   export AZ10_REGION=swedencentral    # one region for everything (default: swedencentral)
#   export BUDGET_EMAIL=you@example.com # adds a US$5 monthly budget alert on the resource group (skipped if unset)
#
# The step-by-step version, with the "before" estate and every finding, is GUIDED-BUILD.md. This script builds only
# the "after" state. Cost: a few US cents (GUIDED-BUILD.md G7). Use a subscription you own, never your employer's.
set -euo pipefail

ENVFILE="$HOME/.az10.env"
FOUNDRY_USER=53ca6127-db72-4b80-b1b0-d745d6d5456d     # Foundry User (by ID: Microsoft renamed the Azure AI roles)
POL_MODELS=aafe3651-cb78-4f68-9f81-e7e41509110f       # Foundry model deployments should only use approved models
POL_KEYS=71ef260a-8f18-47b7-abcb-62d0673d94dc         # Azure AI Services resources should have key access disabled
MODEL=gpt-5-mini; MODEL_VER=2025-08-07

say()  { printf '\n== %s\n' "$*"; }
need() { command -v "$1" >/dev/null || { echo "Needs $1. Azure Cloud Shell has it."; exit 1; }; }
need az; need curl
az account show -o none 2>/dev/null || { echo "Sign in first: az login"; exit 1; }

load() {
  # shellcheck source=/dev/null
  if [ -z "${AZ10_NAME:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi   # Terraform users pass AZ10_NAME
  AZ10_NAME="${AZ10_NAME:-}"; AZ10_REGION="${AZ10_REGION:-swedencentral}"
  [ -n "$AZ10_NAME" ] || { echo "No estate found. Run: bash deploy.sh up"; exit 1; }
  RG="rg-$AZ10_NAME"
}

case "${1:-}" in
  up)
    AZ10_NAME="${AZ10_NAME:-az10-$(od -An -N3 -tx1 /dev/urandom | tr -d " \n")}"
    AZ10_REGION="${AZ10_REGION:-swedencentral}"
    RG="rg-$AZ10_NAME"
    printf 'AZ10_NAME=%s\nAZ10_REGION=%s\n' "$AZ10_NAME" "$AZ10_REGION" > "$ENVFILE"
    echo "Subscription: $(az account show --query name -o tsv)   Name: $AZ10_NAME   Region: $AZ10_REGION"

    say "1/8 Resource group $RG"
    az group create -n "$RG" -l "$AZ10_REGION" -o none
    SCOPE=$(az group show -n "$RG" --query id -o tsv)

    say "2/8 Budget alarm first (US\$5 a month, alerts at 50% actual and 100% forecast)"
    if [ -n "${BUDGET_EMAIL:-}" ]; then
      START=$(date -u +%Y-%m-01)
      az rest --method put -o none \
        --url "https://management.azure.com$SCOPE/providers/Microsoft.Consumption/budgets/az10-budget?api-version=2023-05-01" \
        --body "{\"properties\":{\"category\":\"Cost\",\"amount\":5,\"timeGrain\":\"Monthly\",
          \"timePeriod\":{\"startDate\":\"${START}T00:00:00Z\"},
          \"notifications\":{
            \"actual50\":{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":50,\"thresholdType\":\"Actual\",\"contactEmails\":[\"$BUDGET_EMAIL\"]},
            \"forecast100\":{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":100,\"thresholdType\":\"Forecasted\",\"contactEmails\":[\"$BUDGET_EMAIL\"]}}}}"
      echo "Budget az10-budget created. A budget alerts; it never stops anything."
    else
      echo "Skipped: set BUDGET_EMAIL to add it."
    fi

    say "3/8 Foundry resource $AZ10_NAME (AIServices, S0)"
    az cognitiveservices account create -n "$AZ10_NAME" -g "$RG" -l "$AZ10_REGION" --kind AIServices --sku S0 \
      --custom-domain "$AZ10_NAME" --allow-project-management true --assign-identity --yes -o none
    FID=$(az cognitiveservices account show -n "$AZ10_NAME" -g "$RG" --query id -o tsv)

    say "4/8 Model deployment 'chat' ($MODEL $MODEL_VER), EU data zone if your quota allows, else Global"
    if az cognitiveservices account deployment create -g "$RG" -n "$AZ10_NAME" --deployment-name chat \
         --model-name $MODEL --model-version $MODEL_VER --model-format OpenAI \
         --sku-name DataZoneStandard --sku-capacity 1 -o none 2>/dev/null; then
      echo "Deployed as DataZoneStandard."
    else
      az cognitiveservices account deployment create -g "$RG" -n "$AZ10_NAME" --deployment-name chat \
        --model-name $MODEL --model-version $MODEL_VER --model-format OpenAI \
        --sku-name GlobalStandard --sku-capacity 1 -o none
      az resource tag --ids "$FID" --tags deployment-type-reason="DataZoneStandard quota 0 in this subscription" \
        -i -o none
      echo "No DataZoneStandard quota here, so GlobalStandard; the reason is written as a tag on the resource."
    fi

    say "5/8 App identity id-az10-app with Foundry User on this one resource (no Contributor)"
    az identity create -g "$RG" -n id-az10-app -o none
    APP_PID=$(az identity show -g "$RG" -n id-az10-app --query principalId -o tsv)
    az role assignment create --assignee-object-id "$APP_PID" --assignee-principal-type ServicePrincipal \
      --role $FOUNDRY_USER --scope "$FID" -o none
    ME=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)
    if [ -n "$ME" ]; then   # you need a data role too, for the test
      az role assignment create --assignee-object-id "$ME" --assignee-principal-type User \
        --role $FOUNDRY_USER --scope "$FID" -o none
    fi

    say "6/8 Logs: Log Analytics workspace + diagnostic setting (Audit, RequestResponse, Trace)"
    az monitor log-analytics workspace create -g "$RG" -n "law-$AZ10_NAME" -l "$AZ10_REGION" -o none
    az monitor diagnostic-settings create -n to-law --resource "$FID" --workspace "law-$AZ10_NAME" -o none \
      --logs '[{"category":"Audit","enabled":true},{"category":"RequestResponse","enabled":true},{"category":"Trace","enabled":true}]'

    say "7/8 Guardrails: approved models only (Deny, no publishers), key access must be off (Deny)"
    az policy assignment create --name az10-approved-models --scope "$SCOPE" --policy $POL_MODELS -o none \
      --params "{\"effect\":{\"value\":\"Deny\"},\"allowedPublishers\":{\"value\":[]},
                 \"allowedAssetIds\":{\"value\":[\"azureml://registries/azure-openai/models/$MODEL/\"]}}"
    az policy assignment create --name az10-deny-key-access --scope "$SCOPE" --policy $POL_KEYS -o none \
      --params '{"effect":{"value":"Deny"}}'

    say "8/8 Keys off"
    az resource update --ids "$FID" --set properties.disableLocalAuth=true -o none
    echo "disableLocalAuth = $(az cognitiveservices account show -n "$AZ10_NAME" -g "$RG" --query properties.disableLocalAuth -o tsv)"

    say "Done. Policies take at least 15 minutes, roles up to 5. Then: bash deploy.sh test"
    ;;

  test)
    load
    FID=$(az cognitiveservices account show -n "$AZ10_NAME" -g "$RG" --query id -o tsv)
    EP=$(az cognitiveservices account show -n "$AZ10_NAME" -g "$RG" --query properties.endpoint -o tsv)
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }

    say "T1 You can call the model with your Entra ID token (Foundry User). No key involved."
    TOKEN=$(az account get-access-token --resource https://cognitiveservices.azure.com --query accessToken -o tsv)
    code=000
    for i in 1 2 3 4 5; do
      code=$(curl -s -o /tmp/az10-t1.json -w '%{http_code}' "${EP%/}/openai/v1/chat/completions" \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d '{"model":"chat","messages":[{"role":"user","content":"Reply with OK"}],"max_completion_tokens":1000}')
      echo "try $i: HTTP $code"
      [ "$code" = 200 ] || [ "$code" = 429 ] && break
      sleep 60; TOKEN=$(az account get-access-token --resource https://cognitiveservices.azure.com --query accessToken -o tsv)
    done
    rm -f /tmp/az10-t1.json
    case $code in 200|429) rec PASS "T1 Entra ID call answered (HTTP $code; 429 = capacity 1 is busy, still allowed)";;
                  401|403) rec WAIT "T1 HTTP $code: the role may still be spreading (up to 5 min). Run test again";;
                  *)       rec FAIL "T1 HTTP $code";; esac

    say "T2 A key is refused (keys are off). The key is read into memory only, never printed."
    KEY=$(az cognitiveservices account keys list -n "$AZ10_NAME" -g "$RG" --query key1 -o tsv 2>/dev/null || true)
    if [ -z "$KEY" ]; then
      rec PASS "T2 the key could not even be listed"
    else
      code=$(curl -s -o /dev/null -w '%{http_code}' "${EP%/}/openai/models?api-version=2024-10-21" -H "api-key: $KEY")
      unset KEY
      case $code in 401|403) rec PASS "T2 key refused (HTTP $code)";;
                    200)     rec WAIT "T2 key still accepted: the gateway caches keys for minutes. Run test again";;
                    *)       rec FAIL "T2 HTTP $code";; esac
    fi

    say "T3 An unapproved model (gpt-5-nano) is refused at deployment time"
    if out=$(az cognitiveservices account deployment create -g "$RG" -n "$AZ10_NAME" --deployment-name not-approved \
          --model-name gpt-5-nano --model-version 2025-08-07 --model-format OpenAI \
          --sku-name GlobalStandard --sku-capacity 1 -o none 2>&1); then
      az cognitiveservices account deployment delete -g "$RG" -n "$AZ10_NAME" --deployment-name not-approved -o none
      rec WAIT "T3 it was created (and deleted again): the policy is not active yet. In our run it took hours"
    elif grep -q -i policy <<<"$out"; then
      rec PASS "T3 refused by policy"
    else
      rec FAIL "T3 refused, but not by policy: $(head -c 200 <<<"$out")"
    fi

    say "T4 Nobody can switch keys back on, not even the subscription Owner"
    if out=$(az resource update --ids "$FID" --set properties.disableLocalAuth=false -o none 2>&1); then
      az resource update --ids "$FID" --set properties.disableLocalAuth=true -o none
      rec WAIT "T4 it was allowed (keys switched off again at once): the policy is not active yet"
    elif grep -q -i policy <<<"$out"; then
      rec PASS "T4 refused by policy (az10-deny-key-access)"
    else
      rec FAIL "T4 refused, but not by policy: $(head -c 200 <<<"$out")"
    fi

    say "T5 The trail: the Activity Log has the key listing (T2) and the refusals"
    n=$(az monitor activity-log list -g "$RG" --offset 6h \
          --query "length([?contains(operationName.value, 'listKeys')])" -o tsv 2>/dev/null || echo 0)
    [ "${n:-0}" -gt 0 ] && rec PASS "T5 $n listKeys event(s) in the Activity Log" \
                        || rec WAIT "T5 no listKeys event yet: the Activity Log can lag a few minutes"

    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    echo "WAIT means Azure has not caught up yet (roles up to 5 min, key cache minutes, policy 15 min or more)."
    ;;

  down)
    load
    SCOPE=$(az group show -n "$RG" --query id -o tsv 2>/dev/null || true)
    if [ -n "$SCOPE" ]; then
      say "Deleting the policy assignments, then $RG (takes a few minutes)"
      az policy assignment delete --name az10-approved-models --scope "$SCOPE" -o none 2>/dev/null || true
      az policy assignment delete --name az10-deny-key-access --scope "$SCOPE" -o none 2>/dev/null || true
      az group delete -n "$RG" --yes
    fi
    say "Purging the soft-deleted Foundry resource (frees the name now, not in 48 hours)"
    if az cognitiveservices account list-deleted --query "[?name=='$AZ10_NAME'] | length(@)" -o tsv | grep -q '^[1-9]'; then
      az cognitiveservices account purge -l "$AZ10_REGION" -g "$RG" -n "$AZ10_NAME" -o none || \
        echo "Purge refused for now; it frees itself after 48 hours."
    fi
    rm -f "$ENVFILE"
    echo "Done. Tomorrow: az group show -n $RG should say ResourceGroupNotFound."
    ;;

  *)
    sed -n '2,8p' "$0"; exit 1;;
esac
