#!/usr/bin/env bash
# AZ16 in one go: the logged, Defender-watched Foundry model from lesson 16.6, its proof, and its teardown.
#
#   bash deploy.sh up      # build it: Foundry resource (keys off) + model, Log Analytics + diagnostic logs, your role,
#                          #   Defender for AI services with prompt evidence, alert export, Activity log export
#   bash deploy.sh test    # prove it: 5 checks, each prints PASS, WAIT or FAIL
#   bash deploy.sh down    # Defender for AI services back to Free, exports off, everything deleted (do it today)
#
# Runs in Azure Cloud Shell (Bash). It downloads the course labs repo (public, read-only) into ~/tsg-labs. Your names
# are saved in ~/.az16.env.
#
# Optional before `up`:
#   export AZ16_NAME=az16-ab1234       # 3 to 20 lowercase letters, digits, hyphens; globally unique (default: random)
#   export AZ16_REGION=eastus          # default eastus (our run)
#
# Defender for AI services is a SUBSCRIPTION-wide plan: `up` turns it on and `down` turns it back to Free. If your
# subscription already uses it, don't run `down` as is. Defender bills by tokens scanned (check its pricing page; new
# plans usually start with a free trial). The model costs a few US cents. Use a subscription you own, never your
# employer's.
set -euo pipefail

ENVFILE="$HOME/.az16.env"
REPO="$HOME/tsg-labs"

say() { printf '\n== %s\n' "$*"; }
for t in az python3 git curl; do command -v $t >/dev/null || { echo "Needs $t (Azure Cloud Shell has it)."; exit 1; }; done
az account show -o none 2>/dev/null || { echo "Sign in first: az login"; exit 1; }

repo() {
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/az16"
}
load() {
  # shellcheck source=/dev/null
  if [ -z "${AZ16_NAME:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  [ -n "${AZ16_NAME:-}" ] || { echo "No build found. Run: bash deploy.sh up"; exit 1; }
  export AZ16_NAME AZ16_REGION="${AZ16_REGION:-eastus}" RG="rg-$AZ16_NAME"
  SUB=$(az account show --query id -o tsv)
}
cloud() { bash "$LAB/cloud/cloud.sh" "$@"; }
law_id() { az monitor log-analytics workspace show -g "$RG" -n "law-$AZ16_NAME" --query "$1" -o tsv; }

case "${1:-}" in
  up)
    repo
    export AZ16_NAME="${AZ16_NAME:-az16-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')}"
    export AZ16_REGION="${AZ16_REGION:-eastus}"
    printf 'AZ16_NAME=%s\nAZ16_REGION=%s\n' "$AZ16_NAME" "$AZ16_REGION" > "$ENVFILE"
    load
    echo "Subscription: $(az account show --query name -o tsv)   Name: $AZ16_NAME   Region: $AZ16_REGION"
    for ns in Microsoft.CognitiveServices Microsoft.OperationalInsights Microsoft.Insights Microsoft.Security \
              Microsoft.OperationsManagement; do az provider register --namespace $ns -o none; done
    say "1/5 Foundry resource, keys off, gpt-5-mini as chat (capacity 100: 1 gave us empty answers and 429s)"
    az group create -n "$RG" -l "$AZ16_REGION" -o none
    az cognitiveservices account create -n "$AZ16_NAME" -g "$RG" -l "$AZ16_REGION" --kind AIServices --sku S0 \
      --custom-domain "$AZ16_NAME" --allow-project-management true --assign-identity --yes -o none
    FID=$(az cognitiveservices account show -n "$AZ16_NAME" -g "$RG" --query id -o tsv)
    az resource update --ids "$FID" --set properties.disableLocalAuth=true -o none
    AZ16_NAME=$AZ16_NAME cloud deploy
    say "2/5 Log Analytics, all three log categories on the resource, Foundry User for you"
    az monitor log-analytics workspace create -g "$RG" -n "law-$AZ16_NAME" -l "$AZ16_REGION" -o none
    az monitor diagnostic-settings create -n to-law --resource "$FID" --workspace "$(law_id id)" \
      --logs '[{"category":"Audit","enabled":true},{"category":"RequestResponse","enabled":true},{"category":"Trace","enabled":true}]' -o none
    az role assignment create --assignee-object-id "$(az ad signed-in-user show --query id -o tsv)" \
      --assignee-principal-type User --role 53ca6127-db72-4b80-b1b0-d745d6d5456d --scope "$FID" -o none
    say "3/5 Defender for AI services on, with user prompt evidence"
    az security pricing create -n AI --tier standard --extensions name=AIPromptEvidence isEnabled=True -o none
    say "4/5 Continuous export: security alerts of EVERY severity to the workspace"
    az rest --method put \
      --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Security/automations/export-az16?api-version=2019-01-01-preview" \
      --body "{\"location\": \"$AZ16_REGION\", \"properties\": {\"isEnabled\": true,
        \"scopes\": [{\"description\": \"lab subscription\", \"scopePath\": \"/subscriptions/$SUB\"}],
        \"sources\": [{\"eventSource\": \"Alerts\"}],
        \"actions\": [{\"actionType\": \"Workspace\", \"workspaceResourceId\": \"$(law_id id)\"}]}}" -o none
    say "5/5 The subscription's Activity log to the workspace (free to ingest)"
    AZ16_NAME=$AZ16_NAME cloud activity
    say "Done. Roles take a few minutes. Then: bash deploy.sh test (Defender's alert can take 30 minutes or more)"
    ;;

  test)
    repo; load
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }

    say "T1 and T2 Four requests with user context (20 s apart)"
    out=$(AZ16_NAME=$AZ16_NAME cloud ask 2>&1) || true; echo "$out"
    r1=$(awk '/^== request 1/{f=1;next} f&&/^HTTP/{print $2;exit}' <<<"$out")
    r2=$(awk '/^== request 2/{f=1;next} f&&/^HTTP/{print $2;exit}' <<<"$out")
    if [ "$r1" = 200 ]; then rec PASS "T1 a normal request with your token: 200"
    elif [ "$r1" = 401 ] || [ "$r1" = 403 ]; then rec WAIT "T1 $r1: your role may still be spreading"
    else rec FAIL "T1 request 1 got ${r1:-nothing}"; fi
    if [ "$r2" = 400 ] && awk '/^== request 2/{f=1} f' <<<"$out" | head -3 | grep -q jailbreak; then
      rec PASS "T2 the jailbreak placeholder: 400, Prompt Shields jailbreak filtered"
    else rec FAIL "T2 request 2 got ${r2:-nothing}"; fi

    say "T3 Defender for AI services: Standard, with prompt evidence"
    p=$(az security pricing show -n AI --query "[pricingTier, extensions[?name=='AIPromptEvidence'].isEnabled | [0]]" -o tsv | tr '\n' ' ')
    echo "tier, prompt evidence: $p"
    if [ "$p" = "Standard True " ]; then rec PASS "T3 Defender for AI services on, prompt evidence on"
    else rec FAIL "T3 got $p"; fi

    say "T4 Keys off, and all three log categories go to the workspace"
    FID=$(az cognitiveservices account show -n "$AZ16_NAME" -g "$RG" --query id -o tsv)
    k=$(az cognitiveservices account show -n "$AZ16_NAME" -g "$RG" --query properties.disableLocalAuth -o tsv)
    c=$(az monitor diagnostic-settings show -n to-law --resource "$FID" --query "logs[?enabled].category" -o tsv | sort | tr '\n' ' ')
    echo "keys disabled: $k   categories: $c"
    if [ "$k" = true ] && [ "$c" = "Audit RequestResponse Trace " ]; then rec PASS "T4 keys off; Audit, RequestResponse, Trace logged"
    else rec FAIL "T4 got keys disabled=$k categories=$c"; fi

    say "T5 The evidence in Log Analytics (ours took about 45 minutes to arrive)"
    q="union isfuzzy=true (AzureDiagnostics | where ResourceProvider == 'MICROSOFT.COGNITIVESERVICES' | summarize n=count() | extend t='AzureDiagnostics'), (SecurityAlert | where AlertName has 'Jailbreak' | summarize n=count() | extend t='SecurityAlert')"
    rows=$(az monitor log-analytics query -w "$(law_id customerId)" --analytics-query "$q" --query "[].[t, n]" -o tsv 2>/dev/null || true)
    echo "${rows:-no rows yet}"
    if grep -q 'SecurityAlert[[:space:]]*[1-9]' <<<"$rows"; then rec PASS "T5 Defender's jailbreak alert is in SecurityAlert"
    elif grep -q 'AzureDiagnostics[[:space:]]*[1-9]' <<<"$rows"; then rec WAIT "T5 request logs are in; the alert isn't yet (Defender: 30 min or more)"
    else rec WAIT "T5 nothing in the workspace yet: run test again in 30 minutes"; fi

    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    echo "WAIT means Azure has not caught up yet. Also look at Defender for Cloud > Security alerts in the portal."
    ;;

  down)
    repo; load
    say "Defender for AI services back to Free, Activity log export off, the resource group (and the alert export in it)"
    AZ16_NAME=$AZ16_NAME cloud down || true
    az cognitiveservices account purge -n "$AZ16_NAME" -g "$RG" -l "$AZ16_REGION" -o none 2>/dev/null || true
    rm -f "$ENVFILE"
    echo "Done. Tomorrow: az group show -n $RG should say ResourceGroupNotFound."
    ;;

  *) sed -n '2,8p' "$0"; exit 1;;
esac
