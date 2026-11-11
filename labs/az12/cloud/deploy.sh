#!/usr/bin/env bash
# AZ12 in one go: the guardrail build from lesson 12.5, its proof, and its teardown.
#
#   bash deploy.sh up      # build it: Content Safety (free tier), Foundry + helpdesk-chat, the blocklist, the guardrail
#   bash deploy.sh test    # prove it: 5 checks, each prints PASS, WAIT or FAIL
#   bash deploy.sh down    # delete everything this script made (do it today)
#
# Runs in Azure Cloud Shell (Bash): it has the Azure CLI and Python. On your own machine you need both, signed in
# with az login. The script downloads the course labs repo (public, read-only) into ~/tsg-labs.
# Your name is saved in ~/.az12.env so test and down find the same build.
#
# Optional before `up`:
#   export AZ12_NAME=az12-ab1234       # 3 to 20 lowercase letters, digits, hyphens; globally unique (default: random)
#   export AZ12_REGION=eastus          # a region with Prompt Shields (default eastus)
#
# This builds its OWN small Foundry resource (public endpoint, keys off). To put the guardrail on your private AZ11
# build instead, follow GUIDED-BUILD/README Step 9 with AZ11_NAME set. Cost: pennies (F0 is free; you pay tokens).
# Use a subscription you own, never your employer's.
set -euo pipefail

ENVFILE="$HOME/.az12.env"
REPO="$HOME/tsg-labs"

say() { printf '\n== %s\n' "$*"; }
for t in az python3 git; do command -v $t >/dev/null || { echo "Needs $t (Azure Cloud Shell has it)."; exit 1; }; done
az account show -o none 2>/dev/null || { echo "Sign in first: az login"; exit 1; }

repo() {
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/az12"
}
load() {
  # shellcheck source=/dev/null
  if [ -z "${AZ12_NAME:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  [ -n "${AZ12_NAME:-}" ] || { echo "No build found. Run: bash deploy.sh up"; exit 1; }
  export AZ12_NAME AZ12_REGION="${AZ12_REGION:-eastus}"
}
cloud() { (cd "$LAB/cloud" && env -u AZ11_NAME bash cloud.sh "$@"); }   # always this lab's own Foundry resource

case "${1:-}" in
  up)
    repo
    export AZ12_NAME="${AZ12_NAME:-az12-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')}"
    export AZ12_REGION="${AZ12_REGION:-eastus}"
    printf 'AZ12_NAME=%s\nAZ12_REGION=%s\n' "$AZ12_NAME" "$AZ12_REGION" > "$ENVFILE"
    echo "Subscription: $(az account show --query name -o tsv)   Name: $AZ12_NAME   Region: $AZ12_REGION"
    az provider register --namespace Microsoft.CognitiveServices -o none
    say "1/4 Content Safety on the free tier (F0), keys off, Cognitive Services User for you"
    cloud cs-up
    say "2/4 Foundry resource $AZ12_NAME-fdy with helpdesk-chat (gpt-5-mini), keys off"
    cloud foundry-up
    say "3/4 Blocklist contoso-codenames with the term NIGHTJAR"
    cloud blocklist-up
    say "4/4 Guardrail contoso-helpdesk-v2, assigned to helpdesk-chat"
    cloud guardrail-up
    say "Done. Roles and the blocklist term take about 5 minutes. Then: bash deploy.sh test"
    ;;

  test)
    repo; load
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }

    say "T1 Prompt Shields and the harm classifiers, 28 requests (input side)"
    out=$(cloud cs-suite 2>&1) || true; echo "$out" | tail -8
    line=$(grep -o 'flagged [0-9]* of [0-9]* attacks, [0-9]* of [0-9]* legitimate' <<<"$out" || true)
    read -r _ fa _ _ _ fb _ _ <<<"${line//,/}"
    if [ -z "$line" ]; then
      if grep -q '401\|403' <<<"$out"; then rec WAIT "T1 401/403: your role may still be spreading (up to 5 min)"
      else rec FAIL "T1 no summary line: see the output above"; fi
    elif [ "$fa" -ge 5 ] && [ "$fb" -eq 0 ]; then rec PASS "T1 $fa attacks flagged, $fb legitimate requests flagged"
    else rec FAIL "T1 $fa attacks flagged, $fb legitimate requests flagged"; fi

    say "T2 to T4 The guardrail on the model: A05 (hidden instruction), A14 (code name in the answer), B01 (normal question)"
    out=$(PICK=B01,A05,A14 cloud guardrail-probe 2>&1) || true; grep -v '^ *raw:' <<<"$out"
    if grep -q '^A05 HTTP 400.*indirect_attack' <<<"$out"; then rec PASS "T2 A05 blocked: indirect_attack (400)"
    elif grep -q 'HTTP 401' <<<"$out"; then rec WAIT "T2 401: your role may still be spreading (up to 5 min)"
    else rec FAIL "T2 A05 was not blocked by indirect_attack"; fi
    if grep -q '^A14 .*custom_blocklists' <<<"$out"; then rec PASS "T3 A14 blocked by the contoso-codenames blocklist"
    else rec WAIT "T3 A14 not blocked yet: Microsoft says new terms can take about 5 minutes"; fi
    if grep -q '^B01 HTTP 200' <<<"$out"; then rec PASS "T4 B01 answered (200): the guardrail lets normal work through"
    else rec FAIL "T4 B01 did not get a 200"; fi

    say "T5 Evidence an auditor asks for: the deployment's guardrail and keys off"
    FID=$(az cognitiveservices account show -n "$AZ12_NAME-fdy" -g "rg-$AZ12_NAME" --query id -o tsv)
    g=$(az rest --method get --url "https://management.azure.com$FID/deployments/helpdesk-chat?api-version=2024-10-01" \
      --query properties.raiPolicyName -o tsv)
    k=$(az cognitiveservices account list -g "rg-$AZ12_NAME" --query "[].properties.disableLocalAuth" -o tsv | sort -u | tr '\n' ' ')
    echo "helpdesk-chat guardrail: $g   keys disabled on both resources: $k"
    if [ "$g" = contoso-helpdesk-v2 ] && [ "$k" = "true " ]; then rec PASS "T5 helpdesk-chat uses contoso-helpdesk-v2, keys off on both"
    else rec FAIL "T5 got guardrail=$g keys-disabled=$k"; fi

    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    echo "WAIT means Azure has not caught up yet (roles and blocklist terms take about 5 minutes)."
    ;;

  down)
    repo; load
    say "Removing the guardrail and blocklist, then both resources (purged, so the names are free again)"
    cloud down || true
    rm -f "$ENVFILE"
    echo "Done. The resource group is deleting in the background (a minute or two)."
    ;;

  *) sed -n '2,8p' "$0"; exit 1;;
esac
