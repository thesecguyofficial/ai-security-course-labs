#!/usr/bin/env bash
# AZ15 in one go: the private, token-only model endpoint from lesson 15.5, its proof, and its teardown.
#
#   bash deploy.sh up      # build it: Machine Learning workspace (approved outbound only), its four egress rules,
#                          #   a client network + private endpoint + VM, the teardown timer, the endpoint, its logs
#   bash deploy.sh test    # prove it: 5 checks, each prints PASS, WAIT or FAIL (run it within 60 minutes of up)
#   bash deploy.sh down    # delete everything this script made (do it today)
#   bash deploy.sh content # only after `terraform apply`: timer, endpoint, deployment, scorer role, logs
#   bash deploy.sh timer   # give the endpoint another 60 minutes before the timer deletes it
#
# Runs in Azure Cloud Shell (Bash): it has the Azure CLI; the script adds the ml extension. It downloads the course
# labs repo (public, read-only) into ~/tsg-labs. Your names are saved in ~/.az15.env.
#
# Optional before `up`:
#   export AZ15_NAME=az15-ab1234           # 3 to 24 lowercase letters, digits, hyphens; starts with a letter
#   export AZ15_REGION=eastus              # default eastus (our run)
#   export INSTANCE=Standard_E2s_v3        # must be on the model's own SKU list and inside your quota
#
# COST: this is the expensive lab. The endpoint's VM, the client VM and the managed firewall (the egress rules bring it
# in) bill every hour they exist, called or not: a few US dollars for the hour this takes. A Logic App timer deletes
# the endpoint 60 minutes after it is ready; `down` deletes the rest. Use a subscription you own, never your
# employer's.
set -euo pipefail

ENVFILE="$HOME/.az15.env"
REPO="$HOME/tsg-labs"
MODEL_ID="${MODEL_ID:-azureml://registries/azureml/models/sshleifer-distilbart-cnn-12-6/versions/13}"

say() { printf '\n== %s\n' "$*"; }
for t in az python3 git; do command -v $t >/dev/null || { echo "Needs $t (Azure Cloud Shell has it)."; exit 1; }; done
az account show -o none 2>/dev/null || { echo "Sign in first: az login"; exit 1; }
az extension show -n ml -o none 2>/dev/null || az extension add -n ml -y -o none

repo() {
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/az15"
}
load() {
  # shellcheck source=/dev/null
  if [ -z "${AZ15_NAME:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  [ -n "${AZ15_NAME:-}" ] || { echo "No build found. Run: bash deploy.sh up"; exit 1; }
  export AZ15_NAME AZ15_REGION="${AZ15_REGION:-eastus}"
  RG="rg-$AZ15_NAME"; WS="$AZ15_NAME"; EP="$AZ15_NAME-ep"
}
cloud() { bash "$LAB/cloud/cloud.sh" "$1" "$RG" "$AZ15_REGION" "$WS" "$EP"; }
endpoint() {
    say "3/4 Timer first, then the endpoint (aad_token, public access disabled), its deployment, scorer role, logs"
    MODEL_ID="$MODEL_ID" INSTANCE="${INSTANCE:-Standard_E2s_v3}" cloud deploy
    say "4/4 Request timeout 90 s (the default 5 s gave us 408s on 2 vCPU)"
    az ml online-deployment update -g "$RG" -w "$WS" -e "$EP" -n blue \
      --set request_settings.request_timeout_ms=90000 -o none
    timer_reset
}
timer_reset() {   # the deployment alone took about 40 minutes in our runs: give the test a full hour from now
  local U; U="https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RG"
  U="$U/providers/Microsoft.Logic/workflows/la-tsg-az15-teardown?api-version=2019-05-01"
  az rest --method get --url "$U" > "$HOME/.az15-timer.json"
  python3 - "$HOME/.az15-timer.json" "$(date -u -d '+60 min' +%Y-%m-%dT%H:%M:%SZ)" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["properties"]["definition"]["triggers"]["after_60_minutes"]["recurrence"]["startTime"] = sys.argv[2]
body = {"location": d["location"], "identity": {"type": "SystemAssigned"},
        "properties": {"state": "Enabled", "definition": d["properties"]["definition"]}}
json.dump(body, open(sys.argv[1], "w"))
PY
  az rest --method put --url "$U" --body @"$HOME/.az15-timer.json" -o none && rm -f "$HOME/.az15-timer.json"
  echo "   the timer now deletes the endpoint at $(date -u -d '+60 min' +%H:%M) UTC"
}

case "${1:-}" in
  up)
    repo
    export AZ15_NAME="${AZ15_NAME:-az15-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')}"
    export AZ15_REGION="${AZ15_REGION:-eastus}"
    printf 'AZ15_NAME=%s\nAZ15_REGION=%s\n' "$AZ15_NAME" "$AZ15_REGION" > "$ENVFILE"
    load
    echo "Subscription: $(az account show --query name -o tsv)   Name: $AZ15_NAME   Region: $AZ15_REGION"
    for ns in Microsoft.MachineLearningServices Microsoft.PolicyInsights Microsoft.Logic Microsoft.Network \
              Microsoft.Compute Microsoft.OperationalInsights Microsoft.Insights; do
      az provider register --namespace $ns -o none; done
    say "1/4 Workspace (approved outbound only), managed network, client network + private endpoint + VM, logs"
    cloud up
    say "2/4 Four egress rules, only the hosts the model's container named in our run (about 6 minutes each)"
    for d in conda.anaconda.org repo.anaconda.com pypi.org files.pythonhosted.org; do
      echo "   allow $d"
      az ml workspace outbound-rule set -g "$RG" --workspace-name "$WS" --rule "allow-${d//./-}" \
        --type fqdn --destination "$d" -o none
    done
    endpoint
    say "Done. The timer deletes the endpoint 60 minutes from now. Now: bash deploy.sh test"
    ;;

  content)
    repo; load
    say "Check the four egress rules first (a missing one makes the container fail 40 minutes later)"
    have=$(az ml workspace outbound-rule list -g "$RG" --workspace-name "$WS" --query "[?type=='FQDN'].destination" -o tsv)
    for d in conda.anaconda.org repo.anaconda.com pypi.org files.pythonhosted.org; do
      grep -qx "$d" <<<"$have" || { echo "Missing egress rule for $d: run terraform apply again (or bash deploy.sh up)."; exit 1; }
    done
    echo "All four present."
    say "Provision the managed network now (its firewall too)"
    az ml workspace provision-network -g "$RG" -n "$WS" -o none
    endpoint
    say "Done. The timer deletes the endpoint in 60 minutes. Now: bash deploy.sh test"
    ;;

  timer)
    repo; load; timer_reset
    ;;

  test)
    repo; load
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }
    code() { awk -v s="== $1" 'index($0,s)==1{f=1;next} f&&/HTTP [0-9]+/{match($0,/HTTP [0-9]+/);print substr($0,RSTART+5,RLENGTH-5);exit}' <<<"$out"; }

    say "The four requests of Part C (the VM inside the network, then you from the internet)"
    out=$(cloud ask 2>&1) || true; echo "$out"
    c1=$(code C1); c2=$(code C2); c3=$(code C3); c4=$(code C4)
    if [ "$c1" = 200 ]; then rec PASS "T1 the Helpdesk VM, inside, with its identity: 200"
    else rec FAIL "T1 the VM got ${c1:-nothing} (endpoint gone? the timer deletes it after 60 minutes)"; fi
    if [ "$c2" = 403 ]; then rec PASS "T2 you, from the internet, with a valid token: 403 (public access disabled)"
    else rec FAIL "T2 from outside got ${c2:-nothing}"; fi
    if [ "$c3" = 401 ]; then rec PASS "T3 a made-up key instead of a token: 401 (aad_token only)"
    else rec FAIL "T3 got ${c3:-nothing}"; fi
    if [ "$c4" = 404 ]; then rec PASS "T4 a deployment that doesn't exist: 404"
    else rec FAIL "T4 got ${c4:-nothing}"; fi

    say "T5 The evidence: AmlOnlineEndpointTrafficLog rows (Microsoft: can take up to an hour; ours took minutes)"
    WSID=$(az monitor log-analytics workspace show -g "$RG" -n log-tsg-az15 --query customerId -o tsv)
    n=$(az monitor log-analytics query -w "$WSID" --analytics-query \
      "AmlOnlineEndpointTrafficLog | where TimeGenerated > ago(2h) and tostring(ResponseCode) == '403' | summarize n=count()" \
      --query "[0].n" -o tsv 2>/dev/null || true)
    echo "403 rows in the last 2 hours: ${n:-0}"
    if [ "${n:-0}" -gt 0 ] 2>/dev/null; then rec PASS "T5 the outside 403 is in the traffic log ($n rows)"
    else rec WAIT "T5 no 403 rows yet: run test again in a few minutes"; fi

    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    ;;

  down)
    repo; load
    say "Deleting the endpoint, the workspace (permanently) and the resource group, then the custom role"
    cloud down || true
    rm -f "$ENVFILE"
    echo "Done. Tomorrow: az group show -n $RG should say ResourceGroupNotFound."
    ;;

  *) sed -n '2,8p' "$0"; exit 1;;
esac
