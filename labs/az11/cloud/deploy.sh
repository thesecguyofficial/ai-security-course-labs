#!/usr/bin/env bash
# AZ11 in one go: the hardened TSG Helpdesk model access from lesson 11.6, its proof, and its teardown.
#
#   bash deploy.sh up      # build it (Terraform: private endpoint, keys off, your own key, logs, test VM) + guardrails
#   bash deploy.sh test    # prove it: 5 checks, each prints PASS, WAIT or FAIL
#   bash deploy.sh down    # delete everything this script made (do it today: the VM and endpoint bill by the hour)
#
# Runs in Azure Cloud Shell (Bash): it has the Azure CLI, Terraform and Python. On your own machine you need the same
# three, signed in with az login. The script downloads the course labs repo (public, read-only) into ~/tsg-labs.
# Your names are saved in ~/.az11.env so test and down find the same build.
#
# Optional before `up`:
#   export AZ11_NAME=az11-ab1234       # 3 to 21 lowercase letters, digits, hyphens; globally unique (default: random)
#   export MY_IP=<IPv4>                # the only address allowed to create the key (default: this shell's address)
#
# The step-by-step version, with the portal path and every finding, is GUIDED-BUILD.md. Cost: a few US dollars if you
# tear it down the same day (VM, private endpoint, DNS zones). Use a subscription you own, never your employer's.
set -euo pipefail

ENVFILE="$HOME/.az11.env"
REPO="$HOME/tsg-labs"

say() { printf '\n== %s\n' "$*"; }
for t in az terraform python3 curl git; do command -v $t >/dev/null || { echo "Needs $t (Azure Cloud Shell has it)."; exit 1; }; done
az account show -o none 2>/dev/null || { echo "Sign in first: az login"; exit 1; }

repo() {   # the lab files (Terraform, probes, policies) live in the public labs repo
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/az11"
}
load() {
  # shellcheck source=/dev/null
  if [ -z "${AZ11_NAME:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  [ -n "${AZ11_NAME:-}" ] || { echo "No build found. Run: bash deploy.sh up"; exit 1; }
  export AZ11_NAME MY_IP="${MY_IP:-203.0.113.10}" RG="rg-$AZ11_NAME"
}
cloud() { (cd "$LAB/cloud" && bash cloud.sh "$@"); }

case "${1:-}" in
  up)
    repo
    export AZ11_NAME="${AZ11_NAME:-az11-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')}"
    export MY_IP="${MY_IP:-$(curl -s https://api.ipify.org)}"
    printf 'AZ11_NAME=%s\nMY_IP=%s\n' "$AZ11_NAME" "$MY_IP" > "$ENVFILE"
    echo "Subscription: $(az account show --query name -o tsv)   Name: $AZ11_NAME   Key Vault firewall: $MY_IP"
    say "1/3 Resource providers (a new subscription may not have them yet)"
    for ns in Microsoft.CognitiveServices Microsoft.KeyVault Microsoft.Network Microsoft.Compute \
              Microsoft.ManagedIdentity Microsoft.OperationalInsights Microsoft.Insights; do
      az provider register --namespace $ns -o none; done
    say "2/3 Terraform: network, identities, Key Vault + key, Foundry (private, keys off, your key), DNS, logs, roles, VM"
    TF="$LAB/terraform"
    terraform -chdir="$TF" init -input=false >/dev/null
    for try in 1 2; do   # a 403 on the key or on CMK means a role was still spreading: the second run fixes it
      if terraform -chdir="$TF" apply -input=false -auto-approve -var "name=$AZ11_NAME" -var "my_ip=$MY_IP"; then break; fi
      [ $try = 2 ] && { echo "Terraform failed twice: read the error above."; exit 1; }
      echo "Retrying in 2 minutes (role assignments can take up to 5 minutes to spread)."; sleep 120
    done
    say "3/3 Guardrails: deployment type, network, keys, diagnostics (Azure Policy)"
    cloud policy
    say "Done. Policies take at least 15 minutes, roles up to 5. Then: bash deploy.sh test"
    ;;

  test)
    repo; load
    FID=$(az cognitiveservices account show -n "$AZ11_NAME" -g "$RG" --query id -o tsv)
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }

    say "T1 From here (outside the network): the names are public and the request is refused"
    out=$(cloud probe-outside 2>&1); echo "$out"
    code=$(grep -o 'HTTP [0-9]*' <<<"$out" | tail -1 | cut -d' ' -f2)
    case $code in 401|403) rec PASS "T1 outside refused (HTTP $code)";; *) rec FAIL "T1 outside got HTTP ${code:-none}";; esac

    say "T2 From the test VM (inside): private names and a 200, with the VM's own identity"
    out=$(cloud probe-inside 2>&1); echo "$out"
    if grep -q 'HTTP 200' <<<"$out" && ! grep -E -- '-> [0-9.]+' <<<"$out" | grep -v -- '-> 10\.' | grep -q .; then
      rec PASS "T2 inside: private addresses and 200"
    elif grep -q 'HTTP 401' <<<"$out"; then rec WAIT "T2 401: the VM's role may still be spreading (up to 5 min)"
    else rec FAIL "T2 see the output above"; fi

    say "T3 The settings an auditor asks for"
    s=$(az cognitiveservices account show -n "$AZ11_NAME" -g "$RG" --query \
      "[properties.publicNetworkAccess, properties.disableLocalAuth, properties.encryption.keySource]" -o tsv | tr '\n\t' '  ')
    echo "public network access, keys disabled, key source: $s"
    [ "${s,,}" = "disabled true microsoft.keyvault " ] && rec PASS "T3 public access Disabled, keys off, your own key" \
                                                   || rec FAIL "T3 got: $s"

    say "T4 Nobody can switch keys back on, not even the subscription Owner (policy, 15 min or more after up)"
    if out=$(az resource update --ids "$FID" --set properties.disableLocalAuth=false -o none 2>&1); then
      az resource update --ids "$FID" --set properties.disableLocalAuth=true -o none
      rec WAIT "T4 allowed (and switched off again at once): the policy is not active yet"
    elif grep -qi policy <<<"$out"; then rec PASS "T4 refused by policy"
    else rec FAIL "T4 refused, but not by policy: $(head -c 200 <<<"$out")"; fi

    say "T5 The key's own log: Key Vault AuditEvent goes to the workspace"
    # Rows appear only when the key is used, and Foundry caches the unwrapped key, so a fresh build can show 0 rows
    # for hours (our 12 Nov re-run). The setting is what you check; the rows are the evidence when they come.
    KV=$(az keyvault list -g "$RG" --query "[0].id" -o tsv)
    a=$(az monitor diagnostic-settings list --resource "$KV" --query "[].logs[?enabled && category=='AuditEvent'].category | []" -o tsv)
    WS=$(az monitor log-analytics workspace show -g "$RG" -n "law-$AZ11_NAME" --query customerId -o tsv)
    n=$(az monitor log-analytics query -w "$WS" --analytics-query \
      "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' | summarize count()" --query "[0].count_" -o tsv 2>/dev/null || echo 0)
    echo "AuditEvent setting: ${a:-none}   Key Vault rows so far: ${n:-0}"
    if [ "$a" = AuditEvent ]; then rec PASS "T5 Key Vault AuditEvent goes to law-$AZ11_NAME (${n:-0} rows so far)"
    else rec FAIL "T5 no AuditEvent diagnostic setting on the Key Vault"; fi

    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    echo "WAIT means Azure has not caught up yet (roles up to 5 min, policy 15 min or more, logs can take longer)."
    ;;

  down)
    repo; load
    say "Removing the guardrails, then terraform destroy (it also purges the Foundry name)"
    cloud down || true
    if az group show -n "$RG" -o none 2>/dev/null; then   # anything Terraform didn't remove
      az group delete -n "$RG" --yes
      az cognitiveservices account purge -l swedencentral -g "$RG" -n "$AZ11_NAME" -o none 2>/dev/null || true
    fi
    rm -f "$ENVFILE"
    echo "Done. The Key Vault name kv-$AZ11_NAME stays reserved for 7 days (purge protection)."
    ;;

  *) sed -n '2,8p' "$0"; exit 1;;
esac
