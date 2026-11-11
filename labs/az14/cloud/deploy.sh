#!/usr/bin/env bash
# AZ14 in one go: the TSG Helpdesk as a Foundry hosted agent from lesson 14.8, its proof, and its teardown.
#
#   bash deploy.sh up       # build it: Foundry + project + model, storage, registry, your MCP server, the toolbox,
#                           #   the hosted agent, and ONE role for the agent's identity
#   bash deploy.sh test     # prove it: 5 checks, each prints PASS, WAIT or FAIL
#   bash deploy.sh down     # delete everything this script made (do it today)
#   bash deploy.sh content  # only after `terraform apply`: knowledge files, MCP server, toolbox, agent, its role
#
# Runs in Azure Cloud Shell (Bash): it has the Azure CLI and Python; the script installs the Foundry Python SDK for
# your user. No Docker needed: images are built in your registry (or with pip + crane where ACR Tasks are refused).
# The script downloads the course labs repo (public, read-only) into ~/tsg-labs. Names are saved in ~/.az14.env.
#
# Optional before `up`:
#   export AZ14_NAME=az14ab1234        # 3 to 20 lowercase letters and digits only (it names storage and registry too)
#   export AZ14_REGION=swedencentral   # a region with hosted agents and gpt-5-mini (default: swedencentral)
#
# Cost: under US$1 if you tear it down the same day (registry Basic by the day, tokens, a tiny storage account).
# Use a subscription you own, never your employer's.
set -euo pipefail

ENVFILE="$HOME/.az14.env"
REPO="$HOME/tsg-labs"

say() { printf '\n== %s\n' "$*"; }
for t in az python3 git curl; do command -v $t >/dev/null || { echo "Needs $t (Azure Cloud Shell has it)."; exit 1; }; done
az account show -o none 2>/dev/null || { echo "Sign in first: az login"; exit 1; }

repo() {
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/az14"
}
load() {
  # shellcheck source=/dev/null
  if [ -z "${AZ14_NAME:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  [ -n "${AZ14_NAME:-}" ] || { echo "No build found. Run: bash deploy.sh up"; exit 1; }
  export AZ14_NAME AZ14_REGION="${AZ14_REGION:-swedencentral}"
}
sdk() { python3 -c 'import azure.ai.projects, azure.identity, requests, mcp' 2>/dev/null ||
        python3 -m pip install -q --user "azure-ai-projects>=2.3.0" azure-identity requests "mcp<2"; }
cloud() { (cd "$LAB/cloud" && bash cloud.sh "$@"); }
state() {   # cloud/.state/env as cloud.sh up writes it (a Terraform build needs it written here)
  local S="$LAB/cloud/.state"; mkdir -p "$S"
  grep -q '^PROJECT_SCOPE=' "$S/env" 2>/dev/null && return 0
  local FID; FID=$(az cognitiveservices account show -n "$AZ14_NAME" -g "rg-$AZ14_NAME" --query id -o tsv)
  { echo "PROJECT_ENDPOINT=https://$AZ14_NAME.services.ai.azure.com/api/projects/helpdesk"
    echo "STORAGE=st$AZ14_NAME"; echo "IMAGE=cr$AZ14_NAME.azurecr.io/helpdesk-agent:1"
    echo "PROJECT_SCOPE=$FID/projects/helpdesk"; } >> "$S/env"
}
identity() {   # the hosted agent's own Entra identity (it can take a minute to appear)
  (cd "$LAB/cloud" && python3 - <<'PY'
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient
env = dict(l.strip().split("=", 1) for l in open(".state/env") if "=" in l)
p = AIProjectClient(endpoint=env["PROJECT_ENDPOINT"], credential=DefaultAzureCredential())
print((p.agents.get(agent_name="helpdesk-agent").instance_identity or {}).get("principal_id") or "")
PY
  )
}
content() {
  say "The knowledge store: kb-articles (3 articles) and hr-exports (pay bands)"
  cloud kb
  say "Your MCP actions server on Container Apps, its key in a Container Apps secret"
  cloud mcp
  say "The key connection and toolbox helpdesk-tools (require_approval always)"
  sdk; cloud toolbox
  say "The hosted agent: image built in your registry, then the agent version"
  cloud agent
  say "The agent identity gets Storage Blob Data Reader on ONE container"
  AGENT_IDENTITY_ID=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    AGENT_IDENTITY_ID=$(identity 2>/dev/null || true); [ -n "$AGENT_IDENTITY_ID" ] && break
    echo "agent identity not ready yet, waiting 30 s"; sleep 30
  done
  [ -n "$AGENT_IDENTITY_ID" ] || { echo "No agent identity after 5 minutes: run bash deploy.sh content again later."; exit 1; }
  echo "AGENT_IDENTITY_ID=$AGENT_IDENTITY_ID" >> "$ENVFILE"
  export AGENT_IDENTITY_ID; cloud grant
}

case "${1:-}" in
  up)
    repo
    export AZ14_NAME="${AZ14_NAME:-az14$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')}"
    export AZ14_REGION="${AZ14_REGION:-swedencentral}"
    printf 'AZ14_NAME=%s\nAZ14_REGION=%s\n' "$AZ14_NAME" "$AZ14_REGION" > "$ENVFILE"
    echo "Subscription: $(az account show --query name -o tsv)   Name: $AZ14_NAME   Region: $AZ14_REGION"
    rm -rf "$LAB/cloud/.state"
    say "1/2 Foundry resource + project + helpdesk-chat, storage (no shared keys), registry, your roles"
    cloud up
    echo "Waiting 2 minutes for the roles to spread."; sleep 120
    say "2/2 The content"
    content
    say "Done. The agent's role can take a few minutes. Then: bash deploy.sh test"
    ;;

  content)
    repo; load; state; content
    ;;

  test)
    repo; load; state; sdk
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }
    MCP_URL=$(grep '^MCP_URL=' "$LAB/cloud/.state/env" | cut -d= -f2-)

    say "T1 Your MCP server refuses a caller without its key"
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$MCP_URL" || true); echo "POST $MCP_URL without x-api-key -> $code"
    if [ "$code" = 401 ]; then rec PASS "T1 no key, 401"; else rec FAIL "T1 got HTTP $code"; fi

    say "T2 Request 1, a normal question: the agent reads kb-articles and answers"
    out=$(PICK=1 cloud ask < /dev/null 2>&1) || true; echo "$out" | head -12
    if grep -q 'answer:' <<<"$out" && grep -q 'kb-articles' <<<"$out"; then rec PASS "T2 answered from kb-articles"
    elif grep -qi '403\|AuthorizationPermissionMismatch' <<<"$out"; then rec WAIT "T2 403: the agent's role may still be spreading"
    else rec FAIL "T2 see the output above"; fi

    say "T3 Request 2, the pay bands from hr-exports: the agent's identity can't read that container"
    out=$(PICK=2 cloud ask < /dev/null 2>&1) || true; echo "$out" | head -12
    if grep -q 'CANARY-AZ14-BANDS-4417' <<<"$out"; then rec FAIL "T3 the canary leaked"
    elif grep -qi 'AuthorizationPermissionMismatch\|403' <<<"$out"; then rec PASS "T3 hr-exports refused by RBAC (403), no canary"
    else rec FAIL "T3 no 403 seen: see the output above"; fi

    say "T4 The agent identity has exactly one role, on one container"
    AID=$(grep '^AGENT_IDENTITY_ID=' "$ENVFILE" | tail -1 | cut -d= -f2)
    roles=$(az role assignment list --assignee "$AID" --all --query "[].[roleDefinitionName, scope]" -o tsv)
    echo "$roles"
    if [ "$(grep -c . <<<"$roles")" = 1 ] && grep -q 'Storage Blob Data Reader.*/containers/kb-articles$' <<<"$roles"; then
      rec PASS "T4 one role: Storage Blob Data Reader on kb-articles"
    else rec FAIL "T4 expected one role on kb-articles"; fi

    say "T5 Request 5 calls your MCP tool through the toolbox: it waits for a yes (we answer no)"
    out=$(yes n | PICK=5 cloud ask 2>&1) || true; echo "$out" | head -12
    if grep -q 'needs_confirmation' <<<"$out" && grep -q 'nothing ran' <<<"$out"; then
      rec PASS "T5 needs_confirmation, refused, nothing ran"
    else rec FAIL "T5 no confirmation step seen"; fi

    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    echo "WAIT means Azure has not caught up yet (a new role can take a few minutes)."
    ;;

  down)
    repo; load; state
    say "Deleting the agent, toolbox, Foundry resource (purged) and the resource group"
    sdk; cloud down || true
    rm -f "$ENVFILE"
    echo "Done. In the Entra admin center, Agents > Agent identities should list nothing named helpdesk-agent."
    ;;

  *) sed -n '2,9p' "$0"; exit 1;;
esac
