#!/usr/bin/env bash
# GC14 in one go: an Agent Runtime agent with its own Agent Identity, behind an Agent Gateway, with one DENY rule
# (GUIDED-BUILD.md Steps 1 to 5), the proof, and the teardown. Terraform does the infrastructure in two passes.
#
#   bash deploy.sh up        # pass 1 (APIs, datasets, bucket, Agent Registry endpoints, the gateway in DRY RUN), the
#                            #   fake rows, the agent deployed with Agent Identity, then pass 2 (its access policy + IAM)
#   bash deploy.sh test      # R1 to R4 through the agent, then the gateway's request log
#   bash deploy.sh enforce   # gateway to ENFORCE, then R1, R3, R4 again: R3 and R4 refused at the gateway
#   bash deploy.sh logs      # the newest gateway and IAP entries in full (what each field holds)
#   bash deploy.sh down      # delete the agent, then terraform destroy
#
# Runs in Google Cloud Shell in the project you're signed in to; downloads the course labs repo into ~/tsg-labs.
# Optional: export GC14_REGION=us-central1 TSG_MODEL=gemini-3.1-flash-lite TSG_MODEL_LOCATION=global
# Cost: under US$1 if you tear down the same day (Agent Runtime's free tier covers a few requests).
set -euo pipefail

ENVFILE="$HOME/.gc14.env"
REPO="$HOME/tsg-labs"
VENV="$HOME/.gc14-venv"
say() { printf '\n== %s\n' "$*"; }
for t in gcloud bq python3 git curl; do command -v $t >/dev/null || { echo "Needs $t (Cloud Shell has it)."; exit 1; }; done

repo() {
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only 2>/dev/null || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/gc14"; TF="$LAB/cloud/terraform"
}
load() {
  # shellcheck source=/dev/null
  if [ -z "${GC14_PROJECT:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  P="${GC14_PROJECT:-$(gcloud config get project 2>/dev/null)}"
  [ -n "$P" ] || { echo "No project: gcloud config set project PROJECT_ID"; exit 1; }
  R="${GC14_REGION:-us-central1}"
  gcloud config set project "$P" >/dev/null 2>&1
}
save() { printf 'GC14_PROJECT=%s\nGC14_REGION=%s\nAGENT=%s\nAGENT_PRINCIPAL=%s\n' "$P" "$R" "${AGENT:-}" "${AGENT_PRINCIPAL:-}" > "$ENVFILE"; }
need_terraform() {   # Cloud Shell stopped shipping Terraform (12 Nov 2026): install HashiCorp's zip into ~/bin
  export PATH="$HOME/bin:$PATH"
  terraform version 2>/dev/null | grep -q '^Terraform v' && return 0
  local v=1.13.4 d; d=$(mktemp -d)
  echo "Terraform is not installed here: installing $v from releases.hashicorp.com into ~/bin (checksum verified)"
  curl -sSfo "$d/tf.zip" "https://releases.hashicorp.com/terraform/$v/terraform_${v}_linux_amd64.zip"
  curl -sSfo "$d/sums" "https://releases.hashicorp.com/terraform/$v/terraform_${v}_SHA256SUMS"
  (cd "$d" && grep "linux_amd64.zip" sums | sed "s/terraform_${v}_linux_amd64.zip/tf.zip/" | sha256sum -c --quiet) ||
    { echo "Checksum mismatch: not installing."; exit 1; }
  mkdir -p "$HOME/bin" && unzip -oq "$d/tf.zip" terraform -d "$HOME/bin" && rm -rf "$d"
  terraform version | head -1 || true
}
tf() { (cd "$TF" && terraform "$@" -input=false -var "project_id=$P" -var "region=$R" \
          -var "agent_principal=${AGENT_PRINCIPAL:-}" -var "enforcement=${ENF:-DRY_RUN}"); }
venv() {
  [ -d "$VENV" ] || python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$LAB/cloud/agent/requirements.txt"
}
ask() { (cd "$LAB/cloud/agent" && "$VENV/bin/python" ask.py --project "$P" --region "$R" --agent "$AGENT" "$@" 2>&1 |
         grep -v "Warning\|warn(" || true); }
gw_logs() {
  say "The gateway's request log, last 30 minutes (telemetry and logging calls left out)"
  gcloud logging read "logName=\"projects/$P/logs/networkservices.googleapis.com%2Fgateway_requests\" AND NOT httpRequest.requestUrl:(\"telemetry\" OR \"logging\" OR \"monitoring\" OR \"cloudtrace\")" \
    --limit=12 --freshness=30m \
    --format="table(timestamp.date('%H:%M:%S'):label=TIME, httpRequest.status:label=STATUS, jsonPayload.authzPolicyInfo.result:label=AUTHZ, jsonPayload.agentGatewayInfo.mcpInfo.method:label=MCP, httpRequest.requestUrl.slice(0:45).join(''):label=URL)" || true
}

case "${1:-}" in
  up)
    repo; load; need_terraform; save
    echo "Project: $P   Region: $R"
    gcloud services enable cloudresourcemanager.googleapis.com serviceusage.googleapis.com iam.googleapis.com
    say "1 Terraform pass 1: APIs, datasets, staging bucket, Agent Registry endpoints, the gateway (DRY RUN)"
    (cd "$TF" && terraform init -input=false >/dev/null)
    tf apply -auto-approve
    GATEWAY=$(cd "$TF" && terraform output -raw gateway); STAGING=$(cd "$TF" && terraform output -raw staging_bucket)
    say "1b Fake rows: four tickets, two payroll rows (test-user-1, test-user-2)"
    bq query --use_legacy_sql=false -q "DELETE FROM helpdesk.tickets WHERE TRUE" >/dev/null 2>&1 || true
    bq query --use_legacy_sql=false -q "INSERT INTO helpdesk.tickets (ticket_id, status, summary) VALUES
      ('T-1001', 'open', 'VPN drops after sleep'), ('T-1002', 'open', 'Printer on floor 3 offline'),
      ('T-1003', 'open', 'Password reset loop'), ('T-1004', 'closed', 'New laptop request')" >/dev/null
    bq query --use_legacy_sql=false -q "DELETE FROM finance_exports.payroll WHERE TRUE" >/dev/null 2>&1 || true
    bq query --use_legacy_sql=false -q \
      "INSERT INTO finance_exports.payroll (employee, band) VALUES ('test-user-1', 'B2'), ('test-user-2', 'B3')" >/dev/null
    say "2 The agent: Agent Runtime, Agent Identity, bound to the gateway (several minutes)"
    venv
    if [ -z "${AGENT:-}" ]; then   # an agent from an earlier run? (deploying twice makes two agents)
      found=$(curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
        "https://$R-aiplatform.googleapis.com/v1beta1/projects/$P/locations/$R/reasoningEngines" |
        python3 -c 'import json,sys
for e in json.load(sys.stdin).get("reasoningEngines", []):
    if e.get("displayName") == "tsg-gc14-helpdesk":
        print(e["name"], (e.get("spec") or {}).get("effectiveIdentity", "")); break' || true)
      if [ -n "$found" ]; then AGENT=${found%% *}; AGENT_PRINCIPAL=${found#* }; echo "   found the agent from an earlier run"; fi
    fi
    if [ -z "${AGENT:-}" ]; then
      out=$(cd "$LAB/cloud/agent" && "$VENV/bin/python" deploy.py --project "$P" --region "$R" --gateway "$GATEWAY" \
            --staging-bucket "$STAGING" 2>&1 | grep -v "Warning\|warn(") || { echo "$out" | tail -20; exit 1; }
      echo "$out" | tail -8
      # deploy.py prints one JSON object that starts with "name" (warnings above it can hold braces too)
      read -r AGENT AGENT_PRINCIPAL < <(python3 -c 'import json,re,sys
m = re.search(r"\{\s*\"name\".*?\}", sys.stdin.read(), re.S); d = json.loads(m.group(0))
print(d["name"], d["effectiveIdentity"] or "")' <<<"$out")
    fi
    # The API gives the identity without its scheme; IAM wants principal://...
    [ -z "${AGENT_PRINCIPAL:-}" ] || [[ "$AGENT_PRINCIPAL" == principal://* ]] || AGENT_PRINCIPAL="principal://$AGENT_PRINCIPAL"
    save
    echo "AGENT=$AGENT"; echo "AGENT_PRINCIPAL=${AGENT_PRINCIPAL:0:60}..."
    say "3 Terraform pass 2: the access policy (one DENY rule) bound to the gateway, the agent's IAM"
    tf apply -auto-approve
    say "Done. IAM takes a few minutes. Then: bash deploy.sh test"
    ;;

  test)
    repo; load
    say "R1 to R4 through the agent (gateway in ${ENF:-$(cd "$TF" 2>/dev/null && terraform output -raw enforcement 2>/dev/null || echo DRY_RUN)})"
    ask
    gw_logs
    echo
    echo "Read it: R1 allowed; R2 allowed by the gateway, refused by IAM on finance_exports; R3 and R4 go through in dry"
    echo "run (BigQuery's IAM refuses R3's write; example.com answers 200). Then: bash deploy.sh enforce"
    ;;

  logs)
    repo; load
    say "The newest gateway entries for BigQuery's MCP server and for example.com, in full"
    gcloud logging read "logName=\"projects/$P/logs/networkservices.googleapis.com%2Fgateway_requests\" AND (httpRequest.requestUrl:\"bigquery\" OR httpRequest.requestUrl:\"example.com\")" \
      --limit=2 --freshness=1h --format=yaml || true
    say "The newest IAP decision, in full (IAP writes them to the Data Access audit log)"
    gcloud logging read 'protoPayload.serviceName="iap.googleapis.com"' --limit=1 --freshness=1h --format=yaml || true
    ;;

  enforce)
    repo; load; need_terraform
    say "Gateway to ENFORCE"
    ENF=ENFORCE tf apply -auto-approve
    echo "Waiting 3 minutes for enforcement to reach the gateway..."; sleep 180
    say "R1, R3 and R4 again: the allowed tool still works; the DENY rule and the unregistered host are refused"
    ask --pick 1; ask --pick 3; ask --pick 4
    gw_logs
    ;;

  down)
    repo; load; need_terraform
    if [ -n "${AGENT:-}" ]; then
      say "Delete the agent (and its sessions and memories)"
      curl -s -o /dev/null -w "   DELETE agent: HTTP %{http_code}\n" -X DELETE -H "Authorization: Bearer $(gcloud auth print-access-token)" \
        "https://$R-aiplatform.googleapis.com/v1/$AGENT?force=true"
      sleep 30
    fi
    say "terraform destroy"
    # one retry: our run hit a passing "connection refused" from the BigQuery API while Terraform refreshed state
    tf destroy -auto-approve || { echo "terraform destroy failed: trying once more in 30 s"; sleep 30; tf destroy -auto-approve; }
    rm -f "$ENVFILE"
    echo "Done. The agent's principal stops existing with the agent; check the billing report tomorrow."
    ;;

  *) sed -n '2,12p' "$0"; exit 1;;
esac
