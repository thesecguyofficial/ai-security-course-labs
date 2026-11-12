#!/usr/bin/env bash
# GC10 in one go: the locked-down AI footprint from lesson 10.6 (GUIDED-BUILD.md), its proof, and its teardown.
#
#   bash deploy.sh up      # budget alert, APIs, two test service accounts, Data Access logs, two restricted API keys,
#                          #   prompt caching off
#   bash deploy.sh test    # prove it: R1 to R5 from the guide, each prints PASS, WAIT or FAIL
#   bash deploy.sh down    # delete what `up` made (keys, accounts, binding, budget); caching back on, logs back off
#   bash deploy.sh tf apply|destroy   # the Terraform build instead of `up`/`down` (labs/gc10/terraform), same test
#
# Runs in Google Cloud Shell (it has gcloud, Python and git) in the project you're signed in to. It downloads the
# course labs repo (public, read-only) into ~/tsg-labs. The project is saved in ~/.gc10.env so test and down use it.
#
# Optional before `up`:
#   export GC10_PROJECT=my-sandbox-123   # default: the Cloud Shell project (gcloud config get project)
#   export GC10_MODEL=gemini-3.1-flash-lite
#
# Cost: cents at most (two or three short Gemini calls). Use a project you own, never your employer's.
set -euo pipefail

ENVFILE="$HOME/.gc10.env"
REPO="$HOME/tsg-labs"
say() { printf '\n== %s\n' "$*"; }
for t in gcloud python3 git curl; do command -v $t >/dev/null || { echo "Needs $t (Cloud Shell has it)."; exit 1; }; done

repo() {
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/gc10"
}
load() {
  # shellcheck source=/dev/null
  if [ -z "${GC10_PROJECT:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  P="${GC10_PROJECT:-$(gcloud config get project 2>/dev/null)}"
  [ -n "$P" ] || { echo "No project: gcloud config set project PROJECT_ID"; exit 1; }
  MODEL="${GC10_MODEL:-gemini-3.1-flash-lite}"
  ME=$(gcloud config get account 2>/dev/null)
  CALLER="gc10-caller@$P.iam.gserviceaccount.com"; NOBODY="gc10-nobody@$P.iam.gserviceaccount.com"
  URL="https://aiplatform.googleapis.com/v1/projects/$P/locations/global/publishers/google/models/$MODEL:generateContent"
  BODY='{"contents":[{"role":"user","parts":[{"text":"Say hello in five words."}]}],"generationConfig":{"maxOutputTokens":50}}'
  BA=$(gcloud billing projects describe "$P" --format="value(billingAccountName)" | sed 's#billingAccounts/##')
}
need_terraform() {   # Cloud Shell stopped shipping Terraform (our 12 Nov 2026 run): install HashiCorp's zip into ~/bin
  export PATH="$HOME/bin:$PATH"
  terraform version 2>/dev/null | grep -q '^Terraform v' && return 0   # Cloud Shell's stub only prints install help
  local v=1.13.4 d; d=$(mktemp -d)
  echo "Terraform is not installed here: installing $v from releases.hashicorp.com into ~/bin (checksum verified)"
  curl -sSfo "$d/tf.zip" "https://releases.hashicorp.com/terraform/$v/terraform_${v}_linux_amd64.zip"
  curl -sSfo "$d/sums" "https://releases.hashicorp.com/terraform/$v/terraform_${v}_SHA256SUMS"
  (cd "$d" && grep "linux_amd64.zip" sums | sed "s/terraform_${v}_linux_amd64.zip/tf.zip/" | sha256sum -c --quiet) ||
    { echo "Checksum mismatch: not installing."; exit 1; }
  mkdir -p "$HOME/bin" && unzip -oq "$d/tf.zip" terraform -d "$HOME/bin" && rm -rf "$d"
  export PATH="$HOME/bin:$PATH"; terraform version | head -1
}
key_name() { gcloud services api-keys list --project="$P" --filter="displayName=${1:-gc10-build}" --format="value(name)" 2>/dev/null | head -1; }
cache() { curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://us-central1-aiplatform.googleapis.com/v1/projects/$P/cacheConfig"; }
set_cache() { curl -s -o /dev/null -w "%{http_code}" -X PATCH -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" "https://us-central1-aiplatform.googleapis.com/v1/projects/$P/cacheConfig" \
  -d "{\"name\": \"projects/$P/cacheConfig\", \"disableCache\": $1}"; }
audit_logs() {   # $1 = on|off: Data Access (DATA_READ) logs for aiplatform.googleapis.com, everything else untouched
  gcloud projects get-iam-policy "$P" --format=json > "$HOME/.gc10-policy.json"
  python3 - "$HOME/.gc10-policy.json" "$1" <<'PY'
import json, sys
f, mode = sys.argv[1:]; p = json.load(open(f))
cfgs = [c for c in p.get("auditConfigs", []) if c.get("service") != "aiplatform.googleapis.com"]
if mode == "on":
    cfgs.append({"service": "aiplatform.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]})
p["auditConfigs"] = cfgs
json.dump(p, open(f, "w"))
PY
  gcloud projects set-iam-policy "$P" "$HOME/.gc10-policy.json" --format="value(etag)" >/dev/null
  rm -f "$HOME/.gc10-policy.json"
}

case "${1:-}" in
  up)
    repo; load
    printf 'GC10_PROJECT=%s\n' "$P" > "$ENVFILE"
    echo "Project: $P   Model: $MODEL"
    say "0 Budget alert (lesson 10.5: it only emails you, hours late), APIs"
    gcloud services enable billingbudgets.googleapis.com --project="$P"   # the budget command needs it first
    CUR=$(gcloud billing accounts describe "$BA" --format="value(currencyCode)")
    AMT=5; [ "$CUR" = INR ] && AMT=500
    gcloud billing budgets list --billing-account="$BA" --format="value(displayName)" | grep -qx "gc10-build alerts" ||
      gcloud billing budgets create --billing-account="$BA" --display-name="gc10-build alerts" \
        --budget-amount="${AMT}${CUR}" --filter-projects="projects/$P" \
        --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0 --format="value(name)"
    gcloud services enable aiplatform.googleapis.com apikeys.googleapis.com cloudasset.googleapis.com --project="$P"
    say "2a Two test identities: gc10-caller (Agent Platform User) and gc10-nobody (no AI role)"
    for SA in gc10-caller gc10-nobody; do
      gcloud iam service-accounts describe "$SA@$P.iam.gserviceaccount.com" --project="$P" >/dev/null 2>&1 ||
        gcloud iam service-accounts create "$SA" --project="$P" --display-name="GC10 $SA"
    done
    gcloud projects add-iam-policy-binding "$P" --member="serviceAccount:$CALLER" --role="roles/aiplatform.user" \
      --condition=None --format="value(etag)" >/dev/null
    for SA in "$CALLER" "$NOBODY"; do   # Token Creator on each account, not on the project (lesson 11.1)
      gcloud iam service-accounts add-iam-policy-binding "$SA" --project="$P" --member="user:$ME" \
        --role="roles/iam.serviceAccountTokenCreator" --format="value(etag)" >/dev/null
    done
    say "2b Data Access audit logs on for Agent Platform"
    audit_logs on
    say "2c One API key: Agent Platform only, and only from 192.0.2.10 (a documentation address)"
    [ -n "$(key_name)" ] || gcloud services api-keys create --project="$P" --display-name=gc10-build \
      --api-target=service=aiplatform.googleapis.com --allowed-ips=192.0.2.10 --format="value(name)" 2>&1 | tail -1
    say "2c (bound) The kind of key Agent Platform accepts: bound to gc10-caller, same two restrictions (lesson 10.4)"
    [ -n "$(key_name gc10-bound)" ] || gcloud services api-keys create --project="$P" --display-name=gc10-bound \
      --service-account="$CALLER" --api-target=service=aiplatform.googleapis.com --allowed-ips=192.0.2.10 \
      --format="value(name)" 2>&1 | tail -1
    say "2d Prompt caching off"
    echo "PATCH cacheConfig: HTTP $(set_cache true)"
    say "Done. IAM takes a few minutes to reach every service. Then: bash deploy.sh test"
    ;;

  test)
    repo; load
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }
    call() { curl -s -w "\nHTTP %{http_code}" -X POST "$@" -H "Content-Type: application/json" "$URL" -d "$BODY"; }

    say "R1 gc10-nobody (no AI role) calls the model"
    T=$(gcloud auth print-access-token --impersonate-service-account="$NOBODY" 2>/dev/null)
    out=$(call -H "Authorization: Bearer $T"); echo "$out" | grep -E '"(code|status|reason|message)"|HTTP' | head -6
    if grep -q 'HTTP 403' <<<"$out" && grep -q IAM_PERMISSION_DENIED <<<"$out"; then rec PASS "R1 403 IAM_PERMISSION_DENIED"
    else rec FAIL "R1 expected 403 IAM_PERMISSION_DENIED"; fi

    say "R2 gc10-caller (Agent Platform User) calls the model"
    T=$(gcloud auth print-access-token --impersonate-service-account="$CALLER" 2>/dev/null)
    out=$(call -H "Authorization: Bearer $T"); echo "$out" | grep -E '"text"|"(promptTokenCount|candidatesTokenCount)"|"modelVersion"|"status"|HTTP' | head -6
    if grep -q 'HTTP 200' <<<"$out"; then rec PASS "R2 200 from gc10-caller"
    elif grep -q 'HTTP 403' <<<"$out"; then rec WAIT "R2 403: the role may still be spreading (a few minutes)"
    else rec FAIL "R2 see the output above"; fi

    say "R3 two API keys from the wrong place (key strings are used, never printed)"
    K=$(gcloud services api-keys get-key-string "$(key_name)" --format="value(keyString)")
    echo "-- plain key gc10-build:"
    out=$(call -H "x-goog-api-key: $K"); echo "$out" | grep -E '"(status|reason|message)"|HTTP' | head -4
    plain=$(grep -c 'API keys are not supported' <<<"$out" || true)
    K=$(gcloud services api-keys get-key-string "$(key_name gc10-bound)" --format="value(keyString)")
    echo "-- key bound to gc10-caller, gc10-bound:"
    out=$(call -H "x-goog-api-key: $K"); unset K; echo "$out" | grep -E '"(status|reason|message)"|HTTP' | head -4
    if [ "$plain" -gt 0 ] && grep -q 'HTTP 403' <<<"$out" && grep -q API_KEY_IP_ADDRESS_BLOCKED <<<"$out"; then
      rec PASS "R3 plain key 401 (API keys not supported), bound key 403 API_KEY_IP_ADDRESS_BLOCKED"
    elif [ "$plain" -gt 0 ] && grep -q 'HTTP 200' <<<"$out"; then rec FAIL "R3 the bound key WORKED from here: check its IP restriction"
    else rec FAIL "R3 see the output above"; fi

    say "R4 the trail: R1 and R2 in the Data Access audit log (minutes to arrive)"
    gcloud logging read 'log_id("cloudaudit.googleapis.com/data_access") AND protoPayload.serviceName="aiplatform.googleapis.com"' \
      --project="$P" --freshness=1h --format=json > "$HOME/.gc10-audit.json"
    python3 - "$HOME/.gc10-audit.json" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
for e in rows[:6]:
    p = e.get("protoPayload", {}); a = p.get("authenticationInfo", {})
    deleg = [d.get("firstPartyPrincipal", {}).get("principalEmail", "") for d in a.get("serviceAccountDelegationInfo", [])]
    granted = [z.get("granted") for z in p.get("authorizationInfo", [])]
    print(f'{p.get("methodName","?")} {a.get("principalEmail","?").split("@")[0]:<12} '
          f'via={"you" if deleg else "-":<4} granted={granted} status={p.get("status",{}).get("code",0)}')
print(f"rows: {len(rows)}")
PY
    n=$(python3 -c "import json;print(len(json.load(open('$HOME/.gc10-audit.json'))))"); rm -f "$HOME/.gc10-audit.json"
    if [ "$n" -gt 0 ]; then rec PASS "R4 $n Data Access rows for aiplatform.googleapis.com"
    else rec WAIT "R4 no rows yet: run test again in a few minutes"; fi

    say "R5 re-run the inventory: caching, the key's restrictions, who holds Agent Platform User"
    c=$(cache); echo "cacheConfig: $c"
    gcloud services api-keys describe "$(key_name)" --format="value(restrictions.apiTargets[0].service,restrictions.serverKeyRestrictions.allowedIps)"
    gcloud projects get-iam-policy "$P" --flatten="bindings[].members" --filter="bindings.role=roles/aiplatform.user" \
      --format="value(bindings.members)"
    if grep -q '"disableCache": true' <<<"$c"; then rec PASS "R5 caching off, key restricted, one AI caller"
    else rec FAIL "R5 cacheConfig: $c"; fi

    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    echo "WAIT means Google Cloud has not caught up yet (IAM a few minutes, audit logs a few minutes)."
    ;;

  down)
    repo; load
    say "Delete the key, the binding, both accounts and the budget; caching back on; Data Access logs back off"
    for kn in gc10-build gc10-bound; do
      k=$(key_name $kn); [ -z "$k" ] || gcloud services api-keys delete "$k" --project="$P" --quiet 2>&1 | tail -1
    done
    gcloud projects remove-iam-policy-binding "$P" --member="serviceAccount:$CALLER" --role="roles/aiplatform.user" \
      --condition=None --format="value(etag)" >/dev/null 2>&1 || true
    for SA in "$CALLER" "$NOBODY"; do gcloud iam service-accounts delete "$SA" --project="$P" --quiet 2>/dev/null || true; done
    for b in $(gcloud billing budgets list --billing-account="$BA" --filter='displayName="gc10-build alerts"' --format="value(name)"); do
      gcloud billing budgets delete "$b" --quiet; done
    echo "PATCH cacheConfig: HTTP $(set_cache false)"
    audit_logs off
    rm -f "$ENVFILE"
    echo "Done. Deleted API keys can be restored for 30 days; deleted service accounts for 30 days (undelete)."
    ;;

  tf)
    repo; load
    need_terraform
    printf 'GC10_PROJECT=%s\n' "$P" > "$ENVFILE"
    # Terraform's project and billing lookups need these first (a new project has them off: our 12 Nov run)
    gcloud services enable cloudresourcemanager.googleapis.com cloudbilling.googleapis.com billingbudgets.googleapis.com iam.googleapis.com \
      --project="$P"
    cd "$REPO/labs/gc10/terraform"
    terraform init -input=false >/dev/null
    terraform "${2:-apply}" -input=false -auto-approve -var "project=$P" -var "me=$ME"
    ;;

  *) sed -n '2,9p' "$0"; exit 1;;
esac
