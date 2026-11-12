#!/usr/bin/env bash
# GC11 in one go: the hardened Helpdesk model access from lesson 11.6 (GUIDED-BUILD.md), its proof, and its teardown.
#
#   bash deploy.sh up        # predict-only identities, private VPC + PSC endpoint + DNS + egress rules, your own key on
#                            #   BigQuery, cache in memory only, Data Access + request-response logging, test VM
#   bash deploy.sh test      # prove it: Tests 1 to 5 from the guide, each prints PASS, WAIT or FAIL
#   bash deploy.sh trap      # Step 3, the residency trap: the VM calls the eu multi-region endpoint (then `untrap`)
#   bash deploy.sh keyon     # turn the key back on after Test 5
#   bash deploy.sh down      # delete everything (the key ring and key stay: Google never deletes them; v1 destroyed)
#   bash deploy.sh tf apply|destroy   # the Terraform build (labs/gc11/terraform, with the test VM) instead of up/down
#
# Runs in Google Cloud Shell in the project you're signed in to; downloads the course labs repo into ~/tsg-labs.
# Optional before `up`: export GC11_PROJECT=... GC11_REGION=europe-west4 GC11_MODEL=gemini-3.1-flash-lite
# Cost: cents plus a small VM while it runs. Delete it the same day. Use a project you own, never your employer's.
set -euo pipefail

ENVFILE="$HOME/.gc11.env"
REPO="$HOME/tsg-labs"
say() { printf '\n== %s\n' "$*"; }
for t in gcloud bq python3 git curl; do command -v $t >/dev/null || { echo "Needs $t (Cloud Shell has it)."; exit 1; }; done

repo() {
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only 2>/dev/null || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/gc11"
}
load() {
  local r_in="${GC11_REGION:-}" m_in="${GC11_MODEL:-}"   # what you export wins over the saved file
  # shellcheck source=/dev/null
  if [ -z "${GC11_PROJECT:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  GC11_REGION="${r_in:-${GC11_REGION:-}}"; GC11_MODEL="${m_in:-${GC11_MODEL:-}}"
  P="${GC11_PROJECT:-$(gcloud config get project 2>/dev/null)}"
  [ -n "$P" ] || { echo "No project: gcloud config set project PROJECT_ID"; exit 1; }
  R="${GC11_REGION:-europe-west4}"; Z="$R-a"
  MODEL="publishers/google/models/${GC11_MODEL:-gemini-3.1-flash-lite}"
  ME=$(gcloud config get account 2>/dev/null)
  PN=$(gcloud projects describe "$P" --format="value(projectNumber)")
  RUNTIME="chatbot-runtime@$P.iam.gserviceaccount.com"; SUMM="ticket-summariser@$P.iam.gserviceaccount.com"
  ROLE="projects/$P/roles/helpdeskModelCaller"
  KEY="projects/$P/locations/$R/keyRings/helpdesk-eu/cryptoKeys/helpdesk-data"
  gcloud config set project "$P" >/dev/null 2>&1
}
exists() { "$@" >/dev/null 2>&1; }
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
  terraform version | head -1
}
smoke() {   # render the VM's startup script ($1 = regional | eu)
  sed -e "s/\${project}/$P/g" -e "s/\${region}/$R/g" -e "s#\${model}#$MODEL#g" -e 's/%%/%/g' \
    "$LAB/terraform/scripts/smoke_call.sh.tftpl" > "$HOME/.gc11-smoke.sh"
  if [ "${1:-regional}" = eu ]; then
    sed -i -e "s#https://$R-aiplatform.googleapis.com#https://aiplatform.eu.rep.googleapis.com#" \
      -e "s#locations/$R#locations/eu#" -e "s#getent hosts $R-aiplatform.googleapis.com#getent hosts aiplatform.eu.rep.googleapis.com#" \
      "$HOME/.gc11-smoke.sh"
  fi
}
serial() { gcloud compute instances get-serial-port-output helpdesk-vm --zone="$Z" 2>/dev/null | grep TSG-SMOKE | tail -"${1:-4}"; }
audit_logs() {   # $1 on|off: DATA_READ + DATA_WRITE for aiplatform.googleapis.com, everything else untouched
  gcloud projects get-iam-policy "$P" --format=json > "$HOME/.gc11-policy.json"
  python3 - "$HOME/.gc11-policy.json" "$1" <<'PY'
import json, sys
f, mode = sys.argv[1:]; p = json.load(open(f))
cfgs = [c for c in p.get("auditConfigs", []) if c.get("service") != "aiplatform.googleapis.com"]
if mode == "on":
    cfgs.append({"service": "aiplatform.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]})
p["auditConfigs"] = cfgs
json.dump(p, open(f, "w"))
PY
  gcloud projects set-iam-policy "$P" "$HOME/.gc11-policy.json" --format="value(etag)" >/dev/null
  rm -f "$HOME/.gc11-policy.json"
}
cache() {   # $1 = EPHEMERAL (in memory only) | default
  local body="{\"name\": \"projects/$P/cacheConfig\", \"disableCache\": false}"
  [ "$1" = EPHEMERAL ] && body="{\"name\": \"projects/$P/cacheConfig\", \"disableCache\": false, \"retentionConfig\": {\"retentionType\": \"EPHEMERAL\"}}"
  curl -s -o /dev/null -w "%{http_code}" -X PATCH -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json" "https://$R-aiplatform.googleapis.com/v1/projects/$P/cacheConfig" -d "$body"
}

case "${1:-}" in
  up)
    repo; load
    printf 'GC11_PROJECT=%s\nGC11_REGION=%s\n' "$P" "$R" > "$ENVFILE"
    echo "Project: $P   Region: $R   Model: $MODEL"
    say "0 APIs"
    gcloud services enable aiplatform.googleapis.com bigquery.googleapis.com cloudkms.googleapis.com \
      compute.googleapis.com dns.googleapis.com iam.googleapis.com servicedirectory.googleapis.com
    say "1a Two service accounts, no keys, a predict-only custom role"
    for SA in chatbot-runtime ticket-summariser; do
      exists gcloud iam service-accounts describe "$SA@$P.iam.gserviceaccount.com" ||
        gcloud iam service-accounts create "$SA" --display-name="GC11 $SA"
    done
    exists gcloud iam roles describe helpdeskModelCaller --project="$P" ||
      gcloud iam roles create helpdeskModelCaller --project="$P" --title="Helpdesk model caller" \
        --description="Call Agent Platform models. Nothing else." --permissions=aiplatform.endpoints.predict --stage=GA
    for SA in "$RUNTIME" "$SUMM"; do
      gcloud projects add-iam-policy-binding "$P" --role="$ROLE" --member="serviceAccount:$SA" --condition=None \
        --format="value(etag)" >/dev/null
    done
    say "1b Network: no internet route, Google APIs through a PSC endpoint at 10.100.0.2"
    exists gcloud compute networks describe helpdesk-vpc || gcloud compute networks create helpdesk-vpc --subnet-mode=custom
    exists gcloud compute networks subnets describe helpdesk-eu --region="$R" ||
      gcloud compute networks subnets create helpdesk-eu --network=helpdesk-vpc --region="$R" \
        --range=10.10.0.0/24 --enable-private-ip-google-access
    exists gcloud compute addresses describe psc-google-apis --global ||
      gcloud compute addresses create psc-google-apis --global --purpose=PRIVATE_SERVICE_CONNECT \
        --addresses=10.100.0.2 --network=helpdesk-vpc
    exists gcloud compute forwarding-rules describe tsgapis --global ||
      gcloud compute forwarding-rules create tsgapis --global --network=helpdesk-vpc \
        --address=psc-google-apis --target-google-apis-bundle=vpc-sc
    exists gcloud dns managed-zones describe googleapis-private ||
      gcloud dns managed-zones create googleapis-private --dns-name=googleapis.com. --visibility=private \
        --networks=helpdesk-vpc --description="Google APIs through the PSC endpoint"
    exists gcloud dns record-sets describe googleapis.com. --zone=googleapis-private --type=A ||
      gcloud dns record-sets create googleapis.com. --zone=googleapis-private --type=A --ttl=300 --rrdatas=10.100.0.2
    exists gcloud dns record-sets describe "*.googleapis.com." --zone=googleapis-private --type=CNAME ||
      gcloud dns record-sets create "*.googleapis.com." --zone=googleapis-private --type=CNAME --ttl=300 \
        --rrdatas=googleapis.com.
    exists gcloud compute firewall-rules describe deny-all-egress ||
      gcloud compute firewall-rules create deny-all-egress --network=helpdesk-vpc --direction=EGRESS \
        --action=DENY --rules=all --destination-ranges=0.0.0.0/0 --priority=65000
    exists gcloud compute firewall-rules describe allow-google-apis-egress ||
      gcloud compute firewall-rules create allow-google-apis-egress --network=helpdesk-vpc --direction=EGRESS \
        --action=ALLOW --rules=tcp:443 --destination-ranges=10.100.0.2/32 --priority=1000
    say "1c Your key on the data (key rings can't be deleted: an existing one is reused), datasets, cache in memory only"
    exists gcloud kms keyrings describe helpdesk-eu --location="$R" || gcloud kms keyrings create helpdesk-eu --location="$R"
    exists gcloud kms keys describe helpdesk-data --keyring=helpdesk-eu --location="$R" ||
      gcloud kms keys create helpdesk-data --keyring=helpdesk-eu --location="$R" --purpose=encryption \
        --rotation-period=90d --next-rotation-time="$(date -u -d '+90 days' +%Y-%m-%dT00:00:00Z)"
    # a key left over from an earlier run may have only destroyed versions: make sure one version is enabled
    gcloud kms keys versions list --key=helpdesk-data --keyring=helpdesk-eu --location="$R" --filter="state=ENABLED" \
      --format="value(name)" | grep -q . || gcloud kms keys versions create --key=helpdesk-data --keyring=helpdesk-eu \
        --location="$R" --primary --format="value(name)"
    bq show --encryption_service_account --project_id="$P" >/dev/null
    gcloud kms keys add-iam-policy-binding helpdesk-data --keyring=helpdesk-eu --location="$R" \
      --member="serviceAccount:bq-$PN@bigquery-encryption.iam.gserviceaccount.com" \
      --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" --format="value(etag)" >/dev/null
    for DS in helpdesk_tickets ai_logs; do
      exists bq show "$P:$DS" || bq mk --dataset --location="$R" --default_kms_key="$KEY" "$P:$DS"
    done
    bq query --use_legacy_sql=false -q \
      "GRANT \`roles/bigquery.dataViewer\` ON SCHEMA \`$P.helpdesk_tickets\` TO \"serviceAccount:$RUNTIME\"" >/dev/null
    bq query --use_legacy_sql=false -q \
      "GRANT \`roles/bigquery.dataEditor\` ON SCHEMA \`$P.helpdesk_tickets\` TO \"serviceAccount:$SUMM\"" >/dev/null
    echo "cacheConfig (in memory only): HTTP $(cache EPHEMERAL)"
    say "1d Data Access logs (read + write) and request-response logging into ai_logs (v1beta1, Preview)"
    audit_logs on
    rr_out=$(bash "$LAB/terraform/scripts/request_response_logging.sh" on "$P" "$R"); echo "${rr_out:0:300}"
    say "1g The test VM: no external IP, runs as chatbot-runtime, calls Gemini once at boot through the private path"
    smoke regional
    exists gcloud compute instances describe helpdesk-vm --zone="$Z" ||
      gcloud compute instances create helpdesk-vm --zone="$Z" --machine-type=e2-small \
        --subnet=helpdesk-eu --no-address --shielded-secure-boot \
        --service-account="$RUNTIME" --scopes=cloud-platform \
        --image-family=debian-12 --image-project=debian-cloud --metadata-from-file=startup-script="$HOME/.gc11-smoke.sh"
    say "Done. Give the VM two minutes, then: bash deploy.sh test"
    ;;

  test)
    repo; load
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }

    say "Test 1 The VM's private path works, the internet doesn't (its serial port)"
    out=$(serial 4); echo "$out"
    if grep -q 'resolve: 10.100.0.2' <<<"$out" && grep -q 'HTTP 200' <<<"$out" && grep -q 'internet test: 000' <<<"$out"; then
      rec PASS "T1 10.100.0.2, 200 through PSC, internet blocked"
    elif [ -z "$out" ]; then rec WAIT "T1 nothing on the serial port yet: the VM may still be booting (2 minutes)"
    else rec FAIL "T1 see the serial lines above"; fi

    say "Test 2 chatbot-runtime can't deploy anything (you act as it with Token Creator on that one account)"
    gcloud iam service-accounts add-iam-policy-binding "$RUNTIME" --member="user:$ME" \
      --role="roles/iam.serviceAccountTokenCreator" --format="value(etag)" >/dev/null
    for i in $(seq 1 18); do   # Token Creator can take a few minutes to reach the token service
      gcloud auth print-access-token --impersonate-service-account="$RUNTIME" >/dev/null 2>&1 && break; sleep 10; done
    out=$(gcloud ai endpoints create --region="$R" --display-name=should-fail --impersonate-service-account="$RUNTIME" 2>&1 || true)
    echo "$out" | grep -v WARNING | head -3
    if grep -q "aiplatform.endpoints.create" <<<"$out" && grep -qi "denied" <<<"$out"; then
      rec PASS "T2 PERMISSION_DENIED on aiplatform.endpoints.create"
    elif grep -qi "serviceAccountTokenCreator\|getAccessToken" <<<"$out"; then
      rec WAIT "T2 Token Creator still spreading: run test again in a minute"
    else rec FAIL "T2 expected PERMISSION_DENIED on aiplatform.endpoints.create"; fi

    say "Test 3 the same identity over the public path, from Cloud Shell (no perimeter: expect 200)"
    T=$(gcloud auth print-access-token --impersonate-service-account="$RUNTIME" 2>/dev/null || true)
    code=$(curl -s -o "$HOME/.gc11-pub.json" -w "%{http_code}" -X POST -H "Authorization: Bearer $T" \
      -H "Content-Type: application/json" \
      "https://$R-aiplatform.googleapis.com/v1/projects/$P/locations/$R/$MODEL:generateContent" \
      -d '{"contents": [{"role": "user", "parts": [{"text": "Reply with one word: public"}]}], "generationConfig": {"maxOutputTokens": 10}}')
    echo "HTTP $code   $(grep -o '"text": *"[^"]*"' "$HOME/.gc11-pub.json" | head -1)"; rm -f "$HOME/.gc11-pub.json"
    gcloud iam service-accounts remove-iam-policy-binding "$RUNTIME" --member="user:$ME" \
      --role="roles/iam.serviceAccountTokenCreator" --format="value(etag)" >/dev/null 2>&1 || true
    if [ "$code" = 200 ]; then rec PASS "T3 200 from outside: a stolen token works anywhere until a perimeter checks the source"
    else rec FAIL "T3 got $code (with an enforced perimeter that's the point; without one, expected 200)"; fi

    say "Test 4 The trail: who and from where (Data Access log), and what was said (request-response table)"
    gcloud logging read 'log_id("cloudaudit.googleapis.com/data_access") AND protoPayload.serviceName="aiplatform.googleapis.com" AND protoPayload.methodName:"GenerateContent"' \
      --project="$P" --freshness=2h --format=json > "$HOME/.gc11-audit.json"
    python3 - "$HOME/.gc11-audit.json" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
for e in rows[:4]:
    p = e.get("protoPayload", {}); a = p.get("authenticationInfo", {})
    d = "you" if a.get("serviceAccountDelegationInfo") else "-"
    print(f'{p.get("methodName","?").split(".")[-1]:<16} {a.get("principalEmail","?").split("@")[0]:<16} '
          f'callerIp={p.get("requestMetadata",{}).get("callerIp","?"):<16} via={d:<4} {p.get("resourceName","").split("/locations/")[-1][:40]}')
print("data access rows:", len(rows))
PY
    internal=$(python3 -c "import json;r=json.load(open('$HOME/.gc11-audit.json'));print(sum(1 for e in r if e.get('protoPayload',{}).get('requestMetadata',{}).get('callerIp','').startswith('10.10.')))")
    rm -f "$HOME/.gc11-audit.json"
    rr=$(bq query --use_legacy_sql=false --format=csv -q \
      "SELECT COUNT(*) FROM \`$P.ai_logs.request_response_logging\`" 2>/dev/null | tail -1 || echo 0)
    echo "VM calls with an internal callerIp: $internal   request-response rows: ${rr:-0}"
    if [ "$internal" -gt 0 ] && [ "${rr:-0}" -gt 0 ] 2>/dev/null; then rec PASS "T4 internal callerIp in Data Access + a request-response row"
    else rec WAIT "T4 logs not there yet (Data Access: minutes; request-response: minutes after the config, maybe reset the VM)"; fi

    say "Test 5 Your key, switched off: the logged prompts become unreadable"
    st=$(gcloud kms keys versions list --key=helpdesk-data --keyring=helpdesk-eu --location="$R" --format="value(state)" | sort -u | tr '\n' ' ')
    if ! grep -q DISABLED <<<"$st" && [ "${rr:-0}" = 0 ]; then
      rec WAIT "T5 waits for T4's request-response rows (nothing to lock away yet)"
    elif ! grep -q DISABLED <<<"$st"; then
      v=$(gcloud kms keys versions list --key=helpdesk-data --keyring=helpdesk-eu --location="$R" --filter="state=ENABLED" --format="value(name)" | head -1)
      gcloud kms keys versions disable "${v##*/}" --key=helpdesk-data --keyring=helpdesk-eu --location="$R" --format="value(state)"
      rec WAIT "T5 key version disabled just now: BigQuery follows 'within an hour'; run test again (then: bash deploy.sh keyon)"
    else
      out=$(bq query --use_legacy_sql=false -q "SELECT COUNT(*) FROM \`$P.ai_logs.request_response_logging\`" 2>&1 || true)
      echo "$out" | tail -2
      if grep -qi "disabled\|kms" <<<"$out"; then rec PASS "T5 query refused: the key is disabled (bash deploy.sh keyon to restore)"
      else rec WAIT "T5 key disabled, BigQuery still reads (it can take up to an hour)"; fi
    fi

    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    echo "WAIT means Google Cloud has not caught up yet. Step 3, the residency trap: bash deploy.sh trap"
    ;;

  trap|untrap)
    repo; load
    if [ "$1" = trap ]; then smoke eu; say "The VM now calls aiplatform.eu.rep.googleapis.com (locations/eu)"
    else smoke regional; say "The VM's regional script is back"; fi
    gcloud compute instances add-metadata helpdesk-vm --zone="$Z" --metadata-from-file=startup-script="$HOME/.gc11-smoke.sh"
    gcloud compute instances reset helpdesk-vm --zone="$Z" --quiet
    echo "Waiting 120 s for the VM to boot and call once..."; sleep 120
    serial 4
    [ "$1" = trap ] && echo "Anything but 200 is the trap: the private path breaks. Put it back: bash deploy.sh untrap"
    ;;

  bundle)   # swap the PSC endpoint's target bundle (vpc-sc | all-apis), restart the VM, show its call
    repo; load
    B="${2:?vpc-sc or all-apis}"
    gcloud compute forwarding-rules delete tsgapis --global --quiet
    gcloud compute forwarding-rules create tsgapis --global --network=helpdesk-vpc --address=psc-google-apis \
      --target-google-apis-bundle="$B"
    gcloud compute instances reset helpdesk-vm --zone="$Z" --quiet
    echo "Waiting 120 s for the VM to boot and call once..."; sleep 120
    gcloud compute instances get-serial-port-output helpdesk-vm --zone="$Z" 2>/dev/null | grep -A6 "generateContent HTTP" | tail -7
    serial 4
    ;;

  models)   # which Gemini models answer on this region's endpoint (as you, from Cloud Shell)
    repo; load
    for m in ${2:-gemini-3.1-flash-lite gemini-3-flash gemini-2.5-flash-lite gemini-2.5-flash gemini-2.0-flash-lite-001}; do
      case "$R" in global) H=aiplatform.googleapis.com;; eu|us) H="aiplatform.$R.rep.googleapis.com";; *) H="$R-aiplatform.googleapis.com";; esac
      c=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
        -H "Content-Type: application/json" \
        "https://$H/v1/projects/$P/locations/$R/publishers/google/models/$m:generateContent" \
        -d '{"contents":[{"role":"user","parts":[{"text":"Reply with OK"}]}],"generationConfig":{"maxOutputTokens":5}}')
      echo "$R  $m  HTTP $c"
    done
    ;;

  rep)   # EXPERIMENT: a PSC endpoint for the eu multi-region host (aiplatform.eu.rep.googleapis.com) in the subnet
    repo; load
    gcloud services enable networkconnectivity.googleapis.com
    exists gcloud network-connectivity regional-endpoints describe aiplatform-eu --region="$R" ||
      gcloud network-connectivity regional-endpoints create aiplatform-eu --region="$R" --address=10.10.0.10 \
        --network="projects/$P/global/networks/helpdesk-vpc" \
        --subnetwork="projects/$P/regions/$R/subnetworks/helpdesk-eu" --target-google-api=aiplatform.eu.rep.googleapis.com
    exists gcloud dns managed-zones describe aiplatform-eu-rep ||
      gcloud dns managed-zones create aiplatform-eu-rep --dns-name=aiplatform.eu.rep.googleapis.com. --visibility=private \
        --networks=helpdesk-vpc --description="Agent Platform eu multi-region through its PSC endpoint"
    exists gcloud dns record-sets describe aiplatform.eu.rep.googleapis.com. --zone=aiplatform-eu-rep --type=A ||
      gcloud dns record-sets create aiplatform.eu.rep.googleapis.com. --zone=aiplatform-eu-rep --type=A --ttl=300 --rrdatas=10.10.0.10
    exists gcloud compute firewall-rules describe allow-aiplatform-eu-egress ||
      gcloud compute firewall-rules create allow-aiplatform-eu-egress --network=helpdesk-vpc --direction=EGRESS \
        --action=ALLOW --rules=tcp:443 --destination-ranges=10.10.0.10/32 --priority=1000
    gcloud network-connectivity regional-endpoints describe aiplatform-eu --region="$R" --format="value(address,targetGoogleApi,state)" 2>&1 | tail -2
    smoke eu
    gcloud compute instances add-metadata helpdesk-vm --zone="$Z" --metadata-from-file=startup-script="$HOME/.gc11-smoke.sh"
    gcloud compute instances reset helpdesk-vm --zone="$Z" --quiet
    echo "Waiting 120 s for the VM to boot and call the eu endpoint once..."; sleep 120
    gcloud compute instances get-serial-port-output helpdesk-vm --zone="$Z" 2>/dev/null | grep -A6 "TSG-SMOKE" | grep -v google_ | tail -9
    ;;

  serial)
    repo; load
    gcloud compute instances get-serial-port-output helpdesk-vm --zone="$Z" 2>/dev/null | grep -A9 "generateContent HTTP" | head -12
    ;;

  keyon)
    repo; load
    for v in $(gcloud kms keys versions list --key=helpdesk-data --keyring=helpdesk-eu --location="$R" --filter="state=DISABLED" --format="value(name)"); do
      gcloud kms keys versions enable "${v##*/}" --key=helpdesk-data --keyring=helpdesk-eu --location="$R" --format="value(state)"
    done
    ;;

  down)
    repo; load
    say "Request-response logging off, then everything this script made, in dependency order"
    bash "$LAB/terraform/scripts/request_response_logging.sh" off "$P" "$R" >/dev/null 2>&1 || true
    gcloud compute instances delete helpdesk-vm --zone="$Z" --quiet 2>/dev/null || true
    gcloud compute firewall-rules delete deny-all-egress allow-google-apis-egress --quiet 2>/dev/null || true
    gcloud dns record-sets delete "*.googleapis.com." --zone=googleapis-private --type=CNAME 2>/dev/null || true
    gcloud dns record-sets delete googleapis.com. --zone=googleapis-private --type=A 2>/dev/null || true
    gcloud dns managed-zones delete googleapis-private --quiet 2>/dev/null || true
    gcloud compute forwarding-rules delete tsgapis --global --quiet 2>/dev/null || true
    gcloud compute addresses delete psc-google-apis --global --quiet 2>/dev/null || true
    gcloud compute networks subnets delete helpdesk-eu --region="$R" --quiet 2>/dev/null || true
    gcloud compute networks delete helpdesk-vpc --quiet 2>/dev/null || true
    bq rm -r -f -d "$P:ai_logs" 2>/dev/null || true
    bq rm -r -f -d "$P:helpdesk_tickets" 2>/dev/null || true
    for v in $(gcloud kms keys versions list --key=helpdesk-data --keyring=helpdesk-eu --location="$R" \
               --filter="state=ENABLED OR state=DISABLED" --format="value(name)" 2>/dev/null); do
      gcloud kms keys versions destroy "${v##*/}" --key=helpdesk-data --keyring=helpdesk-eu --location="$R" --format="value(state)"
    done
    for SA in "$RUNTIME" "$SUMM"; do
      gcloud projects remove-iam-policy-binding "$P" --role="$ROLE" --member="serviceAccount:$SA" --condition=None \
        --format="value(etag)" >/dev/null 2>&1 || true
      gcloud iam service-accounts delete "$SA" --quiet 2>/dev/null || true
    done
    gcloud iam roles delete helpdeskModelCaller --project="$P" --quiet >/dev/null 2>&1 || true
    echo "cacheConfig back to the default: HTTP $(cache default)"
    audit_logs off
    rm -f "$ENVFILE" "$HOME/.gc11-smoke.sh"
    echo "Done. The key ring and key stay (Google never deletes them); destroyed versions cost nothing after 30 days."
    echo "The custom role is soft-deleted for 7 days (gcloud iam roles undelete brings it back)."
    ;;

  tf)
    repo; load; need_terraform
    gcloud services enable cloudresourcemanager.googleapis.com iam.googleapis.com serviceusage.googleapis.com
    printf 'GC11_PROJECT=%s\nGC11_REGION=%s\n' "$P" "$R" > "$ENVFILE"
    cd "$LAB/terraform"
    terraform init -input=false >/dev/null
    if [ "${2:-apply}" = destroy ]; then
      bash scripts/request_response_logging.sh off "$P" "$R" >/dev/null 2>&1 || true
      terraform destroy -input=false -auto-approve -var "project_id=$P" -var "region=$R" -var create_test_vm=true
    else
      terraform apply -input=false -auto-approve -var "project_id=$P" -var "region=$R" -var create_test_vm=true
      rr_out=$(bash scripts/request_response_logging.sh on "$P" "$R"); echo "${rr_out:0:300}"
      echo "cacheConfig (in memory only): HTTP $(cache EPHEMERAL)"   # the Data Access logs are in logging.tf
      echo "Then: bash ../cloud/deploy.sh test"
    fi
    ;;

  *) sed -n '2,11p' "$0"; exit 1;;
esac
