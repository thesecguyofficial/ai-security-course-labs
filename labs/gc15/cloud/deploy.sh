#!/usr/bin/env bash
# GC15 in one go: a private endpoint for an open model (GUIDED-BUILD.md Parts A to G), the proof, and the teardown.
#
#   bash deploy.sh up      # A: three service accounts, a KMS key, a bucket, an image repo, a private network
#                          # B: the serving image (Cloud Build), pinned by digest, its vulnerability scan
#                          # C: Qwen/Qwen3-0.6B downloaded here, scanned, hashed, uploaded and registered
#                          # D: a Private Service Connect endpoint with your key, the auto-undeploy job FIRST, then
#                          #    the deployment (20 to 40 minutes), predict-only access for the app, the PSC address
#   bash deploy.sh test    # E: a VM inside the network calls three tickets privately; you call the public host; the
#                          #    Data Access trail. Each prints PASS, WAIT or FAIL
#   bash deploy.sh rrlog   # F: request-response logging on (100%) into a BigQuery dataset, one more call, the row
#   bash deploy.sh down    # G: undeploy, then delete everything (the key ring stays: Google never deletes them)
#   bash deploy.sh tf apply|destroy   # Part A, the endpoint and the audit logs from terraform/, then the rest of `up`
#
# COST: the deployed model bills every hour it's deployed, called or not (e2-standard-4: about $0.15 an hour in
# us-central1). The auto-undeploy job undeploys it 60 minutes after `up` starts the deployment. Run `down` today.
# Runs in Google Cloud Shell in the project you're signed in to; downloads the course labs repo into ~/tsg-labs.
set -euo pipefail

ENVFILE="$HOME/.gc15.env"
REPO="$HOME/tsg-labs"
VENV="$HOME/.gc15-venv"
MODEL_REPO="${GC15_HF_MODEL:-Qwen/Qwen3-0.6B}"
DEPLOYED_ID=150101
say() { printf '\n== %s\n' "$*"; }
for t in gcloud bq python3 git curl; do command -v $t >/dev/null || { echo "Needs $t (Cloud Shell has it)."; exit 1; }; done

repo() {
  if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only 2>/dev/null || true
  else git clone -q --depth 1 https://github.com/thesecguyofficial/ai-security-course-labs "$REPO"; fi
  LAB="$REPO/labs/gc15"
}
load() {
  # shellcheck source=/dev/null
  if [ -z "${GC15_PROJECT:-}" ] && [ -f "$ENVFILE" ]; then . "$ENVFILE"; fi
  P="${GC15_PROJECT:-$(gcloud config get project 2>/dev/null)}"
  [ -n "$P" ] || { echo "No project: gcloud config set project PROJECT_ID"; exit 1; }
  R="${GC15_REGION:-us-central1}"; Z="$R-a"
  PN=$(gcloud projects describe "$P" --format="value(projectNumber)")
  API="https://$R-aiplatform.googleapis.com/v1/projects/$P/locations/$R"
  KEY="projects/$P/locations/$R/keyRings/tsg-gc15/cryptoKeys/tsg-gc15-ai"
  RUNTIME="tsg-gc15-runtime@$P.iam.gserviceaccount.com"; APP="tsg-gc15-app@$P.iam.gserviceaccount.com"
  TEARDOWN="tsg-gc15-teardown@$P.iam.gserviceaccount.com"
  IMG="$R-docker.pkg.dev/$P/tsg-gc15/summariser"
  gcloud config set project "$P" >/dev/null 2>&1
}
save() { printf 'GC15_PROJECT=%s\nGC15_REGION=%s\nENDPOINT_ID=%s\nMODEL_ID=%s\nIMAGE=%s\n' \
           "$P" "$R" "${ENDPOINT_ID:-}" "${MODEL_ID:-}" "${IMAGE:-}" > "$ENVFILE"; }
exists() { "$@" >/dev/null 2>&1; }
tok() { gcloud auth print-access-token; }
wait_op() {   # wait_op <operation name>, up to 20 minutes
  local i d
  for i in $(seq 1 120); do
    d=$(curl -s -H "Authorization: Bearer $(tok)" "https://$R-aiplatform.googleapis.com/v1/$1")
    grep -q '"done": true' <<<"$d" && { grep -q '"error"' <<<"$d" && echo "${d:0:500}"; return 0; }
    sleep 10
  done
  echo "still running after 20 minutes: $1"
}
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
audit_logs() {   # $1 on|off: DATA_READ for aiplatform.googleapis.com, every other setting kept
  gcloud projects get-iam-policy "$P" --format=json > "$HOME/.gc15-policy.json"
  python3 - "$HOME/.gc15-policy.json" "$1" <<'PY'
import json, sys
f, mode = sys.argv[1:]; p = json.load(open(f))
cfgs = [c for c in p.get("auditConfigs", []) if c.get("service") != "aiplatform.googleapis.com"]
if mode == "on":
    cfgs.append({"service": "aiplatform.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]})
p["auditConfigs"] = cfgs
json.dump(p, open(f, "w"))
PY
  gcloud projects set-iam-policy "$P" "$HOME/.gc15-policy.json" --format="value(etag)" >/dev/null
  rm -f "$HOME/.gc15-policy.json"
}

case "${1:-}" in
  up)
    repo; load; save
    echo "Project: $P   Region: $R   Model: $MODEL_REPO"
    say "A1 APIs"
    gcloud services enable aiplatform.googleapis.com compute.googleapis.com artifactregistry.googleapis.com \
      cloudbuild.googleapis.com cloudkms.googleapis.com cloudscheduler.googleapis.com storage.googleapis.com \
      containerscanning.googleapis.com bigquery.googleapis.com
    say "A2 Three service accounts, each with one job; the teardown one may only undeploy"
    for sa in tsg-gc15-runtime tsg-gc15-app tsg-gc15-teardown; do
      exists gcloud iam service-accounts describe "$sa@$P.iam.gserviceaccount.com" ||
        gcloud iam service-accounts create "$sa" --display-name="GC15 lab $sa"
    done
    for role in "tsgGc15Undeploy aiplatform.endpoints.undeploy,aiplatform.endpoints.get" "tsgGc15PredictOnly aiplatform.endpoints.predict"; do
      set -- $role
      case "$(gcloud iam roles describe "$1" --project="$P" --format='value(deleted)' 2>/dev/null || echo none)" in
        True) gcloud iam roles undelete "$1" --project="$P" --format="value(name)";;
        none) gcloud iam roles create "$1" --project="$P" --title="GC15 $1" --permissions="$2" --stage=GA --format="value(name)";;
      esac
    done
    gcloud projects add-iam-policy-binding "$P" --member="serviceAccount:$TEARDOWN" \
      --role="projects/$P/roles/tsgGc15Undeploy" --condition=None --format="value(etag)" >/dev/null
    say "A3 A Cloud KMS key, and Agent Platform's service agent may use it"
    exists gcloud kms keyrings describe tsg-gc15 --location="$R" || gcloud kms keyrings create tsg-gc15 --location="$R"
    exists gcloud kms keys describe tsg-gc15-ai --keyring=tsg-gc15 --location="$R" ||
      gcloud kms keys create tsg-gc15-ai --keyring=tsg-gc15 --location="$R" --purpose=encryption
    on=$(gcloud kms keys versions list --key=tsg-gc15-ai --keyring=tsg-gc15 --location="$R" --filter="state=ENABLED" \
      --format="value(name)")
    [ -n "$on" ] || gcloud kms keys versions create --key=tsg-gc15-ai --keyring=tsg-gc15 --location="$R" --primary --format="value(name)"
    gcloud beta services identity create --service=aiplatform.googleapis.com --format="value(email)" 2>/dev/null || true
    gcloud kms keys add-iam-policy-binding tsg-gc15-ai --keyring=tsg-gc15 --location="$R" \
      --member="serviceAccount:service-$PN@gcp-sa-aiplatform.iam.gserviceaccount.com" \
      --role=roles/cloudkms.cryptoKeyEncrypterDecrypter --format="value(etag)" >/dev/null
    say "A4 A private model bucket, an image repository, and a network with no internet route"
    exists gcloud storage buckets describe "gs://$P-tsg-gc15-models" ||
      gcloud storage buckets create "gs://$P-tsg-gc15-models" --location="$R" --uniform-bucket-level-access --public-access-prevention
    exists gcloud artifacts repositories describe tsg-gc15 --location="$R" ||
      gcloud artifacts repositories create tsg-gc15 --repository-format=docker --location="$R"
    exists gcloud compute networks describe tsg-gc15-vpc || gcloud compute networks create tsg-gc15-vpc --subnet-mode=custom
    exists gcloud compute networks subnets describe tsg-gc15-subnet --region="$R" ||
      gcloud compute networks subnets create tsg-gc15-subnet --network=tsg-gc15-vpc --region="$R" --range=10.15.0.0/24
    say "B The serving image: Cloud Build, then pinned by digest and its scan (5 to 10 minutes)"
    if ! exists gcloud artifacts docker images describe "$IMG:lab-1"; then
      gcloud builds submit "$LAB/cloud/serve" --region="$R" --tag="$IMG:lab-1" --quiet 2>&1 | tail -3
    fi
    IMAGE=$(gcloud artifacts docker images describe "$IMG:lab-1" --format='value(image_summary.fully_qualified_digest)')
    echo "   $IMAGE"; save
    gcloud artifacts docker images describe "$IMAGE" --show-package-vulnerability --format=json 2>/dev/null |
      python3 -c 'import json,sys,collections
d=json.load(sys.stdin); v=d.get("package_vulnerability_summary",{}).get("vulnerabilities",{})
print("   vulnerabilities by severity:", {k: len(x) for k, x in v.items()} or "none reported yet (the scan can take minutes)")' || true
    say "C The model: download here, scan before anything else touches it, hash, upload, register"
    if [ -z "${MODEL_ID:-}" ]; then
      [ -d "$VENV" ] || python3 -m venv "$VENV"
      "$VENV/bin/pip" install -q huggingface_hub
      MD="$HOME/.gc15-model"
      # A run that stopped after the download keeps the folder: reuse it instead of fetching 1.4 GiB again.
      [ -f "$MD/model.safetensors" ] && echo "   reusing the download in $MD" || {
      # Progress bars on: with --quiet our run (12 Nov 2026) sat silent for over 10 minutes and looked stuck. Plain HTTPS
      # (no Xet) keeps the transfer simple to follow; the 1.4 GiB upload after it ran at about 2 MiB/s.
      HF_HUB_DISABLE_XET=1 "$VENV/bin/hf" download "$MODEL_REPO" --local-dir "$MD" >/dev/null; }
      rm -rf "$MD/.cache"
      python3 "$LAB/model_files.py" scan "$MD" | tail -4
      python3 "$LAB/model_files.py" scan "$MD" | grep -q "SAFE FORMATS ONLY" || { echo "Not safe formats only: stopping."; exit 1; }
      LIC=$(python3 -c 'import re,sys; t=open(sys.argv[1]).read(); m=re.search(r"^license:\s*([\w.-]+)", t, re.M); print(re.sub(r"[^a-z0-9_-]", "_", (m.group(1) if m else "unknown").lower()))' "$MD/README.md" 2>/dev/null || echo unknown)
      # Label values allow only lowercase letters, digits, "_" and "-": apache-2.0 is recorded as apache-2_0.
      LABELS=$(python3 "$LAB/model_files.py" manifest "$MD" | python3 -c 'import json,sys; print(",".join(f"{k}={v}" for k,v in json.load(sys.stdin).items()))')
      echo "   licence (from the model card): $LIC"
      gcloud storage rsync "$MD" "gs://$P-tsg-gc15-models/qwen3-0.6b/v1/" --recursive --checksums-only --quiet   # skips files already there
      gcloud ai models upload --region="$R" --display-name=tsg-gc15-summariser --container-image-uri="$IMAGE" \
        --artifact-uri="gs://$P-tsg-gc15-models/qwen3-0.6b/v1/" --container-ports=8080 --container-predict-route=/predict \
        --container-health-route=/health --labels="licence=$LIC,$LABELS" 2>&1 | tail -6
      MODEL_ID=$(gcloud ai models list --region="$R" --filter='displayName=tsg-gc15-summariser' --format='value(name)')
      MODEL_ID=$(basename "${MODEL_ID%%$'\n'*}")
      # Registration failed: keep the download so the next run doesn't fetch and upload it again.
      [ -n "$MODEL_ID" ] || { echo "Model registration failed (above). The download stays in $MD for the next run."; exit 1; }
      rm -rf "$MD"; save
    fi
    echo "   model $MODEL_ID"
    say "D1 A Private Service Connect endpoint, encrypted with your key, open to this project only"
    if [ -z "${ENDPOINT_ID:-}" ]; then
      sed -e "s/PROJECT_ID/$P/g" -e "s#locations/us-central1#locations/$R#" "$LAB/cloud/requests/create-endpoint.json" > "$HOME/.gc15-ep.json"
      op=$(curl -s -X POST -H "Authorization: Bearer $(tok)" -H "Content-Type: application/json" -d @"$HOME/.gc15-ep.json" "$API/endpoints" |
        python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("name") or json.dumps(d)[:400])')
      rm -f "$HOME/.gc15-ep.json"; echo "   $op"; [[ "$op" == projects/* ]] || exit 1
      wait_op "$op"
      ENDPOINT_ID=$(sed -E 's#.*/endpoints/([0-9]+)/operations/.*#\1#' <<<"$op"); save
    fi
    echo "   endpoint $ENDPOINT_ID"
    say "D2 The auto-undeploy job, BEFORE the deployment: it undeploys 60 minutes from now"
    WHEN=$(date -u -d '+60 min' '+%M %H %d %m')
    sed "s/DEPLOYED_MODEL_ID/$DEPLOYED_ID/" "$LAB/cloud/requests/undeploy-schedule-body.json" > "$HOME/.gc15-undeploy.json"
    gcloud scheduler jobs delete tsg-gc15-undeploy --location="$R" --quiet >/dev/null 2>&1 || true
    gcloud scheduler jobs create http tsg-gc15-undeploy --location="$R" --schedule="$WHEN *" --time-zone=Etc/UTC \
      --uri="$API/endpoints/$ENDPOINT_ID:undeployModel" --http-method=POST --headers=Content-Type=application/json \
      --message-body-from-file="$HOME/.gc15-undeploy.json" --oauth-service-account-email="$TEARDOWN" --format="value(schedule)"
    rm -f "$HOME/.gc15-undeploy.json"
    say "D3 Deploy, as the role-free runtime account, access logging on (20 to 40 minutes)"
    dms=$(gcloud ai endpoints describe "$ENDPOINT_ID" --region="$R" --format='value(deployedModels[].id)')
    if [[ "$dms" != *"$DEPLOYED_ID"* ]]; then
      gcloud ai endpoints deploy-model "$ENDPOINT_ID" --region="$R" --model="$MODEL_ID" --display-name=tsg-gc15-summariser \
        --deployed-model-id="$DEPLOYED_ID" --machine-type=e2-standard-4 --min-replica-count=1 --max-replica-count=1 \
        --service-account="$RUNTIME" --enable-access-logging 2>&1 | tail -3
    fi
    say "D4 Only the app account may call this endpoint (a role on the endpoint, not the project)"
    curl -s -o /dev/null -w "   setIamPolicy: HTTP %{http_code}\n" -X POST -H "Authorization: Bearer $(tok)" -H "Content-Type: application/json" \
      -d "{\"policy\": {\"bindings\": [{\"role\": \"projects/$P/roles/tsgGc15PredictOnly\", \"members\": [\"serviceAccount:$APP\"]}]}}" \
      "https://$R-aiplatform.googleapis.com/v1beta1/projects/$P/locations/$R/endpoints/$ENDPOINT_ID:setIamPolicy"
    say "D5 Your network's door to it: an internal address and a forwarding rule to the service attachment"
    # The service attachment exists only once a model is deployed, and sits on the deployed model, not on the
    # endpoint's privateServiceConnectConfig (empty in our run, 12 Nov 2026).
    SA_URI=$(gcloud ai endpoints describe "$ENDPOINT_ID" --region="$R" --format='value(deployedModels[0].privateEndpoints.serviceAttachment)')
    [ -n "$SA_URI" ] || { echo "No service attachment on the endpoint yet: is the model deployed?"; exit 1; }
    echo "   service attachment ${SA_URI##*/}"
    exists gcloud compute addresses describe tsg-gc15-psc-ip --region="$R" ||
      gcloud compute addresses create tsg-gc15-psc-ip --region="$R" --subnet=tsg-gc15-subnet
    exists gcloud compute forwarding-rules describe tsg-gc15-psc --region="$R" ||
      gcloud compute forwarding-rules create tsg-gc15-psc --region="$R" --network=tsg-gc15-vpc \
        --address=tsg-gc15-psc-ip --target-service-attachment="$SA_URI"
    gcloud compute forwarding-rules describe tsg-gc15-psc --region="$R" --format='table(IPAddress,pscConnectionStatus)'
    say "D6 Data Access audit logs on for Agent Platform"
    audit_logs on
    say "Done. Then: bash deploy.sh test   (the auto-undeploy job fires at $(date -u -d '+60 min' +%H:%M) UTC)"
    ;;

  test)
    repo; load
    PASS=0; RES=()
    rec() { RES+=("$1  $2"); [ "$1" = PASS ] && PASS=$((PASS+1)); return 0; }
    IP=$(gcloud compute forwarding-rules describe tsg-gc15-psc --region="$R" --format='value(IPAddress)')
    say "E1, E3, E4 A VM inside the network (no external IP, the app account) sends three tickets to $IP"
    python3 - "$LAB/cloud/requests" "$P" "$R" "$ENDPOINT_ID" "$IP" > "$HOME/.gc15-client.sh" <<'PY'
import json, pathlib, sys
d, p, r, ep, ip = sys.argv[1:]
url = f"http://{ip}/v1/projects/{p}/locations/{r}/endpoints/{ep}:predict"
lines = ["#!/bin/bash",
         'T=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | sed -E \'s/.*"access_token":"([^"]+)".*/\\1/\')']
for name in ("normal", "personal-data", "injection"):
    body = pathlib.Path(d, f"predict-{name}.json").read_text().strip().replace("'", "'\\''")
    lines.append(f"echo \"TSG-GC15 {name}: $(curl -s -m 60 -w ' HTTP %{{http_code}}' -H \"Authorization: Bearer $T\" "
                 f"-H 'Content-Type: application/json' -d '{body}' {url} | head -c 400)\" > /dev/ttyS0")
print("\n".join(lines))
PY
    if exists gcloud compute instances describe tsg-gc15-client --zone="$Z"; then
      gcloud compute instances add-metadata tsg-gc15-client --zone="$Z" --metadata-from-file=startup-script="$HOME/.gc15-client.sh" >/dev/null
      gcloud compute instances reset tsg-gc15-client --zone="$Z" --quiet >/dev/null
    else
      gcloud compute instances create tsg-gc15-client --zone="$Z" --machine-type=e2-micro --subnet=tsg-gc15-subnet \
        --no-address --service-account="$APP" --scopes=cloud-platform --image-family=debian-12 --image-project=debian-cloud \
        --metadata-from-file=startup-script="$HOME/.gc15-client.sh" --format="value(name)"
    fi
    echo "   waiting 120 s for it to boot and call..."; sleep 120
    out=$(gcloud compute instances get-serial-port-output tsg-gc15-client --zone="$Z" 2>/dev/null | grep "TSG-GC15" | tail -3 || true)
    echo "$out" | cut -c1-300
    if grep -q "normal:.*HTTP 200" <<<"$out"; then rec PASS "E1 a summary through the private address, as the app account"
    elif [ -z "$out" ]; then rec WAIT "E1 nothing on the serial port yet: run test again"
    else rec FAIL "E1 see the line above"; fi
    if grep -q "injection:.*HTTP 200" <<<"$out"; then rec PASS "E4 the injected ticket went straight to the model: nothing screened it (GC12 would)"
    else rec WAIT "E4 no answer yet"; fi
    say "E2 The same call from Cloud Shell, through the public API host (a PSC endpoint: expect an error)"
    code=$(curl -s -o "$HOME/.gc15-pub.json" -w "%{http_code}" -H "Authorization: Bearer $(tok)" -H "Content-Type: application/json" \
      -d @"$LAB/cloud/requests/predict-normal.json" "$API/endpoints/$ENDPOINT_ID:predict")
    echo "   HTTP $code  $(head -c 300 "$HOME/.gc15-pub.json")"; rm -f "$HOME/.gc15-pub.json"
    if [ "$code" != 200 ]; then rec PASS "E2 the public path is closed ($code)"
    else rec FAIL "E2 the public host answered 200"; fi
    say "E5 The trail: Predict in the Data Access log"
    rows=$(gcloud logging read 'protoPayload.serviceName="aiplatform.googleapis.com" AND protoPayload.methodName:"Predict"' \
      --freshness=30m --limit=4 --format="value(protoPayload.authenticationInfo.principalEmail,protoPayload.requestMetadata.callerIp,protoPayload.status.code)" || true)
    echo "$rows" | sed 's/^/   /'
    if grep -q "tsg-gc15-app" <<<"$rows"; then rec PASS "E5 the app's calls are in the Data Access log"
    else rec WAIT "E5 no rows yet (minutes): run test again"; fi
    say "Result: $PASS of 5 passed"
    printf '  %s\n' "${RES[@]}"
    ;;

  rrlog)
    repo; load
    say "F Request-response logging: 100% of calls into tsg_gc15_audit.requests (a second copy of every prompt)"
    exists bq show "$P:tsg_gc15_audit" || bq --location="$R" mk --dataset "$P:tsg_gc15_audit" >/dev/null
    curl -s -o /dev/null -w "   PATCH endpoint: HTTP %{http_code}\n" -X PATCH -H "Authorization: Bearer $(tok)" -H "Content-Type: application/json" \
      -d "{\"predictRequestResponseLoggingConfig\": {\"enabled\": true, \"samplingRate\": 1.0, \"bigqueryDestination\": {\"outputUri\": \"bq://$P.tsg_gc15_audit.requests\"}}}" \
      "$API/endpoints/$ENDPOINT_ID?updateMask=predictRequestResponseLoggingConfig"
    echo "   now run: bash deploy.sh test   then, a few minutes later:"
    echo "   bq query --use_legacy_sql=false 'SELECT logging_time, LEFT(TO_JSON_STRING(request_payload), 160) FROM \`$P.tsg_gc15_audit.requests\` ORDER BY logging_time DESC LIMIT 3'"
    ;;

  down)
    repo; load
    say "G Undeploy first (an endpoint must be empty before it can be deleted), then everything else"
    if [ -n "${ENDPOINT_ID:-}" ]; then
      for dm in $(gcloud ai endpoints describe "$ENDPOINT_ID" --region="$R" --format='value(deployedModels[].id)' 2>/dev/null | tr ';' ' '); do
        gcloud ai endpoints undeploy-model "$ENDPOINT_ID" --region="$R" --deployed-model-id="$dm" --quiet; done
    fi
    gcloud compute instances delete tsg-gc15-client --zone="$Z" --quiet 2>/dev/null || true
    gcloud compute forwarding-rules delete tsg-gc15-psc --region="$R" --quiet 2>/dev/null || true
    gcloud compute addresses delete tsg-gc15-psc-ip --region="$R" --quiet 2>/dev/null || true
    [ -z "${ENDPOINT_ID:-}" ] || gcloud ai endpoints delete "$ENDPOINT_ID" --region="$R" --quiet 2>/dev/null || true
    for m in $(gcloud ai models list --region="$R" --filter='displayName=tsg-gc15-summariser' --format='value(name)' 2>/dev/null); do
      gcloud ai models delete "$m" --region="$R" --quiet; done
    gcloud scheduler jobs delete tsg-gc15-undeploy --location="$R" --quiet 2>/dev/null || true
    gcloud storage rm --recursive "gs://$P-tsg-gc15-models" --quiet 2>/dev/null || true
    gcloud artifacts repositories delete tsg-gc15 --location="$R" --quiet 2>/dev/null || true
    gcloud compute networks subnets delete tsg-gc15-subnet --region="$R" --quiet 2>/dev/null || true
    gcloud compute networks delete tsg-gc15-vpc --quiet 2>/dev/null || true
    bq rm -r -f -d "$P:tsg_gc15_audit" 2>/dev/null || true
    for v in $(gcloud kms keys versions list --key=tsg-gc15-ai --keyring=tsg-gc15 --location="$R" \
               --filter="state=ENABLED OR state=DISABLED" --format="value(name)" 2>/dev/null); do
      gcloud kms keys versions destroy "${v##*/}" --key=tsg-gc15-ai --keyring=tsg-gc15 --location="$R" --format="value(state)"; done
    gcloud projects remove-iam-policy-binding "$P" --member="serviceAccount:$TEARDOWN" \
      --role="projects/$P/roles/tsgGc15Undeploy" --condition=None --format="value(etag)" >/dev/null 2>&1 || true
    for sa in tsg-gc15-runtime tsg-gc15-app tsg-gc15-teardown; do
      gcloud iam service-accounts delete "$sa@$P.iam.gserviceaccount.com" --quiet 2>/dev/null || true; done
    for r in tsgGc15Undeploy tsgGc15PredictOnly; do gcloud iam roles delete "$r" --project="$P" --quiet >/dev/null 2>&1 || true; done
    audit_logs off
    rm -f "$ENVFILE" "$HOME/.gc15-client.sh"
    echo "Done. The key ring tsg-gc15 stays (Google never deletes key rings); destroyed versions are free after 30 days."
    ;;

  tf)
    repo; load; need_terraform
    gcloud services enable cloudresourcemanager.googleapis.com iam.googleapis.com serviceusage.googleapis.com
    TFD="$LAB/terraform"; TFV=(-var "project_id=$P" -var "region=$R")
    (cd "$TFD" && terraform init -input=false >/dev/null)
    if [ "${2:-apply}" = destroy ]; then
      say "First what Terraform doesn't own: the deployment, the model, the VM, the forwarding rule, the job"
      EP=$(cd "$TFD" && terraform output -raw endpoint_id 2>/dev/null || true)
      if [ -n "$EP" ]; then
        dms=$(gcloud ai endpoints describe "$EP" --region="$R" --format='value(deployedModels[].id)' 2>/dev/null || true)
        for dm in ${dms//;/ }; do gcloud ai endpoints undeploy-model "$EP" --region="$R" --deployed-model-id="$dm" --quiet; done
      fi
      for m in $(gcloud ai models list --region="$R" --filter='displayName=tsg-gc15-summariser' --format='value(name)' 2>/dev/null); do
        gcloud ai models delete "$m" --region="$R" --quiet; done
      gcloud compute instances delete tsg-gc15-client --zone="$Z" --quiet 2>/dev/null || true
      gcloud compute forwarding-rules delete tsg-gc15-psc --region="$R" --quiet 2>/dev/null || true
      gcloud compute addresses delete tsg-gc15-psc-ip --region="$R" --quiet 2>/dev/null || true
      gcloud scheduler jobs delete tsg-gc15-undeploy --location="$R" --quiet 2>/dev/null || true
      bq rm -r -f -d "$P:tsg_gc15_audit" 2>/dev/null || true
      say "terraform destroy"
      (cd "$TFD" && terraform destroy -input=false -auto-approve "${TFV[@]}") ||
        { echo "terraform destroy failed: trying once more in 30 s"; sleep 30; (cd "$TFD" && terraform destroy -input=false -auto-approve "${TFV[@]}"); }
      for v in $(gcloud kms keys versions list --key=tsg-gc15-ai --keyring=tsg-gc15 --location="$R" \
                 --filter="state=ENABLED OR state=DISABLED" --format="value(name)" 2>/dev/null); do
        gcloud kms keys versions destroy "${v##*/}" --key=tsg-gc15-ai --keyring=tsg-gc15 --location="$R" --format="value(state)"; done
      rm -f "$ENVFILE" "$HOME/.gc15-client.sh"
      echo "Done. The key ring stays (Google never deletes key rings); Terraform let go of it."
    else
      # Key rings and keys can't be deleted, so an earlier run left them behind: adopt them, and give the key an
      # enabled version (an earlier teardown destroyed the old ones).
      if gcloud kms keys describe tsg-gc15-ai --keyring=tsg-gc15 --location="$R" >/dev/null 2>&1; then
        st=$(cd "$TFD" && terraform state list 2>/dev/null || true)
        [[ "$st" == *google_kms_key_ring.gc15* ]] ||
          (cd "$TFD" && terraform import -input=false "${TFV[@]}" google_kms_key_ring.gc15 "projects/$P/locations/$R/keyRings/tsg-gc15" >/dev/null)
        [[ "$st" == *google_kms_crypto_key.ai* ]] ||
          (cd "$TFD" && terraform import -input=false "${TFV[@]}" google_kms_crypto_key.ai "$KEY" >/dev/null)
        on=$(gcloud kms keys versions list --key=tsg-gc15-ai --keyring=tsg-gc15 --location="$R" --filter="state=ENABLED" --format="value(name)")
        [ -n "$on" ] || gcloud kms keys versions create --key=tsg-gc15-ai --keyring=tsg-gc15 --location="$R" --primary --format="value(name)"
        echo "Adopted the existing key ring and key tsg-gc15/tsg-gc15-ai"
      fi
      (cd "$TFD" && terraform apply -input=false -auto-approve "${TFV[@]}")
      ENDPOINT_ID=$(cd "$TFD" && terraform output -raw endpoint_id); save
      say "Terraform made Part A, the endpoint and the audit logs; up does the image, the model and the deployment"
      bash "$0" up
    fi
    ;;

  *) sed -n '2,14p' "$0"; exit 1;;
esac
