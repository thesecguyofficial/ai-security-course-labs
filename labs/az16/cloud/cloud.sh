#!/usr/bin/env bash
# AZ16 guided build helper (GUIDED-BUILD.md). Portal first: make the Foundry resource, the workspace, the diagnostic
# setting, the Defender plan, continuous export and the alert rule in the portal; this script does only what the
# portal can't do quickly (a model deployment by CLI, the four requests, the guardrail switch, the activity log export).
# Usage: AZ16_NAME=... bash cloud/cloud.sh check|deploy|activity|ask|annotate|block|down
set -euo pipefail
: "${AZ16_NAME:?export AZ16_NAME=az16-<yours> first}"
RG=${RG:-rg-$AZ16_NAME}; HERE=$(cd "$(dirname "$0")" && pwd)
FID=$(az cognitiveservices account show -n "$AZ16_NAME" -g "$RG" --query id -o tsv)
EP=https://$AZ16_NAME.openai.azure.com
LAW=$(az monitor log-analytics workspace show -g "$RG" -n "law-$AZ16_NAME" --query id -o tsv 2>/dev/null || true)
API=2024-10-01

ask() {   # one prompt with user_security_context; prints the status, the filter result and the answer's first line
  TOKEN=$(az account get-access-token --resource https://cognitiveservices.azure.com --query accessToken -o tsv)
  python3 - "$1" > /tmp/az16-body.json <<'PY'
import json, sys, os
body = json.load(open(os.path.join(os.environ["HERE"], "chat-with-user-context.json")))
body.pop("_about")
body["messages"][1]["content"] = sys.argv[1]
print(json.dumps(body))
PY
  curl -s -o /tmp/az16-out.json -w "HTTP %{http_code}\n" "$EP/openai/deployments/chat/chat/completions?api-version=2025-04-01-preview" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @/tmp/az16-body.json
  python3 - <<'PY'
import json
d = json.load(open("/tmp/az16-out.json"))
if "error" in d:
    e = d["error"]; inner = (e.get("innererror") or {}).get("content_filter_result", {})
    print("  error:", e.get("code"), {k: v for k, v in inner.items() if isinstance(v, dict) and (v.get("filtered") or v.get("detected"))})
else:
    pf = d.get("prompt_filter_results", [{}])[0].get("content_filter_results", {})
    print("  prompt filters:", {k: v for k, v in pf.items() if isinstance(v, dict) and (v.get("filtered") or v.get("detected"))} or "nothing flagged")
    c = d["choices"][0] if d.get("choices") else {}
    text = ((c.get("message") or {}).get("content") or "").strip()
    print("  answer:", (text.splitlines() or ["(empty, finish_reason " + str(c.get("finish_reason")) + ")"])[0][:110])
PY
}
export HERE

case "${1:?check|deploy|activity|ask|annotate|block|down}" in
check)
  az cognitiveservices account show -n "$AZ16_NAME" -g "$RG" --query "{name:name, kind:kind, sku:sku.name, endpoint:properties.endpoint}" -o json
  az security pricing show -n AI --query "{plan:name, tier:pricingTier, extensions:extensions[].{name:name, on:isEnabled}}" -o json
  ;;
deploy)
  echo "== A the model: gpt-5-mini 2025-08-07, Global Standard, deployment name chat"
  az cognitiveservices account deployment create -g "$RG" -n "$AZ16_NAME" --deployment-name chat \
    --model-name gpt-5-mini --model-version 2025-08-07 --model-format OpenAI --sku-name GlobalStandard --sku-capacity 100 \
    --query "{deployment:name, model:properties.model.name, state:properties.provisioningState, guardrail:properties.raiPolicyName}" -o json
  ;;
activity)
  echo "== the subscription's Activity log to the workspace (AzureActivity is free to ingest; D03 needs it)"
  az monitor diagnostic-settings subscription create -n to-law-az16 --location "${AZ16_REGION:-eastus}" --workspace "$LAW" \
    --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true}]' -o none
  echo "   done"
  ;;
ask)
  i=0
  grep -v '^#' "$HERE/requests.txt" | while IFS= read -r p; do
    i=$((i+1)); [ $i -gt 1 ] && sleep 20   # Azure counts max_completion_tokens against the per-minute quota up front
    echo "== request $i: $p"; ask "$p"
  done
  ;;
ask2|ask3)
  n=${1#ask}; echo "== request $n again"; ask "$(grep -v '^#' "$HERE/requests.txt" | sed -n ${n}p)"
  echo "   raw error body (if any):"; python3 -c "import json; d=json.load(open('/tmp/az16-out.json')); print('  ', json.dumps(d.get('error',{}))[:400])"
  ;;
annotate|block)
  [ "$1" = annotate ] && B=false || B=true
  echo "== guardrail tsg-az16-$1: Prompt Shields for user prompts (jailbreak) blocking=$B; harm filters stay at Medium, blocking"
  BODY=$(python3 - "$B" <<'PY'
import json, sys
b = sys.argv[1] == "true"
f = [{"name": n, "enabled": True, "blocking": True, "severityThreshold": "Medium", "source": s}
     for s in ("Prompt", "Completion") for n in ("Hate", "Sexual", "Violence", "Selfharm")]
f += [{"name": "Jailbreak", "enabled": True, "blocking": b, "source": "Prompt"},
      {"name": "Indirect Attack", "enabled": True, "blocking": True, "source": "Prompt"}]
print(json.dumps({"properties": {"basePolicyName": "Microsoft.DefaultV2", "mode": "Default", "contentFilters": f}}))
PY
)
  az rest --method put --url "https://management.azure.com$FID/raiPolicies/tsg-az16-$1?api-version=$API" --body "$BODY" -o none
  az rest --method get --url "https://management.azure.com$FID/deployments/chat?api-version=$API" > /tmp/az16-dep-now.json
  python3 - "$1" > /tmp/az16-dep.json <<'PY'
import json, sys
d = json.load(open("/tmp/az16-dep-now.json"))
print(json.dumps({"sku": d["sku"], "properties": {"model": d["properties"]["model"], "raiPolicyName": "tsg-az16-" + sys.argv[1]}}))
PY
  az rest --method put --url "https://management.azure.com$FID/deployments/chat?api-version=$API" --body @/tmp/az16-dep.json \
    --query "{deployment:name, guardrail:properties.raiPolicyName}" -o json
  ;;
down)
  echo "== Part F: Defender for AI services back to Free, the activity export off, then the resource group"
  az security pricing create -n AI --tier free --query "{plan:name, tier:pricingTier}" -o json
  az monitor diagnostic-settings subscription delete -n to-law-az16 --yes 2>/dev/null || true
  az group delete -n "$RG" --yes
  echo "   done; remove continuous export in the portal (Environment settings > subscription > Continuous export)"
  ;;
*) echo "usage: cloud.sh check|deploy|activity|ask|ask2|annotate|block|down"; exit 2;;
esac
