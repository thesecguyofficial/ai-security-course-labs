#!/usr/bin/env bash
# AZ12 cloud path (OPTIONAL): real guardrails in YOUR OWN subscription. README Step 9 explains every command.
# Needs: Azure CLI (az login), Python 3.10+. guardrail-* also need the AZ11 build to be up (AZ11_NAME, its terraform/).
# Usage: ./cloud.sh cost | cs-up | cs-try | cs-suite | blocklist-up | guardrail-up | guardrail-probe | evidence | down
# Not run by the course team (no Azure subscription in the build): treat the output as yours to verify.
set -euo pipefail
cd "$(dirname "$0")"
: "${AZ12_NAME:?set AZ12_NAME, e.g. export AZ12_NAME=az12-cs-ab1234 (globally unique: it becomes <name>.cognitiveservices.azure.com)}"
REGION="${AZ12_REGION:-eastus}"          # Prompt Shields must be available there: check Microsoft's region table
RG="rg-$AZ12_NAME"
API="2024-10-01"                         # api-version of Microsoft's RAI policies REST reference (reads)
BAPI="2024-10-01"                        # the version Microsoft's blocklist how-to uses for raiBlocklists + raiPolicies bodies
RAPI="2025-12-01"                        # reads of RAI policies: first stable schema that lists PreToolCall/PostToolCall sources
POLICY="contoso-helpdesk-v2"
BLOCKLIST="contoso-codenames"

foundry_id() { : "${AZ11_NAME:?set AZ11_NAME to the name you used in lab AZ11}"; az cognitiveservices account show -n "$AZ11_NAME" -g "rg-$AZ11_NAME" --query id -o tsv; }
tfout() { "${TF:-terraform}" -chdir=../../az11/terraform output -raw "$1"; }

case "${1:-}" in
  cost)
    cat <<'TXT'
What this path bills:
  - Content Safety resource on the FREE tier (F0): Microsoft's pricing page lists 5,000 text records a month free
    (Prompt Shields, protected material and groundedness are counted as text). The suite uses well under 100.
    A text record is up to 1,000 characters on the Standard tier; F0 has a 5 requests-per-second limit.
  - The guardrail on your AZ11 deployment: the Microsoft pages used in this lab list no separate guardrail meter;
    you pay tokens. For streaming, Microsoft says a filtered prompt (400) is charged for prompt evaluation, and
    finish_reason content_filter for tokens generated before filtering. guardrail-probe: 5 short requests (G5), 1 more in G6.
  - The AZ11 build itself (private endpoint, VM, disk) bills hourly while it exists: see lab AZ11 `make cost`.
Set a budget alert first (lab AZ10). Tear down with ./cloud.sh down, then lab AZ11's make down.
TXT
    ;;
  cs-up)       # a free-tier Content Safety resource, Entra ID only
    az cognitiveservices account list-kinds -o tsv | grep -qx ContentSafety || { echo "kind ContentSafety not offered to you"; exit 1; }
    az group create -n "$RG" -l "$REGION" -o none
    az cognitiveservices account create -n "$AZ12_NAME" -g "$RG" -l "$REGION" --kind ContentSafety --sku F0 \
      --custom-domain "$AZ12_NAME" --yes -o none
    ID="$(az cognitiveservices account show -n "$AZ12_NAME" -g "$RG" --query id -o tsv)"
    az resource update --ids "$ID" --set properties.disableLocalAuth=true -o none      # keys off: Entra ID only
    az role assignment create --assignee "$(az ad signed-in-user show --query id -o tsv)" \
      --role "Cognitive Services User" --scope "$ID" -o none
    echo "Created $AZ12_NAME (F0, keys disabled). Role assignments can take up to 5 minutes to apply: wait, then ./cloud.sh cs-suite"
    ;;
  cs-try)      # four single calls, raw JSON printed: read the fields yourself (README Step 9, G2)
    python3 cs_suite.py --endpoint "https://$AZ12_NAME.cognitiveservices.azure.com" --examples
    ;;
  cs-suite)    # the 28-request suite against the real classifiers
    python3 cs_suite.py --endpoint "https://$AZ12_NAME.cognitiveservices.azure.com"
    ;;
  blocklist-up)   # a custom blocklist with one term, on the AZ11 resource (REST shape from Microsoft's blocklist how-to)
    FID="$(foundry_id)"
    az rest --method put --url "https://management.azure.com$FID/raiBlocklists/$BLOCKLIST?api-version=$BAPI" \
      --body '{"properties": {"description": "Contoso internal code names (lab AZ12)"}}' -o none
    az rest --method put --url "https://management.azure.com$FID/raiBlocklists/$BLOCKLIST/raiBlocklistItems/nightjar?api-version=$BAPI" \
      --body '{"properties": {"pattern": "NIGHTJAR", "isRegex": false}}' -o none
    echo "Blocklist $BLOCKLIST created with 1 term. Microsoft: new terms can take about 5 minutes to take effect."
    ;;
  guardrail-up)   # contoso-helpdesk-v2 as a real RAI policy on the AZ11 resource, assigned to helpdesk-chat
    FID="$(foundry_id)"
    python3 - "$POLICY" "$BLOCKLIST" "${VIOLENCE_INPUT:-Medium}" > .rai-body.json <<'PY'
import json, sys
p = json.load(open("../fixes/rai-policies.json"))["policies"][sys.argv[1]]["properties"]
skip = {"PII", "Indirect Attack Spotlighting"}   # set these two in the portal (README Step 9, G3)
filters = []
for f in p["contentFilters"]:
    if f["name"] in skip:
        continue
    f = {k: v for k, v in f.items() if not k.startswith("x-")}
    if f["name"] == "Violence" and f["source"] == "Prompt":
        f["severityThreshold"] = sys.argv[3]     # G6: VIOLENCE_INPUT=Low make guardrail-up
    filters.append(f)
# Body shape from the ARM schema for api-version 2024-10-01 (azure-rest-api-specs, RaiPolicyProperties):
# contentFilters + customBlocklists [{blocklistName, blocking, source}]. The blocklist how-to page shows an older
# "completionBlocklists" field that the 2024-10-01 schema doesn't define, so it isn't used here.
print(json.dumps({"properties": {"basePolicyName": p["basePolicyName"], "mode": p["mode"], "contentFilters": filters,
                                 "customBlocklists": [{"blocklistName": sys.argv[2], "blocking": True, "source": "Completion"}]}}))
PY
    az rest --method put --url "https://management.azure.com$FID/raiPolicies/$POLICY?api-version=$BAPI" --body @.rai-body.json -o none
    az rest --method get --url "https://management.azure.com$FID/deployments/helpdesk-chat?api-version=$BAPI" > .dep.json
    python3 - "$POLICY" > .dep-body.json <<'PY'
import json, sys
d = json.load(open(".dep.json"))
props = {k: v for k, v in d["properties"].items() if k in ("model", "versionUpgradeOption")}
props["raiPolicyName"] = sys.argv[1]
print(json.dumps({"sku": d["sku"], "properties": props}))
PY
    az rest --method put --url "https://management.azure.com$FID/deployments/helpdesk-chat?api-version=$BAPI" --body @.dep-body.json -o none
    rm -f .rai-body.json .dep.json .dep-body.json
    echo "helpdesk-chat now uses $POLICY (Violence on input: ${VIOLENCE_INPUT:-Medium}). Next: make guardrail-probe"
    ;;
  guardrail-probe)   # suite cases from INSIDE the VNet (the AZ11 resource has public access disabled)
    : "${AZ11_NAME:?set AZ11_NAME}"
    CASES="$(PICK="${PICK:-B01,A01,A05,A12,A14}" python3 - <<'PY'
import base64, json, os, sys
sys.path.insert(0, "..")
import helpdesk, run_suite
pick = set(os.environ["PICK"].split(","))
out = [{"id": c["id"], "user": c["user"],
        "docs": [helpdesk.kb_doc(k)["text"] for k in c.get("kb", [])] + [helpdesk.ticket_doc(t)["text"] for t in c.get("tickets", [])]}
       for c in run_suite.load_cases() if c["id"] in pick]
print(base64.b64encode(json.dumps(out).encode()).decode())
PY
)"
    sed -e "s/__NAME__/$AZ11_NAME/" -e "s/__CLIENT_ID__/$(tfout jump_identity_client_id)/" \
        -e "s/__DEPLOYMENT__/helpdesk-chat/" -e "s#__CASES_B64__#$CASES#" probe_guardrail.py > .probe.py
    printf '#!/bin/bash\ncat > /tmp/probe.py <<"EOF"\n%s\nEOF\npython3 /tmp/probe.py\n' "$(cat .probe.py)" > .probe.sh
    az vm run-command invoke -g "rg-$AZ11_NAME" -n "$(tfout jump_vm_name)" --command-id RunShellScript --scripts @.probe.sh -o json \
      | python3 -c 'import json,sys; [print(v.get("message", "")) for v in json.load(sys.stdin).get("value", [])]'
    rm -f .probe.py .probe.sh
    ;;
  evidence)    # what an auditor asks for, read back from Azure
    FID="$(foundry_id)"
    az rest --method get --url "https://management.azure.com$FID/deployments?api-version=$API" \
      --query "value[].{deployment:name, guardrail:properties.raiPolicyName}" -o table
    az rest --method get --url "https://management.azure.com$FID/raiPolicies/$POLICY?api-version=$RAPI" \
      --query "properties.{mode:mode, filters:contentFilters[?enabled].[name, source, severityThreshold, blocking], blocklists:customBlocklists}" -o json
    az cognitiveservices account show -n "$AZ12_NAME" -g "$RG" --query "{kind:kind, sku:sku.name, keysDisabled:properties.disableLocalAuth}" -o table
    ;;
  down)
    if [ -n "${AZ11_NAME:-}" ] && FID="$(foundry_id 2>/dev/null)"; then
      az rest --method get --url "https://management.azure.com$FID/deployments/helpdesk-chat?api-version=$API" > .dep.json
      python3 -c 'import json; d=json.load(open(".dep.json")); p={k:v for k,v in d["properties"].items() if k in ("model","versionUpgradeOption")}; p["raiPolicyName"]="Microsoft.DefaultV2"; print(json.dumps({"sku":d["sku"],"properties":p}))' > .dep-body.json
      az rest --method put --url "https://management.azure.com$FID/deployments/helpdesk-chat?api-version=$API" --body @.dep-body.json -o none || true
      az rest --method delete --url "https://management.azure.com$FID/raiPolicies/$POLICY?api-version=$BAPI" -o none || true
      az rest --method delete --url "https://management.azure.com$FID/raiBlocklists/$BLOCKLIST?api-version=$BAPI" -o none || true
      rm -f .dep.json .dep-body.json
    fi
    az cognitiveservices account delete -n "$AZ12_NAME" -g "$RG" 2>/dev/null || true
    az cognitiveservices account purge -n "$AZ12_NAME" -g "$RG" -l "$REGION" 2>/dev/null || true   # Microsoft: a deleted name can't be reused for 48 hours unless purged
    az group delete -n "$RG" --yes --no-wait 2>/dev/null || true
    echo "Done: helpdesk-chat is back on Microsoft.DefaultV2; $POLICY, $BLOCKLIST and $AZ12_NAME are gone. Now run lab AZ11's make down if you're finished."
    ;;
  *) echo "usage: $0 cost | cs-up | cs-try | cs-suite | blocklist-up | guardrail-up | guardrail-probe | evidence | down"; exit 2 ;;
esac
