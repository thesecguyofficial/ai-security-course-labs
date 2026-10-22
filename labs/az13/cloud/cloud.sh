#!/usr/bin/env bash
# AZ13 guided build (OPTIONAL): Azure AI Search (Free) + Foundry IQ knowledge base + a Foundry prompt agent in YOUR OWN
# subscription. GUIDED-BUILD.md explains every command. Needs: Azure CLI (az login), Python 3.10+, and for the agent
# steps: pip install "azure-ai-projects>=2.0.0" azure-identity
# Usage: ./cloud.sh cost | up | index | kb | agent | ask | ask-nohdr | ask-approval | down
# Not run by the course team (no Azure subscription in the build): treat the output as yours to verify.
set -euo pipefail
cd "$(dirname "$0")"
: "${AZ13_NAME:?set AZ13_NAME, e.g. export AZ13_NAME=az13-ab1234 (lowercase, globally unique: it becomes <name>.services.ai.azure.com and srch-<name>.search.windows.net)}"
: "${AZ13_REGION:?set AZ13_REGION to a region that offers agentic retrieval and your model (GUIDED-BUILD.md Step 0)}"
RG="rg-$AZ13_NAME"
SEARCH="srch-$AZ13_NAME"
PROJECT="helpdesk"
MODEL="${AZ13_MODEL:-gpt-4.1-mini}"
MODEL_VERSION="${AZ13_MODEL_VERSION:-2025-04-14}"
PROJ_API="2025-06-01"            # ARM api-version for accounts/projects (stable; defined in azure-rest-api-specs)
mkdir -p .state

me()         { az ad signed-in-user show --query id -o tsv; }
search_id()  { az search service show -n "$SEARCH" -g "$RG" --query id -o tsv; }
foundry_id() { az cognitiveservices account show -n "$AZ13_NAME" -g "$RG" --query id -o tsv; }

case "${1:-}" in
  cost)
    cat <<'TXT'
What this guided build bills (estimate):
  - Azure AI Search on the FREE tier: $0. One free service per subscription; 50 MB, 3 indexes, 3 knowledge bases.
    Agentic retrieval uses the free plan's monthly token allowance by default (no LLM is attached to this
    knowledge base: minimal reasoning effort).
  - Foundry resource and project: no hourly charge for the resource itself; you pay model tokens.
  - Model tokens: G5-G6 send about ten short requests to the agent. Expect a few US cents. Check your model's
    price in the Azure pricing calculator before you start.
  - Microsoft Entra groups: free.
Set a budget alert first (lab AZ10). Tear down today with ./cloud.sh down.
TXT
    ;;

  up)          # G1: resource group, search (Free, keys off), Foundry resource + project + model, roles
    ME="$(me)"
    az group create -n "$RG" -l "$AZ13_REGION" -o none
    az search service create -n "$SEARCH" -g "$RG" -l "$AZ13_REGION" --sku free --disable-local-auth true -o none
    az role assignment create --assignee "$ME" --role "Search Service Contributor" --scope "$(search_id)" -o none
    az role assignment create --assignee "$ME" --role "Search Index Data Contributor" --scope "$(search_id)" -o none
    az cognitiveservices account create -n "$AZ13_NAME" -g "$RG" -l "$AZ13_REGION" --kind AIServices --sku S0 \
      --custom-domain "$AZ13_NAME" --allow-project-management true --assign-identity --yes -o none
    az resource update --ids "$(foundry_id)" --set properties.disableLocalAuth=true -o none   # keys off: Entra ID only
    az rest --method put --url "https://management.azure.com$(foundry_id)/projects/$PROJECT?api-version=$PROJ_API" \
      --body "{\"location\": \"$AZ13_REGION\", \"identity\": {\"type\": \"SystemAssigned\"}, \"properties\": {}}" -o none
    az cognitiveservices account deployment create -g "$RG" -n "$AZ13_NAME" --deployment-name helpdesk-chat \
      --model-name "$MODEL" --model-version "$MODEL_VERSION" --model-format OpenAI --sku-name GlobalStandard --sku-capacity 1 -o none
    # Foundry User (formerly Azure AI User), by role definition ID as Microsoft recommends during the rename
    az role assignment create --assignee "$ME" --role 53ca6127-db72-4b80-b1b0-d745d6d5456d --scope "$(foundry_id)" -o none
    PMI="$(az rest --method get --url "https://management.azure.com$(foundry_id)/projects/$PROJECT?api-version=$PROJ_API" --query identity.principalId -o tsv)"
    # the project's identity READS the index: Search Index Data Reader, nothing more
    az role assignment create --assignee-object-id "$PMI" --assignee-principal-type ServicePrincipal \
      --role "Search Index Data Reader" --scope "$(search_id)" -o none
    echo "PROJECT_ENDPOINT=https://$AZ13_NAME.services.ai.azure.com/api/projects/$PROJECT" | tee .state/env
    echo "SEARCH_ENDPOINT=https://$SEARCH.search.windows.net" | tee -a .state/env
    echo "PROJECT_ID=$(foundry_id)/projects/$PROJECT" | tee -a .state/env
    echo "Done. Role assignments for managed identities can take a while to apply: if G3/G5 return 403, wait and retry."
    ;;

  index)       # G2: two groups (you're in one), the index, four documents, three direct queries
    ME="$(me)"
    STAFF="$(az ad group create --display-name tsg-az13-staff --mail-nickname tsg-az13-staff --query id -o tsv)"
    HR="$(az ad group create --display-name tsg-az13-hr --mail-nickname tsg-az13-hr --query id -o tsv)"
    az ad group member add --group "$STAFF" --member-id "$ME"
    { echo "STAFF_GROUP=$STAFF"; echo "HR_GROUP=$HR"; } >> .state/env
    python3 build.py index
    ;;

  kb)    python3 build.py kb ;;
  agent) python3 build.py agent ;;
  ask)   python3 build.py ask "${PICK:-}" ;;
  ask-nohdr)    python3 build.py ask-nohdr ;;
  ask-approval) python3 build.py ask-approval ;;

  down)        # G8: everything this build created
    python3 build.py down || true
    set -a; . ./.state/env 2>/dev/null || true; set +a
    [ -n "${STAFF_GROUP:-}" ] && az ad group delete --group "$STAFF_GROUP" || true
    [ -n "${HR_GROUP:-}" ] && az ad group delete --group "$HR_GROUP" || true
    az cognitiveservices account delete -n "$AZ13_NAME" -g "$RG" 2>/dev/null || true
    az cognitiveservices account purge -n "$AZ13_NAME" -g "$RG" -l "$AZ13_REGION" 2>/dev/null || true   # frees the name
    az group delete -n "$RG" --yes --no-wait
    rm -rf .state
    echo "Deleting $RG in the background. Check tomorrow: az group show -n $RG (expect ResourceGroupNotFound)."
    ;;

  *) echo "usage: $0 cost | up | index | kb | agent | ask | ask-nohdr | ask-approval | down"; exit 1 ;;
esac
