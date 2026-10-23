#!/usr/bin/env bash
# AZ14 guided build (OPTIONAL): the TSG Helpdesk as a Foundry HOSTED agent in YOUR OWN subscription.
# GUIDED-BUILD.md explains every command. Needs: Azure CLI 2.80+ (az login), Python 3.10+, and
#   pip install "azure-ai-projects>=2.3.0" azure-identity requests "mcp<2"
# No Docker needed: the image is built in the cloud with `az acr build`.
# Usage: ./cloud.sh cost | up | kb | mcp | toolbox | agent | grant | ask | grant-wide | grant-narrow | direct-call | down
# Not run by the course team (no Azure subscription in the build): treat the output as yours to verify.
set -euo pipefail
cd "$(dirname "$0")"
: "${AZ14_NAME:?set AZ14_NAME, e.g. export AZ14_NAME=az14ab12 (lowercase letters and digits only, 3-20 chars: it names the storage account and registry too)}"
: "${AZ14_REGION:?set AZ14_REGION to a region that offers hosted agents and your model (GUIDED-BUILD.md Step 0)}"
RG="rg-$AZ14_NAME"
ST="st$AZ14_NAME"
ACR="cr$AZ14_NAME"
PROJECT="helpdesk"
MODEL="${AZ14_MODEL:-gpt-4.1-mini}"
MODEL_VERSION="${AZ14_MODEL_VERSION:-2025-04-14}"
PROJ_API="2025-06-01"            # ARM api-version for accounts/projects (as in lab AZ13)
mkdir -p .state

me()         { az ad signed-in-user show --query id -o tsv; }
foundry_id() { az cognitiveservices account show -n "$AZ14_NAME" -g "$RG" --query id -o tsv; }
st_id()      { az storage account show -n "$ST" -g "$RG" --query id -o tsv; }
acr_id()     { az acr show -n "$ACR" -g "$RG" --query id -o tsv; }

case "${1:-}" in
  cost)
    cat <<'TXT'
What this guided build bills (estimates; check the Azure pricing calculator for your region):
  - Hosted agent sandbox: billed for CPU and memory only while a session is active; compute is released after
    the idle timeout (15 minutes by default). Smallest size here: 0.5 vCPU / 1 GiB. A one-hour session: cents.
  - Azure Container Registry, Basic tier: a small daily charge while it exists, plus one cloud build (az acr build).
  - Storage account (Standard LRS, four tiny blobs): well under a cent.
  - Model tokens: about ten short requests, a few US cents.
  - Your MCP server on Azure Container Apps (consumption, scales to zero, 0.25 vCPU): within the monthly free
    grant for most subscriptions; check the Container Apps pricing page.
  - Foundry resource and toolbox: no hourly charge for the resource itself.
  - Application Insights, only if you connect it (G7): data ingestion.
Expect under US$1 if you tear down the same day. Set a budget alert first (lab AZ10). Tear down: ./cloud.sh down
TXT
    ;;

  up)          # G1: resource group, Foundry resource + project + model, storage, registry, roles
    ME="$(me)"
    az group create -n "$RG" -l "$AZ14_REGION" -o none
    az cognitiveservices account create -n "$AZ14_NAME" -g "$RG" -l "$AZ14_REGION" --kind AIServices --sku S0 \
      --custom-domain "$AZ14_NAME" --allow-project-management true --assign-identity --yes -o none
    az resource update --ids "$(foundry_id)" --set properties.disableLocalAuth=true -o none   # Entra ID only
    az rest --method put --url "https://management.azure.com$(foundry_id)/projects/$PROJECT?api-version=$PROJ_API" \
      --body "{\"location\": \"$AZ14_REGION\", \"identity\": {\"type\": \"SystemAssigned\"}, \"properties\": {}}" -o none
    az cognitiveservices account deployment create -g "$RG" -n "$AZ14_NAME" --deployment-name helpdesk-chat \
      --model-name "$MODEL" --model-version "$MODEL_VERSION" --model-format OpenAI --sku-name GlobalStandard --sku-capacity 1 -o none
    # You deploy agents: Foundry Project Manager at project scope (Microsoft: needed "to deploy a hosted agent")
    az role assignment create --assignee "$ME" --role "Foundry Project Manager" --scope "$(foundry_id)/projects/$PROJECT" -o none
    az storage account create -n "$ST" -g "$RG" -l "$AZ14_REGION" --sku Standard_LRS --kind StorageV2 \
      --allow-blob-public-access false --allow-shared-key-access false --min-tls-version TLS1_2 -o none
    az role assignment create --assignee "$ME" --role "Storage Blob Data Contributor" --scope "$(st_id)" -o none
    az acr create -n "$ACR" -g "$RG" -l "$AZ14_REGION" --sku Basic -o none
    az role assignment create --assignee "$ME" --role "Container Registry Repository Writer" --scope "$(acr_id)" -o none
    PMI="$(az rest --method get --url "https://management.azure.com$(foundry_id)/projects/$PROJECT?api-version=$PROJ_API" --query identity.principalId -o tsv)"
    # the PROJECT identity pulls the image. Not the agent identity, and not AcrPull if the newer role works for you.
    az role assignment create --assignee-object-id "$PMI" --assignee-principal-type ServicePrincipal \
      --role "Container Registry Repository Reader" --scope "$(acr_id)" -o none
    {
      echo "PROJECT_ENDPOINT=https://$AZ14_NAME.services.ai.azure.com/api/projects/$PROJECT"
      echo "STORAGE=$ST"
      echo "IMAGE=$ACR.azurecr.io/helpdesk-agent:1"
      echo "PROJECT_SCOPE=$(foundry_id)/projects/$PROJECT"
    } | tee .state/env
    echo "Done. Role assignments can take a few minutes to apply: if a later step returns 403, wait and retry."
    ;;

  kb)          # G2: the 'RAG store': two containers, four blobs (one with a lab-placeholder injection)
    for c in kb hr-exports; do az storage container create -n "$c" --account-name "$ST" --auth-mode login -o none; done
    for f in KB-1001.md KB-1002.md KB-1007.md; do
      az storage blob upload --account-name "$ST" --auth-mode login -c kb -f "kb/$f" -n "$f" --overwrite -o none
    done
    az storage blob upload --account-name "$ST" --auth-mode login -c hr-exports -f kb/paybands-2027.csv \
      -n paybands-2027.csv --overwrite -o none
    az storage blob list --account-name "$ST" --auth-mode login -c kb --query "[].name" -o tsv
    ;;

  mcp)         # G3a: YOUR MCP actions server on Container Apps, its key in a Container Apps secret
    KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    az acr build -r "$ACR" -t helpdesk-mcp:1 --platform linux/amd64 mcp
    az containerapp env create -n "cae-$AZ14_NAME" -g "$RG" -l "$AZ14_REGION" -o none
    az containerapp create -n "ca-$AZ14_NAME" -g "$RG" --environment "cae-$AZ14_NAME" \
      --image "$ACR.azurecr.io/helpdesk-mcp:1" --registry-server "$ACR.azurecr.io" --registry-identity system \
      --ingress external --target-port 8000 --cpu 0.25 --memory 0.5Gi --min-replicas 0 --max-replicas 1 \
      --secrets "mcpkey=$KEY" --env-vars "MCP_API_KEY=secretref:mcpkey" -o none
    FQDN="$(az containerapp show -n "ca-$AZ14_NAME" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)"
    { echo "MCP_URL=https://$FQDN/mcp"; echo "MCP_KEY=$KEY"; } >> .state/env     # .state is git-ignored
    echo "MCP server: https://$FQDN/mcp (401 without x-api-key). Logs: az containerapp logs show -n ca-$AZ14_NAME -g $RG"
    ;;

  toolbox)       python3 build.py toolbox ;;
  toolbox-v2)    python3 build.py toolbox-v2 ;;

  agent)       # G4: build the image IN THE CLOUD (no local Docker), then create the hosted agent version
    cp ../policy.py agent/policy.py                      # YOUR lab policy runs in the cloud too
    az acr build -r "$ACR" -t helpdesk-agent:1 --platform linux/amd64 agent
    python3 build.py agent
    ;;

  grant)       # G4.3: the agent identity READS ONE CONTAINER. Nothing else.
    : "${AGENT_IDENTITY_ID:?export AGENT_IDENTITY_ID=<object ID of the agent identity> (GUIDED-BUILD.md G4.3)}"
    az role assignment create --assignee-object-id "$AGENT_IDENTITY_ID" --assignee-principal-type ServicePrincipal \
      --role "Storage Blob Data Reader" --scope "$(st_id)/blobServices/default/containers/kb" -o none
    az role assignment list --assignee "$AGENT_IDENTITY_ID" --all --query "[].{role:roleDefinitionName, scope:scope}" -o table
    ;;

  ask)         python3 build.py ask "${PICK:-}" ;;

  grant-wide)  # G6: the one-setting change: the same role, scoped to the whole storage account
    : "${AGENT_IDENTITY_ID:?export AGENT_IDENTITY_ID first}"
    az role assignment create --assignee-object-id "$AGENT_IDENTITY_ID" --assignee-principal-type ServicePrincipal \
      --role "Storage Blob Data Reader" --scope "$(st_id)" -o none
    echo "Granted at account scope. Wait a few minutes, then: PICK=2 ./cloud.sh ask"
    ;;

  grant-narrow) # G6: put it back
    : "${AGENT_IDENTITY_ID:?export AGENT_IDENTITY_ID first}"
    az role assignment delete --assignee "$AGENT_IDENTITY_ID" --role "Storage Blob Data Reader" --scope "$(st_id)"
    echo "Account-scope role removed; the container-scope role stays."
    ;;

  direct-call) python3 build.py direct-call ;;

  down)        # G8: everything this build created
    python3 build.py down || true
    az cognitiveservices account delete -n "$AZ14_NAME" -g "$RG" || true
    az cognitiveservices account purge -n "$AZ14_NAME" -g "$RG" -l "$AZ14_REGION" || true
    az group delete -n "$RG" --yes
    echo "Check in the Microsoft Entra admin center: Entra ID > Agent ID > All agent identities. Nothing named"
    echo "helpdesk-agent should be left from this build. Microsoft doesn't document whether deleting the agent removes it."
    rm -rf .state agent/policy.py
    ;;

  *) sed -n '2,7p' "$0" ;;
esac
