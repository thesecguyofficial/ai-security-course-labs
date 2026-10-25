#!/usr/bin/env bash
# AZ15 guided build helper. Read GUIDED-BUILD.md first: it explains every step and what it costs.
# Usage: cloud.sh up|deploy|ask|down <resource-group> <location> <workspace> [endpoint]
# Needs: Azure CLI signed in to YOUR sandbox subscription, the ml extension (az extension add -n ml), and for
# `deploy`, MODEL_ID=azureml://registries/azureml/models/<name>/versions/<version>.
set -euo pipefail

CMD=${1:?up|deploy|ask|down}; RG=${2:?resource group}; LOC=${3:?location}; WS=${4:?workspace}; EP=${5:-tsg-az15-summariser}
HERE=$(cd "$(dirname "$0")" && pwd); OUT="$HERE/out"; mkdir -p "$OUT"
SUB=$(az account show --query id -o tsv)
VNET=vnet-tsg-az15; SUBNET=clients; VM=vm-tsg-az15-client; TIMER=la-tsg-az15-teardown; LAW=log-tsg-az15

ws_id()  { az ml workspace show -g "$RG" -n "$WS" --query id -o tsv; }
ep_id()  { echo "$(ws_id)/onlineEndpoints/$EP"; }

case "$CMD" in
up)
  echo "== A1 resource group (tagged, so you can find it again)"
  az group create -n "$RG" -l "$LOC" --tags purpose=tsg-az15-lab delete-by="$(date -u -d '+1 day' +%F 2>/dev/null || date -u -v+1d +%F)" -o none
  echo "== A2 workspace: managed VNet in approved-outbound mode, no FQDN rules (so no Azure Firewall)"
  az ml workspace create -g "$RG" -n "$WS" -l "$LOC" --managed-network allow_only_approved_outbound -o none
  echo "== A3 provision the managed network now (otherwise it waits for the first compute)"
  az ml workspace provision-network -g "$RG" -n "$WS" -o none
  echo "== A4 a client network with a private endpoint to the workspace"
  az network vnet create -g "$RG" -n "$VNET" --address-prefixes 10.15.0.0/16 --subnet-name "$SUBNET" --subnet-prefixes 10.15.1.0/24 -o none
  az network private-endpoint create -g "$RG" -n "pe-$WS" --vnet-name "$VNET" --subnet "$SUBNET" \
     --private-connection-resource-id "$(ws_id)" --group-id amlworkspace --connection-name "pe-$WS" -o none
  for z in privatelink.api.azureml.ms privatelink.notebooks.azure.net; do
    az network private-dns zone create -g "$RG" -n "$z" -o none
    az network private-dns link vnet create -g "$RG" -z "$z" -n "link-$VNET" -v "$VNET" -e false -o none
  done
  az network private-endpoint dns-zone-group create -g "$RG" --endpoint-name "pe-$WS" -n default \
     --private-dns-zone privatelink.api.azureml.ms --zone-name api -o none
  az network private-endpoint dns-zone-group add -g "$RG" --endpoint-name "pe-$WS" -n default \
     --private-dns-zone privatelink.notebooks.azure.net --zone-name notebooks -o none
  echo "== A5 a small client VM with no public IP and a managed identity (it plays the Helpdesk app)"
  az vm create -g "$RG" -n "$VM" --image Canonical:ubuntu-24_04-lts:server:latest --size Standard_B1s --vnet-name "$VNET" --subnet "$SUBNET" \
     --public-ip-address "" --nsg "" --assign-identity '[system]' --generate-ssh-keys -o none
  echo "== A6 a Log Analytics workspace for the endpoint's logs"
  az monitor log-analytics workspace create -g "$RG" -n "$LAW" -l "$LOC" -o none
  echo "Done. Next: MODEL_ID=... make cloud-deploy"
  ;;
deploy)
  : "${MODEL_ID:?set MODEL_ID=azureml://registries/azureml/models/<name>/versions/<version> (GUIDED-BUILD Part B)}"
  echo "== B1 the teardown timer FIRST: a Logic App that deletes the endpoint 60 minutes from now"
  START=$(date -u -d '+60 min' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+60M +%Y-%m-%dT%H:%M:%SZ)
  sed -e "s#__START__#$START#" -e "s#__LOCATION__#$LOC#" -e "s#__ENDPOINT_ID__#$(ep_id)#" "$HERE/teardown-timer.json" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); d.pop("_note"); print(json.dumps(d))' > "$OUT/timer.json"
  az rest --method put --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Logic/workflows/$TIMER?api-version=2019-05-01" \
     --body @"$OUT/timer.json" -o none
  TIMER_OID=$(az rest --method get --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Logic/workflows/$TIMER?api-version=2019-05-01" --query identity.principalId -o tsv)
  az role assignment create --assignee-object-id "$TIMER_OID" --assignee-principal-type ServicePrincipal \
     --role "AzureML Data Scientist" --scope "$(ws_id)" -o none
  echo "   the timer fires at $START (UTC) and deletes $EP"
  echo "== B2 the endpoint: aad_token auth, public_network_access disabled"
  sed "s#__EP__#$EP#" "$HERE/endpoint.yml" > "$OUT/endpoint.yml"
  az ml online-endpoint create -g "$RG" -w "$WS" -f "$OUT/endpoint.yml" -o none
  echo "== B3 the deployment (this is the part that bills by the hour)"
  sed -e "s#__EP__#$EP#" -e "s#__MODEL_ID__#$MODEL_ID#" "$HERE/deployment.yml" > "$OUT/deployment.yml"
  az ml online-deployment create -g "$RG" -w "$WS" -f "$OUT/deployment.yml" --all-traffic -o none
  echo "== B4 the client VM may score this endpoint and do nothing else"
  sed "s#__SUB__#$SUB#" "$HERE/scorer-role.json" > "$OUT/scorer-role.json"
  az role definition create --role-definition @"$OUT/scorer-role.json" -o none 2>/dev/null || echo "   (role already exists)"
  VM_OID=$(az vm show -g "$RG" -n "$VM" --query identity.principalId -o tsv)
  az role assignment create --assignee-object-id "$VM_OID" --assignee-principal-type ServicePrincipal \
     --role "TSG AZ15 lab scorer" --scope "$(ep_id)" -o none
  echo "== B5 send the endpoint's traffic, event and console logs to Log Analytics"
  az monitor diagnostic-settings create -n to-law --resource "$(ep_id)" \
     --workspace "$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query id -o tsv)" \
     --logs '[{"category":"AmlOnlineEndpointTrafficLog","enabled":true},{"category":"AmlOnlineEndpointEventLog","enabled":true},{"category":"AmlOnlineEndpointConsoleLog","enabled":true}]' -o none
  echo "Done. Next: make cloud-ask"
  ;;
ask)
  URI=$(az ml online-endpoint show -g "$RG" -w "$WS" -n "$EP" --query scoring_uri -o tsv)
  echo "scoring URI: $URI"
  BODY=$(cat "$HERE/request.json")
  echo "== C1 the Helpdesk (client VM, inside the network, Entra token from its managed identity)"
  az vm run-command invoke -g "$RG" -n "$VM" --command-id RunShellScript --query 'value[0].message' -o tsv --scripts "
    T=\$(curl -s -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://ml.azure.com' | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"access_token\"])')
    curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST '$URI' -H \"Authorization: Bearer \$T\" -H 'Content-Type: application/json' -d '$BODY'"
  echo "== C2 your laptop, from the internet, with your own Entra token"
  T=$(az account get-access-token --resource https://ml.azure.com --query accessToken -o tsv)
  curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST "$URI" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d "$BODY" || true
  echo "== C3 the client VM with a made-up key instead of a token"
  az vm run-command invoke -g "$RG" -n "$VM" --command-id RunShellScript --query 'value[0].message' -o tsv --scripts "
    curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST '$URI' -H 'Authorization: Bearer LAB-PLACEHOLDER-KEY' -H 'Content-Type: application/json' -d '$BODY'"
  echo "== C4 the client VM names a deployment that doesn't exist (azureml-model-deployment header)"
  az vm run-command invoke -g "$RG" -n "$VM" --command-id RunShellScript --query 'value[0].message' -o tsv --scripts "
    T=\$(curl -s -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://ml.azure.com' | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"access_token\"])')
    curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST '$URI' -H \"Authorization: Bearer \$T\" -H 'azureml-model-deployment: debug' -H 'Content-Type: application/json' -d '$BODY'"
  echo "== C5 the evidence: run the query in GUIDED-BUILD Part C5 in Log Analytics ($LAW) in a few minutes"
  ;;
down)
  echo "== delete the endpoint (the hourly cost), the workspace, then the resource group"
  az ml online-endpoint delete -g "$RG" -w "$WS" -n "$EP" --yes || true
  az ml workspace delete -g "$RG" -n "$WS" --all-resources --permanently-delete --yes || true
  az group delete -n "$RG" --yes
  az role definition delete --name "TSG AZ15 lab scorer" || true
  echo "Done. Check with: make cloud-check"
  ;;
*) echo "usage: cloud.sh up|deploy|ask|down <rg> <location> <workspace> [endpoint]"; exit 2;;
esac
