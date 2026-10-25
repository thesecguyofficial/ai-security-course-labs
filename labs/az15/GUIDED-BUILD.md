# AZ15 guided build: a private endpoint for an open model (your own subscription, costs money)

This is Step 9 of the AZ15 lab, and it's optional. You build the hardened design's core for real: a workspace whose
managed VNet allows only approved outbound traffic (with no FQDN rules, so no Azure Firewall), an online endpoint that
accepts only Entra tokens and only through the workspace's private endpoint, a client VM that plays the Helpdesk, and
the endpoint's traffic log in Log Analytics. Then five requests, one changed setting, and teardown.

**Status:** written from Microsoft's documentation and checked for shell syntax. It hasn't been run end to end in a
sandbox yet, so every response below is labelled "Example response (shape from the provider's docs, values
illustrative)". Before this lab is released, it gets one real run and the examples are replaced with real output.

## Before you start: cost and safety

- **The endpoint bills for its VM every hour it exists, called or not.** This guide uses one `Standard_DS3_v2`
  instance. Look up its hourly price for your region on the
  [Azure Machine Learning pricing page](https://azure.microsoft.com/pricing/details/machine-learning/) before you
  start. The Azure Machine Learning managed VNet itself "is free"; private endpoints are charged
  ([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-managed-network?view=azureml-api-2)).
- Smaller items: one `Standard_B1s` client VM, one private endpoint, Log Analytics ingestion, the workspace's storage
  account and key vault. No Azure Firewall: Microsoft deploys one only "if an FQDN outbound rule is created", and this
  guide creates none (same page).
- **Auto-teardown:** `make cloud-deploy` creates a Logic App timer before it creates the endpoint. Sixty minutes later
  it sends a DELETE for the endpoint with its own managed identity. It stops the hourly VM cost; it doesn't delete the
  rest. `make cloud-down` deletes everything. Run it the same day.
- Use your own sandbox subscription (lesson 0.7) with a budget alert. Never a work subscription.

You need the Azure CLI with the `ml` extension (`az extension add -n ml`), signed in with `az login`, and the right
subscription selected (`az account set -s <id>`). Check with `make cloud-check-tools`.

## Part A · The workspace and the private path

### A.1 Console (Azure portal)

1. Search for **Azure Machine Learning**, then **Create** > **New workspace**.
2. **Basics:** a new resource group `rg-tsg-az15-lab`, name `tsg-az15-lab`, your region.
3. **Networking:** choose **Private with Approved Outbound**. Don't add any user-defined outbound rules. Then add a
   **private endpoint** in a new VNet `vnet-tsg-az15` (subnet `clients`, `10.15.1.0/24`), with private DNS integration.
4. **Review + create.** Then open the workspace and, under **Networking**, check that the managed network shows
   approved outbound and only the required rules.

Portal labels move between releases. If a label differs, the CLI below is the reference.

### A.2 CLI

```bash
make cloud-up               # = bash cloud/cloud.sh up rg-tsg-az15-lab eastus tsg-az15-lab
```

What it runs, in order (`cloud/cloud.sh`, section `up`):

1. `az group create` with a `delete-by` tag.
2. `az ml workspace create ... --managed-network allow_only_approved_outbound`.
3. `az ml workspace provision-network`: Microsoft defers the managed VNet "until a compute resource is created or
   provisioning is manually started", and "To create an online deployment, you must manually provision the managed
   network, or create a compute instance first"
   ([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-managed-network?view=azureml-api-2)).
4. A VNet, a private endpoint to the workspace (`--group-id amlworkspace`) and the private DNS zones
   `privatelink.api.azureml.ms` and `privatelink.notebooks.azure.net`, as in Microsoft's
   [private link guide](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-configure-private-link?view=azureml-api-2).
5. A client VM with no public IP and a system-assigned managed identity. You reach it only with
   `az vm run-command invoke`.
6. A Log Analytics workspace.

## Part B · An open model, the timer, the endpoint

### B.1 Pick a model you can deploy without FQDN rules

In approved-outbound mode, the models curated by Azure Machine Learning work without extra rules: the managed VNet
"uses a Service Endpoint Policy to Azure Machine Learning managed storage accounts" and "has default outbound to the
Microsoft Container Registry that contains the docker image used to deploy the models"
([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-network-isolation-model-catalog?view=azureml-api-2)).
Hugging Face collection models don't: their weights come "directly from Hugging Face hub", which needs FQDN rules and
so a firewall (same page).

1. In the studio (ml.azure.com), open **Model catalog** and filter to the collection curated by Azure Machine Learning.
2. Pick a small text model whose model card lists a CPU SKU for online endpoints. Read its **licence** on the card:
   "Model providers set the license terms and price for their models"
   ([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/concept-model-catalog?view=azureml-api-2)).
3. Copy its asset ID, `azureml://registries/azureml/models/<name>/versions/<version>`.
4. Optional, but it's the point of lesson 15.3: download the files and scan them before you deploy anything.

   ```bash
   az ml model download --name <name> --version <version> --registry-name azureml --download-path ./model-check
   python3 model_files.py scan ./model-check
   python3 model_files.py manifest ./model-check
   ```

### B.2 Deploy, timer first

```bash
MODEL_ID=azureml://registries/azureml/models/<name>/versions/<version> make cloud-deploy
```

What it runs (`cloud/cloud.sh`, section `deploy`):

1. **The timer.** A Logic App (Consumption) from `cloud/teardown-timer.json`: a Recurrence trigger that starts 60
   minutes from now and an HTTP action that sends `DELETE` for the endpoint, authenticated with its own system-assigned
   identity. Microsoft: for Azure Resource Manager the audience is "`https://management.azure.com/`", and Consumption
   logic apps "don't automatically enable the system identity"
   ([Microsoft](https://learn.microsoft.com/en-us/azure/logic-apps/authenticate-with-managed-identity)), so the body
   turns it on. The identity gets AzureML Data Scientist on this workspace only (it can delete endpoints; it can't
   create compute or change the workspace).
2. **The endpoint** from `cloud/endpoint.yml`: `auth_mode: aad_token` and `public_network_access: disabled`. With
   `disabled`, "inbound scoring requests are received using the private endpoint of the Azure Machine Learning
   workspace and the endpoint can't be reached from public networks"
   ([YAML reference](https://learn.microsoft.com/en-us/azure/machine-learning/reference-yaml-endpoint-online?view=azureml-api-2)).
3. **The deployment** `blue` from `cloud/deployment.yml`, with all traffic. This is the hourly cost.
4. **A custom role** `TSG AZ15 lab scorer` with one action,
   `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/score/action`, assigned to the client VM's identity
   at the endpoint's scope. Compare it with Microsoft's sample role, `onlineEndpoints/*/action`, which also grants
   `listKeys` (lesson 15.3).
5. **A diagnostic setting** that sends `AmlOnlineEndpointTrafficLog`, `AmlOnlineEndpointEventLog` and
   `AmlOnlineEndpointConsoleLog` to Log Analytics.

Console check: in the studio, **Endpoints** > `tsg-az15-summariser` shows the auth type, the deployment and its
traffic share.

## Part C · Five requests

```bash
make cloud-ask
```

1. **Normal use: the Helpdesk, inside the network, with an Entra token.** The client VM gets a token for
   `https://ml.azure.com` from its managed identity and posts `cloud/request.json` to the scoring URI.

   ```output
   Example response (shape from the provider's docs, values illustrative)
   HTTP 200
   ```

2. **Stolen credentials from outside: your laptop, with your own valid Entra token.** You may even be Owner. It
   doesn't matter: the network refuses first.

   ```output
   Example response (shape from the provider's docs, values illustrative)
   HTTP 403
   ```

3. **A key instead of a token.** The VM sends `Authorization: Bearer LAB-PLACEHOLDER-KEY`. An `aad_token` endpoint
   expects a Microsoft Entra token.

   ```output
   Example response (shape from the provider's docs, values illustrative)
   HTTP 401
   ```

4. **A named deployment.** The VM adds the header `azureml-model-deployment: debug`. The header routes to a named
   deployment whatever its traffic share
   ([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online?view=azureml-api-2));
   there's no `debug` here, so the request fails. In a real endpoint with a test deployment at 0%, it would answer.

   ```output
   Example response (shape from the provider's docs, values illustrative)
   HTTP 404
   ```

5. **The evidence.** Wait a while (Microsoft: "It can take up to an hour for the connection to the Log Analytics workspace to be available",
   [monitoring guide](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-monitor-online-endpoints?view=azureml-api-2)),
   then run this in the Log Analytics workspace `log-tsg-az15` (**Logs**):

   ```kusto
   AmlOnlineEndpointTrafficLog
   | where TimeGenerated > ago(2h)
   | project TimeGenerated, EndpointName, DeploymentName, AuthType, IdentityData, ResponseCode, UserAgent, XRequestId
   | order by TimeGenerated asc
   ```

   ```output
   Example response (shape from the provider's docs, values illustrative)
   TimeGenerated         EndpointName          DeploymentName  AuthType  IdentityData                          ResponseCode
   2027-01-30T10:02:11Z  tsg-az15-summariser   blue            AADToken  <object ID of the VM's identity>      200
   ```

   Read it like a reviewer: request 1 is there with the VM's object ID in `IdentityData`. Request 2 isn't: the network
   refused it before the endpoint saw it. Whether requests 3 and 4 appear depends on where the endpoint refused them;
   write down what you see. There's no prompt text in this table, by design: the column list has no request body
   ([table reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/amlonlineendpointtrafficlog)).
   Then check the Activity Log for the endpoint and deployment `write` operations you made, with your object ID as the
   caller.

## Part D · Change one setting and re-run

Open the front door for five minutes, so you see what the flag does:

```bash
az ml online-endpoint update -g rg-tsg-az15-lab -w tsg-az15-lab -n tsg-az15-summariser --set public_network_access=enabled
make cloud-ask
```

Request 2 (your laptop, your Entra token) now gets through. You hold AzureML-level rights in your sandbox, so you pass
the `score/action` check too. That's the trade-off: with the flag enabled, only RBAC stands between the internet and
the model. Put it back:

```bash
az ml online-endpoint update -g rg-tsg-az15-lab -w tsg-az15-lab -n tsg-az15-summariser --set public_network_access=disabled
```

## Teardown (today)

```bash
make cloud-down             # endpoint, workspace (with its storage, key vault and other dependents), resource group, custom role
make cloud-check            # should list nothing
```

If `az ml workspace delete` complains about a flag, run `az ml workspace delete -h` and use the flags your CLI version
lists; then delete the resource group in the portal (**Resource groups** > `rg-tsg-az15-lab` > **Delete resource
group**). Check **Cost Management** the next day for anything still billing.
