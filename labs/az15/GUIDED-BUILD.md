# AZ15 guided build: a private endpoint for an open model (your own subscription, costs money)

This is Step 9 of the AZ15 lab, and it's optional. You build the hardened design's core for real: a workspace whose
managed VNet allows only approved outbound traffic (with no FQDN rules, so no Azure Firewall), an online endpoint that
accepts only Entra tokens and only through the workspace's private endpoint, a client VM that plays the Helpdesk, and
the endpoint's traffic log in Log Analytics. Then five requests, one changed setting, and teardown.

**Status:** run end to end on 10 November 2026 in East US, in a personal sandbox subscription. The table below shows
what really happened, including four things that didn't work the first time. The responses in Part C are from that run.

## What happened in our real run (10 November 2026, East US)

| Step | What we expected | What really happened | What we changed |
|---|---|---|---|
| A.1 portal workspace | Approved outbound, managed network provisions | The workspace made in the portal never provisioned its managed network: "InternalServerError: Received 404 from a service request", three times, with Basic and with Standard firewall SKU | A workspace made with the CLI (`az ml workspace create --managed-network allow_only_approved_outbound`) in the same group provisioned in about 6 minutes. We used that one. |
| A.5 client VM | `Standard_B1s` | Every B size was restricted for this subscription in East US | `Standard_D2as_v4` (2 vCPU). `cloud.sh` now tries D sizes after B sizes |
| B.2 endpoint create | Endpoint created | "SubscriptionNotRegistered: Resource provider [N/A] isn't registered" | Registered `Microsoft.PolicyInsights`; `cloud.sh` now does it |
| B.2 instance type | `Standard_DS3_v2` | The curated model only accepts its own list of SKUs (`Standard_DS2_v2` was refused). DS3_v2 needed 8 cores of Azure Machine Learning quota; the DSv2 limit was 6 | `Standard_E2s_v3` is on the model's list and the ESv3 limit was 20. Cheaper too |
| B.2 deployment | Curated model works without FQDN rules | The container crashed (liveness probe 502). Its log: it installs conda packages when it starts, from `conda.anaconda.org`, then `repo.anaconda.com`, and approved outbound blocks both | Four FQDN rules (`conda.anaconda.org`, `repo.anaconda.com`, `pypi.org`, `files.pythonhosted.org`). FQDN rules bring in a managed Azure Firewall, which bills by the hour |
| C1 first calls | HTTP 200 | HTTP 408 twice: the default request timeout is 5 seconds and the first summary on 2 vCPU took longer | `request_settings.request_timeout_ms=90000`, then 200 |
| C2 to C4 | 403, 401, 404 | 403, 401, 404 | Nothing |
| C5 logs | Request 2 missing (the network refuses it first) | Request 2 IS in `AmlOnlineEndpointTrafficLog` with ResponseCode 403, a minute after the call | The text in C5 now says so |
| Part D | Request 2 gets through | HTTP 200 from the internet with our own token, and a real summary back | Put back to `disabled` |
| Timer | Deletes the endpoint after 60 minutes | It did: our first endpoint was gone at the timer's time, and the next `make cloud-deploy` made a new one | We paused it once (`properties.state=Disabled`) while a deployment update rolled, then ran teardown |

The lesson behind the B.2 row: "curated" doesn't mean "needs no internet". Read the deployment log before you open
egress, and open only the hosts the log names.

## Before you start: cost and safety

- **The endpoint bills for its VM every hour it exists, called or not.** Our run used one `Standard_E2s_v3`
  instance (the model's list of allowed SKUs and our quota decided it; see the table above). Look up its hourly price for your region on the
  [Azure Machine Learning pricing page](https://azure.microsoft.com/pricing/details/machine-learning/) before you
  start. The Azure Machine Learning managed VNet itself "is free"; private endpoints are charged
  ([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-managed-network?view=azureml-api-2)).
- **The FQDN rules this model needs bring in a managed Azure Firewall**, billed by the hour while the workspace exists
  (Standard SKU in our run). Run teardown the same day.
- Smaller items: one small client VM (`Standard_D2as_v4` in our run), one private endpoint, Log Analytics ingestion, the workspace's storage
  account and key vault. Microsoft deploys the firewall only "if an FQDN outbound rule is created" (same page); we
  planned for none, but the model in our run needed four (Part B.1).
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
4. **Review + create.** Then open the workspace and, under **Networking** > **Workspace managed outbound access**,
   check that it shows **Allow Only Approved Outbound** and only the required rules (ours listed 13, all "Inactive"
   until the network is provisioned).

In our run the portal-made workspace then refused to provision its managed network ("Received 404 from a service
request", three tries). If that happens to you, make the workspace with the CLI instead (`make cloud-up` creates it
when the name is new, for example `make cloud-up WS=tsg-az15-cli`) and pass the same `WS=` to every later `make`.

Portal labels move between releases. If a label differs, the CLI below is the reference.

### A.2 CLI

```bash
make cloud-up
```

Same as `bash cloud/cloud.sh up rg-tsg-az15-lab eastus tsg-az15-lab`.

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

### B.1 Pick a model, and find out what it needs from the internet

Microsoft's page says the models curated by Azure Machine Learning work in approved-outbound mode: the managed VNet
"uses a Service Endpoint Policy to Azure Machine Learning managed storage accounts" and "has default outbound to the
Microsoft Container Registry that contains the docker image used to deploy the models"
([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-network-isolation-model-catalog?view=azureml-api-2)).
Hugging Face collection models don't: their weights come "directly from Hugging Face hub", which needs FQDN rules and
so a firewall (same page).

Our run says: check. We used `sshleifer-distilbart-cnn-12-6` version 13 (Apache-2.0, text summarization). Its
container installed conda packages at start-up, approved outbound blocked them, and the deployment crashed. Read the
log with `az ml online-deployment get-logs ... --lines 400`, list the hosts it tried, and add one FQDN rule per host:

```bash
for d in conda.anaconda.org repo.anaconda.com pypi.org files.pythonhosted.org; do
  az ml workspace outbound-rule set -g rg-tsg-az15-lab --workspace-name "$WS" --rule "allow-${d//./-}" \
     --type fqdn --destination "$d"
done
```

Each rule took about 6 minutes in our run, and the first one brings in the managed firewall. This is the egress review
from lesson 15.2 done for real: four named hosts, nothing else. `repo.anaconda.com` is Anaconda's own channel; check
its terms of service for your organization before you allow it at work.

1. In the studio (ml.azure.com), open **Model catalog** and filter to the collection curated by Azure Machine Learning.
2. Pick a small text model whose model card lists a CPU SKU for online endpoints. The list is enforced: our model
   refused `Standard_DS2_v2` because it wasn't on it. Check your quota for the size you pick (Machine Learning quota
   per VM family); a 4-core size needs 8 cores of quota for a single instance. Read its **license** on the card:
   "Model providers set the license terms and price for their models"
   ([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/concept-model-catalog?view=azureml-api-2)).
3. Copy its asset ID, `azureml://registries/azureml/models/<name>/versions/<version>`. The request format differs
   from model to model: copy the sample request from the model card's inference samples into `cloud/request.json`,
   or request 1 fails on the body, not on the network.
4. Optional, but it's the point of lesson 15.3: download the files and scan them before you deploy anything.

   ```bash
   az ml model download --name <name> --version <version> --registry-name azureml --download-path ./model-check
   python3 model_files.py scan ./model-check
   python3 model_files.py manifest ./model-check
   ```

### B.2 Deploy, timer first

```bash
INSTANCE=Standard_E2s_v3 MODEL_ID=azureml://registries/azureml/models/<name>/versions/<version> make cloud-deploy
```

If the first requests in Part C come back `HTTP 408`, the model is slower than the default 5-second request timeout
(ours was, on 2 vCPU). Raise it:

```bash
az ml online-deployment update -g rg-tsg-az15-lab -w "$WS" -e tsg-az15-summariser -n blue \
   --set request_settings.request_timeout_ms=90000
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
   Our run (10 Nov 2026), after the timeout change
   HTTP 200
   ```

2. **Stolen credentials from outside: your laptop, with your own valid Entra token.** You may even be Owner. It
   doesn't matter: the network refuses first.

   ```output
   Our run (10 Nov 2026)
   HTTP 403
   ```

3. **A key instead of a token.** The VM sends `Authorization: Bearer LAB-PLACEHOLDER-KEY`. An `aad_token` endpoint
   expects a Microsoft Entra token.

   ```output
   Our run (10 Nov 2026)
   HTTP 401
   ```

4. **A named deployment.** The VM adds the header `azureml-model-deployment: debug`. The header routes to a named
   deployment whatever its traffic share
   ([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online?view=azureml-api-2));
   there's no `debug` here, so the request fails. In a real endpoint with a test deployment at 0%, it would answer.

   ```output
   Our run (10 Nov 2026)
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
   Our run (10 Nov 2026), columns trimmed; the logs showed up within minutes, not an hour
   TimeGenerated (UTC)   DeploymentName  AuthType  ResponseCode
   07:50:16              blue            AADToken  200     request 1, the Helpdesk VM
   07:50:49              blue            AADToken  403     request 2, from outside
   07:50:54              blue            AADToken  401     request 3, the made-up key
   07:51:26                              AADToken  404     request 4, no deployment named debug
   07:54:11              blue            AADToken  200     Part D, request 1
   07:54:43              blue            AADToken  200     Part D, request 2 from outside: now it gets in
   ```

   Read it like a reviewer: request 1 is there; check `IdentityData` for the VM's object ID. We expected request 2 to be
   missing, because the network refuses it. It isn't: the refusal at the endpoint's front door is logged with
   ResponseCode 403, so the table shows outside attempts too. That's useful for detection: a 403 here means someone
   outside your network holds a valid token and tried. Request 4 has no deployment name, because no deployment got it. There's no prompt text in this table, by design: the column list has no request body
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
make cloud-down
make cloud-check
```

What each command does, and what to look for:

- `make cloud-down`: endpoint, workspace (with its storage, key vault and other dependents), resource group, custom role
- `make cloud-check`: should list nothing

If `az ml workspace delete` complains about a flag, run `az ml workspace delete -h` and use the flags your CLI version
lists; then delete the resource group in the portal (**Resource groups** > `rg-tsg-az15-lab` > **Delete resource
group**). Check **Cost Management** the next day for anything still billing.
