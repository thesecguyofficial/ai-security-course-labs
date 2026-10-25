# AZ10 guided build: inventory your Azure AI footprint and lock it down, in your own subscription

The offline lab (README Steps 1 to 7) teaches the mechanics at $0, on Contoso's fake estate. This guide does the same
job on a real one: **yours**. You build a small Foundry estate the way most teams start (keys on, an app identity with
Contributor, a Global deployment, no logs, no guardrails), inventory it with the questions from lessons 10.1 to 10.5,
lock it down, and prove every fix with a request that should now fail. About 75 minutes, most of it waiting for Azure.
Cost: a few US cents (table in G7). Teardown is the last step: do it today.

> **Read this first: about the responses shown below.** We wrote this guide without access to an Azure subscription,
> so **no response in this file comes from a real run**. Every response block is labelled **"Example response (shape
> from Microsoft docs, values illustrative)"** and names the page its shape comes from. Field names, error codes and
> error texts are copied from Microsoft Learn (October 2026). **The values (names, IDs, times, counts) are our
> guesses.** Write your real results into the table in G5.
>
> **This is not lab Step 8.** README Step 8 (`azure-twin/twin.sh`) repeats three results in about 20 minutes and is a
> fine warm-up. This guide is the longer version: inventory first, then the full lockdown, then the proof. Use a
> different name for each, or tear the twin down first.

Set these shell variables (again in every new terminal):

| Variable | What it holds | Example |
|---|---|---|
| `AZ10_NAME` | your lowercase, globally unique name for the Foundry resource | `az10-ab1234` |
| `AZ10_REGION` | one region for everything | `swedencentral` (the twin's default) |
| `RG` | resource group | `rg-az10-ab1234` |
| `FID` | the Foundry resource's ID (set in G1) | `/subscriptions/.../accounts/az10-ab1234` |
| `EP` | its OpenAI endpoint | `https://az10-ab1234.openai.azure.com` |

## Step 0 · Before you start (10 minutes)

1. **A subscription you own.** Never your employer's. A free account is ideal: its spending limit stops services when
   the credit runs out (lesson 10.5).
2. **Permissions.** You need to create role assignments and policy assignments. If you created the subscription you
   are its **Owner**, which covers both. Otherwise ask for **Contributor** plus **User Access Administrator** and
   **Resource Policy Contributor** on the resource group you'll use.
3. **Tools.** Azure CLI (`az version`), signed in with `az login`, plus Bicep (`az bicep install`, once), `curl` and
   Python 3. The first `az graph` command installs the CLI's resource-graph extension by itself, and the first
   `az monitor log-analytics query` may offer to install its extension: say yes.
4. **Names and region.**

   ```bash
   cd labs/az10
   export AZ10_NAME=az10-ab1234            # yours: lowercase letters, digits, hyphens
   export AZ10_REGION=swedencentral
   export RG=rg-$AZ10_NAME
   az group create -n $RG -l $AZ10_REGION -o none
   ```

5. **Budget alarm, first.** CLI: deploy the lab's own budget file (a US$5 monthly budget on the resource group, 50 %
   actual and 100 % forecast alerts):

   ```bash
   az deployment group create -g $RG -f azure-twin/budget.bicep \
     -p email=you@example.com startDate="$(date -u +%Y-%m-01)" -o none
   ```

   Portal: **Cost Management**, **Budgets**, add a monthly budget of US$5 on the resource group with an email alert
   (labels may differ slightly). Remember lesson 10.5: a budget alerts, it never stops anything, and cost data "is
   typically available within 8-24 hours".

## G1 · Build the "before" estate from zero

Five things, each one a finding you'll make in G2: a Foundry resource with keys on, one model deployment of type
Global Standard, a user-assigned managed identity for a pretend helpdesk app holding **Contributor**, no diagnostic
setting, no policy.

### Path A: portal clicks

Labels quoted from Microsoft Learn where it quotes them; "(label may differ slightly)" where it doesn't.

1. **Foundry resource.** Azure portal, search for **Foundry** and select **Create a resource** (Microsoft's network
   isolation page uses these words). **Basics**: your subscription, resource group `rg-<name>`, region, name
   `<name>`. Leave the **Networking** tab as it is. **Review + create**, then **Create**.
2. **Model deployment.** Open the resource in the Foundry portal (`ai.azure.com`) and deploy `gpt-5-mini` (version
   `2025-08-07`) with deployment name **`chat`**, deployment type **Global Standard**, the smallest capacity offered
   (labels may differ slightly). Why not `gpt-4.1-mini`? Microsoft lists it as Deprecated, and a Deprecated model is
   "No longer available to new customers", judged per subscription, so a fresh lab subscription can't deploy it
   ([model retirements](https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/model-retirements)).
   `gpt-5-mini` 2025-08-07 is GA and offered as Global Standard and Data Zone Standard in `swedencentral`
   ([region availability](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure-region-availability)). Microsoft's own `00-basic` sample uses Global Standard, which is why so many estates start here.
3. **App identity.** Search for **Managed Identities**, create one named `id-az10-app` in `rg-<name>` (label may differ
   slightly).
4. **The bad role.** On the Foundry resource: **Access control (IAM)**, **Add role assignment**, **Contributor**,
   assign access to **Managed identity**, select `id-az10-app` (label may differ slightly; Contributor sits under the
   privileged administrator roles).

### Path B: Azure CLI

```bash
az cognitiveservices account create -n $AZ10_NAME -g $RG -l $AZ10_REGION --kind AIServices --sku S0 \
  --custom-domain $AZ10_NAME --allow-project-management true --assign-identity --yes
export FID=$(az cognitiveservices account show -n $AZ10_NAME -g $RG --query id -o tsv)
export EP=https://$AZ10_NAME.openai.azure.com
az cognitiveservices account deployment create -g $RG -n $AZ10_NAME --deployment-name chat \
  --model-name gpt-5-mini --model-version 2025-08-07 --model-format OpenAI \
  --sku-name GlobalStandard --sku-capacity 1
az identity create -g $RG -n id-az10-app -o none
APP_PID=$(az identity show -g $RG -n id-az10-app --query principalId -o tsv)
az role assignment create --assignee-object-id $APP_PID --assignee-principal-type ServicePrincipal \
  --role Contributor --scope $FID -o none
```

### Path C: Bicep (resource and project), then the CLI for the rest

`azure-twin/main.bicep` is Microsoft's `00-basic` sample with the model deployment taken out and `disableLocalAuth` as
a parameter:

```bash
az deployment group create -g $RG -f azure-twin/main.bicep -p name=$AZ10_NAME disableLocalAuth=false -o none
```

Then run the Path B lines from `export FID=` down.

**Whichever path:** set `FID` and `EP` as in Path B, then keep one key the way a thief would, in this terminal only
(never in a file you might commit):

```bash
OLD_KEY=$(az cognitiveservices account keys list -n $AZ10_NAME -g $RG --query key1 -o tsv)
curl -s -o /dev/null -w "GET /openai/models with the key -> HTTP %{http_code}\n" \
  "$EP/openai/models?api-version=2024-10-21" -H "api-key: $OLD_KEY"
```

Keep this terminal open until T2: `OLD_KEY` lives only here. Expect `HTTP 200`. That call lists models and generates no tokens
([Models - List](https://learn.microsoft.com/en-us/rest/api/azureopenai/models/list)). Note what you just did:
`keys list` is the control-plane action `Microsoft.CognitiveServices/accounts/listKeys/action`, and you're Owner. G2
will find it in the Activity Log.

## G2 · Inventory: six questions, one command each

Write every answer into the "before" column of the table at the end of this step.

**Q1. Which AI resources exist, anywhere I can see?** Azure Resource Graph searches every subscription you can read:

```bash
az graph query -q "resources
  | where type =~ 'microsoft.cognitiveservices/accounts'
  | project name, kind, resourceGroup, location,
            keysOff = properties.disableLocalAuth, network = properties.publicNetworkAccess" -o table
```

Portal: **Resource Graph Explorer**, paste the same query (label may differ slightly). Lesson 10.1's
`az cognitiveservices account list` gives the same answer for one subscription. An empty or `false` `keysOff` means
keys still work.

**Example response (shape from Microsoft docs, values illustrative)** (`az graph query` returns a `data` list; with
`-o table` you see the projected columns):

```text
Name         Kind        ResourceGroup    Location       KeysOff    Network
-----------  ----------  ---------------  -------------  ---------  -------
az10-ab1234  AIServices  rg-az10-ab1234   swedencentral  False      Enabled
```

**Q2. Which models run there, of which type and size?** (lessons 10.2 and 10.5)

```bash
az cognitiveservices account deployment list -g $RG -n $AZ10_NAME \
  --query "[].{deployment:name, model:properties.model.name, version:properties.model.version, type:sku.name, capacity:sku.capacity}" -o table
```

`GlobalStandard` means prompts "may be processed in any Azure region" (deployment types page).

**Q3. Who can call the model, and who can read its keys?** Every assignment that covers the resource, including the
ones inherited from the resource group and the subscription:

```bash
az role assignment list --scope $FID --include-inherited \
  --query "[].{who:principalName, type:principalType, role:roleDefinitionName, scope:scope}" -o table
```

Portal: the resource's **Access control (IAM)**, **Role assignments** tab; the **Check access** tab answers the same
question for one identity (labels may differ slightly). Read it with lessons 10.3 and 10.4:

| Role you find | Can call the model (Entra ID) | Can list the keys |
|---|---|---|
| Owner, Contributor | no (no data actions) | **yes** (`Actions: *`) |
| Cognitive Services Contributor | no | **yes** |
| Foundry User | **yes** | **yes** (its Actions include `accounts/listkeys/action`) |
| Foundry Account Owner, Foundry Owner | Account Owner no, Owner yes | **yes** (`Microsoft.CognitiveServices/*`) |
| Reader | no | no |

So today the answer to "who can read the keys" is at least: you (Owner) and `id-az10-app` (Contributor). And while
keys are on, anyone holding a key can call the model, with no role at all.

**Q4. Are keys on, and who has listed them lately?**

```bash
az cognitiveservices account show -n $AZ10_NAME -g $RG --query properties.disableLocalAuth
az monitor activity-log list --resource-id $FID --offset 1d \
  --query "[?contains(operationName.value, 'listKeys')].{time:eventTimestamp, caller:caller, status:status.value}" -o table
```

`null` or `false` = keys on. The second command should show **your** `keys list` from G1. In a real estate, every
name in that list is a question for its owner (lab rule H01).

**Q5. Which guardrails apply?**

```bash
az policy assignment list -g $RG --query "[].{name:name, definition:policyDefinitionId, mode:enforcementMode}" -o table
```

Expect nothing in a fresh subscription. In a real organisation, also look at the subscription and management group
(`az policy assignment list` with no `-g` shows the subscription's).

**Q6. Is anything logged, and is anyone told about cost?**

```bash
az monitor diagnostic-settings list --resource $FID -o table
az consumption budget list -o table      # subscription budgets; check the resource group's in the portal
```

No diagnostic setting means no `Audit`, `RequestResponse` or `Trace` logs exist anywhere: only the Activity Log (free,
90 days) and the metrics.

| Question | Before (your answer) | After G3 (your answer) |
|---|---|---|
| Q1 AI resources, keys off? | | |
| Q2 deployments, types, capacity | | |
| Q3 who can call / who can list keys | | |
| Q4 keys on? who listed them? | | |
| Q5 policy assignments | | |
| Q6 diagnostic settings, budgets | | |

## G3 · Lock it down, in the order lesson 10.4 gives

Order matters: move the callers to Entra ID before you turn the keys off, or you break your own app first.

### 1. Give the app the right role on the one resource, take Contributor away

```bash
az role assignment create --assignee-object-id $APP_PID --assignee-principal-type ServicePrincipal \
  --role 53ca6127-db72-4b80-b1b0-d745d6d5456d --scope $FID -o none     # Foundry User, by ID
az role assignment delete --assignee $APP_PID --role Contributor --scope $FID
```

Microsoft says to "use the role definition ID (GUID) instead of the role name in your code" while the Azure AI to
Foundry role rename rolls out. (`APP_PID` is set in Path B. If you used the portal:
`APP_PID=$(az identity show -g $RG -n id-az10-app --query principalId -o tsv)`.) Portal: **Access control (IAM)**,
**Add role assignment**, **Foundry User**, then remove the Contributor row on the **Role assignments** tab.

A pipeline would get the custom deployer role from `fixes/custom-role-foundry-deployer.json` instead. This build has no
pipeline, so we skip it.

### 2. Turn logging on

```bash
az monitor log-analytics workspace create -g $RG -n law-$AZ10_NAME -l $AZ10_REGION -o none
az monitor diagnostic-settings create -n to-law --resource $FID --workspace law-$AZ10_NAME \
  --logs '[{"category":"Audit","enabled":true},{"category":"RequestResponse","enabled":true},{"category":"Trace","enabled":true}]'
```

Portal: on the resource, **Monitoring**, **Diagnostic settings**, **Add diagnostic setting**, tick **Audit**,
**RequestResponse** and **Trace** under **Logs**, choose your Log Analytics workspace under **Destination details**
(Microsoft's create-diagnostic-settings page). Skip `AzureOpenAIRequestUsage` and `ManagedNetworkEvent` here: they
are the two categories with "Costs to export". Microsoft: data "should start flowing to your selected destinations
within 90 minutes".

### 3. Fix the deployment type

Lesson 10.2: pick the type on purpose. If your standard says EU data zone (Contoso's does), replace `chat`:

```bash
az cognitiveservices account deployment delete -g $RG -n $AZ10_NAME --deployment-name chat
az cognitiveservices account deployment create -g $RG -n $AZ10_NAME --deployment-name chat \
  --model-name gpt-5-mini --model-version 2025-08-07 --model-format OpenAI \
  --sku-name DataZoneStandard --sku-capacity 1
```

If your region doesn't offer this model as `DataZoneStandard`, keep Global and write down why, or pick a GA model your
region offers as `DataZoneStandard` or `Standard` (Microsoft's table has no `Standard` row for `gpt-5-mini`).

### 4. Assign the two guardrail policies (resource group scope, for this sandbox)

```bash
SCOPE=$(az group show -n $RG --query id -o tsv)
az policy assignment create --name az10-approved-models --scope $SCOPE \
  --policy aafe3651-cb78-4f68-9f81-e7e41509110f --params @azure-twin/approved-models.params.json -o none
az policy assignment create --name az10-deny-key-access --scope $SCOPE \
  --policy 71ef260a-8f18-47b7-abcb-62d0673d94dc --params '{"effect":{"value":"Deny"}}' -o none
```

Open `azure-twin/approved-models.params.json` first: effect `Deny`, **empty** `allowedPublishers`, and one asset ID
ending in `/` (every version of `gpt-5-mini`, nothing else). The second is "Azure AI Services resources should have
key access disabled (disable local authentication)" on `Deny`. Portal: **Policy**, **Assignments**, **Assign Policy**,
pick the scope and the definition, set the parameters on the **Parameters** tab, **Review + create**, **Create**
(Microsoft's assign-policy quickstart). In real life you assign both at the subscription or management group.
Microsoft: "Wait at least 15 minutes for the policy assignment to take effect."

Why the key-access policy before step 5? It changes nothing that exists ("resources that match a `deny` policy
definition are marked as non-compliant"), but from now on nobody can create or switch a resource to keys on. Step 5
turns them off; test T4 proves they stay off.

### 5. Turn keys off

```bash
az resource update --ids $FID --set properties.disableLocalAuth=true -o none
az cognitiveservices account show -n $AZ10_NAME -g $RG --query properties.disableLocalAuth   # true
```

The disable-local-auth page documents Bicep/ARM (`disableLocalAuth: true`), PowerShell and the policy, but no portal
switch and no dedicated `az` flag, so we use the generic `az resource update`. The Bicep way:
`az deployment group create -g $RG -f azure-twin/main.bicep -p name=$AZ10_NAME disableLocalAuth=true`.

Now run G2's six questions again and fill in the "after" column.

## G4 · Prove it: five requests

Get a token for yourself first (the scope Microsoft's keyless guide uses):

```bash
TOKEN=$(az account get-access-token --resource https://ai.azure.com --query accessToken -o tsv)
ask() { curl -s -w "\nHTTP %{http_code}\n" "$EP/openai/v1/responses" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"model":"chat","input":"Reply with OK","max_output_tokens":1000}'; }
```

Why 1000 and not 16? `gpt-5-mini` is a reasoning model, and Microsoft: "To cap the total the model generates, set
`max_output_tokens` with the Responses API or `max_completion_tokens` with the Chat Completions API. Both limits cover
reasoning tokens, visible output tokens, and formatting tokens." A tiny cap can end the answer during reasoning, with
`"status": "incomplete"` and no text. Reasoning models also refuse `temperature`, `top_p` and `max_tokens`
([reasoning models](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/reasoning)).

### T1 · The subscription Owner can't call the model

```bash
ask
```

You are Owner, and Owner has no data actions. Microsoft's keyless guide: "Roles like **Owner** or **Contributor**
don't provide access via Microsoft Entra ID."

**Example response (shape from Microsoft docs, values illustrative)** ([keyless authentication, troubleshooting
table](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/how-to/configure-entra-id); the page names the
status and the error, not the full body, so yours will carry more fields):

```text
... "PermissionDenied" ... "Principal does not have access to API/Operation." ...
HTTP 401
```

Now give yourself the data role on this one resource, wait, and ask again:

```bash
ME=$(az ad signed-in-user show --query id -o tsv)
az role assignment create --assignee-object-id $ME --assignee-principal-type User \
  --role 53ca6127-db72-4b80-b1b0-d745d6d5456d --scope $FID -o none
# Microsoft: "Azure role assignments can take up to 5 minutes to propagate." Wait, then get a fresh token.
TOKEN=$(az account get-access-token --resource https://ai.azure.com --query accessToken -o tsv); ask
```

**Example response (shape from Microsoft docs, values illustrative)** (top-level fields of a created response, from the
[Responses REST reference](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/responses?view=rest-microsoft-foundry-v1&preserve-view=true);
inner fields of `output` and `usage` shortened):

```text
{"id": "resp_67cb32528d6881909eb2859a55e18a85", "object": "response", "created_at": 1792656000,
 "status": "completed", "model": "gpt-5-mini", "output": [ ... ], "output_text": "OK", "usage": { ... }}
HTTP 200
```

What it proves: "who can call" is the data roles, nothing else. Before step 5 there was a second answer: anyone with
a key.

### T2 · The old key is refused

```bash
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$EP/openai/models?api-version=2024-10-21" -H "api-key: $OLD_KEY")
  echo "$(date -u +%H:%M:%S) old key -> HTTP $code"; [ "$code" = "401" ] && break; sleep 60
done
```

Microsoft's test: the service returns "an HTTP 401 response with an `Access denied due to invalid subscription key or
wrong API endpoint` error". Expect `200` for a while first: the gateway "can continue to accept previously valid keys
until its cached configuration refreshes", "typically ... within a few minutes, but it can take up to several hours".
Still `200` after 30 minutes? Run the loop again later. That delay is exactly why lesson 10.4 says to regenerate both
keys straight away when one has leaked.

**Example response (shape from Microsoft docs, values illustrative)**
([disable local auth](https://learn.microsoft.com/azure/ai-services/disable-local-auth)):

```text
14:02:10 old key -> HTTP 200
14:03:10 old key -> HTTP 200
14:04:11 old key -> HTTP 401
```

Add `-o -` instead of `-o /dev/null` to one call to see the body with the error text.

### T3 · An unapproved model is refused at deployment time

At least 15 minutes after step 4:

```bash
az cognitiveservices account deployment create -g $RG -n $AZ10_NAME --deployment-name not-approved \
  --model-name gpt-5-nano --model-version 2025-08-07 --model-format OpenAI --sku-name GlobalStandard --sku-capacity 1
```

Pick the unapproved model from the GA list, never a Deprecated one: a fresh subscription can't deploy a Deprecated
model at all, so its error would look like a refusal without proving anything about your policy. If `gpt-5-nano`
isn't offered in your region, pick any other GA model from
`az cognitiveservices account list-models -n $AZ10_NAME -g $RG -o table`. If it **is** created, the assignment
wasn't active yet: delete it straight away (`az cognitiveservices account deployment delete -g $RG -n $AZ10_NAME
--deployment-name not-approved`) and try later.

**Example response (shape from Microsoft docs, values illustrative)**. Microsoft's model deployment policy page says
only that "the deployment fails with a policy violation error" and that the message includes the policy name and
assignment ID. The shape below is Resource Manager's general policy error
([RequestDisallowedByPolicy](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-policy-requestdisallowedbypolicy));
this policy runs in a resource provider mode, so your wording may differ:

```text
(RequestDisallowedByPolicy) Resource 'not-approved' was disallowed by policy. Policy identifiers:
'[{"policyAssignment":{"name":"az10-approved-models","id":"/subscriptions/.../policyAssignments/az10-approved-models"},
   "policyDefinition":{"name":"Foundry model deployments should only use approved models", ...}}]'.
```

### T4 · Nobody can switch keys back on, not even you

```bash
az resource update --ids $FID --set properties.disableLocalAuth=false -o none
```

You're Owner, so RBAC allows it. The key-access policy on `Deny` doesn't: Azure Policy's deny effect returns
"`403 (Forbidden)`". This is lab step B9 for real.

**Example response (shape from Microsoft docs, values illustrative)**
([RequestDisallowedByPolicy](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-policy-requestdisallowedbypolicy)):

```text
(RequestDisallowedByPolicy) Resource 'az10-ab1234' was disallowed by policy. Policy identifiers:
'[{"policyAssignment":{"name":"az10-deny-key-access", ...},"policyDefinition":{"name":"Azure AI Services resources
should have key access disabled (disable local authentication)", ...}}]'.
```

### T5 · The trail: control plane and data plane

The Activity Log (free, no setup) has your `listKeys` from G1, the deployments, the role changes and the refusals:

```bash
az monitor activity-log list -g $RG --offset 6h \
  --query "[].{time:eventTimestamp, category:category.value, op:operationName.value, status:status.value, caller:caller}" -o table
```

Look for `Microsoft.CognitiveServices/accounts/listKeys/action`, `Microsoft.CognitiveServices/accounts/deployments/write`
with status `Failed` (T3), and rows in the **Policy** category. Then the resource log from the diagnostic setting
(give it up to 90 minutes after T1's `200`):

```bash
WS=$(az monitor log-analytics workspace show -g $RG -n law-$AZ10_NAME --query customerId -o tsv)
az monitor log-analytics query -w $WS --analytics-query "AzureDiagnostics
  | where ResourceProvider == 'MICROSOFT.COGNITIVESERVICES'
  | project Category, OperationName, ResultSignature, CallerIPAddress, DurationMs" -o table
```

The column names are from Microsoft's `AzureDiagnostics` table reference. Expect at least one `RequestResponse` row for
T1, with your laptop's public address in `CallerIPAddress`. Look at one row's `properties_s` too: lesson 11.4 notes
that Microsoft doesn't say whether these categories hold prompt text. Does "Reply with OK" appear? Write it down.

## G5 · Change one setting and re-run: list the publisher

This is the mistake Microsoft's own example parameters invite (lesson 10.3): add `"OpenAI"` to `allowedPublishers`.

```bash
cat > /tmp/az10-publisher.json <<'JSON'
{"effect": {"value": "Deny"}, "allowedPublishers": {"value": ["OpenAI"]},
 "allowedAssetIds": {"value": ["azureml://registries/azure-openai/models/gpt-5-mini/"]}}
JSON
az policy assignment delete --name az10-approved-models --scope $SCOPE
az policy assignment create --name az10-approved-models --scope $SCOPE \
  --policy aafe3651-cb78-4f68-9f81-e7e41509110f --params @/tmp/az10-publisher.json -o none
```

Wait 15 minutes, then run T3 again. If the rule works the way lesson 10.3 reads it (publisher `notin` the list **and**
no asset ID matches), `not-approved` is now **created**: the publisher alone approves every OpenAI model. Delete it at
once:

```bash
az cognitiveservices account deployment delete -g $RG -n $AZ10_NAME --deployment-name not-approved
```

This run also settles something our fact-check could only infer: that Azure stores `OpenAI` as `model.publisher` for
Azure OpenAI models. If T3 is still refused, that inference is wrong for your tenant: tell us. Then put the original
assignment back (the two step 4 commands for `az10-approved-models`, after a delete).

| Test | Expected | Your result |
|---|---|---|
| T1 Owner without a data role, then with Foundry User | 401, then 200 | |
| T2 old key after `disableLocalAuth=true` | 200 for a while, then 401 (how long?) | |
| T3 unapproved model | refused by policy | |
| T4 keys back on, as Owner | refused by policy | |
| T5 `RequestResponse` row; prompt text in `properties_s`? | row appears within 90 minutes | |
| G5 publisher listed, T3 again | unapproved model created | |

## G6 · What you just built, in lesson terms

| Lesson | Control | Where |
|---|---|---|
| 10.1 | Inventory across subscriptions | G2 Q1 (Resource Graph) |
| 10.2 | Deployment type chosen on purpose | G3 step 3 |
| 10.3 | App identity: Foundry User on one resource, no Contributor; approved models on Deny, no publishers | G3 steps 1 and 4, T1, T3, G5 |
| 10.4 | Keys off, proved with a 401, kept off with Deny | G3 steps 4 and 5, T2, T4 |
| 10.5 | Budget, logs, and the trail to hunt in | Step 0, G3 step 2, T5 |

## G7 · Cost and teardown (do it today)

| Item | Cost |
|---|---|
| Foundry resource and project | no hourly charge; "Pay-as-you-go for input and output tokens" |
| Model tokens: T1 and its repeats, a few hundred tokens each (reasoning tokens count too) | cents at most (estimate: check your model's price) |
| `GET /openai/models` (G1, T2) | no tokens |
| Deployments that receive no calls | $0 |
| Azure Policy | "There are no charges for using Azure Policy on Azure resources" |
| Budget | Cost Management is "available to Azure customers ... at no additional cost" |
| Activity Log | free, 90 days |
| Log Analytics | per GB ingested (this guide writes a few KB); "31 days of analytics retention at no extra cost" |
| Managed identity | no charge listed by Microsoft that we found (estimate: $0) |

We could not load live prices: Microsoft's pricing pages render prices in the browser. Check Cost Management
tomorrow.

```bash
SCOPE=$(az group show -n $RG --query id -o tsv)
az policy assignment delete --name az10-approved-models --scope $SCOPE
az policy assignment delete --name az10-deny-key-access --scope $SCOPE
az consumption budget delete --budget-name az10-twin-budget --resource-group $RG
az group delete -n $RG --yes
az cognitiveservices account purge -l $AZ10_REGION -g $RG -n $AZ10_NAME   # frees the name now, not in 48 hours
rm -f /tmp/az10-publisher.json
```

The role assignments you made on the resource go with it. Tomorrow, check: `az group show -n $RG` should say
`ResourceGroupNotFound`, and `az cognitiveservices account list-deleted -o table` shouldn't list your resource.

## What we could not verify (October 2026)

- **No real run.** Every response above is illustrative. Before release the course team runs this guide in a sandbox
  and replaces them with real output.
- Portal labels for the Foundry portal's deploy dialog, Managed Identities, IAM role tabs, Resource Graph Explorer and
  Cost Management budgets (marked "label may differ slightly").
- The exact error bodies for T1, T3 and T4. Microsoft documents the error codes and texts we quote, not full bodies,
  and the approved-models policy runs in a resource provider mode, where "the resource provider manages the
  evaluation".
- Whether `az resource update` is accepted for `disableLocalAuth` on every account (Microsoft documents Bicep/ARM and
  PowerShell). If it fails, use the Bicep line in G3 step 5.
- Whether `gpt-5-mini` 2025-08-07 is offered as `DataZoneStandard` in your region if you left `swedencentral`, and
  whether `gpt-5-nano` is offered there (G3 step 3 and T3 say what to do).
- The `model.publisher` value Azure stores for Azure OpenAI models: G5 is the test (lab AZ10 fact-check, caveat C1).
- Whether `RequestResponse` rows hold prompt text (T5 asks you to look).
- Model token prices (estimate only).
