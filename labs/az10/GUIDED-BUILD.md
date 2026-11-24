# M1 guided build: inventory your Azure AI footprint and lock it down, in your own subscription

The offline lab (README Steps 1 to 7) teaches the mechanics at $0, on Contoso's fake estate. This guide does the same
job on a real one: **yours**. You build a small Foundry estate the way most teams start (keys on, an app identity with
Contributor, a Global deployment, no logs, no guardrails), inventory it with the questions from lessons 1.1 to 1.5,
lock it down, and prove every fix with a request that should now fail. About 75 minutes, most of it waiting for Azure.
Cost: a few US cents (table in G7). Teardown is the last step: do it today.

> **Read this first: about the responses shown below.** We wrote this guide from Microsoft's documentation and then
> ran it end to end on 9 November 2026. The response blocks are still the documented shapes; **what really happened
> in our run is in the table near the end**, and where the two differ, the table is right. Every response block is labeled **"Example response (shape
> from Microsoft docs, values illustrative)"** and names the page its shape comes from. Field names, error codes and
> error texts are copied from Microsoft Learn (October 2026). The values (names, IDs, times, counts) are illustrative. Write your real results into the table in G5.
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
   the credit runs out (lesson 1.5).
2. **Permissions.** You need to create role assignments and policy assignments. If you created the subscription you
   are its **Owner**, which covers both. Otherwise ask for **Contributor** plus **User Access Administrator** and
   **Resource Policy Contributor** on the resource group you'll use.
3. **Tools.** Azure CLI (`az version`), signed in with `az login`, plus Bicep (`az bicep install`, once), `curl` and
   Python 3. The first `az graph` command installs the CLI's resource-graph extension by itself, and the first
   `az monitor log-analytics query` may offer to install its extension: say yes.
4. **Names and region.**

   ```bash
   cd labs/az10
   export AZ10_NAME=az10-ab1234
   export AZ10_REGION=swedencentral
   export RG=rg-$AZ10_NAME
   az group create -n $RG -l $AZ10_REGION -o none
   ```

   - `AZ10_NAME`: yours: lowercase letters, digits, hyphens

5. **Budget alarm, first.** CLI: deploy the lab's own budget file (a US$5 monthly budget on the resource group, 50 %
   actual and 100 % forecast alerts):

   ```bash
   az deployment group create -g $RG -f azure-twin/budget.bicep \
     -p email=you@example.com startDate="$(date -u +%Y-%m-01)" -o none
   ```

   Portal: **Cost Management**, **Budgets**, add a monthly budget of US$5 on the resource group with an email alert
   (labels may differ slightly). Remember lesson 1.5: a budget alerts, it never stops anything, and cost data "is
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
            keysOff = properties.disableLocalAuth, network = properties.publicNetworkAccess" --query data -o table
```

`--query data` matters: `az graph query` returns a `data` list plus a count, and in our run `-o table` without it
printed only the count. Portal: **Resource Graph Explorer**, paste the same query (label may differ slightly). Lesson
10.1's `az cognitiveservices account list` gives the same answer for one subscription. An empty or `false` `keysOff`
means keys still work.

**Example response (shape from Microsoft docs, values illustrative)** (the rows of the `data` list, as a table):

```text
Name         Kind        ResourceGroup    Location       KeysOff    Network
-----------  ----------  ---------------  -------------  ---------  -------
az10-ab1234  AIServices  rg-az10-ab1234   swedencentral  False      Enabled
```

**Q2. Which models run there, of which type and size?** (lessons 1.2 and 1.5)

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
question for one identity (labels may differ slightly). Read it with lessons 1.3 and 1.4:

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

Expect nothing in a fresh subscription. In a real organization, also look at the subscription and management group
(`az policy assignment list` with no `-g` shows the subscription's).

**Q6. Is anything logged, and is anyone told about cost?**

```bash
az monitor diagnostic-settings list --resource $FID -o table
az consumption budget list -o table
```

- `az consumption budget list -o table`: subscription budgets; check the resource group's in the portal

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

## G3 · Lock it down, in the order lesson 1.4 gives

Order matters: move the callers to Entra ID before you turn the keys off, or you break your own app first.

### 1. Give the app the right role on the one resource, take Contributor away

```bash
az role assignment create --assignee-object-id $APP_PID --assignee-principal-type ServicePrincipal \
  --role 53ca6127-db72-4b80-b1b0-d745d6d5456d --scope $FID -o none
az role assignment delete --assignee $APP_PID --role Contributor --scope $FID
```

- `az role assignment create`: Foundry User, by ID

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

Lesson 1.2: pick the type on purpose. Contoso's standard says EU data zone. **Check your quota before you delete
anything**:

```bash
az cognitiveservices usage list -l $AZ10_REGION \
  --query "[?ends_with(name.value, '.gpt-5-mini')].{quota:name.value, used:currentValue, limit:limit}" -o table
```

Find the row whose name contains `DataZoneStandard` and read its `limit`. In our run, in a free-credit subscription,
Global Standard was 500 and Data Zone Standard was **0**.

**If the Data Zone limit is 0 (or there is no such row): keep `chat` as it is.** Do not delete it: the replacement
can't be created, and you would have no model left for T1. Write the reason where the next person will find it:

```bash
az resource tag --ids $FID -i \
  --tags deployment-type-reason="DataZoneStandard quota is 0 here. Global accepted: demo data only" --query tags -o json
```

`-i` adds the tag and keeps the others. This is what we did, and it is what `cloud/deploy.sh` does.

**Only if the Data Zone limit is above 0**, replace `chat`:

```bash
az cognitiveservices account deployment delete -g $RG -n $AZ10_NAME --deployment-name chat
az cognitiveservices account deployment create -g $RG -n $AZ10_NAME --deployment-name chat \
  --model-name gpt-5-mini --model-version 2025-08-07 --model-format OpenAI \
  --sku-name DataZoneStandard --sku-capacity 1
```

If that create fails anyway, put the Global deployment back with the G1 Path B `deployment create` command and add
the tag above.

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
Microsoft: "Wait at least 15 minutes for the policy assignment to take effect." In our run the approved-models
assignment still let an unapproved model through at 15 and 27 minutes, and refused it hours later. Until then a Deny
assignment denies nothing and nothing tells you, so T3 has to be run more than once.

Why the key-access policy before step 5? It changes nothing that exists ("resources that match a `deny` policy
definition are marked as non-compliant"), but from now on nobody can create or switch a resource to keys on. Step 5
turns them off; test T4 proves they stay off.

### 5. Turn keys off

```bash
az resource update --ids $FID --set properties.disableLocalAuth=true -o none
az cognitiveservices account show -n $AZ10_NAME -g $RG --query properties.disableLocalAuth
```

What to look for: the `show` command prints `true`.

The disable-local-auth page documents Bicep/ARM (`disableLocalAuth: true`), PowerShell and the policy, but no portal
switch and no dedicated `az` flag, so we use the generic `az resource update`. The Bicep way:
`az deployment group create -g $RG -f azure-twin/main.bicep -p name=$AZ10_NAME disableLocalAuth=true`.

Now run G2's six questions again and fill in the "after" column.

## G4 · Prove it: five requests

Get a token for yourself first (the scope Microsoft's keyless guide uses), and two small functions. `ask` uses the
Responses route, `ask_chat` the chat completions route. You need both: in our run they did not behave the same (T1).

```bash
TOKEN=$(az account get-access-token --resource https://ai.azure.com --query accessToken -o tsv)
ask() { curl -s -w "\nHTTP %{http_code}\n" "$EP/openai/v1/responses" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"model":"chat","input":"Reply with OK","max_output_tokens":1000}'; }
ask_chat() { curl -s -w "\nHTTP %{http_code}\n" "$EP/openai/deployments/chat/chat/completions?api-version=2024-10-21" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Reply with OK"}],"max_completion_tokens":1000}'; }
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
```

Microsoft: "Azure role assignments can take up to 5 minutes to propagate." Wait, then get a fresh token and ask on
the chat completions route:

```bash
TOKEN=$(az account get-access-token --resource https://ai.azure.com --query accessToken -o tsv); ask_chat
```

Expect `HTTP 200` and a JSON body with a `choices` list. This is the route that answered 200 in our run. Still 401
after 5 minutes? Wait a few more and run the line again. A `429` means the capacity of 1 is busy: the call was
allowed, try again in a minute.

Now the same token on the Responses route, the one Microsoft's keyless guide shows:

```bash
ask
```

**Documented response (shape from Microsoft docs, values illustrative)** (top-level fields of a created response, from the
[Responses REST reference](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/responses?view=rest-microsoft-foundry-v1&preserve-view=true);
inner fields of `output` and `usage` shortened):

```text
{"id": "resp_67cb32528d6881909eb2859a55e18a85", "object": "response", "created_at": 1792656000,
 "status": "completed", "model": "gpt-5-mini", "output": [ ... ], "output_text": "OK", "usage": { ... }}
HTTP 200
```

**What we saw instead:** with Foundry User in place, this route on `openai.azure.com` kept answering **401**, however
long we waited, while `ask_chat` with the same token answered 200. If yours is 401 too, the role is not the problem
and waiting won't help. The Responses route did work on the resource's other address, with a token for that address
(this is the pair `cloud/deploy.sh test` uses, with chat completions):

```bash
CS_TOKEN=$(az account get-access-token --resource https://cognitiveservices.azure.com --query accessToken -o tsv)
curl -s -o /dev/null -w "cognitiveservices token, v1 responses -> HTTP %{http_code}\n" \
  "https://$AZ10_NAME.cognitiveservices.azure.com/openai/v1/responses" -H "Authorization: Bearer $CS_TOKEN" \
  -H "Content-Type: application/json" -d '{"model":"chat","input":"Reply with OK","max_output_tokens":1000}'
```

Ours printed `429` there (capacity 1 was busy), which still means allowed. Write all three codes into the table in G5.

What it proves: "who can call" is the data roles, nothing else. Before step 5 there was a second answer: anyone with
a key. And one role can answer differently per route and token audience, so test the exact route your app uses
before you turn keys off for it.

### T2 · The old key is refused

```bash
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$EP/openai/models?api-version=2024-10-21" -H "api-key: $OLD_KEY")
  echo "$(date -u +%H:%M:%S) old key -> HTTP $code"; [ "$code" = "401" ] || [ "$code" = "403" ] && break; sleep 60
done
```

The loop stops on 401 or 403: either means refused. Microsoft's test: the service returns "an HTTP 401 response with
an `Access denied due to invalid subscription key or wrong API endpoint` error". Ours was refused after about a
minute with **403** `AuthenticationTypeDisabled`. You may see `200` for a while first: the gateway "can continue to
accept previously valid keys until its cached configuration refreshes", "typically ... within a few minutes, but it
can take up to several hours". Still `200` after 30 minutes? Run the loop again later. That delay is exactly why
lesson 1.4 says to regenerate both keys straight away when one has leaked.

**Example response (shape from Microsoft docs, values illustrative)**
([disable local auth](https://learn.microsoft.com/azure/ai-services/disable-local-auth)). The documented last line is
`HTTP 401`; ours read `HTTP 403`:

```text
14:02:10 old key -> HTTP 200
14:03:10 old key -> HTTP 200
14:04:11 old key -> HTTP 401     (ours: HTTP 403)
```

Add `-o -` instead of `-o /dev/null` to one call to see the body with the error text.

### T3 · An unapproved model is refused at deployment time

Microsoft says at least 15 minutes after step 4. Ours took hours, so expect to run this more than once:

```bash
az cognitiveservices account deployment create -g $RG -n $AZ10_NAME --deployment-name not-approved \
  --model-name gpt-5-nano --model-version 2025-08-07 --model-format OpenAI --sku-name GlobalStandard --sku-capacity 1
```

Pick the unapproved model from the GA list, never a Deprecated one: a fresh subscription can't deploy a Deprecated
model at all, so its error would look like a refusal without proving anything about your policy. If `gpt-5-nano`
isn't offered in your region, pick any other GA model from
`az cognitiveservices account list-models -n $AZ10_NAME -g $RG -o table`. If it **is** created, the assignment
wasn't active yet: delete it straight away (`az cognitiveservices account deployment delete -g $RG -n $AZ10_NAME
--deployment-name not-approved`) and try again in an hour. That happened to us at 15 and at 27 minutes. Carry on with
T4 and T5 meanwhile, and leave the estate up until T3 has refused once (it costs nothing while no calls are made).
When ours was refused, hours later, the error said `NonCompliant` and named `az10-approved-models`.

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
with status `Failed` (T3), and rows in the **Policy** category. Then the resource log from the diagnostic setting.
Microsoft says data starts flowing within 90 minutes of creating the setting; in our runs it took hours, so run this
query again later if it comes back empty (count from T1's `200` on the chat completions route):

```bash
WS=$(az monitor log-analytics workspace show -g $RG -n law-$AZ10_NAME --query customerId -o tsv)
az monitor log-analytics query -w $WS --analytics-query "AzureDiagnostics
  | where ResourceProvider == 'MICROSOFT.COGNITIVESERVICES'
  | project Category, OperationName, ResultSignature, CallerIPAddress, DurationMs" -o table
```

The column names are from Microsoft's `AzureDiagnostics` table reference. Expect at least one `RequestResponse` row for
T1, with your laptop's public address in `CallerIPAddress`. Look at one row's `properties_s` too: lesson 2.4 notes
that Microsoft doesn't say whether these categories hold prompt text. Does "Reply with OK" appear? Write it down. Our
real-run table has no row for this query: we recorded the Activity Log result only.

## G5 · Change one setting and re-run: list the publisher

This is the mistake Microsoft's own example parameters invite (lesson 1.3): add `"OpenAI"` to `allowedPublishers`.

```bash
cat > /tmp/az10-publisher.json <<'JSON'
{"effect": {"value": "Deny"}, "allowedPublishers": {"value": ["OpenAI"]},
 "allowedAssetIds": {"value": ["azureml://registries/azure-openai/models/gpt-5-mini/"]}}
JSON
az policy assignment delete --name az10-approved-models --scope $SCOPE
az policy assignment create --name az10-approved-models --scope $SCOPE \
  --policy aafe3651-cb78-4f68-9f81-e7e41509110f --params @/tmp/az10-publisher.json -o none
```

**Only start G5 after T3 has been refused once.** Otherwise you can't tell the two cases apart: in our run a brand
new assignment with **no** publisher listed also let the unapproved model through, at 15 and at 27 minutes, simply
because it wasn't active yet. A "created" a few minutes after the commands above proves nothing about the publisher.

So this step needs a control, and it needs hours, not minutes:

1. **Control: is the new assignment active?** Try a model that neither the publisher nor the asset ID approves.
   Azure OpenAI models all come from the publisher this assignment lists, so pick a GA model from a **different**
   publisher: run `az cognitiveservices account list-models -n $AZ10_NAME -g $RG --query "[].{format:format,
   name:name, version:version}" -o table`, take a row whose format is not `OpenAI`, and pass its format, name and
   version to the T3 command. Repeat it once an hour until the error names the policy `az10-approved-models`. A
   refusal for any other reason (no quota, not offered, terms not accepted) is not a control. If you can't get a
   policy refusal this way, you have no control: stop here and put the original assignment back.
2. **Then the test:** run T3 again (`gpt-5-nano`). If the rule works the way lesson 1.3 reads it (publisher `notin`
   the list **and** no asset ID matches), `not-approved` is now **created**: the publisher alone approves every
   OpenAI model.

Delete whatever was created at once:

```bash
az cognitiveservices account deployment delete -g $RG -n $AZ10_NAME --deployment-name not-approved
```

**We have not run G5 on real Azure** (15 November 2026): our real-run table below has no G5 row. What is proven is
the rule's text and the offline lab, which evaluates that same rule JSON (README Step 5, B4 and B8). G5 would also
show whether Azure stores `OpenAI` as `model.publisher` for Azure OpenAI models, which we only infer from the rule
and Microsoft's examples. If the control is refused and T3 is refused too, that inference is wrong for your tenant.
Then put the original assignment back (the two step 4 commands for `az10-approved-models`, after a delete).

| Test | Expected | Your result |
|---|---|---|
| T1 Owner without a data role | 401 | |
| T1 again with Foundry User: `ask_chat`, `ask`, the `cognitiveservices.azure.com` route | 200 on chat completions. Responses on `openai.azure.com`: 200 documented, 401 in our run. Third route: 200 or 429 | |
| T2 old key after `disableLocalAuth=true` | maybe 200 for a while, then refused: 401 documented, 403 `AuthenticationTypeDisabled` in our run (how long?) | |
| T3 unapproved model | refused by policy (15 minutes documented, hours in our run) | |
| T4 keys back on, as Owner | refused by policy | |
| T5 `RequestResponse` row; prompt text in `properties_s`? | row appears (90 minutes documented, hours in our runs) | |
| G5 control (other publisher's model), then T3 again | control refused, then unapproved OpenAI model created (not run by us) | |

## G6 · What you just built, in lesson terms

| Lesson | Control | Where |
|---|---|---|
| 1.1 | Inventory across subscriptions | G2 Q1 (Resource Graph) |
| 1.2 | Deployment type chosen on purpose | G3 step 3 |
| 1.3 | App identity: Foundry User on one resource, no Contributor; approved models on Deny, no publishers | G3 steps 1 and 4, T1, T3, G5 |
| 1.4 | Keys off, proved with a refused key (401 or 403), kept off with Deny | G3 steps 4 and 5, T2, T4 |
| 1.5 | Budget, logs, and the trail to hunt in | Step 0, G3 step 2, T5 |

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

This table has no live prices. Check Cost Management tomorrow.

```bash
SCOPE=$(az group show -n $RG --query id -o tsv)
az policy assignment delete --name az10-approved-models --scope $SCOPE
az policy assignment delete --name az10-deny-key-access --scope $SCOPE
az consumption budget delete --budget-name az10-twin-budget --resource-group $RG
az group delete -n $RG --yes
az cognitiveservices account purge -l $AZ10_REGION -g $RG -n $AZ10_NAME
rm -f /tmp/az10-publisher.json
```

- `az cognitiveservices account purge -l $AZ10_REGION -g $RG -n $AZ10_NAME`: frees the name now, not in 48 hours

The role assignments you made on the resource go with it. Tomorrow, check: `az group show -n $RG` should say
`ResourceGroupNotFound`, and `az cognitiveservices account list-deleted -o table` shouldn't list your resource.

## What happened in our real run (9 November 2026, Sweden Central)

The course team ran this guide end to end in a free-credit subscription and recorded it for the lab videos. The
example blocks above stay illustrative; this is what we saw.

| Step | Real result |
|---|---|
| G2 Q1 | `az graph query ... -o table` printed only a count; add `--query data` to see the rows |
| G3 step 3 | Data Zone Standard quota for gpt-5-mini was **0** in this subscription, so we kept Global Standard and recorded why as a tag |
| T1 | As subscription Owner: 401, the principal lacks the data action. Owner and Contributor have no data actions |
| T1 again | With Foundry User: the Responses route on `openai.azure.com` kept answering 401, while chat completions with the same token answered 200, and the v1 route on `cognitiveservices.azure.com` worked (its 429 was the capacity of 1). Test the exact route your app uses |
| T2 | The old key was refused after about a minute, with **403** (`AuthenticationTypeDisabled`), not 401 |
| T3 | The approved-models policy still allowed an unapproved model at 15 and 27 minutes (we deleted it at once); hours later it was refused (`NonCompliant ... az10-approved-models`). Test a guardrail again later |
| T4 | Switching keys back on as Owner: refused by `az10-deny-key-access`; the setting stayed `True` |
| T5 | The Activity Log showed every step, including the `listKeys` action from the start |

## What our run didn't settle

- Portal labels for the Foundry portal's deploy dialog, Managed Identities, IAM role tabs, Resource Graph Explorer and
  Cost Management budgets (marked "label may differ slightly").
- The exact error bodies for T1, T3 and T4. Microsoft documents the error codes and texts we quote, not full bodies,
  and the approved-models policy runs in a resource provider mode, where "the resource provider manages the
  evaluation".
- Whether `az resource update` is accepted for `disableLocalAuth` on every account (Microsoft documents Bicep/ARM and
  PowerShell). If it fails, use the Bicep line in G3 step 5.
- Whether `gpt-5-mini` 2025-08-07 is offered as `DataZoneStandard` in your region if you left `swedencentral`, and
  whether `gpt-5-nano` is offered there (G3 step 3 and T3 say what to do).
- The `model.publisher` value Azure stores for Azure OpenAI models, and whether a listed publisher approves every
  model on real Azure: G5 is the test, and we have not run it.
- Whether a `RequestResponse` row arrived for T1 and whether it holds prompt text (T5 asks you to look).
- Model token prices (estimate only).
