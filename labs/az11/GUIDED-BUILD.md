# AZ11 guided build: hardened model access on Microsoft Foundry, in your own subscription

The offline lab (README Steps 1 to 7) teaches every control at $0 on Contoso's plan. This guide builds the hardened
TSG Helpdesk model access for real, from zero, in **your own** subscription, exactly as Module 11 teaches it: one
identity per app with Foundry User on one resource (11.1), public network access **Disabled** with a private endpoint
and all three privatelink zones (11.2), a customer-managed key in a same-region Key Vault with purge protection
(11.3), resource logs to Log Analytics (11.4), and a Data Zone deployment with a policy that refuses Global ones
(11.5). Then you prove each control with a request that should fail, change one setting and watch it break. About 2
hours. It has hourly charges while it exists (G6), so teardown is the last step: do it today.

> **Read this first: about the responses shown below.** We wrote this guide without access to an Azure subscription,
> so **no response in this file comes from a real run**. Every response block is labelled **"Example response (shape
> from Microsoft docs, values illustrative)"** and names the page its shape comes from. Field names, error codes and
> texts are copied from Microsoft Learn (October 2026) unless the block says otherwise. **The values (addresses, IDs,
> versions, counts) are our guesses.** Write your real results into the table in G4.
>
> **Path B is README Step 8.** The Terraform in `terraform/` and the script `cloud/cloud.sh` are the same build. This
> guide adds the portal path, explains each step against the lessons, and adds the tests. The Terraform was
> format-checked, not applied (fact-check item U1): expect to adjust a value for your region.

Set these shell variables (again in every new terminal):

| Variable | What it holds | Example |
|---|---|---|
| `AZ11_NAME` | 3 to 21 lowercase letters, digits or hyphens, globally unique | `az11-ab1234` |
| `MY_IP` | your laptop's public IPv4 address (only it may create the key) | your router's WAN address |
| `RG` | resource group (`terraform/` uses `rg-$AZ11_NAME`) | `rg-az11-ab1234` |
| `FID` | the Foundry resource's ID (set in G1) | `/subscriptions/.../accounts/az11-ab1234` |

Region: `swedencentral` (the Terraform default in `terraform/variables.tf`). Use one region for everything:
Microsoft says to "Deploy the key store and the Foundry resource in the same Azure region."

## Step 0 · Before you start (15 minutes)

1. **A subscription you own**, never your employer's. A free account's spending limit stops services when the credit
   runs out.
2. **Budget alarm first.** If you did lab AZ10's guided build, you have one on that resource group, which is gone now.
   Put one on the subscription: **Cost Management**, **Budgets**, a monthly budget of US$10 with an email alert
   (labels may differ slightly). It alerts; it stops nothing (lesson 10.5).
3. **Permissions.** This build creates role assignments (Key Vault Crypto Officer for you, Key Vault Crypto User for
   the key's identity, Foundry User for two identities) and a custom policy definition. Owner of the subscription
   covers all of it. Otherwise: Contributor, User Access Administrator and Resource Policy Contributor.
4. **Tools.** Azure CLI signed in (`az login`), Terraform 1.6+ or OpenTofu (`export TF=tofu`), Python 3.11+.
5. **Resource providers.** A new subscription may not have them registered yet (you'd see
   `MissingSubscriptionRegistration`):

   ```bash
   for ns in Microsoft.CognitiveServices Microsoft.KeyVault Microsoft.Network Microsoft.Compute \
             Microsoft.ManagedIdentity Microsoft.OperationalInsights Microsoft.Insights; do
     az provider register --namespace $ns; done
   ```

6. **Model and deployment type.** Check your region offers `gpt-4.1-mini` 2025-04-14 as `DataZoneStandard`:

   ```bash
   az cognitiveservices model list -l swedencentral \
     --query "[?model.name=='gpt-4.1-mini'].{version:model.version, types:join(',', model.skus[].name)}" -o table
   ```

   No `DataZoneStandard`? Use `Standard`, or another model, and change `terraform/variables.tf` to match (README Step 8
   notes). If the query prints nothing, drop `--query` and read the raw output.

7. **Names.**

   ```bash
   cd labs/az11
   export AZ11_NAME=az11-ab1234
   export MY_IP=<your public IPv4>
   export RG=rg-$AZ11_NAME
   make cost          # the meters this build bills, to price in the Azure pricing calculator
   ```

## G1 · Build it from zero

Ten pieces, in an order that matters twice: the key's identity must hold its role **before** customer-managed keys
are switched on ("If the identity can't access the key when encryption is enabled, the operation fails"), and the
DNS zones must exist before anything inside the VNet calls the model.

### Path A: portal clicks

Labels quoted from Microsoft Learn where it quotes them; "(label may differ slightly)" everywhere else.

1. **Resource group** `rg-<name>` in your region.
2. **Virtual network** `vnet-helpdesk`, address space `10.20.0.0/16`, two subnets: `snet-pe` `10.20.2.0/24` (the
   private endpoint) and `snet-jump` `10.20.3.0/24` (the test VM; tick the private subnet option, no default outbound
   access) (labels may differ slightly).
3. **Log Analytics workspace** `law-<name>` (label may differ slightly).
4. **Three user-assigned managed identities** (search **Managed Identities**): `id-<name>-cmk` (used only by the
   Foundry resource to reach its key), `id-helpdesk-app` (the app, nothing else), `id-jump` (the test VM). One per job:
   lesson 11.1's shared-badge finding is what happens otherwise.
5. **Key Vault** `kv-<name>`, same region. Permission model **Azure role-based access control**, soft-delete retention
   **7 days**, **purge protection on**. Networking: public access only from selected networks, your `MY_IP` in the
   firewall, and trusted Microsoft services allowed to bypass it (labels may differ slightly). Purge protection "is
   **not enabled by default**", and once on it can't be turned off.
6. **Key Vault roles.** On the vault, **Access control (IAM)**, **Add role assignment**: **Key Vault Crypto Officer**
   to yourself (to create the key), **Key Vault Crypto User** to `id-<name>-cmk` (Microsoft: "For Key Vault with Azure
   RBAC, assign the Key Vault Crypto User role to the managed identity"). Wait 5 minutes.
7. **The key.** In the vault, **Keys**, generate an RSA 2048 key named `cmk-foundry` (Microsoft: "Use an RSA key with a
   minimum size of 2048 bits") (labels may differ slightly).
8. **The Foundry resource.** Search for **Foundry** and select **Create a resource**. On **Basics**: `rg-<name>`, your
   region, name `<name>`. Then, quoting Microsoft's network isolation page: "select the **Networking** tab and then
   select the **Disabled** option for public access", "From the **Private endpoint** section, select **+ Add private
   endpoint**", same **Region** as the VNet, subnet `snet-pe`; the target "should be labeled as an "account"". For
   encryption, Microsoft: "the wizard guides you to use a user-assigned or system-assigned managed identity. It also
   guides you to select a key vault or Managed HSM where your key is stored": pick `id-<name>-cmk`, `kv-<name>`,
   `cmk-foundry`. **Review + create**, **Create**. (Missed the encryption step? **Resource Management**,
   **Encryption**, **Customer-Managed Keys**, enter the key vault URL and key name, **Save**, all quoted from
   Microsoft's CMK page. There's no way back: "Projects can be updated from Microsoft-managed keys to CMKs but not
   reverted.")
9. **All three DNS zones.** Microsoft: creating a private endpoint "by default also creates a private DNS zone that
   corresponds to the `privatelink` subdomain". You need **three**: `privatelink.cognitiveservices.azure.com`,
   `privatelink.openai.azure.com` and `privatelink.services.ai.azure.com`. In **Private DNS zones**, check each exists
   and has a virtual network link to `vnet-helpdesk`; on the private endpoint's DNS configuration, check all three are
   in its zone group; create and link whatever is missing (labels may differ slightly). This is the step lab rule
   AZ11-03 catches when it's half done.
10. **Keys off, model, logs, roles, test VM.**
    - Keys off: Microsoft documents no portal switch (Bicep/ARM, PowerShell or policy). From your laptop:
      `az resource update --ids $(az cognitiveservices account show -n <name> -g rg-<name> --query id -o tsv) --set properties.disableLocalAuth=true`.
    - Model: with public access Disabled, the Foundry portal at `ai.azure.com` may not open the resource from your
      laptop. Deploy with the CLI instead (a control-plane call, which doesn't go through the closed door):
      `az cognitiveservices account deployment create -g rg-<name> -n <name> --deployment-name helpdesk-chat --model-name gpt-4.1-mini --model-version 2025-04-14 --model-format OpenAI --sku-name DataZoneStandard --sku-capacity 1`.
    - Logs: on the Foundry resource, **Monitoring**, **Diagnostic settings**, **Add diagnostic setting**, tick
      **Audit**, **RequestResponse** and **Trace**, **Destination details**: `law-<name>` (Microsoft's
      create-diagnostic-settings page). Do the same on the Key Vault with **AuditEvent**.
    - Roles: on the Foundry resource, **Access control (IAM)**, **Add role assignment**, **Foundry User**, managed
      identities `id-helpdesk-app` and `id-jump`. On this resource only, not the resource group.
    - Test VM `vm-jump`: Ubuntu Server 22.04 LTS, size `Standard_B1s`, subnet `snet-jump`, **no public IP**, no inbound
      ports, identity `id-jump` (labels may differ slightly). You'll never sign in to it: G3 uses Run Command.

### Path B: Terraform (`make up`)

```bash
make up            # terraform init + plan, the lab's checker on YOUR plan, then apply after you type yes
make cloud-check   # the checker again on cloud-plan.json
```

`make up` saves `terraform show -json` as `cloud-plan.json` and runs `checker.py --plan` on it before asking to apply,
so you see lab findings on your real plan before anything exists. Read `terraform/main.tf` while it runs: every block
carries its lesson number. Three details worth checking against Path A:

- `local_auth_enabled = false` and `public_network_access_enabled = false`: the azurerm provider defaults both to
  `true`.
- `time_sleep.rbac` (120 seconds) and `depends_on` on the account: the Crypto User role first, then CMK.
- `local.foundry_zones` creates all three zones, links and the zone group in one `for_each`.

If apply fails with 403 on the key or on CMK, role assignments were still propagating ("can take up to 5 minutes"):
run `make up` again.

**Whichever path**, set `FID` for the tests:

```bash
export FID=$(az cognitiveservices account show -n $AZ11_NAME -g $RG --query id -o tsv)
make evidence      # the settings an auditor asks for, read back from Azure
```

**Example response (shape from Microsoft docs, values illustrative)** (property names from Microsoft's
`32-customer-managed-keys-user-assigned-identity` Bicep sample, which sets `encryption.keySource` and
`keyVaultProperties`; table columns are the names `cloud.sh evidence` gives them):

```text
PublicNetworkAccess    DisableLocalAuth    KeySource           KeyVaultUri
---------------------  ------------------  ------------------  ------------------------------------
Disabled               True                Microsoft.KeyVault  https://kv-az11-ab1234.vault.azure.net/
Name           Type
-------------  ----------------
helpdesk-chat  DataZoneStandard
```

**Built with Path A?** `cloud.sh probe-outside`, `probe-inside`, `logs` and the last line of `evidence` read
Terraform outputs, so they won't find your resources. Use these instead (same script, same results):

```bash
# instead of probe-outside
for h in $AZ11_NAME.openai.azure.com $AZ11_NAME.cognitiveservices.azure.com $AZ11_NAME.services.ai.azure.com; do
  nslookup $h; done
TOKEN=$(az account get-access-token --scope https://ai.azure.com/.default --query accessToken -o tsv)
curl -s -w "\nHTTP %{http_code}\n" "https://$AZ11_NAME.openai.azure.com/openai/v1/responses" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"model":"helpdesk-chat","input":"Reply with OK","max_output_tokens":16}'
# instead of probe-inside
CLIENT_ID=$(az identity show -g $RG -n id-jump --query clientId -o tsv)
sed -e "s/__NAME__/$AZ11_NAME/g" -e "s/__CLIENT_ID__/$CLIENT_ID/g" -e "s/__DEPLOYMENT__/helpdesk-chat/g" \
  cloud/probe-inside.sh > /tmp/az11-probe.sh
az vm run-command invoke -g $RG -n vm-jump --command-id RunShellScript --scripts @/tmp/az11-probe.sh \
  --query "value[].message" -o tsv
```

The `@/tmp/az11-probe.sh` form is how `cloud.sh` passes the script too (the CLI's "`@{file}` to load a file").

## G2 · Guardrails that keep it this way (`make policy`)

`make policy` assigns four policies on your resource group: your custom deployment-type policy (from
`fixes/policies/deny-global-deployments.json`, so finish lab challenge 1 first or it refuses only `GlobalStandard`),
"Azure AI Services resources should restrict network access" on Deny, the key-access policy on Deny, and the
diagnostic-logs audit. Portal, for the built-in ones: **Policy**, **Assignments**, **Assign Policy**, choose the scope
and the definition, set the effect on the **Parameters** tab, **Review + create**, **Create**. Wait at least 15
minutes before G3's T4.

Remember what each one can and can't see (lessons 11.2 to 11.5): the network policy passes "Selected networks" with a
Deny default; the diagnostic policy only checks that **some** log category exists; the built-in CMK policy skips
`AIServices` by default, which is why it isn't in the list.

## G3 · Prove it: five tests

### T1 · The public path is refused, even with a valid token

```bash
./cloud/cloud.sh probe-outside
```

It resolves the three hostnames from your laptop, gets a token for you (`--scope https://ai.azure.com/.default`) and
sends one tiny `POST /openai/v1/responses`. You don't hold Foundry User, but that doesn't matter here: the network
refuses before identity is checked (lab step A1).

**Example response (shape from Microsoft docs, values illustrative)**. Microsoft's network isolation page: "From
outside the virtual network, the same name resolves to the public endpoint." Microsoft Learn doesn't document the body
of a network refusal; the message below is the text users report on Microsoft Q&A, and `403` is our expectation, not
a documented code:

```text
az11-ab1234.openai.azure.com -> 198.51.100.20
az11-ab1234.cognitiveservices.azure.com -> 198.51.100.20
az11-ab1234.services.ai.azure.com -> 198.51.100.20
POST /openai/v1/responses from your laptop -> HTTP 403 (expect a refusal: public network access is Disabled)
... "Public access is disabled. Please configure private endpoint." ...
```

### T2 · The private path works, and leaves a log entry

```bash
./cloud/cloud.sh probe-inside      # runs cloud/probe-inside.sh on vm-jump through Run Command
```

Inside the VNet, each name should resolve to the private endpoint, and the VM's own managed identity (token from the
metadata endpoint, `Metadata:true` header) calls the model.

**Example response (shape from Microsoft docs, values illustrative)** (top-level fields from the
[Responses REST reference](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/responses?view=rest-microsoft-foundry-v1&preserve-view=true);
`output` and `usage` shortened):

```text
az11-ab1234.openai.azure.com -> 10.20.2.4   (expect 10.20.2.x: the private endpoint)
az11-ab1234.cognitiveservices.azure.com -> 10.20.2.4   (expect 10.20.2.x: the private endpoint)
az11-ab1234.services.ai.azure.com -> 10.20.2.4   (expect 10.20.2.x: the private endpoint)
token for audience https://ai.azure.com: obtained (not printed)
POST /openai/v1/responses from inside the VNet -> HTTP 200 (expect 200)
{"id": "resp_67cb32528d6881909eb2859a55e18a85", "object": "response", "created_at": 1792656000, "status": "completed", ...
```

Two open questions from our fact-check get answered here. **Foundry User is enough for inference**, or you'd get a
401 (Microsoft's keyless guide still names Cognitive Services User; item U3). And **which token audience works**: the
script tries `https://ai.azure.com` first (item U6). Note both.

Now the log entry. Microsoft: data "should start flowing to your selected destinations within 90 minutes".

```bash
make logs          # counts AzureDiagnostics rows by Category and OperationName
```

**Example response (shape from Microsoft docs, values illustrative)** (column names from Microsoft's `AzureDiagnostics`
table reference; the operation names are yours to read):

```text
Category         OperationName    Count
---------------  ---------------  -----
Audit            ...              2
RequestResponse  ...              1
```

Then the row itself:

```bash
WS=$(az monitor log-analytics workspace show -g $RG -n law-$AZ11_NAME --query customerId -o tsv)
az monitor log-analytics query -w $WS --analytics-query "AzureDiagnostics
  | where ResourceProvider == 'MICROSOFT.COGNITIVESERVICES' and Category == 'RequestResponse'
  | project OperationName, ResultSignature, CallerIPAddress, DurationMs, properties_s" -o json
```

Read the `CallerIPAddress` of the `RequestResponse` row: it should be the VM's `10.20.3.x`, never a public address.
Then search `properties_s` for "Reply with OK". Microsoft doesn't say whether these categories hold prompt text (item
U5), which is why lesson 11.4 sends prompt-level audit to the API Management gateway. Your answer settles it.

### T3 · Right network, wrong identity

Same VM, same private path, but the identity loses its role:

```bash
JUMP_PID=$(az identity show -g $RG -n id-jump --query principalId -o tsv)
az role assignment delete --assignee $JUMP_PID --role 53ca6127-db72-4b80-b1b0-d745d6d5456d --scope $FID
# wait 5 to 10 minutes, then:
./cloud/cloud.sh probe-inside
```

The DNS lines stay private; the call doesn't get through. This is lab step A3 the other way round: the network is the
first door, the role on **this one resource** is the second.

**Example response (shape from Microsoft docs, values illustrative)** ([keyless authentication, troubleshooting
table](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/how-to/configure-entra-id); it names the status and
error, not the full body):

```text
POST /openai/v1/responses from inside the VNet -> HTTP 401 (expect 200)
... "PermissionDenied" ... "Principal does not have access to API/Operation." ...
```

Put the role back with `make up` (Terraform re-creates the assignment; type `yes`) or the portal, wait, and re-run
`probe-inside` until it's 200 again.

### T4 · The doors can't be re-opened, not even by you

At least 15 minutes after `make policy`. Three changes an attacker with a stolen admin session would try (lab steps
A4, A6 and B9 from AZ10):

```bash
# 1. a Global deployment: prompts "may be processed in any Azure region"
az cognitiveservices account deployment create -g $RG -n $AZ11_NAME --deployment-name test-global \
  --model-name gpt-4.1-mini --model-version 2025-04-14 --model-format OpenAI --sku-name GlobalStandard --sku-capacity 1
# 2. keys back on
az resource update --ids $FID --set properties.disableLocalAuth=false -o none
# 3. the internet back in
az resource update --ids $FID --set properties.publicNetworkAccess=Enabled properties.networkAcls.defaultAction=Allow -o none
```

You're Owner, so RBAC allows all three. Policy doesn't: Azure Policy's deny effect returns "`403 (Forbidden)`".

**Example response (shape from Microsoft docs, values illustrative)**
([RequestDisallowedByPolicy](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-policy-requestdisallowedbypolicy)),
for change 1:

```text
(RequestDisallowedByPolicy) Resource 'test-global' was disallowed by policy. Policy identifiers:
'[{"policyAssignment":{"name":"az11-deployment-types","id":"/subscriptions/.../policyAssignments/az11-deployment-types"},
   "policyDefinition":{"name":"contoso-az11-deployment-types", ...}}]'.
```

If change 1 **succeeds**, delete `test-global` at once (`az cognitiveservices account deployment delete -g $RG -n
$AZ11_NAME --deployment-name test-global`): either the assignment wasn't active yet or your challenge-1 policy has a
gap. Change 3 is lab test 12 for real: Owner flips `publicNetworkAccess`, the network policy on Deny refuses.

### T5 · The key is yours: who used it, and a rotation

Who touched the key? Key Vault's diagnostic category is `AuditEvent`, and key operations have "the `Key<action>`
format" (Microsoft's Key Vault logging page):

```bash
az monitor log-analytics query -w $WS --analytics-query "AzureDiagnostics
  | where ResourceProvider == 'MICROSOFT.KEYVAULT'
  | summarize count() by OperationName, CallerIPAddress, ResultSignature" -o table
```

Expect your own `Key<action>` rows from creating the key (from `MY_IP`), and rows from the Foundry resource's identity
using it. Write down which operation names appear: Microsoft's page lists them on a tab we couldn't read.

Now rotate. Microsoft's CMK page: "Periodically create a new version of your key in your key store. Update the
Foundry resource to reference the latest key version in its encryption settings."

```bash
KV=kv-$AZ11_NAME
az cognitiveservices account show -n $AZ11_NAME -g $RG --query properties.encryption.keyVaultProperties.keyVersion -o tsv
az keyvault key rotate --vault-name $KV --name cmk-foundry -o none            # a new version (from MY_IP)
NEW=$(az keyvault key show --vault-name $KV --name cmk-foundry --query key.kid -o tsv); NEW=${NEW##*/}
az cognitiveservices account show -n $AZ11_NAME -g $RG --query properties.encryption.keyVaultProperties.keyVersion -o tsv
```

The second `show` still prints the **old** version: a new key version does nothing until the resource points at it.
Point it there, with the property names from Microsoft's CMK Bicep sample:

```bash
CMK_CLIENT=$(az identity show -g $RG -n id-$AZ11_NAME-cmk --query clientId -o tsv)
az cognitiveservices account update -n $AZ11_NAME -g $RG --encryption "{\"keySource\": \"Microsoft.KeyVault\",
  \"keyVaultProperties\": {\"keyName\": \"cmk-foundry\", \"keyVersion\": \"$NEW\",
  \"keyVaultUri\": \"https://$KV.vault.azure.net/\", \"identityClientId\": \"$CMK_CLIENT\"}}" -o none
az cognitiveservices account show -n $AZ11_NAME -g $RG --query properties.encryption.keyVaultProperties.keyVersion -o tsv
./cloud/cloud.sh probe-inside       # still 200
```

Terraform will now see the change too: the next `make up` plan shows whether it wants to move the resource back or
forward. Read it before you type `yes`.

We don't ask you to disable or delete the key. Microsoft says "data encrypted with that key becomes inaccessible until
the key is restored" but doesn't say what that does to inference on a stateless model, and with purge protection a
mistake here keeps the vault name locked for 7 days.

## G4 · Change one setting and re-run: drop one DNS link

Lesson 11.2's quietest failure: one privatelink zone loses its link to the VNet. Delete the link for
`privatelink.openai.azure.com` only:

```bash
${TF:-terraform} -chdir=terraform destroy -var "name=$AZ11_NAME" -var "my_ip=$MY_IP" \
  -target='azurerm_private_dns_zone_virtual_network_link.foundry["privatelink.openai.azure.com"]'
./cloud/cloud.sh probe-inside
```

Portal instead: **Private DNS zones**, `privatelink.openai.azure.com`, **Virtual network links**, delete the link
(labels may differ slightly).

**Example response (shape from Microsoft docs, values illustrative)** (Microsoft: "If the name resolves to a public IP
inside the virtual network", confirm the zone "exists and is linked to your virtual network"):

```text
az11-ab1234.openai.azure.com -> 198.51.100.20   (expect 10.20.2.x: the private endpoint)
az11-ab1234.cognitiveservices.azure.com -> 10.20.2.4   (expect 10.20.2.x: the private endpoint)
az11-ab1234.services.ai.azure.com -> 10.20.2.4   (expect 10.20.2.x: the private endpoint)
POST /openai/v1/responses from inside the VNet -> HTTP 403 (expect 200)
```

Same VM, same identity, same role, same model: refused, because one name now leads to the public door, which is shut.
With public access Enabled (Contoso's version 1), the same mistake would have **worked**, over the internet, and nobody
would have noticed (lab steps L2 and L3). The tempting fix is to re-open public access; T4 showed the policy won't let
you, and lesson 11.2 says fix DNS. Restore it with `make up` and run `probe-inside` once more.

| Test | Expected | Your result |
|---|---|---|
| T1 laptop, public path | public addresses, refused | |
| T2 VM, private path; `CallerIPAddress`; prompt text in `properties_s`? | 10.20.2.x, 200, a `RequestResponse` row | |
| T3 VM without Foundry User | 401 | |
| T4 Global deployment, keys on, internet on | all three refused by policy | |
| T5 `Key<action>` names; key version before and after | old version until you update it | |
| G4 one zone link deleted | that hostname public, call refused | |

## G5 · Prompt-level audit: what this build doesn't do

Lesson 11.4: Microsoft documents prompt and completion logging in the API Management AI gateway ("Log LLM messages"),
not in the Foundry resource's own categories. This build has no gateway, so checker rule AZ11-14 stays as an accepted
LOW finding, and T2's `properties_s` check tells you what you do get without one. If you add a gateway later, keep it
private (the Foundry portal's AI Gateway "is automatically public"), give the LLM log a short retention, and let only a
small incident group read the workspace.

## G6 · Cost and teardown (do it today)

| Item | How it bills |
|---|---|
| Private endpoint | per hour, plus per GB through it |
| `vm-jump` (`Standard_B1s`) and its `Standard_LRS` OS disk | per hour |
| 3 private DNS zones | per zone per month (a few hours is a fraction) |
| Log Analytics | per GB ingested (a few MB here); "31 days of analytics retention at no extra cost" |
| Key Vault | per 10,000 key operations; a handful here |
| Model tokens | `probe-inside` runs a few times, a few dozen tokens each |
| Foundry resource, Azure Policy | no hourly charge for the resource; "no charges for using Azure Policy on Azure resources" |

We can't give you a total: Microsoft's pricing pages render prices in the browser and we couldn't load them (item U2).
Put the first five lines into the Azure pricing calculator for your region with 2 hours each; the VM and the private
endpoint are the hourly part, so the clock matters more than the number of tests.

```bash
make down
```

It removes the four policy assignments and the custom definition, then runs `terraform destroy`, which also purges the
Foundry resource so its name is free again. Two things survive on purpose: the Key Vault stays soft-deleted for 7 days
(purge protection: a deleted object "can't be purged until the retention period passes"), so `kv-<name>` can't be
reused until then; and anything you created by hand in Path A, which Terraform doesn't know about. For Path A, delete
the resource group instead (`az group delete -n $RG --yes`), purge the Foundry resource
(`az cognitiveservices account purge --location swedencentral --resource-group $RG --name $AZ11_NAME`), delete the
custom policy definition (`az policy definition delete --name contoso-az11-deployment-types`) and
`rm -f /tmp/az11-probe.sh`. Microsoft also
notes: "Storage-related charges for CMK encryption continue during soft-deleted retention."

Tomorrow, check: `az group show -n $RG` says `ResourceGroupNotFound`, `az keyvault list-deleted -o table` lists only
the vault you expect, and Cost Management shows the session.

## What we could not verify (October 2026)

- **No real run, and the Terraform was never planned or applied** (fact-check U1). Every response above is
  illustrative. Before release the course team runs this guide in a sandbox and replaces them with real output.
- Portal labels for the VNet, Key Vault, managed identity, VM and private DNS screens, and whether the Foundry create
  wizard shows its encryption step under that name (marked "label may differ slightly").
- The status code and body of a network refusal (T1, G4). Microsoft Learn doesn't document them.
- The role (U3), token audience (U6) and prompt-text (U5) questions: T2 answers them.
- Run Command and the metadata endpoint on a subnet without default outbound access (U7).
- Whether `gpt-4.1-mini` 2025-04-14 is offered as `DataZoneStandard` in `swedencentral` (U8): Step 0.6 checks.
- Whether `az cognitiveservices account update --encryption` accepts a version change without other properties, and
  what Terraform plans after it (T5).
- Prices (U2).
