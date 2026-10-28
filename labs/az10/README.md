# Lab AZ10: find the risky Azure AI settings, cut the keys and roles, allow-list models, then hunt LLMjacking

Companion to lessons **10.2 to 10.5** of *AI Security Engineer* (The Sec Guy), Azure stream. About 60 minutes,
**$0**, all on your laptop. **Nothing to install** (Python standard library only) and **no Azure subscription
needed**. An optional last step repeats the key and policy tests in your own Azure subscription, also at an expected
cost of $0.

You are the new cloud security engineer at **Contoso** (a fictional company; "Contoso" is the placeholder name
Microsoft uses in its own documentation). Contoso runs the TSG Helpdesk chatbot on a Microsoft Foundry resource in
production and lets data scientists try models in a sandbox. Its helpdesk repository was public for three days. In
one sitting you will:

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Run a checker over Contoso's role assignments, policy assignments, Foundry resources, deployments and budgets | 10.2 to 10.5 |
| **Scan** | See what a thief finds in the repository that went public | 10.4 |
| **Break** | Replay what a thief can do with the leaked keys and the CI pipeline's secret: 10 of 12 requests work | 10.3 to 10.5 |
| **Fix** | Apply least-privilege roles, `disableLocalAuth`, the approved-models policy on Deny, budgets, and replay | 10.3 to 10.5 |
| **Hunt** | Search the Activity Log, request logs and token metrics for the two intrusions of 14 October | 10.5 |
| **Challenge** | Close the three gaps the fixes still leave. No solution included | 10.3 to 10.5 |

## Get the lab files

This folder is part of the free, public course labs repository, [thesecguyofficial/ai-security-course-labs](https://github.com/thesecguyofficial/ai-security-course-labs).

**First time, or you deleted the folder:** download it once.

```bash
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git
cd ai-security-course-labs
```

**Already downloaded it:** go to that folder and get the latest version.

```bash
cd ai-security-course-labs
git pull
```

**No git?** On the [labs page](https://github.com/thesecguyofficial/ai-security-course-labs), click **Code → Download ZIP**, unzip it and open a terminal in that folder (download it again to get updates).

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/az10`.

## What's in this folder

| File | What it is |
|---|---|
| `checker.py` | The checker: 14 rules (`AZ10-01` to `AZ10-14`), each from a Microsoft document |
| `secret_scan.py` | A tiny secret scanner (read all of it; use a real one at work) |
| `attack.py` | 17 requests (12 attacker, 5 legitimate), `--mode vulnerable` or `--mode safe` |
| `azure_model.py` | A **teaching model** of Azure RBAC, keys and Azure Policy (see below) |
| `hunt.py` | Six hunting rules (`H01` to `H06`), `H07` for you to write, and `--naive` |
| `contoso/estate.json` | Contoso's Foundry resources and model deployments (shaped like Azure CLI output) |
| `contoso/principals.json`, `contoso/role-assignments.json` | Who exists, and which roles they hold where |
| `contoso/roles/` | Built-in role definitions copied from Microsoft's docs (including four Foundry roles), and the Foundry roles' permission matrix |
| `contoso/policy-assignments.json`, `contoso/policy-definitions/` | Contoso's policy assignments, and the **real** policy rules of the two built-in definitions used |
| `contoso/standards.json`, `contoso/budgets.json` | What Contoso's standards say, and the budgets it has |
| `contoso/repo-snapshot/` | The repository that went public (every secret is a fake containing EXAMPLE) |
| `fixes/` | The fixed estate, role assignments (plus a custom role), policy assignments and budgets |
| `logs/` | **Fake** Activity Log, request logs (`RequestResponse`) and token metrics for 9 to 14 October 2026 |
| `azure-twin/` | Optional Step 8: Bicep, policy parameters and `twin.sh` for your own subscription |
| `GUIDED-BUILD.md` | Inventory and lock down a real Foundry estate in your own subscription, step by step |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 17 tests for the lab, 4 for the challenge |

**About `azure_model.py`.** It is not Azure. It models only what this lab needs, each rule from Microsoft's docs:

- A role assignment applies to its scope and everything below it. Effective permissions are Actions minus NotActions
  (managing a resource) and DataActions minus NotDataActions (using it). No matching assignment means denied.
- Foundry User, Foundry Project Manager, Foundry Account Owner and Foundry Owner are evaluated from their real JSON,
  copied from Microsoft's built-in roles page into `contoso/roles/`. Read `foundry-user.json`: its Actions include
  `Microsoft.CognitiveServices/accounts/listkeys/action`, so even the least-privilege Foundry role can read the keys
  while key access is on. Foundry Agent Consumer's JSON isn't on that page, so it alone is evaluated from the Foundry
  RBAC page's capability matrix (`foundry-roles-matrix.json`); check any role with
  `az role definition list --name "<role>"`.
- A request carrying the resource's key is accepted whenever `disableLocalAuth` isn't `true`, with no role check.
- The two built-in policies are evaluated by a small interpreter of their **real** `policyRule` JSON (case-insensitive
  string tests, as in Azure Policy). `Deny` refuses; `Audit` lets the request through and logs a warning.

It does not model deny assignments, role conditions, PIM, Conditional Access, network rules, other policies, or the
real propagation delays (15 minutes or more for new policy assignments, minutes to hours for `disableLocalAuth`).
The Cognitive Services Contributor definition is trimmed to the actions this lab needs (its NotActions are complete).

**About the data and safety.** The tenant, subscription and object IDs are Microsoft documentation example GUIDs
(from the Azure Monitor activity log schema sample); role and policy definition IDs are the real built-in IDs, which
are the same in every tenant. Every IP address is from the documentation ranges in
[RFC 5737](https://www.rfc-editor.org/rfc/rfc5737). Model asset IDs follow Microsoft's documented format;
`fabrikam-chat-xl` is invented. Nothing here contacts Azure or any other system. Test 17 fails if a non-documentation
GUID or IP, or a secret without EXAMPLE in it, ever creeps in.

**Guided build (your own subscription).** `GUIDED-BUILD.md` builds a small Foundry estate from zero, inventories it with
lessons 10.1 to 10.5, locks it down (Foundry User on one resource, keys off, approved models and key access on Deny,
logs, a budget) and proves each fix with a request that should now fail. About 75 minutes, a few US cents.

## Needs

- Python **3.11 or newer** (tested on 3.13). Check with `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 8 only: the Azure CLI with Bicep, and **your own** Azure subscription, never your employer's.

## Step 1 · Check: find the risky settings

```bash
cd labs/az10
make check
```

- `cd labs/az10`: run it from the course labs repository folder (`ai-security-course-labs`)
- `make check`: same as `python3 checker.py`

Real output (Linux, Python 3.13):

```text
--- AZ10 checker · Contoso today ---

  HIGH    AZ10-01  contoso-helpdesk-ai
          Key access is ON (disableLocalAuth is not true): anyone holding a key gets full access, no role check.
          fix: Move callers to Entra ID, then set disableLocalAuth: true (lesson 10.4).
  HIGH    AZ10-01  contoso-sandbox-ai
          Key access is ON (disableLocalAuth is not true): anyone holding a key gets full access, no role check.
          fix: Move callers to Entra ID, then set disableLocalAuth: true (lesson 10.4).
  HIGH    AZ10-02  ci-deployer on contoso-helpdesk-ai
          Contributor @ rg:rg-helpdesk-prod can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  HIGH    AZ10-02  ci-deployer on contoso-sandbox-ai
          Contributor @ rg:rg-ai-sandbox can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  HIGH    AZ10-02  helpdesk-app on contoso-helpdesk-ai
          Contributor @ contoso-helpdesk-ai can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  HIGH    AZ10-07  allow-only-approved-models
          Effect is Audit: unapproved deployments still succeed (Audit only logs).
          fix: Set the effect to Deny once the list is right (lesson 10.3).
  HIGH    AZ10-08  allow-only-approved-models
          allowedPublishers = ['OpenAI']: the rule denies only when the publisher is NOT listed AND no asset ID matches, so every model from these publishers is approved, including future ones.
          fix: Empty allowedPublishers; list asset IDs only (lesson 10.3).
  MEDIUM  AZ10-02  contractor on contoso-sandbox-ai
          Cognitive Services Contributor @ contoso-sandbox-ai can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  MEDIUM  AZ10-02  data-science on contoso-helpdesk-ai
          Foundry User @ subscription can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  MEDIUM  AZ10-02  data-science on contoso-sandbox-ai
          Foundry User @ subscription can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  MEDIUM  AZ10-02  platform-admin on contoso-helpdesk-ai
          Owner @ subscription can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  MEDIUM  AZ10-02  platform-admin on contoso-sandbox-ai
          Owner @ subscription can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  MEDIUM  AZ10-03  ci-deployer
          Workload identity has Contributor @ rg:rg-helpdesk-prod, rg:rg-ai-sandbox: it can read keys, change content filters and settings, yet has no data actions (so an app given it ends up calling the model with a key).
          fix: Give it only its job: Foundry User on one resource to call models, or a custom role that manages deployments only (lesson 10.3).
  MEDIUM  AZ10-03  contractor
          Cognitive Services Contributor @ contoso-sandbox-ai: Microsoft says not to use 'Cognitive Services' roles for Foundry (except Usages Reader). This one can read and regenerate keys.
          fix: Use Foundry User / Foundry Project Manager instead (lesson 10.3).
  MEDIUM  AZ10-03  helpdesk-app
          Workload identity has Contributor @ contoso-helpdesk-ai: it can read keys, change content filters and settings, yet has no data actions (so an app given it ends up calling the model with a key).
          fix: Give it only its job: Foundry User on one resource to call models, or a custom role that manages deployments only (lesson 10.3).
  MEDIUM  AZ10-04  data-science
          Foundry User @ subscription: data access to EVERY Foundry resource below it.
          fix: Assign it on the one Foundry resource or project they use (lesson 10.3).
  MEDIUM  AZ10-06  data-science
          Azure AI Developer is for Azure Machine Learning workspaces and Foundry hubs, not Foundry projects (despite the name), and it carries OpenAI data actions.
          fix: Use Foundry User; remove this role (lesson 10.3).
  MEDIUM  AZ10-09  allow-only-approved-models
          Asset ID 'gpt-5' has no trailing slash or version: it also matches every model whose name starts the same way (gpt-5 also matches gpt-5.2 and gpt-5.4).
          fix: End it with '/' (all versions of that model) or '/versions/<n>' (one version) (lesson 10.3).
  MEDIUM  AZ10-10  contoso-sandbox-ai/sandbox-gpt54
          Deployment of gpt-5.4 v1 is not on Contoso's approved list. The policy is checked at deployment time, so this one already exists.
          fix: Delete it or approve it; the policy compliance view lists it as non-compliant (lesson 10.3).
  MEDIUM  AZ10-11  subscription
          No policy for key access: nobody is told when a Foundry resource is created or changed with keys on.
          fix: Assign 'Azure AI Services resources should have key access disabled' (Audit, then Deny) (lesson 10.4).
  MEDIUM  AZ10-12  contoso-helpdesk-ai/helpdesk-gpt5
          Deployment type GlobalStandard: prompts may be processed in any Azure region. Contoso's standard says EU data zone or the resource's geography.
          fix: Redeploy as DataZoneStandard (or Standard) (lesson 10.2).
  MEDIUM  AZ10-13  contoso-sandbox-ai/sandbox-gpt54
          Capacity 300 units is above Contoso's sandbox limit of 10. Capacity sets tokens per minute: a speed limit, not a spending cap.
          fix: Lower it to 10 or less, and add a budget alert (lesson 10.5).
  MEDIUM  AZ10-14  rg-ai-sandbox
          No budget on this AI resource group: the only alert is the company-wide one.
          fix: Add a budget with an early actual alert and a forecast alert to the team that can act (lesson 10.5).
  MEDIUM  AZ10-14  rg-helpdesk-prod
          No budget on this AI resource group: the only alert is the company-wide one.
          fix: Add a budget with an early actual alert and a forecast alert to the team that can act (lesson 10.5).
  LOW     AZ10-05  helpdesk-app
          Foundry Agent Consumer at resource scope: every agent endpoint in every project. The portal can only assign it here.
          fix: Assign it at project or agent scope with the Azure CLI (lesson 10.3).

7 HIGH, 17 MEDIUM, 1 LOW  (25 findings)
Remember: a budget alerts, it never stops spending; a TPM quota limits speed, not the monthly bill.
```

How to read it, highest first:

- **AZ10-01, AZ10-02**: keys are on for both Foundry resources, and six assignments can list them. The CI pipeline
  and the helpdesk app hold **Contributor**; the contractor holds **Cognitive Services Contributor**, whose own
  description is "Lets you create, read, update, delete and manage keys of Cognitive Services." Even the data
  scientists' **Foundry User** can: its Actions include `Microsoft.CognitiveServices/accounts/listkeys/action`.
- **AZ10-07, AZ10-08, AZ10-09**: the approved-models policy is on `Audit`, lists the publisher `OpenAI`, and its one
  asset ID has no trailing slash. Open `contoso/policy-definitions/approved-models.json` and read the `policyRule`:
  non-compliant only if the publisher is `notin` the list **and** no asset ID is `contains`-matched.
- **AZ10-03 to AZ10-06**: role hygiene. Contributor on workloads, an AI role at subscription scope, Agent Consumer at
  resource scope (the portal can't do better; the CLI can), and Azure AI Developer used because of its name.
- **AZ10-10 to AZ10-14**: an existing deployment that isn't approved and is far too big for a sandbox, a Global
  deployment for EU helpdesk data, no key-access policy, and no budget on either AI resource group.

## Step 2 · Scan: what a thief sees

```bash
make scan
```

Same as `python3 secret_scan.py contoso/repo-snapshot`.

```text
--- secret scan · contoso/repo-snapshot ---

  .github/workflows/deploy-models.yml:10  Service principal client secret  EXAMPL…MPLE
      a service principal secret works wherever that identity's roles reach: check its role assignments
  helpdesk-web/call_model.sh:4  Key sent in an api-key header  EXAMPL…MPLE
      resource named in the same file: contoso-sandbox-ai
  helpdesk-web/settings.env:4  Foundry/Azure OpenAI key in a setting  EXAMPL…MPLE
      resource named in the same file: contoso-helpdesk-ai

3 secrets found. Treat every one as stolen: rotate or revoke it first, then find out who used it (hunt.py).
```

The scanner exits with code 1 when it finds something, so `make` shows the step as ignored (`-`). That's on purpose: in
CI, a found secret should fail the build.

## Step 3 · Break it: what can a thief do today?

```bash
make attack
```

Same as `python3 attack.py --mode vulnerable`.

Real output:

```text
--- AZ10 lab · VULNERABLE · contoso/ ---
    (azure_model.py: a teaching model of Azure RBAC, keys and Azure Policy; nothing is sent to Azure)

  !! A1  ALLOWED 200    Leaked PROD key: list the models on the helpdesk resource
                     key access is ON: the key grants full access, no role is checked
  !! A2  ALLOWED 200    Leaked PROD key: chat with helpdesk-gpt5 on Contoso's bill
                     key access is ON: the key grants full access, no role is checked
  !! A3  ALLOWED 200    Leaked SANDBOX key: chat with sandbox-gpt52
                     key access is ON: the key grants full access, no role is checked
  ok B1  DENIED  401    Stolen CI secret: call the model with an Entra ID token
                     no    Contributor: no DataActions (management only) @ rg:rg-helpdesk-prod
  !! B2  ALLOWED 200    Stolen CI secret: read the PROD keys (listKeys)
                     GRANT Contributor: Actions '*' covers Microsoft.CognitiveServices/accounts/listKeys/action @ rg:rg-helpdesk-prod
  !! B3  ALLOWED Audit  Stolen CI secret: deploy an unapproved model (fabrikam-chat-xl)
                     POLICY allow-only-approved-models: Audit (allowed, logged as a warning)
  !! B4  ALLOWED 200    Stolen CI secret: deploy gpt-5.4 (not on Contoso's list)
                     GRANT Contributor: Actions '*' covers Microsoft.CognitiveServices/accounts/deployments/write @ rg:rg-ai-sandbox
  !! B5  ALLOWED 200    Stolen CI secret: replace the content filter (raiPolicies/write)
                     GRANT Contributor: Actions '*' covers Microsoft.CognitiveServices/accounts/raiPolicies/write @ rg:rg-helpdesk-prod
  ok B6  DENIED  403    Stolen CI secret: give itself Foundry User (roleAssignments/write)
                     no    Contributor: NotActions removes Microsoft.Authorization/roleAssignments/write @ rg:rg-helpdesk-prod
  !! B7  ALLOWED 200    Stolen CI secret: switch key access back on (disableLocalAuth=false)
                     GRANT Contributor: Actions '*' covers Microsoft.CognitiveServices/accounts/write @ rg:rg-helpdesk-prod
  !! B8  ALLOWED 200    Stolen CI secret: deploy gpt-5.2 version 2 (only version 1 is approved)
                     GRANT Contributor: Actions '*' covers Microsoft.CognitiveServices/accounts/deployments/write @ rg:rg-ai-sandbox
  !! B9  ALLOWED 200    Phished ADMIN session: switch key access back on (Owner!)
                     GRANT Owner: Actions '*' covers Microsoft.CognitiveServices/accounts/write @ subscription
  ok L1  ALLOWED 200    Helpdesk app answers a customer (today: key; fixed: Entra ID token)
                     key access is ON: the key grants full access, no role is checked
  ok L2  ALLOWED 200    CI pipeline rolls out approved gpt-5 version 1
                     GRANT Contributor: Actions '*' covers Microsoft.CognitiveServices/accounts/deployments/write @ rg:rg-helpdesk-prod
  ok L3  ALLOWED 200    Data scientist calls sandbox-gpt52 with an Entra ID token
                     GRANT Azure AI Developer: DataActions ['Microsoft.CognitiveServices/accounts/OpenAI/*'] @ rg:rg-ai-sandbox
  ok L4  ALLOWED 200    Contractor reads the sandbox resource's settings
                     GRANT Cognitive Services Contributor: Actions 'Microsoft.CognitiveServices/*' covers Microsoft.CognitiveServices/accounts/read @ contoso-sandbox-ai
  ok L5  ALLOWED 200    Platform admin reads the prod keys during a planned rotation
                     GRANT Owner: Actions '*' covers Microsoft.CognitiveServices/accounts/listKeys/action @ subscription

Attacker requests allowed: 10 of 12   ·   legitimate requests allowed: 5 of 5
```

Add `-v` to see every role and policy that was checked for each request. What to notice:

- **A1 to A3**: the keys from the repository work on both resources, and the reason line says why: no role is
  checked at all.
- **B1 vs B2**: the CI identity's Entra ID token can't call the model (Contributor has no DataActions), but the same
  identity lists the keys. That's the RBAC bypass from lessons 10.3 and 10.4.
- **B3, B4, B8**: an unapproved publisher deploys with only an audit warning; gpt-5.4 and gpt-5.2 version 2 deploy
  without even that, because the publisher `OpenAI` is approved.
- **B5, B7, B9**: content filters replaced, keys switched back on. **B6** is the one thing Contributor can't do:
  `Microsoft.Authorization/*/Write` is in its NotActions.

## Step 4 · Read the fixes

Open each file in `fixes/` before you run them:

- `role-assignments.json`: the helpdesk app gets **Foundry User** on its one resource and calls with an Entra ID token;
  the CI pipeline gets `custom-role-foundry-deployer.json` (read, and write or delete deployments, nothing else); data
  science gets Foundry User and Reader on the sandbox resource only; Agent Consumer and Azure AI Developer are gone.
- `estate.json`: production has `disableLocalAuth: true` and a `DataZoneStandard` deployment; the oversized gpt-5.4
  sandbox deployment is deleted.
- `policy-assignments.json`: approved models on **Deny** with no publishers, and the key-access policy on **Deny**.
- `budgets.json`: a budget on each AI resource group with a 50 % actual and an 80 % forecast alert.

```bash
make check-fixed
```

Same as `python3 checker.py --with-fixes`.

```text
--- AZ10 checker · Contoso with fixes/ ---

  HIGH    AZ10-01  contoso-sandbox-ai
          Key access is ON (disableLocalAuth is not true): anyone holding a key gets full access, no role check.
          fix: Move callers to Entra ID, then set disableLocalAuth: true (lesson 10.4).
  MEDIUM  AZ10-02  data-science on contoso-sandbox-ai
          Foundry User @ contoso-sandbox-ai can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  MEDIUM  AZ10-02  platform-admin on contoso-sandbox-ai
          Owner @ subscription can list the keys, and a key bypasses RBAC.
          fix: Remove the role or disable key access on the resource (lessons 10.3, 10.4).
  MEDIUM  AZ10-09  allow-only-approved-models
          Asset ID 'gpt-5' has no trailing slash or version: it also matches every model whose name starts the same way (gpt-5 also matches gpt-5.2 and gpt-5.4).
          fix: End it with '/' (all versions of that model) or '/versions/<n>' (one version) (lesson 10.3).

1 HIGH, 3 MEDIUM, 0 LOW  (4 findings)
Remember: a budget alerts, it never stops spending; a TPM quota limits speed, not the monthly bill.
```

Four findings remain, from two of the three gaps in your challenge (Step 7): while the sandbox accepts keys, the
admin's Owner and the data scientists' Foundry User can both list them.

## Step 5 · Fix it: replay the same requests

```bash
make attack-safe
```

Same as `python3 attack.py --mode safe`.

```text
--- AZ10 lab · SAFE · fixes/ ---
    (azure_model.py: a teaching model of Azure RBAC, keys and Azure Policy; nothing is sent to Azure)

  ok A1  DENIED  401    Leaked PROD key: list the models on the helpdesk resource
                     disableLocalAuth = true: keys are refused (after propagation: minutes, up to hours)
  ok A2  DENIED  401    Leaked PROD key: chat with helpdesk-gpt5 on Contoso's bill
                     disableLocalAuth = true: keys are refused (after propagation: minutes, up to hours)
  !! A3  ALLOWED 200    Leaked SANDBOX key: chat with sandbox-gpt52
                     key access is ON: the key grants full access, no role is checked
  ok B1  DENIED  401    Stolen CI secret: call the model with an Entra ID token
                     no    Contoso Foundry Deployer: no DataActions (management only) @ rg:rg-helpdesk-prod
  ok B2  DENIED  403    Stolen CI secret: read the PROD keys (listKeys)
                     no    Contoso Foundry Deployer: no Action covers Microsoft.CognitiveServices/accounts/listKeys/action @ rg:rg-helpdesk-prod
  ok B3  DENIED  403    Stolen CI secret: deploy an unapproved model (fabrikam-chat-xl)
                     POLICY allow-only-approved-models: Deny
  !! B4  ALLOWED 200    Stolen CI secret: deploy gpt-5.4 (not on Contoso's list)
                     GRANT Contoso Foundry Deployer: Actions 'Microsoft.CognitiveServices/accounts/deployments/write' covers Microsoft.CognitiveServices/accounts/deployments/write @ rg:rg-ai-sandbox
  ok B5  DENIED  403    Stolen CI secret: replace the content filter (raiPolicies/write)
                     no    Contoso Foundry Deployer: no Action covers Microsoft.CognitiveServices/accounts/raiPolicies/write @ rg:rg-helpdesk-prod
  ok B6  DENIED  403    Stolen CI secret: give itself Foundry User (roleAssignments/write)
                     no    Contoso Foundry Deployer: no Action covers Microsoft.Authorization/roleAssignments/write @ rg:rg-helpdesk-prod
  ok B7  DENIED  403    Stolen CI secret: switch key access back on (disableLocalAuth=false)
                     no    Contoso Foundry Deployer: no Action covers Microsoft.CognitiveServices/accounts/write @ rg:rg-helpdesk-prod
  !! B8  ALLOWED 200    Stolen CI secret: deploy gpt-5.2 version 2 (only version 1 is approved)
                     GRANT Contoso Foundry Deployer: Actions 'Microsoft.CognitiveServices/accounts/deployments/write' covers Microsoft.CognitiveServices/accounts/deployments/write @ rg:rg-ai-sandbox
  ok B9  DENIED  403    Phished ADMIN session: switch key access back on (Owner!)
                     POLICY deny-ai-key-access: Deny
  ok L1  ALLOWED 200    Helpdesk app answers a customer (today: key; fixed: Entra ID token)
                     GRANT Foundry User: DataActions ['Microsoft.CognitiveServices/*'] @ contoso-helpdesk-ai
  ok L2  ALLOWED 200    CI pipeline rolls out approved gpt-5 version 1
                     GRANT Contoso Foundry Deployer: Actions 'Microsoft.CognitiveServices/accounts/deployments/write' covers Microsoft.CognitiveServices/accounts/deployments/write @ rg:rg-helpdesk-prod
  ok L3  ALLOWED 200    Data scientist calls sandbox-gpt52 with an Entra ID token
                     GRANT Foundry User: DataActions ['Microsoft.CognitiveServices/*'] @ contoso-sandbox-ai
  ok L4  ALLOWED 200    Contractor reads the sandbox resource's settings
                     GRANT Reader: Actions '*/read' covers Microsoft.CognitiveServices/accounts/read @ subscription
  ok L5  ALLOWED 200    Platform admin reads the prod keys during a planned rotation
                     GRANT Owner: Actions '*' covers Microsoft.CognitiveServices/accounts/listKeys/action @ subscription

Attacker requests allowed: 3 of 12   ·   legitimate requests allowed: 5 of 5
```

All five legitimate requests still work; the helpdesk app (L1) now uses Entra ID instead of a key. Look at **B9**: a
phished Owner session is allowed by RBAC, and only the `deny-ai-key-access` policy stops it re-enabling keys. Roles
decide who can change things; policy decides what the result may look like.

Three attacker requests still succeed: **A3** (the sandbox key) and **B4**, **B8** (the allow-list's `gpt-5` entry is
still a prefix). In real Azure, also remember the delays: at least 15 minutes for a new policy assignment, and minutes
to several hours before the gateway refuses an old key.

## Step 6 · Hunt: find both intrusions in the logs

```bash
make hunt
```

Same as `python3 hunt.py`.

Real output:

```text
--- AZ10 hunt · 13 activity events, 664 request rows, 218 metric rows · baseline before 2026-10-14T00:00:00Z ---

  MEDIUM H05  2026-10-14T01:52:10Z  contoso-helpdesk-ai
         Model calls from IP addresses never seen on this resource
         - 203.0.113.50: 4 calls, first 2026-10-14T01:52:10Z (ListModels)
         - 203.0.113.62: 42 calls, first 2026-10-14T03:00:01Z (ChatCompletions)
         - 203.0.113.66: 26 calls, first 2026-10-14T03:01:45Z (ChatCompletions)
         - 203.0.113.64: 30 calls, first 2026-10-14T03:02:08Z (ChatCompletions)
         - 203.0.113.60: 29 calls, first 2026-10-14T03:08:42Z (ChatCompletions)
         - ... 4 more
  HIGH   H01  2026-10-14T02:14:07Z  00001111-aaaa-2222-bbbb-3333cccc4444
         Keys listed by a caller that never did before
         - 2026-10-14T02:14:07Z listKeys contoso-helpdesk-ai from 203.0.113.77
         - 2026-10-14T02:15:31Z listKeys contoso-sandbox-ai from 203.0.113.77
  HIGH   H06  2026-10-14T02:14:07Z  00001111-aaaa-2222-bbbb-3333cccc4444
         Foundry control-plane activity from a new IP for this caller
         - 2026-10-14T02:14:07Z accounts/listKeys/action contoso-helpdesk-ai from 203.0.113.77 (Succeeded)
         - 2026-10-14T02:15:31Z accounts/listKeys/action contoso-sandbox-ai from 203.0.113.77 (Succeeded)
         - 2026-10-14T02:18:02Z accounts/deployments/write contoso-sandbox-ai/deployments/resale-xl from 203.0.113.77 (Succeeded)
         - 2026-10-14T02:21:40Z accounts/raiPolicies/write contoso-sandbox-ai/raiPolicies/relaxed from 203.0.113.77 (Succeeded)
         - 2026-10-14T02:22:15Z accounts/deployments/write contoso-sandbox-ai/deployments/resale-xl from 203.0.113.77 (Succeeded)
  HIGH   H02  2026-10-14T02:18:03Z  00001111-aaaa-2222-bbbb-3333cccc4444
         Unapproved model deployment (it WENT THROUGH: effect Audit)
         - 2026-10-14T02:18:03Z contoso-sandbox-ai/deployments/resale-xl from 203.0.113.77
  HIGH   H03  2026-10-14T02:23:50Z  00001111-aaaa-2222-bbbb-3333cccc4444
         Failed attempt to change role or policy assignments
         - 2026-10-14T02:23:50Z Microsoft.Authorization/roleAssignments/write from 203.0.113.77 -> Forbidden
  MEDIUM H04  2026-10-14T03:00:00Z  contoso-helpdesk-ai
         Token use above 5x the busiest normal hour (5,110 tokens)
         - 2026-10-14T03:00:00Z 300,914 tokens
         - 2026-10-14T04:00:00Z 299,430 tokens
         - 2026-10-14T05:00:00Z 287,138 tokens
         - 2026-10-14T06:00:00Z 293,320 tokens
         - 2026-10-14T07:00:00Z 283,074 tokens
         - ... 1 more
  MEDIUM H04  2026-10-14T03:00:00Z  contoso-sandbox-ai
         Token use above 5x the busiest normal hour (3,001 tokens)
         - 2026-10-14T03:00:00Z 236,690 tokens
         - 2026-10-14T04:00:00Z 220,519 tokens
         - 2026-10-14T05:00:00Z 222,893 tokens
         - 2026-10-14T06:00:00Z 223,861 tokens
         - 2026-10-14T07:00:00Z 225,939 tokens
         - ... 1 more
  MEDIUM H05  2026-10-14T03:02:10Z  contoso-sandbox-ai
         Model calls from IP addresses never seen on this resource
         - 203.0.113.64: 27 calls, first 2026-10-14T03:02:10Z (ChatCompletions)
         - 203.0.113.66: 23 calls, first 2026-10-14T03:11:28Z (ChatCompletions)
         - 203.0.113.63: 25 calls, first 2026-10-14T03:23:37Z (ChatCompletions)
         - 203.0.113.61: 20 calls, first 2026-10-14T03:25:43Z (ChatCompletions)
         - 203.0.113.62: 23 calls, first 2026-10-14T03:28:38Z (ChatCompletions)
         - ... 3 more

8 hits
```

Read it as a timeline. At 01:52 a new IP lists models with the leaked **key** and sends small test prompts (H05). At
02:14 the CI service principal (`00001111-aaaa-...`, see `contoso/principals.json`) lists both resources' keys from
an IP it has never used (H01, H06), deploys an unapproved model that the Audit policy lets through (H02), changes the
sandbox content filter (H06 shows it; H07 is yours), and fails to grant itself a role (H03). From 03:00 eight new IPs
burn about 300,000 tokens an hour on each resource (H04, H05): resold access.

Now run what most teams actually have:

```bash
make hunt-naive
```

Same as `python3 hunt.py --naive`.

```text
--- AZ10 hunt · 13 activity events, 664 request rows, 218 metric rows · baseline before 2026-10-14T00:00:00Z ---

  LOW    N01  2026-10-14  all resources
         Daily tokens above 3x the normal day (61,482)
         - 2026-10-14: 3,175,284 tokens

1 hit  (naive mode: one daily usage check)
```

One line, for the whole day, after the day is over. In real Azure, budget alerts are worse: cost data "is typically
available within 8-24 hours" and budgets are evaluated "every 24 hours".

**About the log shapes.** `logs/activity-log.json` follows Microsoft's activity log event schema (trimmed).
`logs/azuremetrics-tokens.json` uses the documented metric names `ProcessedPromptTokens` and `GeneratedTokens`,
summed per hour. `logs/azurediagnostics-requestresponse.json` uses `AzureDiagnostics` column names, but its
`OperationName` values and the contents of `properties_s` are **simplified placeholders**. Before you turn a rule into
a real alert, look at your own data, for example:

```kusto
AzureDiagnostics
| where Category == "RequestResponse"
| summarize count() by OperationName, CallerIPAddress
```

## Step 7 · Your turn: `make challenge`

`make test` runs the 17 lab tests on their own and must end with `ALL TESTS PASSED (17 run)`. The challenge adds four:

```bash
make challenge
```

Same as `python3 run_tests.py --challenge`.

```text
[PASS] vulnerable: keys copied from the public repo list models and chat on BOTH Foundry resources, no role checked
[PASS] vulnerable: Contributor can't call the model with Entra ID (no data actions) but CAN list the keys
[PASS] vulnerable: the approved-models policy is on Audit, so the unapproved Fabrikam model deploys (logged only)
[PASS] vulnerable: allowedPublishers=['OpenAI'] makes gpt-5.4 and gpt-5.2 v2 compliant without any audit
[PASS] vulnerable: the CI identity can replace content filters and re-enable keys, but NotActions stop role assignments
[PASS] vulnerable: the daily usage check fires once, for the whole day, and says nothing about keys or deployments
[PASS] checker: Contoso today triggers all 14 rules (AZ10-01 to AZ10-14)
[PASS] checker: with fixes/, only the challenge findings can remain (sandbox keys, gpt-5 asset ID)
[PASS] safe: with disableLocalAuth=true the leaked PROD key gets 401
[PASS] safe: the CI identity can't list keys, change filters or account settings, and Deny stops the Fabrikam model
[PASS] safe: Owner is allowed by RBAC, but the key-access policy (Deny) refuses re-enabling keys
[PASS] safe and vulnerable: the five legitimate requests are allowed in both modes
[PASS] policy: the real rule reproduces Microsoft's examples (no slash = prefix; '/' = one model; '/versions/1' = one version)
[PASS] hunt: keys listed, unapproved model, failed role grab, token spikes, new IPs, new-IP control plane
[PASS] hunt: nothing from Contoso's own IPs, and nothing on the normal days 9-13 October
[PASS] secret scan: the public repo snapshot leaks the prod key, the sandbox key and the CI client secret
[PASS] data: only Microsoft documentation example GUIDs (or built-in role/policy IDs), RFC 5737 IPs, EXAMPLE secrets
[FAIL] challenge: gpt-5.4 and gpt-5.2 v2 are denied, and the approved gpt-5 rollout still works
[FAIL] challenge: the leaked SANDBOX key gets 401, and the data scientist (Entra ID) still works
[FAIL] challenge: H07 flags the content-filter change made with the stolen CI secret
[PASS] challenge: a content-filter change by the platform admin is NOT flagged
  why test_18_allowlist_is_exact: AssertionError: True is not false : B4 is still ALLOWED: the gpt-5 asset ID is a prefix
  why test_19_sandbox_key_refused: AssertionError: True is not false : A3 is still ALLOWED: sandbox key access is on
  why test_20_hunt_content_filter_change: + [('H07', '00001111-aaaa-2222-bbbb-3333cccc4444')] : rule_content_filter_change() must return one H07 hit for the CI identity
----------------------------------------------------------------------
Ran 21 tests in 0.059s

FAILED (failures=3)

3 of 21 TESTS FAILED (21 run)
```

Three tests fail by design (the fourth, "admin change not flagged", passes until you write a rule that is too
broad). Make them pass without breaking the other 17:

1. **Exact allow-list.** Edit `fixes/policy-assignments.json` so gpt-5.4 and gpt-5.2 version 2 are denied and the
   approved gpt-5 rollout (L2) still works. Microsoft's model deployment policy page explains the matching rules.
2. **Sandbox keys.** The Deny policy only stops new or changed resources; existing ones are just marked
   non-compliant. Fix the sandbox resource in `fixes/estate.json`, and check that the data scientist (L3) still works.
3. **Write H07.** In `hunt.py`, fill in `rule_content_filter_change()`: one `Hit` per caller for any
   `raiPolicies` write or delete by someone outside `SECURITY_ADMINS`.

When all 21 pass, `make check-fixed` reports 0 findings and `make attack-safe` reports 0 of 12. No solution is
included: compare notes with other students in the community.

## Step 8 (optional) · The Azure twin, in your own subscription

This repeats three results for real: a key works, an unapproved model deployment is refused, and the old key gets
`401` after `disableLocalAuth: true`. **We have not run this step for you** (this course's build has no Azure
subscription); the expected responses below come from Microsoft's documentation.

**Expected cost: $0.** There are no charges for Azure Policy on Azure resources
([Azure Policy pricing](https://azure.microsoft.com/en-us/pricing/details/azure-policy/)); Cost Management budgets
are "available to Azure customers ... at no additional cost"
([Cost Management pricing](https://azure.microsoft.com/en-us/pricing/details/cost-management/)); Activity Log entries
are free for 90 days. The Foundry resource has no hourly charge in this setup: the one approved deployment is
pay-per-token ("Pay-as-you-go for input and output tokens",
[Azure OpenAI pricing](https://azure.microsoft.com/en-us/pricing/details/azure-openai/)), it receives no calls, and
the script deletes it straight away. The key test calls `GET /openai/models`
([Models - List](https://learn.microsoft.com/en-us/rest/api/azureopenai/models/list)), which lists models and generates no
tokens. Check Cost Management the next day anyway.

**Safety first:** use a subscription you own, never your employer's. A free account works well because its spending
limit stops services when the credit runs out.

```bash
cd azure-twin
az login
az bicep install
export AZ10_NAME=az10-twin-<initials><4 digits>
export AZ10_EMAIL=you@example.com
./twin.sh up
./twin.sh key-test
```

What each command does, and what to look for:

- `az login`: your own subscription
- `az bicep install`: once
- `AZ10_NAME`: globally unique
- `AZ10_EMAIL`: optional: creates the $5 budget
- `./twin.sh up`: resource group, Foundry resource (keys ON), project, budget, two policy assignments
- `./twin.sh key-test`: expect: GET /openai/models with the key -> HTTP 200

Wait at least 15 minutes for the policy assignments:

```bash
./twin.sh policy-test
./twin.sh lock
./twin.sh wait-401
./twin.sh activity
./twin.sh down
```

What each command does, and what to look for:

- `./twin.sh policy-test`: expect: 1) refused by policy (403 Forbidden); 2) the approved model is created, then deleted
- `./twin.sh lock`: redeploys with disableLocalAuth=true; prints true
- `./twin.sh wait-401`: polls with the OLD key: expect HTTP 200 for a while, then 401 (minutes, up to hours)
- `./twin.sh activity`: the control-plane trail: listKeys, deployments/write, the policy events
- `./twin.sh down`: removes the policy assignments, budget and resource group

Notes:

- `policy-test` tries `gpt-5-nano` version `2025-08-07` as the unapproved model. If it isn't offered in your region,
  set `AZ10_BLOCKED_MODEL` and `AZ10_BLOCKED_VERSION` to any other GA model from
  `az cognitiveservices account list-models -n $AZ10_NAME -g rg-az10-twin -o table`. Never pick a Deprecated one: a
  new subscription can't deploy it at all, so the error proves nothing about the policy. The approved one is
  `gpt-5-mini` version `2025-08-07` (GA). Earlier versions of this lab used `gpt-4.1-mini`, which Microsoft now lists
  as Deprecated and "No longer available to new customers"
  ([model retirements](https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/model-retirements)).
- The policy refusal is the deny effect's `403 (Forbidden)`. If the unapproved model is created instead, the
  assignment hadn't taken effect yet: `policy-test` says so, deletes that deployment straight away, and you try again
  later.
- After `down`, the Foundry name is held for 48 hours: "you can't create another one with the same name for 48
  hours" unless you purge it
  ([recover or purge](https://learn.microsoft.com/en-us/azure/ai-services/recover-purge-resources)).
- `key-test` saves the key to `azure-twin/.twin-key` (git-ignored) so that `wait-401` can test the *old* key, like a
  thief would. `down` deletes it.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python3: command not found` | Install Python 3.11+ from python.org, or use `python` on Windows |
| `make: command not found` (Windows) | Run the `python3 ...` command shown under each step |
| A test fails after you edited `contoso/` | The tests check Contoso **as shipped**. Edit `fixes/` and `hunt.py` only, or re-download the lab |
| `make scan` prints `Error 1 (ignored)` | Expected: the scanner exits 1 when it finds secrets |

## What to write in your findings notebook (lesson 0.5)

1. The three ways a Contoso key could be obtained (repository, listKeys by a role that includes it, even Foundry User, a broad custom role) and
   the one setting that makes all three useless.
2. Why `allowedPublishers: ["OpenAI"]` turns the allow-list off for every OpenAI model, quoting the policy rule.
3. Which of your hunt rules would have fired first on 14 October, and how many hours before the naive check.

## Sources

- Microsoft Foundry RBAC: https://learn.microsoft.com/en-us/azure/foundry/concepts/rbac-foundry
- Azure built-in roles (Owner, Contributor, Reader; AI + ML roles): https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged ·
  https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general ·
  https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/ai-machine-learning
- Azure OpenAI (classic) RBAC, who can view keys: https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/role-based-access-control
- Approved-models policy: https://learn.microsoft.com/en-us/azure/foundry/how-to/model-deployment-policy ·
  definition: https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Cognitive%20Services/AllowDeployRegistryModels_Audit.json
- Disable local auth: https://learn.microsoft.com/azure/ai-services/disable-local-auth ·
  definition: https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Azure%20Ai%20Services/DisableLocalAuth_Audit.json
- Azure Policy rule syntax and deny effect: https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule ·
  https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-deny
- Activity log and its schema: https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log ·
  https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema
- Azure OpenAI monitoring reference (log categories, token metrics): https://learn.microsoft.com/en-us/azure/foundry/openai/monitor-openai-reference
- Deployment types: https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/deployment-types
- Budgets: https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets
- Storm-2139: https://blogs.microsoft.com/on-the-issues/2025/02/27/disrupting-cybercrime-abusing-gen-ai/
- Microsoft's 00-basic Foundry Bicep sample: https://github.com/microsoft-foundry/foundry-samples/tree/main/infrastructure/infrastructure-setup-bicep/00-basic
