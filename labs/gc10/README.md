# Lab GC10: find the AI permission, API key and cost mistakes in a Google Cloud setup, fix them, then hunt LLMjacking in Cloud Audit Logs

Companion to lessons **10.3, 10.4 and 10.5** of *AI Security Engineer* (The Sec Guy), Google Cloud stream. About 60
minutes, **$0**, all on your laptop. **Nothing to install** (Python standard library only) and **no Google Cloud
account needed**. An optional last step runs the same ideas in your own Free Trial project.

You are the new cloud security engineer at **ExampleCo** (a fictional company on the documentation domain
`example.com`). It runs the TSG Helpdesk chatbot on Gemini in Agent Platform (formerly Vertex AI) in a production
project, and lets staff try models in a sandbox project. In one sitting you will:

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Run a small checker over ExampleCo's IAM allow policies, organization policies, API keys, budgets and audit-log settings, and read why each finding matters | 10.3 to 10.5 |
| **Break** | Replay what three attackers can do with a leaked API key, a dormant service account's JSON key and an authorization key: 8 of 9 requests work | 10.3, 10.4 |
| **Fix** | Apply the files in `fixes/` (IAM, a model allow-list, API key clean-up, two organization constraints, a spend cap budget) and replay: legitimate traffic still works | 10.3 to 10.5 |
| **Hunt** | Search five days of sample Cloud Audit Logs for two LLMjacking intrusions | 10.5 |
| **Challenge** | Close two gaps the "safe" setup still has, and write one detection. No solution included | 10.3 to 10.5 |

## What's in this folder

| File | What it is |
|---|---|
| `policy_checker.py` | The checker: rules `GC10-01` to `GC10-16`, plus a secret scan for Google API key strings |
| `attack.py` | 17 requests (9 attacker, 8 legitimate), `--mode vulnerable` or `--mode safe`, plus `--preview-org-policy` |
| `gcp_eval.py` | A **teaching model** of how Google Cloud decides whether a request goes through (see below) |
| `hunt.py` | Nine hunting rules (`H01` to `H09`; `H09` is yours to write), plus `--naive` and `--summary` |
| `examplecorp/` | The company: `hierarchy.json` (organization, folders, projects), `iam/` allow policies, `org-policies/`, `api-keys.json`, `service-accounts.json`, `budgets.json`, `groups.json`, `approved-models.json`, and `repo/` (a demo repo with a committed key) |
| `fixes/` | The fixes: two IAM allow policies, three organization policies, the cleaned-up key inventory, a spend cap budget |
| `auditlogs/examplecorp-2026-10-12_16.jsonl` | 461 **fake** Cloud Audit Logs entries: three normal days, then two intrusions on 15 and 16 October |
| `gcp-twin/` | Files for the optional Google Cloud step |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 19 tests for the lab, 6 for the challenge |

**About `gcp_eval.py`.** It is not Google's authorization engine. It models only the rules this lab depends on, each
from Google's documentation: a standard API key carries no identity and is tied to its project; an authorization key
authenticates as its service account; API restrictions and IP restrictions are checked; the Gemini API rejects
unrestricted standard keys; IAM roles granted on the organization or a folder are inherited; for
`vertexai.allowedModels`, no policy means everything is allowed, an allow rule denies everything not listed, an
explicit deny wins, and `inheritFromParent` merges a policy with its parent's. It does **not** model IAM deny
policies, conditions, VPC Service Controls, quotas, or website (HTTP referrer) restrictions, and its role-to-permission
map is a small subset. One simplification matters for B4: to create an authorization key it checks only
`apikeys.keys.create` and the organization constraint. Google's API keys page also asks for the Service Account User
and Service Account API Key Binding Admin roles; the lab assumes `legacy-etl`'s Editor grant covers them, which Google's
docs neither confirm nor rule out. For real policies, use Policy Simulator and dry run (Step 8) and test in a sandbox.

**Three assumptions, said plainly.** (1) Google documents the unrestricted-key rule for the Gemini API; we found no
such rule for Agent Platform, so the model lets an unrestricted standard key call Agent Platform. (2) Google's
Agent Platform audit-logging page lists `endpoints.predict` and `endpoints.rawPredict` as Data Access operations but
doesn't name Gemini's `generateContent`; the sample logs use the method names from Google's published API definition
([prediction_service.proto](https://github.com/googleapis/googleapis/blob/master/google/cloud/aiplatform/v1/prediction_service.proto)).
Run `python3 hunt.py --summary --file YOUR_EXPORT.json` on your own logs to see the real names. (3) Calls made with an
authorization key appear in the sample under the service account it's bound to, because Google says such a key
"authenticates as a service account". The sample has no entries for Attacker 1's standard key: we didn't find
documentation of what such an entry contains, so we didn't invent one.

**About the data and safety.** Every IP address is from the documentation ranges in
[RFC 5737](https://www.rfc-editor.org/rfc/rfc5737); every identity is on `example.com`; organization, folder and
project numbers are placeholders. The key string in `repo/chatbot/settings.py` is the example string printed in
Google's [API keys documentation](https://docs.cloud.google.com/docs/authentication/api-keys), not a live key. Model
IDs are from Google's model pages (checked 22 Oct 2026); models retire, so check the current list. Nothing here
contacts Google or any other system. Test 19 fails if a real-looking IP, identity or key string creeps in.

## Needs

- Python **3.11 or newer** (tested on 3.13). Check with `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 8 only: the `gcloud` CLI and **your own** Free Trial project (lesson 0.7).

## Step 1 · Check: find the mistakes

```bash
cd labs-export/gc10         # or wherever you put this folder
make check                  # same as: python3 policy_checker.py
```

Real output (Linux, Python 3.13):

```text
--- GC10 policy checker · ExampleCo today ---

  HIGH    GC10-01  folders/111111111111 roles/editor
          Basic role roles/editor for ci-deployer@example-ci.iam.gserviceaccount.com: it can call any model, deploy endpoints and create keys.
          fix: Grant the predefined role the workload needs (e.g. roles/aiplatform.user to call models).
  HIGH    GC10-01  folders/111111111111 roles/editor
          Basic role roles/editor for legacy-etl@example-ci.iam.gserviceaccount.com: it can call any model, deploy endpoints and create keys.
          fix: Grant the predefined role the workload needs (e.g. roles/aiplatform.user to call models).
  HIGH    GC10-01  projects/example-chatbot-prod roles/editor
          Basic role roles/editor for 100000000001-compute@developer.gserviceaccount.com: it can call any model, deploy endpoints and create keys.
          fix: Grant the predefined role the workload needs (e.g. roles/aiplatform.user to call models).
  HIGH    GC10-04  projects/example-chatbot-prod roles/aiplatform.admin
          Workload chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com holds Agent Platform Admin: full access to every Agent Platform resource.
          fix: A workload that only calls a model needs roles/aiplatform.user (aiplatform.endpoints.predict).
  HIGH    GC10-05  key chatbot-frontend
          Unrestricted API key: any API enabled in its project, from anywhere. Google: "Unrestricted API keys are insecure."
          fix: Add an API restriction (apiTargets) AND an application restriction (IPs, referrers or apps).
  HIGH    GC10-06  key ops-eval-key
          Authorization key bound to chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com: it works like a long-lived access token and its calls aren't in service account usage metrics.
          fix: Use the attached service account (ADC) instead; delete the key; keep iam.managed.disableServiceAccountApiKeyCreation enforced.
  HIGH    GC10-16  repo/chatbot/settings.py:9
          Google API key string AIzaSyDa...ewQe in source code.
          fix: Treat it as leaked: restrict or delete the key in the console, then remove it from the code and history.
  MEDIUM  GC10-03  organizations/123456789012 roles/aiplatform.user
          roles/aiplatform.user granted on organizations: every project below inherits it, including ones that never use AI.
          fix: Grant AI roles on the project that needs them, not on a folder or the organization.
  MEDIUM  GC10-07  key ops-eval-key
          Key can call an AI API but has no application restriction: anyone holding the string can use it from anywhere.
          fix: Add serverKeyRestrictions.allowedIps with your egress IPs (or a referrer/app restriction for client apps).
  MEDIUM  GC10-08  key store-locator-website
          A key built for a public web page can also call the Gemini API: its string is in your page source.
          fix: Remove generativelanguage.googleapis.com from this key; give Gemini callers their own server-side key or ADC.
  MEDIUM  GC10-09  organizations/123456789012/policies/iam.managed.disableServiceAccountApiKeyCreation
          iam.managed.disableServiceAccountApiKeyCreation is switched off: anyone with the right roles can bind API keys to service accounts.
          fix: Enforce it again at the organization (Google's default); allow exceptions per project only.
  MEDIUM  GC10-10  organization
          iam.managed.disableServiceAccountKeyCreation is not set (org created before 3 May 2024): anyone with iam.serviceAccountKeys.create can download a service account key.
          fix: Enforce it at the organization (the secure-by-default baseline for newer orgs).
  MEDIUM  GC10-11  projects/example-chatbot-prod
          Agent Platform is enabled and no vertexai.allowedModels allow-list applies: every model and action, including new ones, is allowed.
          fix: Set an allow-list at the folder or organization with the approved publishers/P/models/M:ACTION values.
  MEDIUM  GC10-11  projects/example-ds-sandbox
          Agent Platform is enabled and no vertexai.allowedModels allow-list applies: every model and action, including new ones, is allowed.
          fix: Set an allow-list at the folder or organization with the approved publishers/P/models/M:ACTION values.
  MEDIUM  GC10-14  projects/example-chatbot-prod
          Agent Platform is enabled but no spend cap budget covers it: alerts-only budgets don't cap spending.
          fix: Add a spend cap budget for this project + Agent Platform; keep alert budgets for everything else.
  MEDIUM  GC10-14  projects/example-ds-sandbox
          Agent Platform is enabled but no spend cap budget covers it: alerts-only budgets don't cap spending.
          fix: Add a spend cap budget for this project + Agent Platform; keep alert budgets for everything else.
  MEDIUM  GC10-15  projects/example-ds-sandbox
          Data Access (DATA_READ) audit logs are off for aiplatform.googleapis.com: model calls here leave no audit record.
          fix: Add an auditConfigs entry for aiplatform.googleapis.com with DATA_READ (cost: Cloud Logging ingestion past the free allotment).
  LOW     GC10-12  projects/example-ds-sandbox/policies/vertexai.allowedModels
          Deny-list: it blocks the models it names and allows every model Google adds later.
          fix: Prefer an allow-list (allowedValues). Keep deny-lists as a second layer only.

7 HIGH, 10 MEDIUM, 1 LOW, 0 WARNING  (18 findings)
```

How to read it, highest first:

- **GC10-01, GC10-04**: two service accounts hold Editor on the prod folder, the Compute Engine default account holds
  Editor on the chatbot project, and the chatbot's own account holds Agent Platform **Admin**. Lesson 10.3.
- **GC10-05, GC10-06, GC10-07, GC10-08, GC10-16**: the API key story (lesson 10.4). An unrestricted key, committed
  to a public repo; an **authorization key** bound to the chatbot's service account; a website key that can also call
  the Gemini API.
- **GC10-03**: `legacy-etl` holds Agent Platform User on the whole **organization**.
- **GC10-09, GC10-10**: someone switched off `iam.managed.disableServiceAccountApiKeyCreation`, and the organization is
  older than 3 May 2024, so nobody set the secure-by-default block on service account keys.
- **GC10-11, GC10-12**: no model allow-list anywhere; the sandbox has a deny-list for one model.
- **GC10-14, GC10-15**: no spend cap on the AI projects; Data Access logs off in the sandbox.

Lint your own exports the same way: `python3 policy_checker.py --keys my-keys.json` (from
`gcloud services api-keys list --format=json`), `--iam my-iam.json` (from `gcloud projects get-iam-policy PROJECT_ID
--format=json`), `--orgpolicy file.json`, or `--scan PATH`.

## Step 2 · Break it: what can the attackers do today?

```bash
make attack                 # same as: python3 attack.py --mode vulnerable
```

Real output:

```text
--- GC10 lab · VULNERABLE · ExampleCo today ---
    (gcp_eval.py: a teaching model of Google Cloud's rules; nothing is sent to Google)

Attacker 1 · API keys copied from a public repo and a public web page (from 203.0.113.50)
  [A1] ALLOWED  GenerateContent on the approved model, billed to the chatbot project
         why: every check passed: UNRESTRICTED standard key (no identity; billed to example-chatbot-prod); org policy: no vertexai.allowedModels policy anywhere: all models and actions allowed
  [A2] ALLOWED  GenerateContent on a bigger model nobody approved for prod (Gemini 3.5 Flash)
         why: every check passed: UNRESTRICTED standard key (no identity; billed to example-chatbot-prod); org policy: no vertexai.allowedModels policy anywhere: all models and actions allowed
  [A3] ALLOWED  Gemini API with the store-locator key scraped from www.example.com
         why: every check passed: standard key, restrictions passed (no identity; billed to example-legacy-web)
  [A4] DENIED   Gemini API with the unrestricted chatbot key
         why: the Gemini API rejects requests from unrestricted standard keys

Attacker 2 · the leaked JSON key of legacy-etl, a service account nobody has used since March (from 203.0.113.77)
  [B1] ALLOWED  RawPredict on Claude Opus 4.7 in the sandbox (not approved anywhere)
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on organizations/123456789012; org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [B2] ALLOWED  Deploy Llama 3 to a GPU endpoint in prod (billed by the hour while it runs)
         why: every check passed: IAM: aiplatform.endpoints.deploy via roles/editor on folders/111111111111; org policy: no vertexai.allowedModels policy anywhere: all models and actions allowed
  [B3] ALLOWED  CreateServiceAccountKey for chatbot-runtime (a second way back in)
         why: every check passed: IAM: iam.serviceAccountKeys.create via roles/editor on folders/111111111111; org policy iam.managed.disableServiceAccountKeyCreation: not enforced (not set (org created before 3 May 2024))
  [B4] ALLOWED  CreateKey: an API key bound to chatbot-runtime (persistence that skips SA usage metrics)
         why: every check passed: IAM: apikeys.keys.create via roles/editor on folders/111111111111; org policy iam.managed.disableServiceAccountApiKeyCreation: not enforced (organizations/123456789012/policies/iam.managed.disableServiceAccountApiKeyCreation)

Attacker 3 · the authorization key ops-eval-key, bound to chatbot-runtime (from 203.0.113.90)
  [C1] ALLOWED  GenerateContent on Gemini 3.5 Flash as chatbot-runtime (it holds Agent Platform Admin)
         why: every check passed: authorization key: authenticates as chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com; IAM: aiplatform.endpoints.predict via roles/aiplatform.admin on projects/example-chatbot-prod; org policy: no vertexai.allowedModels policy anywhere: all models and actions allowed

Legitimate traffic · must keep working after the fixes
  [L1] ALLOWED  Chatbot on Cloud Run: GenerateContent on the approved model as chatbot-runtime
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.admin on projects/example-chatbot-prod; org policy: no vertexai.allowedModels policy anywhere: all models and actions allowed
  [L2] ALLOWED  Chatbot web tier: GenerateContent with the chatbot-frontend key from its egress IP
         why: every check passed: UNRESTRICTED standard key (no identity; billed to example-chatbot-prod); org policy: no vertexai.allowedModels policy anywhere: all models and actions allowed
  [L3] ALLOWED  Data scientist: GenerateContent on Gemini 3.5 Flash in the sandbox
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on folders/222222222222 (as data-science@example.com); org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L4] ALLOWED  Data scientist: RawPredict on approved Claude Haiku 4.5 in the sandbox
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on folders/222222222222 (as data-science@example.com); org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L5] ALLOWED  Notebook: GenerateContent with ds-notebook-key from the office range
         why: every check passed: standard key, restrictions passed (no identity; billed to example-ds-sandbox); org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L6] ALLOWED  CI pipeline: nightly eval, GenerateContent on the approved model in the sandbox
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on projects/example-ds-sandbox; org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L7] ALLOWED  CI pipeline: deploy a new chatbot revision to Cloud Run
         why: every check passed: IAM: run.services.create via roles/editor on folders/111111111111
  [L8] ALLOWED  Platform admin: CreateKey, a STANDARD key (not bound to a service account) in the sandbox
         why: every check passed: IAM: apikeys.keys.create via roles/owner on projects/example-ds-sandbox (as cloud-admins@example.com)

8 of 9 attacker requests allowed; 8 of 8 legitimate requests allowed.
```

Read the **why** lines. Attacker 1 copied two keys: the unrestricted chatbot key runs any model on Agent Platform,
and the website key reaches the Gemini API because someone added it to the key's API list (lesson 10.4). One attack
fails, and not because of ExampleCo: the Gemini API "rejects requests from unrestricted standard keys"
([Google](https://ai.google.dev/gemini-api/docs/api-key)). Attacker 2 is a service account nobody has used since
March, with a JSON key that never expires: it runs Claude, deploys a model to an endpoint, and makes itself two new
ways back in. Attacker 3 holds an authorization key, so it *is* the chatbot, with the chatbot's Admin role. Add
`--verbose` to see every check.

## Step 3 · Read the fixes

| File | What it changes | Stops | Lesson |
|---|---|---|---|
| `iam-folders-111111111111.json` | `ci-deployer` gets Cloud Run Developer instead of Editor; `legacy-etl` loses Editor | B3, B4 | 10.3 |
| `iam-projects-example-chatbot-prod.json` | `chatbot-runtime` gets Agent Platform User instead of Admin; the Compute default account loses Editor | over-privilege | 10.3 |
| `orgpolicy-prod-allowed-models.json` | Allow-list on the prod folder: `gemini-3.1-flash-lite:predict` only | A2, B2 | 10.3 |
| `api-keys.json` | `ops-eval-key` deleted; the website key loses the Gemini API; the chatbot key gets an API restriction | A3, A4, C1 | 10.4 |
| `orgpolicy-org-block-sa-api-keys.json` | `iam.managed.disableServiceAccountApiKeyCreation` enforced again | B4 | 10.4 |
| `orgpolicy-org-block-sa-keys.json` | `iam.managed.disableServiceAccountKeyCreation` enforced | B3 | 10.0, 10.4 |
| `budget-spend-cap-chatbot-prod.json` | A spend cap budget for Agent Platform in the chatbot project | the bill | 10.5 |

The spend cap file follows the Budget API's rules for `spendCap`: one project, one service
(`services/C7E2-9256-1C43`, Agent Platform's ID on Google's spend caps page), exactly three current-spend thresholds at
0.5, 0.8 and 1.0, and project-level recipients on
([Budget API](https://docs.cloud.google.com/billing/docs/reference/budget/rest/v1/billingAccounts.budgets)). It
doesn't change any request in `attack.py`; it limits the damage of whatever still gets through.

Run `make check-fixed`: 18 findings drop to 7. Read the 7 that are left. The challenge closes GC10-07 and GC10-11;
the rest are real follow-ups (the key is still in the repo's history, the sandbox has no Data Access logs or spend cap,
and `legacy-etl` still holds its organization-wide role).

```text
--- GC10 policy checker · ExampleCo with fixes/ ---

  HIGH    GC10-16  repo/chatbot/settings.py:9
          Google API key string AIzaSyDa...ewQe in source code.
          fix: Treat it as leaked: restrict or delete the key in the console, then remove it from the code and history.
  MEDIUM  GC10-03  organizations/123456789012 roles/aiplatform.user
          roles/aiplatform.user granted on organizations: every project below inherits it, including ones that never use AI.
          fix: Grant AI roles on the project that needs them, not on a folder or the organization.
  MEDIUM  GC10-07  key chatbot-frontend
          Key can call an AI API but has no application restriction: anyone holding the string can use it from anywhere.
          fix: Add serverKeyRestrictions.allowedIps with your egress IPs (or a referrer/app restriction for client apps).
  MEDIUM  GC10-11  projects/example-ds-sandbox
          Agent Platform is enabled and no vertexai.allowedModels allow-list applies: every model and action, including new ones, is allowed.
          fix: Set an allow-list at the folder or organization with the approved publishers/P/models/M:ACTION values.
  MEDIUM  GC10-14  projects/example-ds-sandbox
          Agent Platform is enabled but no spend cap budget covers it: alerts-only budgets don't cap spending.
          fix: Add a spend cap budget for this project + Agent Platform; keep alert budgets for everything else.
  MEDIUM  GC10-15  projects/example-ds-sandbox
          Data Access (DATA_READ) audit logs are off for aiplatform.googleapis.com: model calls here leave no audit record.
          fix: Add an auditConfigs entry for aiplatform.googleapis.com with DATA_READ (cost: Cloud Logging ingestion past the free allotment).
  LOW     GC10-12  projects/example-ds-sandbox/policies/vertexai.allowedModels
          Deny-list: it blocks the models it names and allows every model Google adds later.
          fix: Prefer an allow-list (allowedValues). Keep deny-lists as a second layer only.

1 HIGH, 5 MEDIUM, 1 LOW, 0 WARNING  (7 findings)
```

## Step 4 · Fix it: replay with the fixes

```bash
make attack-safe            # same as: python3 attack.py --mode safe
```

Real output:

```text
--- GC10 lab · SAFE · fixes applied: orgpolicy-org-block-sa-api-keys.json, orgpolicy-org-block-sa-keys.json, orgpolicy-prod-allowed-models.json, iam-folders-111111111111.json, iam-projects-example-chatbot-prod.json, api-keys.json, budget-spend-cap-chatbot-prod.json ---
    (gcp_eval.py: a teaching model of Google Cloud's rules; nothing is sent to Google)

Attacker 1 · API keys copied from a public repo and a public web page (from 203.0.113.50)
  [A1] ALLOWED  GenerateContent on the approved model, billed to the chatbot project   <-- still open: make challenge
         why: every check passed: standard key, restrictions passed (no identity; billed to example-chatbot-prod); org policy: on the vertexai.allowedModels allow-list (folders/111111111111/policies/vertexai.allowedModels)
  [A2] DENIED   GenerateContent on a bigger model nobody approved for prod (Gemini 3.5 Flash)
         why: org policy: not on the vertexai.allowedModels allow-list (folders/111111111111/policies/vertexai.allowedModels)
  [A3] DENIED   Gemini API with the store-locator key scraped from www.example.com
         why: API restriction: key store-locator-website may only call maps-backend.googleapis.com
  [A4] DENIED   Gemini API with the unrestricted chatbot key
         why: API restriction: key chatbot-frontend may only call aiplatform.googleapis.com

Attacker 2 · the leaked JSON key of legacy-etl, a service account nobody has used since March (from 203.0.113.77)
  [B1] ALLOWED  RawPredict on Claude Opus 4.7 in the sandbox (not approved anywhere)   <-- still open: make challenge
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on organizations/123456789012; org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [B2] DENIED   Deploy Llama 3 to a GPU endpoint in prod (billed by the hour while it runs)
         why: org policy: not on the vertexai.allowedModels allow-list (folders/111111111111/policies/vertexai.allowedModels)
  [B3] DENIED   CreateServiceAccountKey for chatbot-runtime (a second way back in)
         why: IAM: no role on example-chatbot-prod or its folders/org gives legacy-etl@example-ci.iam.gserviceaccount.com iam.serviceAccountKeys.create; org policy iam.managed.disableServiceAccountKeyCreation: ENFORCED (organizations/123456789012/policies/iam.managed.disableServiceAccountKeyCreation)
  [B4] DENIED   CreateKey: an API key bound to chatbot-runtime (persistence that skips SA usage metrics)
         why: IAM: no role on example-chatbot-prod or its folders/org gives legacy-etl@example-ci.iam.gserviceaccount.com apikeys.keys.create; org policy iam.managed.disableServiceAccountApiKeyCreation: ENFORCED (organizations/123456789012/policies/iam.managed.disableServiceAccountApiKeyCreation)

Attacker 3 · the authorization key ops-eval-key, bound to chatbot-runtime (from 203.0.113.90)
  [C1] DENIED   GenerateContent on Gemini 3.5 Flash as chatbot-runtime (it holds Agent Platform Admin)
         why: API key ops-eval-key was deleted

Legitimate traffic · must keep working after the fixes
  [L1] ALLOWED  Chatbot on Cloud Run: GenerateContent on the approved model as chatbot-runtime
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on projects/example-chatbot-prod; org policy: on the vertexai.allowedModels allow-list (folders/111111111111/policies/vertexai.allowedModels)
  [L2] ALLOWED  Chatbot web tier: GenerateContent with the chatbot-frontend key from its egress IP
         why: every check passed: standard key, restrictions passed (no identity; billed to example-chatbot-prod); org policy: on the vertexai.allowedModels allow-list (folders/111111111111/policies/vertexai.allowedModels)
  [L3] ALLOWED  Data scientist: GenerateContent on Gemini 3.5 Flash in the sandbox
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on folders/222222222222 (as data-science@example.com); org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L4] ALLOWED  Data scientist: RawPredict on approved Claude Haiku 4.5 in the sandbox
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on folders/222222222222 (as data-science@example.com); org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L5] ALLOWED  Notebook: GenerateContent with ds-notebook-key from the office range
         why: every check passed: standard key, restrictions passed (no identity; billed to example-ds-sandbox); org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L6] ALLOWED  CI pipeline: nightly eval, GenerateContent on the approved model in the sandbox
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on projects/example-ds-sandbox; org policy: vertexai.allowedModels is only a deny-list here and doesn't name this model (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L7] ALLOWED  CI pipeline: deploy a new chatbot revision to Cloud Run
         why: every check passed: IAM: run.services.create via roles/run.developer on folders/111111111111
  [L8] ALLOWED  Platform admin: CreateKey, a STANDARD key (not bound to a service account) in the sandbox
         why: every check passed: IAM: apikeys.keys.create via roles/owner on projects/example-ds-sandbox (as cloud-admins@example.com)

2 of 9 attacker requests allowed; 8 of 8 legitimate requests allowed.
```

Seven attacks stopped, and all eight legitimate requests still work. Two still get through: A1, because the chatbot
key has an API restriction but no **application** restriction, and B1, because the only model policy above the
sandbox is still a deny-list while `legacy-etl` keeps its organization-wide role. That's Step 7. Look at B2's **why**
line too: IAM no longer stops it. Agent Platform User includes `aiplatform.endpoints.deploy`
([access control](https://docs.cloud.google.com/vertex-ai/docs/general/access-control)), so `legacy-etl`'s
organization-wide grant still allows a deployment; only the prod allow-list refuses it.

## Step 5 · Dry run before you enforce

On Google Cloud you'd put a new model allow-list in `dryRunSpec` first: violations are audit-logged, nothing is
denied (lesson 10.3). Do the same thing locally with the twin's file, a one-model allow-list at the **organization**:

```bash
make twin-preview           # same as: python3 attack.py --preview-org-policy gcp-twin/allowed-models-dryrun.json
```

Real output (last lines):

```text
Legitimate traffic · must keep working after the fixes
  [L1] ALLOWED  Chatbot on Cloud Run: GenerateContent on the approved model as chatbot-runtime
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.admin on projects/example-chatbot-prod; org policy: on the vertexai.allowedModels allow-list (organizations/123456789012/policies/vertexai.allowedModels)
  [L2] ALLOWED  Chatbot web tier: GenerateContent with the chatbot-frontend key from its egress IP
         why: every check passed: UNRESTRICTED standard key (no identity; billed to example-chatbot-prod); org policy: on the vertexai.allowedModels allow-list (organizations/123456789012/policies/vertexai.allowedModels)
  [L3] DENIED   Data scientist: GenerateContent on Gemini 3.5 Flash in the sandbox   <-- newly denied by the previewed policy (LEGITIMATE: fix the list first)
         why: org policy: not on the vertexai.allowedModels allow-list (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L4] DENIED   Data scientist: RawPredict on approved Claude Haiku 4.5 in the sandbox   <-- newly denied by the previewed policy (LEGITIMATE: fix the list first)
         why: org policy: not on the vertexai.allowedModels allow-list (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L5] ALLOWED  Notebook: GenerateContent with ds-notebook-key from the office range
         why: every check passed: standard key, restrictions passed (no identity; billed to example-ds-sandbox); org policy: on the vertexai.allowedModels allow-list (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L6] ALLOWED  CI pipeline: nightly eval, GenerateContent on the approved model in the sandbox
         why: every check passed: IAM: aiplatform.endpoints.predict via roles/aiplatform.user on projects/example-ds-sandbox; org policy: on the vertexai.allowedModels allow-list (projects/example-ds-sandbox/policies/vertexai.allowedModels)
  [L7] ALLOWED  CI pipeline: deploy a new chatbot revision to Cloud Run
         why: every check passed: IAM: run.services.create via roles/editor on folders/111111111111
  [L8] ALLOWED  Platform admin: CreateKey, a STANDARD key (not bound to a service account) in the sandbox
         why: every check passed: IAM: apikeys.keys.create via roles/owner on projects/example-ds-sandbox (as cloud-admins@example.com)

4 of 9 attacker requests allowed; 6 of 8 legitimate requests allowed.
In Google's dry run (dryRunSpec), these denials are only audit-logged as violations; nothing is blocked.
```

It would stop four attacks, and break two data scientists. That's what a week of dry run is for: list the models
people really use before you enforce. The `ORGANIZATION_ID` placeholder in the file is replaced with ExampleCo's for
the preview.

## Step 6 · Hunt: find LLMjacking in Cloud Audit Logs

First, the rule many teams start with: "GenerateContent on a model we didn't approve".

```bash
make hunt-naive             # same as: python3 hunt.py --naive
```

Real output:

```text
--- GC10 LLMjacking hunt · NAIVE rule only · 461 audit log entries ---

  HIGH   NAIVE 2026-10-15T22:10:10Z  chatbot-runtime
         65 GenerateContent call(s) on unapproved ['publishers/google/models/gemini-3.5-flash:predict']

1 finding(s). Attacker entries covered by a finding: 65 of 99.
Not covered: 1 x CreateKey; 1 x CreateServiceAccountKey; 1 x DeployModel; 1 x EnableService; 30 x StreamGenerateContent
Not in this file at all: the sandbox's Claude calls (Data Access audit logs are off there).
```

It sees 65 of 99 attacker entries. It misses 30 `StreamGenerateContent` calls, the model deployment and every key the
attacker created. Now every rule:

```bash
make hunt                   # same as: python3 hunt.py
```

Real output:

```text
--- GC10 LLMjacking hunt · all rules · 461 audit log entries ---

  HIGH   H04   2026-10-15T22:10:10Z  chatbot-runtime
         25 AI call(s) from new source 203.0.113.90
         - baseline IPs: 192.0.2.10
  HIGH   H05   2026-10-15T22:10:10Z  chatbot-runtime
         95 call(s) on unapproved publishers/google/models/gemini-3.5-flash:predict
         - methods: ['GenerateContent', 'StreamGenerateContent']  from ['203.0.113.77', '203.0.113.90']
  MEDIUM H06   2026-10-15T22:10:10Z  chatbot-runtime
         28 inference calls in the hour 2026-10-15T22:00Z (limit 20)
         - baseline peak: 3 per hour
  MEDIUM H06   2026-10-16T01:03:43Z  chatbot-runtime
         26 inference calls in the hour 2026-10-16T01:00Z (limit 20)
         - baseline peak: 3 per hour
  HIGH   H02   2026-10-16T01:40:05Z  legacy-etl
         dormant service account active again (227 days since 2026-03-02)
         - 4 action(s): CreateKey, CreateServiceAccountKey, DeployModel, EnableService
         - from ['203.0.113.77']
  HIGH   H01   2026-10-16T01:41:10Z  legacy-etl
         service account key created for chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com
         - from 203.0.113.77  UA: Python/3.11 aiohttp/3.9.5
  HIGH   H03   2026-10-16T01:41:30Z  legacy-etl
         authorization key 'monitoring' bound to chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com
         - from 203.0.113.77
         - works like a long-lived token; its calls aren't in SA usage metrics
  MEDIUM H04   2026-10-16T01:43:00Z  legacy-etl
         1 AI call(s) from new source 203.0.113.77
         - baseline IPs: none: never seen before
  HIGH   H05   2026-10-16T01:43:00Z  legacy-etl
         1 call(s) on unapproved publishers/meta/models/llama3:deploy
         - methods: ['DeployModel']  from ['203.0.113.77']
  MEDIUM H08   2026-10-16T01:43:00Z  legacy-etl
         first model deployment: publishers/meta/models/llama3:deploy
         - endpoint 9000000000000000001  from 203.0.113.77
  HIGH   H04   2026-10-16T01:45:02Z  chatbot-runtime
         70 AI call(s) from new source 203.0.113.77
         - baseline IPs: 192.0.2.10
  MEDIUM H06   2026-10-16T02:00:29Z  chatbot-runtime
         50 inference calls in the hour 2026-10-16T02:00Z (limit 20)
         - baseline peak: 3 per hour
  MEDIUM H07   2026-10-16T02:14:02Z  chatbot-runtime
         new AI method StreamGenerateContent (30 call(s))
         - baseline methods: ['GenerateContent']

13 finding(s). Attacker entries covered by a finding: 99 of 99.
Not in this file at all: the sandbox's Claude calls (Data Access audit logs are off there).
```

| Rule | Looks for | Why |
|---|---|---|
| H01 | `CreateServiceAccountKey` | a downloadable key is a way back in (lesson 10.0) |
| H02 | a user-managed service account inactive for more than 180 days that acts again | same threshold as Google's "Dormant Service Account Activity in AI Service" finding |
| H03 | `CreateKey`; HIGH when the request binds a `serviceAccountEmail` | authorization keys act as the service account (lesson 10.4) |
| H04 | AI calls from an IP the principal never used in the baseline | the idea behind Google's "New Geography for AI Service" (which uses location, not IPs) |
| H05 | inference or deployment of a model not in `approved-models.json` | your allow-list, as a detection |
| H06 | inference calls per principal per hour above 3 times its baseline peak (minimum 20) | volume is the bill |
| H07 | an AI method the principal never used before | the idea behind Google's "New AI API Method" |
| H08 | the first model deployment by a principal | endpoints bill while a model is deployed, even with no traffic (lesson 10.5) |

Two things to notice. The 15 October calls appear as `chatbot-runtime`, because the authorization key authenticates
as that account: only the new IP and the unapproved model give it away. And the sandbox's Claude calls aren't in the
file at all: Data Access logs are off there (finding GC10-15). No detection can see a log that was never written.

## Step 7 · Your turn: `make challenge`

```bash
make challenge              # same as: python3 run_tests.py --challenge
```

Real output before your fix (last lines):

```text
[FAIL] challenge: the chatbot-frontend key copied from the repo is refused from the attacker's IP
[PASS] challenge: the chatbot web tier still works with the same key from 192.0.2.10
[FAIL] challenge: legacy-etl can't run Claude Opus 4.7 in the sandbox, even with its org-wide IAM grant
[PASS] challenge: data science and the CI eval keep their approved sandbox models
[FAIL] challenge: H09 flags Agent Platform being enabled in example-ci (not approved for AI)
[PASS] challenge: H09 does not flag alice enabling Agent Platform in the approved sandbox
  why test_20_copied_frontend_key_fails_elsewhere: AssertionError: True is not false : A1 is still ALLOWED: the key has an API restriction but no application restriction
  why test_22_org_allow_list_stops_claude_in_the_sandbox: AssertionError: True is not false : B1 is still ALLOWED: nothing above the sandbox allow-lists models
  why test_24_h09_flags_the_attackers_enable: AssertionError: 0 != 1 : 0 of 1 EnableService event flagged
----------------------------------------------------------------------
Ran 25 tests in 0.139s

FAILED (failures=3)

3 of 25 TESTS FAILED (25 run)
make: *** [Makefile:35: challenge] Error 1
```

Three gaps, three fixes. Each test's message is a hint.

1. **A1: the copied chatbot key.** In `fixes/api-keys.json`, give `chatbot-frontend` an application restriction so
   it only works from the web tier's egress IP, `192.0.2.10` (lesson 10.4). Test 21 checks the web tier still works.
2. **B1: Claude in the sandbox.** Create `fixes/orgpolicy-org-allowed-models.json`: a `vertexai.allowedModels` allow-list
   on `organizations/123456789012`. Copy the shape of `fixes/orgpolicy-prod-allowed-models.json`. Which models must be
   on it so test 23 (data science and CI keep working) still passes? `make twin-preview` showed you what happens if you
   get this wrong.
3. **H09.** Write `rule_ai_enabled_in_unapproved_project()` in `hunt.py` (the comment says what to return).

Done when `make challenge` says `ALL TESTS PASSED (25 run)`, `make attack-safe` says `0 of 9 attacker requests
allowed; 8 of 8 legitimate requests allowed.` and `make hunt` shows an H09 finding. No solution is included.

## Step 8 (optional) · The Google Cloud twin, in your own Free Trial project

Everything above runs locally. If you have your own Google Cloud **Free Trial** (lesson 0.7), these steps repeat the
key, logging, budget and allow-list ideas for real. Never run them in a work organization without permission
(lesson 0.8). We wrote these commands from Google's documentation but did not run them against a live project for this
README, so your output will differ.

**Cost, exactly.** On the Free Trial, "You will not be billed for any Google Cloud usage during your Free Trial"
([Free Trial](https://docs.cloud.google.com/free/docs/free-cloud-features)). Off the trial:

| Step | What it uses | Cost |
|---|---|---|
| 8a, 8b, 8d (key) | project, API enablement, budget, API key | configuration only: no compute, storage or tokens |
| 8c, 8e | Data Access logs for `aiplatform.googleapis.com`, and reading them | $0 within Cloud Logging's first 50 GiB per project per month; then $0.50/GiB ([pricing](https://cloud.google.com/stackdriver/pricing)). A handful of calls is a few KB |
| 8d (refused call) | a request refused by the key's IP restriction | $0: no model runs |
| 8d (one real call, optional) | Gemini 3.1 Flash-Lite, about 10 input tokens, `maxOutputTokens` 50 | $0.25 per 1M input and $1.50 per 1M output tokens ([pricing](https://cloud.google.com/gemini-enterprise-agent-platform/generative-ai/pricing)): at most $0.0000775. Even 1,000 output tokens would be $0.0015 |
| 8f | organization policy in dry run (needs an Organization) | $0 |

**8a · A project with Agent Platform switched on.** Replace `PROJECT_ID` (pick a new, unique ID) and
`BILLING_ACCOUNT_ID` (your Free Trial billing account) in every command:

```bash
gcloud projects create PROJECT_ID
gcloud billing projects link PROJECT_ID --billing-account=BILLING_ACCOUNT_ID
gcloud services enable aiplatform.googleapis.com apikeys.googleapis.com --project=PROJECT_ID
```

**8b · An alerts-only budget** at $5 (lesson 10.5: it notifies, hours late, and caps nothing):

```bash
gcloud billing budgets create --billing-account=BILLING_ACCOUNT_ID --display-name="gc10-twin alerts" \
  --budget-amount=5USD --filter-projects=projects/PROJECT_ID \
  --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0
```

Optional: a **spend cap** budget (generally available since 13 October 2026 for a limited set of services, per the [Cloud Billing release notes](https://docs.cloud.google.com/billing/docs/release-notes)). Google's console steps: Budgets & alerts, **Create new budget**, choose
**Spend cap enforcement** (instead of *Alerts only*), a *single* project and the service *Gemini Enterprise Agent
Platform (formerly Vertex AI)*, an amount, **Finish**
([spend caps](https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps)). The same budget as Budget API
JSON is in `gcp-twin/budget-spend-cap.json` (replace `PROJECT_NUMBER`). Spend caps are "limited to first-party Google
Cloud customers", so you may not see the option.

**8c · Switch on Data Access logs for Agent Platform** (they're off by default). Following Google's
[configure Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) page:

```bash
gcloud projects get-iam-policy PROJECT_ID --format=json > policy.json
# edit policy.json: keep "bindings" and "etag" exactly as they are, and add:
#   "auditConfigs": [{"service": "aiplatform.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}]
gcloud projects set-iam-policy PROJECT_ID policy.json
python3 policy_checker.py --iam policy.json      # GC10-15 should not appear
```

**8d · An API key that only works from one IP.** `192.0.2.10` is a documentation address, so the key will refuse
*your* machine:

```bash
gcloud services api-keys create --project=PROJECT_ID --display-name=gc10-twin \
  --api-target=service=aiplatform.googleapis.com --allowed-ips=192.0.2.10
gcloud services api-keys list --project=PROJECT_ID --format=json > my-keys.json
python3 policy_checker.py --keys my-keys.json    # no GC10-05 or GC10-07: both restrictions are set
gcloud services api-keys get-key-string KEY_ID --project=PROJECT_ID   # KEY_ID: the last part of "name" in my-keys.json
```

Call the model with it, sending the key in the `x-goog-api-key` header as Google recommends
([use API keys](https://docs.cloud.google.com/docs/authentication/api-keys-use)):

```bash
curl -sS -X POST -H "Content-Type: application/json" -H "x-goog-api-key: KEY_STRING" \
  "https://aiplatform.googleapis.com/v1/projects/PROJECT_ID/locations/global/publishers/google/models/gemini-3.1-flash-lite:generateContent" \
  -d '{"contents":{"role":"user","parts":{"text":"Say hello in five words."}},"generationConfig":{"maxOutputTokens":50}}'
```

Expect an error: your IP isn't `192.0.2.10`. That's the application restriction working, and it cost nothing.
Optional: `gcloud services api-keys update KEY_ID --project=PROJECT_ID --allowed-ips=YOUR_EGRESS_IP`, run the call once
more, and you get an answer (see the cost table).

**8e · Read your own audit logs** (give them a few minutes to arrive):

```bash
gcloud logging read 'protoPayload.serviceName="aiplatform.googleapis.com"' --project=PROJECT_ID \
  --freshness=1d --format=json > my-audit.json
python3 hunt.py --summary --file my-audit.json
```

`--summary` counts entries by service, method, principal and caller IP, so you can compare the real `methodName`
values with the ones the lab's rules expect.

**8f · Needs an Organization: the model allow-list in dry run.** The Organization Policy Administrator role's
"lowest-level" resource is the organization
([roles](https://docs.cloud.google.com/iam/docs/roles-permissions/orgpolicy)), so a personal project with no
organization can't set these policies. If you have an organization, edit
`gcp-twin/allowed-models-dryrun.json` (replace `ORGANIZATION_ID`, list the models you use), then:

```bash
python3 policy_checker.py --orgpolicy gcp-twin/allowed-models-dryrun.json   # lint before you set it
gcloud org-policies set-policy gcp-twin/allowed-models-dryrun.json --update-mask=policy.dry_run_spec
gcloud org-policies describe vertexai.allowedModels --effective --project=PROJECT_ID
```

In dry run, violations are audit-logged and nothing is denied. **No Organization?** Use the local dry run from
Step 5 (`make twin-preview`) and the lint command above; that's the fallback, and it's all this step needs.

**Teardown** (do it today, not later):

```bash
gcloud services api-keys delete KEY_ID --project=PROJECT_ID
gcloud billing budgets list --billing-account=BILLING_ACCOUNT_ID      # note the budget IDs you created
gcloud billing budgets delete BUDGET_ID --billing-account=BILLING_ACCOUNT_ID
gcloud org-policies delete vertexai.allowedModels --organization=ORGANIZATION_ID   # only if you did 8f
gcloud projects delete PROJECT_ID
```

Budgets live on the billing account, so delete them yourself. A deleted project is "fully deleted after 30 days"
([projects](https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects)).

## Troubleshooting

| Problem | Fix |
|---|---|
| `make: command not found` (Windows) | Run the `python` command shown next to each `make` step |
| `SyntaxError` or `TypeError` on start | You need Python 3.11+: `python3 --version` |
| `json.decoder.JSONDecodeError` after editing a fix | Your JSON has a typo (often a trailing comma). `python3 -m json.tool fixes/<file>.json` shows where |
| A legitimate request (L1 to L8) turns DENIED after your change | Your allow-list or restriction is too narrow. The **why** line names the policy or key check that refused it |
| Test 19 fails | You added a real-looking IP, identity or key string. Use the documentation values |
| `gcloud: command not found` (Step 8) | Install the Google Cloud CLI, or skip Step 8: it's optional |

## What to write in your findings notebook (lesson 0.5)

Three lines: what you found (Editor and Admin roles on workloads, an AI role on the whole organization, an
unrestricted key in a public repo, an authorization key on a service account with Admin, a website key that can call
Gemini, no model allow-list, no spend cap, Data Access logs off), how you fixed it (predefined roles at the project,
an allow-list with dry run first, restricted keys or none, the two organization constraints, a spend cap budget), and
how you'd spot it (dormant accounts acting, new IPs and methods, unapproved models, `CreateKey` with a service
account, first deployments, AI APIs enabled where they shouldn't be).

## Sources

- Control model access (`vertexai.allowedModels`): <https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/control-model-access>
- Organization Policy overview (dry run, inheritance): <https://docs.cloud.google.com/resource-manager/docs/organization-policy/overview> · `gcloud org-policies set-policy`: <https://docs.cloud.google.com/sdk/gcloud/reference/org-policies/set-policy>
- Manage API keys: <https://docs.cloud.google.com/docs/authentication/api-keys> · best practices: <https://docs.cloud.google.com/docs/authentication/api-keys-best-practices> · API Keys API Key resource: <https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys>
- Gemini API keys (unrestricted standard keys, auth keys): <https://ai.google.dev/gemini-api/docs/api-key>
- Secure-by-default organizations: <https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations>
- Agent Platform audit logging: <https://docs.cloud.google.com/gemini-enterprise-agent-platform/machine-learning/general/audit-logging> · configure Data Access logs: <https://docs.cloud.google.com/logging/docs/audit/configure-data-access>
- Activity Analyzer, service account authentication: <https://docs.cloud.google.com/policy-intelligence/docs/activity-analyzer-service-account-authentication>
- Cloud Billing budgets: <https://docs.cloud.google.com/billing/docs/how-to/budgets> · spend caps: <https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps> · Budget API: <https://docs.cloud.google.com/billing/docs/reference/budget/rest/v1/billingAccounts.budgets>
- AI threat findings (Event Threat Detection): <https://docs.cloud.google.com/security-command-center/docs/ai-threats>
- Free Trial: <https://docs.cloud.google.com/free/docs/free-cloud-features> · Agent Platform pricing: <https://cloud.google.com/gemini-enterprise-agent-platform/generative-ai/pricing> · Cloud Logging pricing: <https://cloud.google.com/stackdriver/pricing>
- RFC 5737, documentation IP ranges: <https://www.rfc-editor.org/rfc/rfc5737>
