# Lab GC11: deploy the TSG Helpdesk on Gemini Enterprise Agent Platform: private, least privilege, logged, CMEK

Companion to lessons **11.1 to 11.6** of *AI Security Engineer* (The Sec Guy), Google Cloud stream. About 35 to 50
minutes, **$0**, all on your laptop. **Nothing to install** (Python standard library only) and **no Google Cloud
account needed**. An optional last step deploys the hardened foundation with Terraform in your own project, with the
cost printed first and a one-command teardown.

You are still the cloud security engineer at **ExampleCo** (fictional, on the documentation domain `example.com`). Its
TSG Helpdesk chatbot from Module 10 calls Gemini on Agent Platform (formerly Vertex AI) from project
`example-chatbot-prod`, running as the service account `chatbot-runtime`. ExampleCo has EU customers, so the data
protection officer now requires that their tickets are processed in the EU. In one sitting you will:

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Run a checker over a twin of the Helpdesk deployment and read its 16 findings | 11.1 to 11.5 |
| **Break** | Replay five attacks and an auditor's four questions against the Helpdesk as it runs today | 11.1, 11.2, 11.4, 11.5 |
| **Fix** | Replay them against the hardened twin, which is what `terraform/` builds | all |
| **Dry run** | Read a week of VPC Service Controls dry-run logs before you enforce anything | 11.2 |
| **Trap** | Watch a well-meant switch to the `eu` multi-region endpoint break the private path | 11.5 |
| **Challenge** | Enforce the perimeter without locking out the analysts, write rule GC11-16, close the cache gap. No solution included | 11.2, 11.3, 11.5 |
| **Cloud (optional)** | Deploy the hardened foundation in your own project with Terraform, check it live, tear it down | 11.6 |

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/gc11`.

## What's in this folder

| File | What it is |
|---|---|
| `checker.py` | The checker: rules `GC11-01` to `GC11-15`, plus `GC11-16` for you to write. Reads a twin or your own `terraform show -json` |
| `attack.py` | 9 requests (5 attacker, 4 legitimate) and 4 auditor questions, against any twin |
| `twin.py` | A **teaching model** of the rules that decide each request (see below) |
| `dryrun_report.py` | Groups VPC Service Controls dry-run entries by caller, method and reason |
| `twin/today/` | The Helpdesk as it runs today: `plan.json` (shaped like `terraform show -json`) and `app.json` (settings Terraform can't express: location, endpoint, request-response logging, cache) |
| `twin/hardened/` | What `terraform/` builds, plus its `app.json` |
| `twin/eu-multiregion/` | The hardened twin after a developer moved the app to the `eu` multi-region endpoint |
| `twin/requirements.json`, `twin/groups.json` | ExampleCo's rules (EU processing, CMEK at rest, logging) and who is in which group |
| `logs/vpcsc-dryrun-week.jsonl` | 44 **fake** Policy Denied dry-run entries from one week |
| `terraform/` | The optional cloud path: `*.tf`, `terraform.tfvars.example`, `scripts/` |
| `GUIDED-BUILD.md` | The cloud path step by step (console, gcloud or Terraform): identity, private path, CMEK, logging, region; five tests, one change, cost and teardown |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 21 tests for the lab, 6 for the challenge |

**About `twin.py`.** It is not Google's authorization, networking or VPC Service Controls engine. It models only the
rules this lab depends on, each taken from Google's documentation (Sources, below): a stolen key only works if a
user-managed key exists; IAM needs a role containing the permission, and Agent Platform User contains
`aiplatform.endpoints.predict` **and** `aiplatform.endpoints.create`/`deploy`; `vertexai.allowedModels` allows
everything when no policy exists; a VM with no external IP and no Cloud NAT reaches Google APIs only through a PSC
endpoint (with a private `googleapis.com` zone) or Private Google Access, neither of which reaches
`*.rep.googleapis.com`; a VPC Service Controls perimeter denies access from outside and copies to outside projects
unless an ingress or egress rule allows them, and in dry run it only logs. It does **not** model IAM deny policies,
conditions, VPC-SC method-level rules, quotas or real routing, and its role-to-permission map is a small subset.

**Three assumptions, said plainly.** (1) The hardened design reaches `europe-west4-aiplatform.googleapis.com` through a
PSC endpoint for global Google APIs with the `vpc-sc` bundle. Google says the `all-apis` bundle covers `*.googleapis.com` names
except `*.rep.googleapis.com`, and that `vpc-sc` serves APIs that support VPC Service Controls (Agent Platform does);
we found no page that names the regional Agent Platform host explicitly, so verify it with the optional smoke test.
(2) Google's request-response logging page couldn't be read when this lab was written; the lab relies on Google's
published API definitions (`setPublisherModelConfig`, v1beta1) and on the zero-data-retention page. Check the
feature's launch stage and limitations before you depend on it, including inside a perimeter. (Update, 22 Oct 2026: the page now opens. It marks the feature **Preview** and says nothing about VPC Service Controls or CMEK.) (3) We didn't test that
request-response logging writes into a dataset with a CMEK default key; the BigQuery service account has the key role,
so it should, but confirm it in your project.

**About the data and safety.** Every IP address is a documentation range from
[RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) or private `10.x` space; every identity is on `example.com`;
organization, folder, project and policy numbers are placeholders. There are no keys or tokens anywhere. Test 21 fails
if a real-looking IP, identity or key creeps in. Nothing in the offline part contacts Google or any other system.

## Needs

- Python **3.11 or newer** (tested on 3.13). Check with `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 8 only: Terraform 1.5+, the `gcloud` CLI, and **your own** sandbox project with billing and a budget
  (lesson 0.7 and Module 10).

## Step 1 · Check: what's wrong with the Helpdesk today?

```bash
cd labs/gc11
make check
```

- `cd labs/gc11`: run it from the course labs repository folder (`ai-security-course-labs`)
- `make check`: same as `python3 checker.py --twin today`

Real output (Linux, Python 3.13):

```text
--- GC11 checker · today ---

  HIGH    GC11-01  google_service_account_key for chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com
          A user-managed JSON key exists for an AI workload's service account: anyone holding the file can call your models from anywhere.
          fix: Delete the key; the workload uses its attached service account through ADC. Keep iam.managed.disableServiceAccountKeyCreation enforced (GC10).
  HIGH    GC11-02  google_compute_instance ticket-summariser
          Runs as the Compute Engine default service account (100000000001-compute@developer.gserviceaccount.com), shared by every workload that didn't choose one and often granted Editor.
          fix: Create one service account per workload and attach it.
  HIGH    GC11-05  google_compute_instance helpdesk-vm
          AI workload has an external IP: model calls cross the internet, and a hijacked app can post data anywhere.
          fix: Remove the external IP and NAT; reach Google APIs through a PSC endpoint; add an egress deny-all firewall rule with an allow for the endpoint.
  HIGH    GC11-05  google_compute_instance ticket-summariser
          AI workload reaches the internet through Cloud NAT: model calls cross the internet, and a hijacked app can post data anywhere.
          fix: Remove the external IP and NAT; reach Google APIs through a PSC endpoint; add an egress deny-all firewall rule with an allow for the endpoint.
  HIGH    GC11-12  auditConfigs aiplatform.googleapis.com
          Data Access (DATA_READ) audit logs are off for aiplatform.googleapis.com: model calls leave no audit record.
          fix: google_project_iam_audit_config with DATA_READ for the service (or at the folder or organization).
  HIGH    GC11-14  app location global
          Model calls use location 'global': the global endpoint can process requests in any region and gives no data residency guarantee. Policy: ML processing must stay in the EU.
          fix: Use an approved regional or multi-region location and check the model is offered there.
  MEDIUM  GC11-03  project example-chatbot-prod roles/aiplatform.user
          chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com holds roles/aiplatform.user: it can do far more than call a model (Agent Platform User includes aiplatform.endpoints.create and .deploy).
          fix: Grant a custom role with aiplatform.endpoints.predict only, on the project that calls the model.
  MEDIUM  GC11-03  project example-chatbot-prod roles/editor
          100000000001-compute@developer.gserviceaccount.com holds roles/editor: it can do far more than call a model.
          fix: Grant a custom role with aiplatform.endpoints.predict only, on the project that calls the model.
  MEDIUM  GC11-04  vertexai.allowedModels
          No model allow-list in this deployment: every model and action, including new ones, is allowed for anyone with the IAM permission.
          fix: Set an allow-list (publishers/P/models/M:predict) on the prod folder; dry run first (GC10).
  MEDIUM  GC11-06  google_compute_global_forwarding_rule
          No Private Service Connect endpoint for Google APIs.
          fix: Add a global internal address (purpose PRIVATE_SERVICE_CONNECT) and a forwarding rule with target vpc-sc (or all-apis), plus a private googleapis.com zone.
  MEDIUM  GC11-08  VPC Service Controls
          No service perimeter restricts aiplatform.googleapis.com: a stolen token works from anywhere and a hijacked workload can copy data to any project.
          fix: Create a perimeter for the project restricting aiplatform, bigquery and storage; dry run first, then enforce.
  MEDIUM  GC11-09  google_bigquery_dataset helpdesk_tickets
          Holds customer data with Google default encryption; policy requires a customer-managed key.
          fix: Set default_encryption_configuration.kms_key_name and grant the BigQuery service account Encrypter/Decrypter on the key.
  MEDIUM  GC11-11  projects/example-chatbot-prod/cacheConfig
          Caching is at Google's default: durable caching can store derived cache data at rest with Google default encryption, and CMEK isn't supported for it.
          fix: Set retentionType EPHEMERAL (in-memory only) or disableCache true; record it in app.json.
  MEDIUM  GC11-13  publishers/google/models/gemini-3.1-flash-lite
          Request-response logging is off: no record of what was asked or answered.
          fix: Enable it per model and project (setPublisherModelConfig, v1beta1) into a CMEK dataset only the incident team can read.
  MEDIUM  GC11-15  project example-chatbot-prod roles/iam.serviceAccountTokenCreator
          group:helpdesk-devs@example.com holds roles/iam.serviceAccountTokenCreator on the whole project: it can act as every service account in it, including the Helpdesk's.
          fix: Grant it on the one service account that needs it (google_service_account_iam_member), or not at all.
  LOW     GC11-07  google_compute_subnetwork helpdesk-eu
          Private Google Access is off: VMs without an external IP can't reach Google APIs if the PSC path fails.
          fix: Set private_ip_google_access = true (it doesn't cover *.rep.googleapis.com).

6 HIGH, 9 MEDIUM, 1 LOW, 0 WARNING  (16 findings)
```

Read it by lesson:

- **11.1 identity:** a JSON key for `chatbot-runtime` (GC11-01); the summariser VM on the Compute Engine default
  account, which holds Editor (GC11-02, GC11-03); `chatbot-runtime` holds Agent Platform User (GC11-03); no model
  allow-list (GC11-04); Token Creator for a whole developer group on the project (GC11-15).
- **11.2 network:** a public IP on the Helpdesk VM and Cloud NAT for the summariser (GC11-05), no PSC endpoint
  (GC11-06), PGA off (GC11-07), no perimeter (GC11-08).
- **11.3 encryption:** the tickets dataset on Google default encryption (GC11-09); caching at the default, which
  includes durable caching at rest without CMEK (GC11-11).
- **11.4 logging:** Data Access logs off for `aiplatform.googleapis.com` (GC11-12); request-response logging off
  (GC11-13).
- **11.5 residency:** the `global` endpoint, against an EU-only processing rule (GC11-14).

## Step 2 · Break it: attacks and an auditor

```bash
make attack
```

Same as `python3 attack.py --twin today`.

Real output:

```text
--- GC11 lab · twin: today · TSG Helpdesk in example-chatbot-prod ---
    (twin.py: a teaching model of Google Cloud's rules; nothing is sent to Google)

Attackers
  [A1] ALLOWED  Stolen JSON key of chatbot-runtime, from 203.0.113.66: GenerateContent on Gemini
         why: every check passed
         · IAM: aiplatform.endpoints.predict via roles/aiplatform.user on project
  [A2] ALLOWED  Same key: deploy Llama 3 to a GPU endpoint (bills while it runs)
         why: every check passed
         · IAM: aiplatform.endpoints.deploy via roles/aiplatform.user on project
  [A3] ALLOWED  Prompt-injected Helpdesk copies the tickets table to a project outside ExampleCo
         why: every check passed
         · path: bigquery.googleapis.com over the internet (external IP or Cloud NAT)
         · IAM: bigquery.tables.getData via roles/bigquery.dataViewer on dataset helpdesk_tickets
  [A4] ALLOWED  Prompt-injected Helpdesk posts ticket text to an attacker's HTTPS webhook
         why: data sent to a non-Google destination: VPC Service Controls covers Google APIs only
         · path: the VM has a route to the internet (external IP or Cloud NAT)
  [A5] ALLOWED  A developer's stolen laptop session mints a token for chatbot-runtime from 203.0.113.80
         why: every check passed
         · IAM: aiplatform.endpoints.predict via roles/aiplatform.user on project

Legitimate traffic · must keep working
  [L1] ALLOWED  Helpdesk VM: GenerateContent on the approved Gemini model as chatbot-runtime
         why: every check passed
  [L2] ALLOWED  Helpdesk VM: read ticket history from BigQuery
         why: every check passed
  [L3] ALLOWED  Analyst in the office (198.51.100.21): query the tickets dataset
         why: every check passed
  [L4] ALLOWED  Ticket summariser VM: GenerateContent on the approved Gemini model
         why: every check passed

The auditor's questions
  [Q1] NO   Can we see who called Gemini, as which identity, from which IP?
         Data Access audit logs are off for aiplatform.googleapis.com: no record of model calls
  [Q2] NO   Can we see what each prompt and answer said?
         request-response logging is off
  [Q3] NO   Can we show EU tickets were processed only in the EU?
         calls use location 'global': the global endpoint gives no data residency guarantee
  [Q4] NO   Can we make stored prompts and tickets unreadable in one step (disable the key)?
         datasets use Google default encryption: there's no key of yours to disable

5 of 5 attacker requests allowed; 4 of 4 legitimate requests allowed; 0 of 4 auditor questions answerable.
```

Five different attackers, five successes. And when the auditor asks the four questions any incident or privacy review
will ask, every answer is "no".

## Step 3 · Read the hardened design

Open `twin/hardened/plan.json` next to `terraform/` (they describe the same thing; test 19 and 20 prove it):

| File | Control | Stops |
|---|---|---|
| `identity.tf` | `chatbot-runtime` and `ticket-summariser` service accounts, **no keys**; custom role `helpdeskModelCaller` with only `aiplatform.endpoints.predict`; Service Account User on the one account, for deployers only | A1, A2, A5 |
| `orgpolicy.tf` | `vertexai.allowedModels` on the prod folder: `publishers/google/models/gemini-3.1-flash-lite:predict` (needs an organization) | any model nobody approved |
| `network.tf` | No external IPs, no Cloud NAT; PSC endpoint `tsgapis` at `10.100.0.2` with the `vpc-sc` bundle; private `googleapis.com` zone (A + `*.googleapis.com` CNAME); PGA on; egress deny-all plus an allow to `10.100.0.2:443` | A4, and stolen tokens no longer travel the internet path |
| `perimeter.tf` | VPC Service Controls perimeter around the project, restricting `aiplatform`, `bigquery`, `storage`, **in dry run** (needs an organization) | logs A3 (blocks it once enforced) |
| `encryption.tf` | Cloud KMS key ring `helpdesk-eu`, key `helpdesk-data` (90-day rotation); BigQuery service account may use it; `helpdesk_tickets` and `ai_logs` with that default key | Q4 |
| `logging.tf` | `DATA_READ` and `DATA_WRITE` audit logs for `aiplatform.googleapis.com` | Q1 |
| `scripts/request_response_logging.sh` | `setPublisherModelConfig` (v1beta1), 100% sampling into `ai_logs` | Q2 |
| `twin/hardened/app.json` | `location: europe-west4`, `endpoint_host: europe-west4-aiplatform.googleapis.com` | Q3 |

## Step 4 · Fix it: replay against the hardened twin

```bash
make check-hardened
```

Same as `python3 checker.py --twin hardened`.

```text
--- GC11 checker · hardened ---

  MEDIUM  GC11-11  projects/example-chatbot-prod/cacheConfig
          Caching is at Google's default: durable caching can store derived cache data at rest with Google default encryption, and CMEK isn't supported for it.
          fix: Set retentionType EPHEMERAL (in-memory only) or disableCache true; record it in app.json.
  WARNING GC11-08  accessPolicies/987654321/servicePerimeters/helpdesk
          The perimeter is in DRY RUN: violations are only logged (metadata.dryRun = true), nothing is blocked.
          fix: Read a week of dry-run logs (make dryrun-report), add ingress/egress rules for legitimate callers, then enforce (move the config to status).

0 HIGH, 1 MEDIUM, 0 LOW, 1 WARNING  (2 findings)
```

```bash
make attack-safe
```

Same as `python3 attack.py --twin hardened`.

```text
--- GC11 lab · twin: hardened · TSG Helpdesk in example-chatbot-prod ---
    (twin.py: a teaching model of Google Cloud's rules; nothing is sent to Google)

Attackers
  [A1] DENIED   Stolen JSON key of chatbot-runtime, from 203.0.113.66: GenerateContent on Gemini
         why: no user-managed key exists for chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com: there is nothing to steal
  [A2] DENIED   Same key: deploy Llama 3 to a GPU endpoint (bills while it runs)
         why: no user-managed key exists for chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com: there is nothing to steal
  [A3] ALLOWED  Prompt-injected Helpdesk copies the tickets table to a project outside ExampleCo
         why: every check passed
         · path: Private Service Connect endpoint 10.100.0.2 (vpc-sc bundle)
         · IAM: bigquery.tables.getData via roles/bigquery.dataViewer on dataset helpdesk_tickets
         · VPC Service Controls DRY RUN would block this, but only logs it: copy to projects/999999999999, outside the perimeter (RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER)
  [A4] DENIED   Prompt-injected Helpdesk posts ticket text to an attacker's HTTPS webhook
         why: network: egress firewall denies all traffic except the PSC endpoint
  [A5] DENIED   A developer's stolen laptop session mints a token for chatbot-runtime from 203.0.113.80
         why: can't mint a token for the service account: no role grants iam.serviceAccounts.getAccessToken to user:dev1@example.com

Legitimate traffic · must keep working
  [L1] ALLOWED  Helpdesk VM: GenerateContent on the approved Gemini model as chatbot-runtime
         why: every check passed
  [L2] ALLOWED  Helpdesk VM: read ticket history from BigQuery
         why: every check passed
  [L3] ALLOWED  Analyst in the office (198.51.100.21): query the tickets dataset
         why: every check passed
         · VPC Service Controls DRY RUN would block this, but only logs it: ingress from 198.51.100.21 has no matching ingress rule (NO_MATCHING_ACCESS_LEVEL)
  [L4] ALLOWED  Ticket summariser VM: GenerateContent on the approved Gemini model
         why: every check passed

The auditor's questions
  [Q1] YES  Can we see who called Gemini, as which identity, from which IP?
         Data Access (DATA_READ) audit logs for aiplatform.googleapis.com are on
  [Q2] YES  Can we see what each prompt and answer said?
         request-response logging at 1.0 to bq://example-chatbot-prod.ai_logs.request_response_logging
  [Q3] YES  Can we show EU tickets were processed only in the EU?
         calls use location 'europe-west4', an approved EU location
  [Q4] YES  Can we make stored prompts and tickets unreadable in one step (disable the key)?
         every dataset has a customer-managed default key

1 of 5 attacker requests allowed; 4 of 4 legitimate requests allowed; 4 of 4 auditor questions answerable.
```

Four attacks stopped, everything legitimate still works, and every auditor question has an answer. A3 still works,
on purpose: the perimeter is in dry run, so it **logs** the copy and lets it through. L3 shows the other side: enforce
today and the office analysts are locked out.

## Step 5 · Dry run before you enforce

A dry-run perimeter writes would-be denials to the Policy Denied audit log (`cloudaudit.googleapis.com%2Fpolicy`) with
`protoPayload.metadata.dryRun` set to true. Here is ExampleCo's first week:

```bash
make dryrun-report
```

Same as `python3 dryrun_report.py`.

```text
--- VPC Service Controls dry run · 44 would-be denials in vpcsc-dryrun-week.jsonl ---

  count  principal                                                    caller IP       method          reason
     14  analyst1@example.com                                         198.51.100.20   InsertJob       NO_MATCHING_ACCESS_LEVEL
     14  analyst2@example.com                                         198.51.100.21   InsertJob       NO_MATCHING_ACCESS_LEVEL
     14  analyst3@example.com                                         198.51.100.22   InsertJob       NO_MATCHING_ACCESS_LEVEL
      1  chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com 203.0.113.66    GenerateContent NO_MATCHING_ACCESS_LEVEL
      1  chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com 10.10.0.5       InsertJob       RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER

5 distinct caller/method/reason groups. Before you enforce, label each one: legitimate (write an ingress or egress rule for it) or not (let the perimeter block it).
```

Label each group. The three analysts are legitimate: they need an access level for the office range
`198.51.100.0/24` and an ingress rule for BigQuery. The `GenerateContent` from `203.0.113.66` is a `chatbot-runtime`
token used from the internet (tokens leak too, through debug logs or a compromised laptop). The copy job from
`10.10.0.5` with `RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER` is A3. Those two are exactly what the perimeter is for.

On your own logs: `python3 dryrun_report.py --file my-export.json` (the export command is in the script's header).

## Step 6 · The residency trap

A developer reads that multi-region endpoints have better availability and switches the Helpdesk to
`aiplatform.eu.rep.googleapis.com`. Still EU, so the checker's residency rule is happy:

```bash
make residency-trap
```

Same as `python3 attack.py --twin eu-multiregion`.

```text
--- GC11 lab · twin: eu-multiregion · TSG Helpdesk in example-chatbot-prod ---
    (twin.py: a teaching model of Google Cloud's rules; nothing is sent to Google)

Attackers
  [A1] DENIED   Stolen JSON key of chatbot-runtime, from 203.0.113.66: GenerateContent on Gemini
         why: no user-managed key exists for chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com: there is nothing to steal
  [A2] DENIED   Same key: deploy Llama 3 to a GPU endpoint (bills while it runs)
         why: no user-managed key exists for chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com: there is nothing to steal
  [A3] ALLOWED  Prompt-injected Helpdesk copies the tickets table to a project outside ExampleCo
         why: every check passed
         · path: Private Service Connect endpoint 10.100.0.2 (vpc-sc bundle)
         · IAM: bigquery.tables.getData via roles/bigquery.dataViewer on dataset helpdesk_tickets
         · VPC Service Controls DRY RUN would block this, but only logs it: copy to projects/999999999999, outside the perimeter (RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER)
  [A4] DENIED   Prompt-injected Helpdesk posts ticket text to an attacker's HTTPS webhook
         why: network: egress firewall denies all traffic except the PSC endpoint
  [A5] DENIED   A developer's stolen laptop session mints a token for chatbot-runtime from 203.0.113.80
         why: can't mint a token for the service account: no role grants iam.serviceAccounts.getAccessToken to user:dev1@example.com

Legitimate traffic · must keep working
  [L1] DENIED   Helpdesk VM: GenerateContent on the approved Gemini model as chatbot-runtime
         why: network: aiplatform.eu.rep.googleapis.com ends in rep.googleapis.com: Private Google Access doesn't support it and the PSC bundles for global Google APIs exclude *.rep.googleapis.com
  [L2] ALLOWED  Helpdesk VM: read ticket history from BigQuery
         why: every check passed
  [L3] ALLOWED  Analyst in the office (198.51.100.21): query the tickets dataset
         why: every check passed
         · VPC Service Controls DRY RUN would block this, but only logs it: ingress from 198.51.100.21 has no matching ingress rule (NO_MATCHING_ACCESS_LEVEL)
  [L4] DENIED   Ticket summariser VM: GenerateContent on the approved Gemini model
         why: network: aiplatform.eu.rep.googleapis.com ends in rep.googleapis.com: Private Google Access doesn't support it and the PSC bundles for global Google APIs exclude *.rep.googleapis.com

The auditor's questions
  [Q1] YES  Can we see who called Gemini, as which identity, from which IP?
         Data Access (DATA_READ) audit logs for aiplatform.googleapis.com are on
  [Q2] YES  Can we see what each prompt and answer said?
         request-response logging at 1.0 to bq://example-chatbot-prod.ai_logs.request_response_logging
  [Q3] YES  Can we show EU tickets were processed only in the EU?
         calls use location 'eu', an approved EU location
  [Q4] YES  Can we make stored prompts and tickets unreadable in one step (disable the key)?
         every dataset has a customer-managed default key

1 of 5 attacker requests allowed; 2 of 4 legitimate requests allowed; 4 of 4 auditor questions answerable.
```

The Helpdesk and the summariser are down. Private Google Access doesn't support `rep.googleapis.com` endpoints and the
PSC endpoint is for global Google APIs. Under pressure, the quickest "fix" is `global`, and EU processing is gone.
The right fixes: stay on the regional endpoint, or add a Private Service Connect endpoint for regional Google APIs and
check it supports the service. The checker didn't warn you. That's the challenge.

## Step 7 · Your turn: `make challenge`

```bash
make test
make challenge
```

You should see, from `make test`:

```text
ALL TESTS PASSED (21 run)
```

From `make challenge`:

```text
3 of 27 TESTS FAILED (27 run)
```

The three failing tests pass when you finish.

`make test`, real output (last lines):

```text
OK

ALL TESTS PASSED (21 run)
```

`make challenge`, real output (the challenge part):

```text
[FAIL] challenge: the hijacked Helpdesk's copy to an outside project is DENIED by the enforced perimeter
[PASS] challenge: the office analysts can still query the tickets dataset once the perimeter is enforced
[PASS] challenge: the Helpdesk and the summariser keep working inside the perimeter
[FAIL] challenge: GC11-16 flags the eu-multiregion twin (rep endpoint, only PGA / global-API PSC)
[PASS] challenge: GC11-16 stays quiet on the today and hardened twins
[FAIL] challenge: the hardened twin no longer allows durable caching (no GC11-11)
  why test_22_perimeter_blocks_the_copy: AssertionError: True is not false : A3 is still ALLOWED: the perimeter is only in dry run
  why test_25_gc11_16_flags_rep_endpoint: AssertionError: 0 != 1 : GC11-16 didn't fire on twin/eu-multiregion
  why test_27_no_durable_cache: AssertionError: 'GC11-11' unexpectedly found in ['GC11-08', 'GC11-11'] : set cache_config in twin/hardened/app.json
----------------------------------------------------------------------

FAILED (failures=3)

3 of 27 TESTS FAILED (27 run)
```

1. **Enforce the perimeter (tests 22 to 24).** In `twin/hardened/plan.json`, give the perimeter an enforced `status`
   block (restricted services and resources as in `spec`). Add a `google_access_context_manager_access_level`
   resource named `accessPolicies/987654321/accessLevels/office` with `basic` → `conditions` → `ip_subnetworks`
   `["198.51.100.0/24"]`, and an `ingress_policies` entry that lets `ANY_USER_ACCOUNT` from that access level reach
   `bigquery.googleapis.com`. The field names follow the Terraform provider's `google_access_context_manager_*`
   resources; `terraform/perimeter.tf` already has the same ingress rule behind `office_ranges`. Then do it for real:
   change `terraform/perimeter.tf` from `spec` to `status` only after your own dry-run week is clean.
2. **Write GC11-16 (tests 25 and 26).** In `checker.py`, `rule_rep_endpoint_private_path()` should return one
   `MEDIUM` finding when `app.json`'s `endpoint_host` ends in `.rep.googleapis.com` and the deployment has no internet
   route, so its only private paths are PGA or a PSC endpoint for global Google APIs. It must stay quiet on `today` and
   `hardened`.
3. **Close the cache gap (test 27).** ExampleCo's policy forbids customer data at rest without its own key, and
   durable caching doesn't support CMEK. In `twin/hardened/app.json`, set `cache_config` to what the project should
   be: `{"retention_type": "EPHEMERAL"}` (in-memory caching only) or `{"disable_cache": true}`. Lesson 11.3 has the
   REST call that does it for real; Terraform's `google_vertex_ai_cache_config` can only switch all caching off.

When you're done, `make challenge` prints `ALL TESTS PASSED (27 run)` and `make attack-safe` ends with
`0 of 5 attacker requests allowed; 4 of 4 legitimate requests allowed; 4 of 4 auditor questions answerable.`

## Step 8 (optional) · The cloud path, in your own project

**Want to build it piece by piece?** [`GUIDED-BUILD.md`](GUIDED-BUILD.md) does the same foundation with console clicks or
gcloud (or this Terraform), then proves it with five tests, changes one setting, and tears it down.

Do this only in **your own** sandbox project, never at work, and only after Module 10's budget and spend cap are in
place. Nothing here needs an organization; the allow-list and the perimeter are skipped without one.

### Cost (estimate, checked 22 Oct 2026; prices change, so check the pages)

| Item | Price | One 2-hour session |
|---|---|---|
| PSC endpoint for Google APIs | $0.01 per hour, "No data charge" ([VPC pricing](https://cloud.google.com/vpc/pricing)) | $0.02 |
| Cloud KMS software key version | $0.000082192 per hour (about $0.06 a month); "Scheduled for destruction" still counts as active, default 30 days ([KMS pricing](https://cloud.google.com/kms/pricing), [destroy](https://docs.cloud.google.com/kms/docs/destroy-restore)) | about $0.06 including the 30 days after `make down` |
| KMS cryptographic operations | $0.03 per 10,000 | well under $0.01 |
| BigQuery | first 10 GiB storage and first 1 TiB of queries per month free ([BigQuery pricing](https://cloud.google.com/bigquery/pricing)) | $0 at lab size |
| Cloud Logging | Data Access logs count towards Cloud Logging ingestion (Module 10: 50 GiB per project per month free) | $0 at lab size |
| Private DNS zone, firewall rules, service accounts, IAM | Cloud DNS charges per zone; see Cloud DNS pricing | not estimated here: check |
| Gemini calls | a handful of short `generateContent` calls; see Agent Platform pricing for your region | fractions of a cent |
| Optional test VM (`create_test_vm = true`) | e2-small, billed per second at your region's rate | not included: delete it after the test |

Free Trial: "You can't access or use the $300 credit for a generative AI partner model that is offered as a managed
API" ([Free Trial](https://docs.cloud.google.com/free/docs/free-cloud-features)).

### Deploy

```bash
make cost
cd terraform
cp terraform.tfvars.example terraform.tfvars
cd ..
make plan
make up
terraform/scripts/check_live.sh YOUR_PROJECT_ID europe-west4
terraform/scripts/request_response_logging.sh on YOUR_PROJECT_ID europe-west4
```

- `make cost`: prints the table above
- `cp terraform.tfvars.example terraform.tfvars`: set project_id; keep create_test_vm = false at first
- `make plan`: terraform init + plan, then runs checker.py on YOUR plan
- `make up`: applies the saved plan

`make plan` runs the checker on your real plan with `twin/hardened/app.json`. Without an organization you'll see no
GC11-04 or GC11-08 (they need one), and GC11-11 until you set the cache.

To prove the private path, set `create_test_vm = true` and apply again. The VM has no external IP; at boot it calls
Gemini through the PSC endpoint as `chatbot-runtime` and tries to reach `https://example.com`. Read the result:

```bash
gcloud compute instances get-serial-port-output helpdesk-vm --zone europe-west4-a | grep TSG-SMOKE
```

If the private path works you'll see `generateContent HTTP 200`, and the internet test fails. Then set `create_test_vm = false` and apply
again.

### Teardown

```bash
terraform/scripts/request_response_logging.sh off YOUR_PROJECT_ID europe-west4
make down
```

- `make down`: terraform destroy

Cloud KMS keys can't be deleted. Terraform's provider docs: destroying a key "will remove it from state and delete all
CryptoKeyVersions, rendering the key unusable, but will not delete the resource from the project"
([provider docs](https://github.com/hashicorp/terraform-provider-google/blob/main/website/docs/r/kms_crypto_key.html.markdown)).
Google adds that "Key rings can't be deleted" ([Cloud KMS](https://docs.cloud.google.com/kms/docs/destroy-restore)). The versions sit in
"scheduled for destruction" for 30 days and are billed as active until then. Deleting the whole sandbox project is the
cleanest end.

**Validation status.** The `.tf` files were checked offline for syntax (HCL parse) and for references between
resources; `terraform validate` and a real apply were **not** run when this lab was written. If a provider version
renames an argument, `make plan` tells you; please open an issue.

## Troubleshooting

- `python3: command not found` on Windows: use `py` instead of `python3`.
- `make: command not found`: run the `python3 ...` command shown next to each `make` line.
- Tests fail after you edited a twin file: `python3 -m json.tool twin/hardened/plan.json` finds JSON typos.
- `make plan` errors about `google-beta`: the PSC address and forwarding rule need the beta provider; `terraform init`
  downloads it.
- The smoke test shows HTTP 403: Data Access logs for `aiplatform.googleapis.com` show an IAM denial; if you enforced a
  perimeter, look in the Policy Denied logs (lesson 11.2) too.

## What to write in your findings notebook (lesson 0.5)

- Which GC11 findings would your own AI project have today? Run `checker.py --plan` on a real plan.
- Is `aiplatform.googleapis.com` in a perimeter, and who would a dry run show you'd lock out?
- What location does each AI feature call, and who approved it?

## Sources

- Agent Platform roles and permissions: https://docs.cloud.google.com/iam/docs/roles-permissions/aiplatform
- How Application Default Credentials works: https://docs.cloud.google.com/docs/authentication/application-default-credentials
- Service account best practices: https://docs.cloud.google.com/iam/docs/best-practices-service-accounts
- Private Google Access: https://docs.cloud.google.com/vpc/docs/private-google-access
- PSC endpoints for Google APIs: https://docs.cloud.google.com/vpc/docs/about-accessing-google-apis-endpoints and https://docs.cloud.google.com/vpc/docs/configure-private-service-connect-apis
- VPC Service Controls overview, dry run, audit logging: https://docs.cloud.google.com/vpc-service-controls/docs/overview, https://docs.cloud.google.com/vpc-service-controls/docs/dry-run-mode, https://docs.cloud.google.com/vpc-service-controls/docs/audit-logging
- Agent Platform data residency and zero data retention: https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/data-residency, https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/zero-data-retention
- Generative AI locations (global and multi-region endpoints): https://docs.cloud.google.com/vertex-ai/generative-ai/docs/learn/locations
- Enable Data Access audit logs: https://docs.cloud.google.com/logging/docs/audit/configure-data-access
- Agent Platform API definitions (request-response logging, v1beta1): https://github.com/googleapis/googleapis/tree/master/google/cloud/aiplatform/v1beta1
- Terraform Google provider resources: https://github.com/hashicorp/terraform-provider-google/tree/main/website/docs/r
- Pricing: https://cloud.google.com/vpc/pricing, https://cloud.google.com/kms/pricing, https://cloud.google.com/bigquery/pricing
