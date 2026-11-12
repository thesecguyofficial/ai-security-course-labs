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
| `explore.py` | Read-only helper for Step 1b: `plan`, `model`, `role`, `route`, `network`, `endpoint`, `keys`, `logging`, `record`, each on its own |
| `dryrun_report.py` | Groups VPC Service Controls dry-run entries by caller, method and reason |
| `twin/today/` | The Helpdesk as it runs today: `plan.json` (shaped like `terraform show -json`) and `app.json` (settings Terraform can't express: location, endpoint, request-response logging, cache) |
| `twin/hardened/` | What `terraform/` builds, plus its `app.json` |
| `twin/global-endpoint/` | The hardened twin after a developer moved the app to the `global` endpoint |
| `twin/requirements.json`, `twin/groups.json` | ExampleCo's rules (EU processing, CMEK at rest, logging) and who is in which group |
| `logs/vpcsc-dryrun-week.jsonl` | 44 **fake** Policy Denied dry-run entries from one week |
| `terraform/` | The optional cloud path: `*.tf`, `terraform.tfvars.example`, `scripts/` |
| `GUIDED-BUILD.md` | The cloud path step by step (console, gcloud or Terraform): identity, private path, CMEK, logging, region; five tests, one change, cost and teardown |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 21 tests for the lab, 6 for the challenge |

**About `twin.py`.** It is not Google's authorization, networking or VPC Service Controls engine. It models only the
rules this lab depends on, each taken from Google's documentation (Sources, below): a stolen key only works if a
user-managed key exists; IAM needs a role containing the permission, and Agent Platform User contains
`aiplatform.endpoints.predict` **and** `aiplatform.endpoints.create`/`deploy`; `vertexai.allowedModels` allows
everything when no policy exists; a VM with no external IP and no Cloud NAT reaches a Google host only through a
regional PSC endpoint that targets exactly that host (with a private zone for its name), a PSC endpoint for global
Google APIs (with a private `googleapis.com` zone) or Private Google Access, and only the first reaches
`*.rep.googleapis.com`; a VPC Service Controls perimeter denies access from outside and copies to outside projects
unless an ingress or egress rule allows them, and in dry run it only logs. It does **not** model IAM deny policies,
conditions, VPC-SC method-level rules, quotas or real routing, and its role-to-permission map is a small subset.

**Tested in a real project, 12 November 2026, and the twin follows it.** What the real run found:
`gemini-3.1-flash-lite` answered only on `global`, `eu` and `us`, never on `europe-west4`, and a PSC endpoint for
global Google APIs with the `vpc-sc` bundle returned `503` "VPC network mapping unavailable" in a project with no
organization. So the cloud build calls `aiplatform.eu.rep.googleapis.com` (`locations/eu`) through a **regional**
PSC endpoint for that one host at `10.10.0.10`, and the hardened twin does the same. The twin's Helpdesk also reads
tickets from BigQuery, so the twin adds a second regional endpoint, `bigquery.europe-west4.rep.googleapis.com` at
`10.10.0.11` (Google's [BigQuery regional endpoints](https://docs.cloud.google.com/bigquery/docs/regional-endpoints)
page lists `europe-west4`); the cloud build doesn't need it, because its test VM only calls the model. The residency
trap (Step 6) is now the global endpoint, which the network blocks. Request-response logging into a dataset with a
CMEK default key worked.

**Two assumptions, said plainly.** (1) Google's request-response logging page couldn't be read when this lab was
first written; the lab relies on Google's published API definitions (`setPublisherModelConfig`, v1beta1) and on the
zero-data-retention page. The page now opens: it marks the feature **Preview** and says nothing about VPC Service
Controls. Check its launch stage before you depend on it, including inside a perimeter. (2) The twin's perimeter treats
calls through the regional endpoints as coming from inside the network. Google documents VPC Service Controls for
regional endpoints on the regional endpoints page; test your own perimeter in dry run before you enforce it.

**About the data and safety.** Every IP address is a documentation range from
[RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) or private `10.x` space; every identity is on `example.com`;
organization, folder, project and policy numbers are placeholders. There are no keys or tokens anywhere. Test 21 fails
if a real-looking IP, identity or key creeps in. Nothing in the offline part contacts Google or any other system.

## Needs

- Python **3.11 or newer** (tested on 3.13). Check with `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 8 only: Terraform 1.5+, the `gcloud` CLI, and **your own** sandbox project with billing and a budget
  (lesson 0.7 and Module 10).

## Step 1b · Before you check: look at each piece (about 10 minutes)

New to Agent Platform or Terraform? Do this before Step 1 (lesson 11.6 calls it "Before you start"). `explore.py`
shows each idea from lesson 11.0 ("How Agent Platform works, one idea at a time") on its own. Real output below is
from a fresh Ubuntu machine (recording run 41618272275).

**What it really runs.** Nothing that changes anything: `explore.py` reads the twins in `twin/` (each a `plan.json`
and an `app.json`), `twin/requirements.json` and `twin/groups.json`, and prints what it finds. No network, no Google
Cloud account, no Terraform.

**0. Look before you run.** `make -n setup` prints what `make setup` would run, without running it:

```bash
make -n setup
make setup
```

```text
python3 ../../tools/check_python.py 3.11
Nothing to install for this lab: Python 3.12 and its standard library are all it needs.
```

Other labs make a *virtual environment* here (a private folder for that lab's Python packages, so versions don't
clash; it keeps versions apart, it isn't a security sandbox) and run `pip install`. This lab uses only Python's
standard library, so there is nothing to install. `make -n plan` is worth a look too: it prints Step 8's real
`terraform plan` in your own project, then the same checker on your plan. Don't run it for Steps 1 to 7.

**1. The plan.** What today's Helpdesk is made of. A plan changes nothing; only `apply` would. The twins are written
by hand in the shape `terraform show -json` prints (tests 19 and 20 check the hardened one against `terraform/`):

```bash
python3 explore.py plan
```

```text
Terraform plan, today: twin/today/plan.json
  shaped like `terraform show -json` (format 1.2), written by hand for the lab
  20 resources it WOULD create   (a plan changes nothing; apply would)

   1 x google_bigquery_dataset                              helpdesk_tickets
   3 x google_bigquery_dataset_iam_member                   tickets_chatbot, tickets_ds, tickets_summariser
   2 x google_compute_instance                              helpdesk_vm, ticket_summariser
   1 x google_compute_network                               helpdesk
   1 x google_compute_router_nat                            helpdesk_nat
   1 x google_compute_subnetwork                            helpdesk_eu
   3 x google_project_iam_member                            chatbot_ai_user, default_compute_editor, devs_token_c...
   6 x google_project_service                               aiplatform, bigquery, compute, cloudkms, dns, iam
   1 x google_service_account                               chatbot_runtime
   1 x google_service_account_key                           ops_laptop

Plus twin/today/app.json: settings Terraform can't express (location, endpoint, logging, cache).
20 resources. Nothing exists yet: this is the plan, read before anything is built.
```

**2. The model, and which models may be used.** The full model name, the endpoint the app calls, and the
organization policy `vertexai.allowedModels`. Today there is none:

```bash
python3 explore.py model
```

```text
The Helpdesk's model, today (twin/today/app.json):

  model (publisher model)  publishers/google/models/gemini-3.1-flash-lite
  location                 global
  endpoint the app calls   https://aiplatform.googleapis.com
  path in each call        .../locations/global/publishers/google/models/gemini-3.1-flash-lite:generateContent
  runs as                  chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com

Which models may be used at all? (Organization Policy vertexai.allowedModels)
  no policy: every model and action is allowed
  ALLOWED  publishers/google/models/gemini-3.1-flash-lite:predict
  ALLOWED  publishers/meta/models/llama3:deploy

Gemini is Google's own model. A partner model (Claude, for example) is a managed API too, but switching
it on is a separate right: the Consumer Procurement Entitlement Manager role (lesson 11.1).
```

`python3 explore.py model hardened` shows the allow-list on the prod folder, location `europe-west4`, and `refused`
for Llama 3.

**3. Who holds which role.** Every grant is a principal, a role and a resource:

```bash
python3 explore.py role
```

```text
Who holds which role, today. Each grant = WHO (a principal) + WHICH ROLE + ON WHAT:

  serviceAccount:chatbot-runtime     roles/aiplatform.user                on project example-chatbot-prod
  serviceAccount:100000000001-com... roles/editor                         on project example-chatbot-prod
  group:helpdesk-devs                roles/iam.serviceAccountTokenCreator on project example-chatbot-prod
  serviceAccount:chatbot-runtime     roles/bigquery.dataViewer            on dataset helpdesk_tickets
  group:data-science                 roles/bigquery.dataViewer            on dataset helpdesk_tickets
  serviceAccount:100000000001-com... roles/bigquery.dataEditor            on dataset helpdesk_tickets

What the AI roles contain (twin.py's subset of Google's IAM reference):
  roles/aiplatform.user                  aiplatform.endpoints.create, aiplatform.endpoints.deploy, aiplatform.endpoints.predic...
  roles/editor                           aiplatform.*, bigquery.*, compute.*, iam.serviceAccountKeys.create, storage.*
  roles/iam.serviceAccountTokenCreator   iam.serviceAccounts.getAccessToken

Service account keys (JSON files someone could steal): chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com
```

`python3 explore.py role hardened`: a custom role `helpdeskModelCaller` with only `aiplatform.endpoints.predict`, no
project-wide Token Creator, and no keys.

**4. Where the prompt runs.** The endpoint decides. Try the one the Helpdesk uses today:

```bash
python3 explore.py route global
```

```text
One generateContent call from helpdesk-vm with location global

  endpoint     https://aiplatform.googleapis.com   (global)
  processing   any Google Cloud location in the world
  at rest      stays in the location you selected, whichever endpoint you call

ExampleCo's rule: ML processing must stay in the EU (approved: europe-west4, europe-west1, eu)
Verdict: BREAKS the rule

Can the hardened Helpdesk VM reach it privately?  NO
  no private path to aiplatform.googleapis.com:
  this network's endpoints serve only aiplatform.eu.rep.googleapis.com, bigquery.europe-west4.rep.googleapis.com,
  and the egress firewall blocks everything else
```

Then try `python3 explore.py route eu`: it fits the EU rule, and the hardened VM reaches it through its regional
endpoint `10.10.0.10`. `global` fails twice: it breaks the rule, and the hardened network can't reach it (Step 6).

**5. The network.** Today the Helpdesk VM can send data anywhere:

```bash
python3 explore.py network
```

```text
The Helpdesk's network, today

  VPC      helpdesk-vpc   (a private network; subnets are regional)
  subnet   helpdesk-eu  10.10.0.0/24  europe-west4  Private Google Access off
  VM       helpdesk-vm        external IP YES   runs as chatbot-runtime
  VM       ticket-summariser  external IP none  runs as 100000000001-compute
  Cloud NAT          yes (outbound to the internet for VMs with no external IP)
  egress firewall    no deny-all rule: VMs may send to any address they can route to

Where can the Helpdesk VM send data?
  REACHES  aiplatform.googleapis.com                aiplatform.googleapis.com over the internet (external IP or Cloud NAT)
  REACHES  bigquery.googleapis.com                  bigquery.googleapis.com over the internet (external IP or Cloud NAT)
  REACHES  attacker.example                         the VM has a route to the internet (external IP or Cloud NAT)
```

`python3 explore.py network hardened`: no external IP, no Cloud NAT, egress denied except the two private endpoints,
and `blocked  attacker.example`.

**6. The private doors and the fence.** The hardened twin's two regional Private Service Connect endpoints (one per
Google host), their DNS records, and a VPC Service Controls perimeter still in dry run:

```bash
python3 explore.py endpoint hardened
```

```text
The private doors to Google APIs, hardened

  regional PSC endpoint aiplatform-eu at 10.10.0.10  serves only aiplatform.eu.rep.googleapis.com
  regional PSC endpoint bigquery-eu  at 10.10.0.11  serves only bigquery.europe-west4.rep.googleapis.com
  private DNS zone aiplatform.eu.rep.googleapis.com. (private) for helpdesk-vpc
  private DNS zone bigquery.europe-west4.rep.googleapis.com. (private) for helpdesk-vpc
      A      aiplatform.eu.rep.googleapis.com. -> 10.10.0.10
      A      bigquery.europe-west4.rep.googleapis.com. -> 10.10.0.11

The fence: VPC Service Controls
  perimeter helpdesk: DRY RUN (logs violations, blocks nothing)
    protects     projects/100000000001
    restricts    aiplatform.googleapis.com, bigquery.googleapis.com, storage.googleapis.com
    ingress rules 0, egress rules 0

Who gets past the fence? (the perimeter only; IAM still has to allow the call too)
  passes   Helpdesk VM, inside
           inside the perimeter rules
  LOGGED   a stolen token, from 203.0.113.66
           dry run, would block: ingress from 203.0.113.66 has no matching ingress rule (NO_MATCHING_ACCESS_LEVEL)
  LOGGED   Helpdesk VM copying to another project
           dry run, would block: copy to projects/999999999999, outside the perimeter (RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER)
```

`python3 explore.py endpoint` shows today: no endpoint and `no fence`.

**7. The keys.** Today there is no key of ExampleCo's own:

```bash
python3 explore.py keys
```

```text
Encryption at rest, today

  Cloud KMS keys in the plan: 0. Google encrypts everything with keys Google owns and controls,
  so there is no key of yours to disable.

What holds customer data, and whose key protects it:
  BigQuery dataset helpdesk_tickets  europe-west4  Google default encryption
```

`python3 explore.py keys hardened` shows the key ring, the key and `your key (CMEK)` on both datasets.

**8. What gets recorded.** The hardened twin:

```bash
python3 explore.py logging hardened
```

```text
What gets recorded, hardened

Cloud Audit Logs for aiplatform.googleapis.com (who called, from where; not the prompt):
  Admin Activity   always written, can't be switched off (changes: deploy, create, set policy)
  Data Access      ON: DATA_READ, DATA_WRITE

Request-response logging (what was asked and answered, per model and project):
  on, sampling 1.0 (1.0 = every call), into bq://example-chatbot-prod.ai_logs.request_response_logging

Caching (copies Google may keep to answer faster; lesson 11.3):
  not set: Google default, which includes durable caching at rest
```

`python3 explore.py logging` shows today: Data Access off and request-response logging off.

**9. Two records of one call.** Illustrative: Google's field and column names with fake values. The audit entry keeps
who, from where and which model; the request-response row keeps the conversation:

```bash
python3 explore.py record
```

```text
ILLUSTRATIVE: Google's documented field and column names, fake values. Two records of one Helpdesk call.

1. Data Access audit log entry (Cloud Logging, log cloudaudit.googleapis.com/data_access):
   who      authenticationInfo.principalEmail  chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com
   from     requestMetadata.callerIp           10.10.0.5   (the VM's internal address)
   what     methodName                         google.cloud.aiplatform.v1.PredictionService.GenerateContent
   where    resourceName                       .../locations/europe-west4/publishers/google/models/gemini-3.1-flash-lite
   allowed  authorizationInfo                  aiplatform.endpoints.predict, granted
   said     (nothing)                          the pages we read don't say audit entries hold the prompt

2. Request-response logging row (BigQuery table ai_logs.request_response_logging):
   when     logging_time                       2026-10-19 09:10:00 UTC
   what     model, api_method                  gemini-3.1-flash-lite, generateContent
   said     full_request                       "How do I reset my VPN token?"
   answered full_response                      "Open the self-service portal, choose..."
   more     request_id, endpoint, metadata...  the full column list is on Google's request-response logging page
```

**10. Read one result from the top.** Step 2's tool, first lines only. Each request gets a verdict, a `why:` line, and
one `·` line per check that decided it:

```bash
python3 attack.py --twin today | sed -n 1,8p
```

```text
--- GC11 lab · twin: today · TSG Helpdesk in example-chatbot-prod ---
    (twin.py: a teaching model of Google Cloud's rules; nothing is sent to Google)

Attackers
  [A1] ALLOWED  Stolen JSON key of chatbot-runtime, from 203.0.113.66: GenerateContent on Gemini
         why: every check passed
         · IAM: aiplatform.endpoints.predict via roles/aiplatform.user on project
  [A2] ALLOWED  Same key: deploy Llama 3 to a GPU endpoint (bills while it runs)
```

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
          fix: Remove the external IP and NAT; reach Google APIs through PSC endpoints; add an egress deny-all firewall rule with an allow for each endpoint.
  HIGH    GC11-05  google_compute_instance ticket-summariser
          AI workload reaches the internet through Cloud NAT: model calls cross the internet, and a hijacked app can post data anywhere.
          fix: Remove the external IP and NAT; reach Google APIs through PSC endpoints; add an egress deny-all firewall rule with an allow for each endpoint.
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
  MEDIUM  GC11-06  Private Service Connect
          No Private Service Connect endpoint for Google APIs.
          fix: Add a regional endpoint for each Google host the app calls (google_network_connectivity_regional_endpoint, target_google_api = the host) with a private zone for that name; or, for *.googleapis.com hosts, a PSC endpoint for global Google APIs with a private googleapis.com zone.
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
          No private path at all: Private Google Access is off and there is no PSC endpoint, so VMs without an external IP can't reach Google APIs.
          fix: Prefer PSC endpoints (GC11-06). Private Google Access is the fallback, and it doesn't cover *.rep.googleapis.com.

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
| `network.tf` | No external IPs, no Cloud NAT; a PSC endpoint for one host, `aiplatform.eu.rep.googleapis.com`, at `10.10.0.10`; a private zone for that name; egress deny-all plus an allow to `10.10.0.10:443` (the twin adds `bigquery.europe-west4.rep.googleapis.com` at `10.10.0.11` for its ticket reads) | A4, stolen tokens no longer travel the internet path, and code can't drift to the global endpoint |
| `perimeter.tf` | VPC Service Controls perimeter around the project, restricting `aiplatform`, `bigquery`, `storage`, **in dry run** (needs an organization) | logs A3 (blocks it once enforced) |
| `encryption.tf` | Cloud KMS key ring `helpdesk-eu`, key `helpdesk-data` (90-day rotation); BigQuery service account may use it; `helpdesk_tickets` and `ai_logs` with that default key | Q4 |
| `logging.tf` | `DATA_READ` and `DATA_WRITE` audit logs for `aiplatform.googleapis.com` | Q1 |
| `scripts/request_response_logging.sh` | `setPublisherModelConfig` (v1beta1), 100% sampling into `ai_logs` | Q2 |
| `twin/hardened/app.json` | `location: eu`, `endpoint_host: aiplatform.eu.rep.googleapis.com` | Q3 |

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
         · path: Private Service Connect regional endpoint 10.10.0.11 for bigquery.europe-west4.rep.googleapis.com
         · IAM: bigquery.tables.getData via roles/bigquery.dataViewer on dataset helpdesk_tickets
         · VPC Service Controls DRY RUN would block this, but only logs it: copy to projects/999999999999, outside the perimeter (RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER)
  [A4] DENIED   Prompt-injected Helpdesk posts ticket text to an attacker's HTTPS webhook
         why: network: egress firewall denies all traffic except the private endpoints
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
         calls use location 'eu', an approved EU location
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

A developer reads that the global endpoint has the best availability, and that new models often arrive there first,
and switches the Helpdesk to `aiplatform.googleapis.com` with `locations/global`:

```bash
make residency-trap
```

Same as `python3 attack.py --twin global-endpoint`.

```text
--- GC11 lab · twin: global-endpoint · TSG Helpdesk in example-chatbot-prod ---
    (twin.py: a teaching model of Google Cloud's rules; nothing is sent to Google)

Attackers
  [A1] DENIED   Stolen JSON key of chatbot-runtime, from 203.0.113.66: GenerateContent on Gemini
         why: no user-managed key exists for chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com: there is nothing to steal
  [A2] DENIED   Same key: deploy Llama 3 to a GPU endpoint (bills while it runs)
         why: no user-managed key exists for chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com: there is nothing to steal
  [A3] ALLOWED  Prompt-injected Helpdesk copies the tickets table to a project outside ExampleCo
         why: every check passed
         · path: Private Service Connect regional endpoint 10.10.0.11 for bigquery.europe-west4.rep.googleapis.com
         · IAM: bigquery.tables.getData via roles/bigquery.dataViewer on dataset helpdesk_tickets
         · VPC Service Controls DRY RUN would block this, but only logs it: copy to projects/999999999999, outside the perimeter (RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER)
  [A4] DENIED   Prompt-injected Helpdesk posts ticket text to an attacker's HTTPS webhook
         why: network: egress firewall denies all traffic except the private endpoints
  [A5] DENIED   A developer's stolen laptop session mints a token for chatbot-runtime from 203.0.113.80
         why: can't mint a token for the service account: no role grants iam.serviceAccounts.getAccessToken to user:dev1@example.com

Legitimate traffic · must keep working
  [L1] DENIED   Helpdesk VM: GenerateContent on the approved Gemini model as chatbot-runtime
         why: network: no private path to aiplatform.googleapis.com: this network's endpoints serve only aiplatform.eu.rep.googleapis.com, bigquery.europe-west4.rep.googleapis.com, and the egress firewall blocks everything else
  [L2] ALLOWED  Helpdesk VM: read ticket history from BigQuery
         why: every check passed
  [L3] ALLOWED  Analyst in the office (198.51.100.21): query the tickets dataset
         why: every check passed
         · VPC Service Controls DRY RUN would block this, but only logs it: ingress from 198.51.100.21 has no matching ingress rule (NO_MATCHING_ACCESS_LEVEL)
  [L4] DENIED   Ticket summariser VM: GenerateContent on the approved Gemini model
         why: network: no private path to aiplatform.googleapis.com: this network's endpoints serve only aiplatform.eu.rep.googleapis.com, bigquery.europe-west4.rep.googleapis.com, and the egress firewall blocks everything else

The auditor's questions
  [Q1] YES  Can we see who called Gemini, as which identity, from which IP?
         Data Access (DATA_READ) audit logs for aiplatform.googleapis.com are on
  [Q2] YES  Can we see what each prompt and answer said?
         request-response logging at 1.0 to bq://example-chatbot-prod.ai_logs.request_response_logging
  [Q3] NO   Can we show EU tickets were processed only in the EU?
         calls use location 'global': the global endpoint gives no data residency guarantee
  [Q4] YES  Can we make stored prompts and tickets unreadable in one step (disable the key)?
         every dataset has a customer-managed default key

1 of 5 attacker requests allowed; 2 of 4 legitimate requests allowed; 3 of 4 auditor questions answerable.
```

The Helpdesk and the summariser are down, and that's the network doing its job: the only Google hosts it reaches are
the two EU ones, so a drift to `global` fails loudly instead of sending tickets to any region. The real run showed the
same (lesson 11.6: `000`). Under pressure, the quickest "fix" is to open egress, and EU processing is gone. The right
fix: point the app back at `aiplatform.eu.rep.googleapis.com`. The checker's residency rule (GC11-14) catches
`global`, but nothing tells you the change also takes the Helpdesk down. That's the challenge.

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
[FAIL] challenge: GC11-16 flags the global-endpoint twin (the network has no private path to its model host)
[PASS] challenge: GC11-16 stays quiet on the today and hardened twins
[FAIL] challenge: the hardened twin no longer allows durable caching (no GC11-11)
  why test_22_perimeter_blocks_the_copy: AssertionError: True is not false : A3 is still ALLOWED: the perimeter is only in dry run
  why test_25_gc11_16_flags_unreachable_host: AssertionError: 0 != 1 : GC11-16 didn't fire on twin/global-endpoint
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
2. **Write GC11-16 (tests 25 and 26).** In `checker.py`, `rule_model_host_private_path()` should return one
   `MEDIUM` finding when the deployment has no internet route and nothing private reaches `app.json`'s
   `endpoint_host`: no regional endpoint targets it, and (for a host that isn't `*.rep.googleapis.com`) no PSC endpoint
   for global Google APIs or Private Google Access either. It must fire on `global-endpoint` and stay quiet on `today`
   and `hardened`. `d.regional_endpoint_for(host)` does most of the work.
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
| Cloud Logging | Data Access logs count toward Cloud Logging ingestion (Module 10: 50 GiB per project per month free) | $0 at lab size |
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
