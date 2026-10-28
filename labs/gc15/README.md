# Lab GC15: a private endpoint for an open model on Agent Platform

Companion to lessons **15.0 to 15.5** of the Google Cloud stream of *AI Security Engineer* (The Sec Guy). About 70
minutes for Steps 1 to 8, **$0**, all on your laptop: **Python 3.11+ only**, no packages, no Google Cloud account, no
model download. Step 9 is optional and **costs money every hour a model is deployed**:
[`GUIDED-BUILD.md`](GUIDED-BUILD.md) builds a private endpoint for a small open model on CPU in **your own** sandbox
project, with an auto-undeploy job created before the model is deployed.

You are the cloud security engineer at **ExampleCo** (fictional, on the documentation domain `example.com`). The
Helpdesk now summarises tickets with an **open-weights model** that the data science team fine-tunes. Tickets must
stay in ExampleCo's projects, so the platform team serves the model itself on **Agent Platform** (formerly Vertex AI):
a custom container on an online inference endpoint, versions in the **Model Registry**, notebooks on **Workbench**.
The pull request says "endpoint up, summaries work". That is the **first draft**. Your job: break it, then prove the
hardened version holds.

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Review the first draft: 35 findings, 15 HIGH | 15.1 to 15.4 |
| **Break** | 15 attacks and 6 normal requests: 15 of 15 attacks work, and every normal request works too | 15.2, 15.3 |
| **Files** | Scan the model files: a pickle-based weights file vs safetensors, and the hashes recorded as labels | 15.3 |
| **Harden** | The same suite against the hardened setup: 13 of 15 stopped, 6 of 6 normal requests still work | 15.2, 15.3 |
| **Hunt** | Investigate a morning of Cloud Audit Logs | 15.4 |
| **Prove** | `make test`: 20 tests | 15.5 |
| **Challenge** | Workbench org constraints, a promotion gate, a hunt query. No solution included | 15.2, 15.3, 15.4 |
| **Cloud (optional, costs money)** | [`GUIDED-BUILD.md`](GUIDED-BUILD.md): a Private Service Connect endpoint for an open model, from zero (console and gcloud), five requests, one setting changed, auto-undeploy and teardown | 15.2 to 15.4 |

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/gc15`.

## What's in this folder

| File | What it is |
|---|---|
| `setups/first-draft/` | The pull request. A shared public endpoint and no VPC Service Controls perimeter. The deployed model runs as the Compute Engine default service account, which holds Editor. Version 1 has pickle-based weights and a Hugging Face token in `containerSpec.env`, on an image by tag that Artifact Analysis flagged. A shared Workbench instance in the production project with an external IP. Data scientists with Agent Platform User and Service Account User on the whole project. A user-managed key file for the app. Every prompt logged to a dataset all staff can read |
| `setups/hardened/` | The same summariser, fixed. A Private Service Connect endpoint with a project allow-list and CMEK, an enforced perimeter, and a runtime service account with no project roles. Safetensors versions uploaded by the pipeline with sha256 and licence labels, and the image by digest. Single-user Workbench instances in a separate dev project with no external IP. `vertexai.allowedModels`, Data Access audit logs and alerts. Two gaps left on purpose: the challenge |
| `exampleco.json`, `roles.json`, `images.json` | Who is who, a subset of each role's permissions, the image catalog (lab values) |
| `twin.py` | The **offline stand-in for Agent Platform and Google Cloud**: IAM allow policies with inheritance, VPC Service Controls, what the serving container and a Workbench instance can reach, model uploads and loads, `vertexai.allowedModels`, Workbench org constraints. Read "How faithful is the twin?" below |
| `model_files.py` | Builds the lab's model files and **scans** any model folder (the lab's or a real download): file formats, pickle imports read without loading, sha256 hashes as Model Registry labels |
| `evaluate.py` | 15 attacks and 6 normal requests; prints which attacks worked AND which normal requests still work |
| `checker.py` | 30 review rules, `GC15-01` to `GC15-30` |
| `hunt.py`, `data/incident/` | Three hunting questions over Cloud Audit Logs entries, plus challenge 3 |
| `gate.py` | The promotion gate you write in challenge 2 |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 20 tests for the lab, 7 for the challenge |
| `cloud/` | Optional: `serve/` (a small CPU serving container), `requests/` (request bodies with placeholders), `cost.py` |

## Needs

- Python **3.11 or newer**: `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 9 only: the `gcloud` CLI, your own sandbox project with billing and a budget alert (GC10), and about
  2 GB free disk for the model download.

## Step 1 · Review the first draft

```bash
cd labs/gc15
make check
```

- `make check`: same as `python3 checker.py first-draft`

You should see:

```output
[HIGH  ] GC15-02 (15.1) Artifact Analysis reported 2 CRITICAL vulnerabilities in the serving image, and it still serves production
[HIGH  ] GC15-05 (15.2) no enforced VPC Service Controls perimeter restricts aiplatform.googleapis.com around the project: the serving environment keeps its default internet access, and stolen credentials work from anywhere
[HIGH  ] GC15-07 (15.2) the deployed model runs as compute-default, which holds editor on example-summariser-prod: code in the container (a pickle payload, a bug in the server) acts with all of it
[HIGH  ] GC15-09 (15.2) ds-alice may act as tsg-ci-deployer, tsg-summariser-runtime, compute-default (Service Account User): anything they start, a notebook or a deployment, can run as that account
[HIGH  ] GC15-09 (15.2) ds-bob may act as tsg-ci-deployer, tsg-summariser-runtime, compute-default (Service Account User): anything they start, a notebook or a deployment, can run as that account
[HIGH  ] GC15-10 (15.2) tsg-helpdesk-app has 1 user-managed key(s): a key file works from any laptop until someone deletes it
[HIGH  ] GC15-11 (15.2) secret-looking value in containerSpec.env (HF_TOKEN): models.get returns it to ds-alice, ds-bob, tsg-model-approver, all-staff
[HIGH  ] GC15-13 (15.2) Workbench instance tsg-ds-shared can reach the internet (the instance has a public IP address): anything a notebook can read can be uploaded
[HIGH  ] GC15-15 (15.2) Workbench instance tsg-ds-shared is shared in 'Service account' mode by ds-alice, ds-bob and runs as compute-default: everyone's code runs as one identity, and the logs can't tell who did what
[HIGH  ] GC15-18 (15.3) the summariser is on a shared public endpoint, but only an internal app calls it: use a Private Service Connect endpoint (a dedicated public endpoint doesn't support VPC Service Controls at all)
[HIGH  ] GC15-20 (15.3) the deployed version's files are not safetensors-only: pytorch_model.bin (pickle: imports builtins.print)
[HIGH  ] GC15-21 (15.3) ds-alice, ds-bob may write the folder the next release is uploaded from (gs://example-tsg-models/tsg-summariser/v3/) and the pipeline doesn't re-check hashes before models.upload: files swapped after the scan get copied into the registry
[HIGH  ] GC15-23 (15.3) ds-alice may upload, deploy, update in example-summariser-prod: a data scientist can ship and promote a model with no second pair of eyes
[HIGH  ] GC15-23 (15.3) ds-bob may upload, deploy, update in example-summariser-prod: a data scientist can ship and promote a model with no second pair of eyes
[HIGH  ] GC15-26 (15.4) request-response logging writes every prompt and answer (sampling 1.0) to a dataset group:all-staff@example.com can read: those logs are as sensitive as the tickets
[MEDIUM] GC15-01 (15.1) the serving image was built 210 days ago (ExampleCo rebuilds every 90): a fix in the inference server only reaches the endpoint when you rebuild and redeploy
[MEDIUM] GC15-04 (15.1) the serving image is pinned by tag, not by digest: the same tag can point at different bytes tomorrow
[MEDIUM] GC15-08 (15.2) the Compute Engine default service account has Editor and iam.automaticIamGrantsForDefaultServiceAccounts isn't enforced: every VM, notebook or endpoint that defaults to it inherits Editor
[MEDIUM] GC15-12 (15.2) the endpoint has no encryptionSpec: the model files used for the deployment use Google's default encryption, not a key you control
[MEDIUM] GC15-12 (15.2) the Model has no encryptionSpec: the uploaded model files use Google's default encryption, not your key
[MEDIUM] GC15-14 (15.2) Workbench instance tsg-ds-shared has root, terminal, downloads enabled (the defaults)
[MEDIUM] GC15-16 (15.2) Workbench instance tsg-ds-shared lives in the production project example-summariser-prod: experiments sit next to the production model and its data
[MEDIUM] GC15-17 (15.2) org policy doesn't enforce ainotebooks.restrictPublicIp, ainotebooks.disableRootAccess, ainotebooks.disableTerminal, ainotebooks.disableFileDownloads: today's instances are fine, but the next one anybody creates gets the defaults (challenge 1)
[MEDIUM] GC15-19 (15.3) ds-alice, ds-bob, tsg-model-approver may call predict on the production endpoint: only the Helpdesk app needs to
[MEDIUM] GC15-22 (15.3) version 1 records no file hashes: nobody can prove the files serving today are the ones that were reviewed
[MEDIUM] GC15-22 (15.3) version 1: licence not recorded (checking the licence is your job, not Google's)
[MEDIUM] GC15-24 (15.3) no vertexai.allowedModels policy: any Model Garden model can be deployed (Google: with no policy, all models and actions are allowed)
[MEDIUM] GC15-25 (15.3) no promotion gate: nothing checks formats, hashes, licence and reviewer before the prod alias moves (challenge 2)
[MEDIUM] GC15-26 (15.4) the request-response log dataset isn't encrypted with your key
[MEDIUM] GC15-27 (15.4) Data Access audit logs are off for aiplatform.googleapis.com (the default): predict calls leave no audit record
[MEDIUM] GC15-29 (15.4) the inference server prints prompts to stdout, and container logging sends stdout to Cloud Logging: ticket text sits in logs most engineers can read
[LOW   ] GC15-03 (15.4) the image hasn't been pulled for more than 30 days: Artifact Analysis stops updating its results, so 'no new findings' means nothing
[LOW   ] GC15-28 (15.4) access logging is off on the deployed model (the default): no per-request timestamp and latency in Cloud Logging
[LOW   ] GC15-29 (15.4) no alerts on predict volume, errors or deploys outside the pipeline
[LOW   ] GC15-30 (15.4) the monitoring plan relies on Model Monitoring, which tracks feature drift for tabular models: it won't tell you a summariser is leaking or being abused

15 HIGH, 16 MEDIUM, 4 LOW  (35 findings)
```

Every rule names its lesson. Read the HIGH ones first: they're the ones an attacker uses in Step 2.

## Step 2 · Attack the first draft

```bash
make attack
```

Same as `python3 evaluate.py first-draft`.

```output
  A1   WORKED   Booby-trapped model file: the weights are a pickle, and loading it runs code in the container
         . serves version 1 from the copy made at upload
         . container: loading pytorch_model.bin ran builtins.print (LAB-PLACEHOLDER: a real payload runs here)
  A2   WORKED   Swap after the scan: a data scientist changes the release folder before models.upload copies it
         . ds-bob writes into gs://example-tsg-models/tsg-summariser/v3/ after the pipeline scanned it: allowed (storage.objectAdmin on the bucket example-tsg-models)
         . models.upload copied the folder as it was at upload time
         . the registry now holds config.json, model.safetensors, pytorch_model.bin, tokenizer.json: a pickle the scan never saw
  A3   WORKED   Unreviewed model to production: a hotfix uploaded and deployed straight from a notebook
         . ds-bob models.upload a hotfix from gs://example-tsg-models/bob/experiment/ in example-summariser-prod: allowed (aiplatform.user on the project example-summariser-prod)
         . ds-bob endpoints.deploy a hotfix from gs://example-tsg-models/bob/experiment/ in example-summariser-prod: allowed (aiplatform.user on the project example-summariser-prod)
         . ds-bob acts as the deployed model's service account: allowed (iam.serviceAccountUser on the project example-summariser-prod)
  A4   WORKED   Self-promotion: the author moves the prod alias onto their own version
         . ds-bob moves the prod alias onto version 2, which he trained himself: allowed (aiplatform.user on the project example-summariser-prod)
  A5   WORKED   Data out of the container: code in the serving container posts tickets to the internet
         . code in the serving container posts a ticket to https://collector.example.net: sent (no enforced perimeter: the managed environment keeps its default internet access)
  A6   WORKED   Container identity: code in the container reads another team's bucket
         . code in the container reads the analytics team's export as compute-default: allowed (editor on the project example-summariser-prod)
  A7   WORKED   Leaked key file: predict from the internet with the app's service account key
         . the app's leaked key file, used from 203.0.113.50 on the internet: allowed (aiplatform.user on the project example-summariser-prod)
  A8   WORKED   Prompt logs for everyone: request-response logs in a dataset all staff can read
         . ds-bob reads yesterday's prompts and summaries in bq://example-summariser-prod.analytics_shared.summariser_requests: allowed (all-staff can read the dataset)
  A9   WORKED   Shared notebook identity: a notebook running as the default service account changes production
         . from his notebook (running as compute-default), ds-bob deploys a model to the production endpoint: allowed (editor on the project example-summariser-prod)
  A10  WORKED   Notebook exfiltration: a Workbench instance uploads data to the internet
         . a notebook uploads a ticket export to https://collector.example.net: sent (the instance has a public IP address)
  A11  WORKED   actAs escalation: a data scientist runs a notebook as the pipeline's service account
         . ds-bob acts as tsg-ci-deployer: allowed (iam.serviceAccountUser on the project example-summariser-prod)
         . ds-bob creates a Workbench instance that runs as it: allowed (notebooks.admin on the project example-summariser-prod)
         . as the pipeline, he writes the release folder: allowed (storage.objectAdmin on the bucket example-tsg-models)
  A12  WORKED   Secret in the model: models.get shows the Hugging Face token
         . ds-bob calls models.get and reads HF_TOKEN from containerSpec.env: allowed (aiplatform.user on the project example-summariser-prod)
  A13  WORKED   Unvetted Model Garden model: an open model nobody reviewed is deployed
         . ds-alice deploys publishers/hf-someone/models/fast-summariser-7b from Model Garden in example-summariser-prod: allowed (aiplatform.user on the project example-summariser-prod)
         . org policy: allowed (no vertexai.allowedModels policy: all models and actions are allowed)
  A14  WORKED   Defaults come back: a new Workbench instance with external IP, root, terminal and downloads
         . ds-bob creates 'bob-quick' with the console defaults (external IP, root, terminal, downloads): allowed (notebooks.admin on the project example-summariser-prod)
         . no ainotebooks.* constraint is enforced: the instance is created
  A15  WORKED   Promotion in a hurry: the ML lead promotes a version that fails every check
         . the ML lead moves the prod alias onto version 2 in a hurry (pickle weights, no licence, no hashes): allowed (aiplatform.user on the project example-summariser-prod)
         . no promotion gate: the alias moves, and the pipeline's next deploy of tsg-summariser@prod serves version 2

  N1   works    The Helpdesk gets a ticket summary
  N2   works    The pipeline uploads and deploys a release
  N3   works    The ML lead promotes a clean version
  N4   works    A data scientist opens her own notebook
  N5   works    A data scientist evaluates the approved base model
  N6   works    The endpoint starts

Attacks that worked: 15 of 15  (A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15)   |   normal requests that work: 6 of 6
```

Fifteen attacks work, and so does every normal request. That's why the first draft shipped: nothing a user does
looks wrong. Run `python3 evaluate.py first-draft -v` to see every step of every case.

Two questions to the twin show where the first draft's trust really sits:

```bash
python3 twin.py container first-draft
python3 twin.py decide first-draft tsg-helpdesk-app aiplatform.endpoints.predict --from internet
```

```output
{
  "endpoint_kind": "shared-public",
  "container": {
    "internet": true,
    "identity": "compute-default",
    "why": "no enforced perimeter: the managed environment keeps its default internet access"
  },
  "workbench": {
    "tsg-ds-shared": {
      "internet": true,
      "why": "the instance has a public IP address"
    }
  }
}
ALLOW: aiplatform.user on the project example-summariser-prod
```

## Step 3 · Look at the model files

```bash
make scan
```

- `make scan`: builds artifacts/, then scans version 1 (first draft) and version 3 (hardened)

```output
[OK  ] config.json                  data         
[STOP] pytorch_model.bin            pickle       pickle-based weights (code can run when a loader unpickles it)  imports: builtins.print
[OK  ] tokenizer.json               data         

verdict: DO NOT SHIP (1 file(s) to fix)
[OK  ] config.json                  data         
[OK  ] model.safetensors            safetensors  
[OK  ] tokenizer.json               data         

verdict: SAFE FORMATS ONLY
```

The scanner never loads a file: it reads pickle opcodes with Python's `pickletools`, which only parses. The lab's
pickle is a **placeholder**: if anything did unpickle it, its only effect would be to print one line. Then print the
hashes the pipeline records as labels on a new version:

```bash
python3 model_files.py manifest artifacts/v4-safe
```

```output
{
  "sha256-config_json": "868bbc0cf24d7065e5d606c8f519af00e5ed068ccaf8b1a10bb64a32c498e5f0",
  "sha256-model_safetensors": "854cc1147ef708ee71ba6957304d8982d95b229aba8b80dd103c9832fd2fac9d",
  "sha256-tokenizer_json": "ea991de3c734d41384ad6b47bf781c803c1550b381b435823b9232ec03ee380d"
}
```

Model Registry label keys and values can be up to 64 characters, lowercase letters, digits, `_` and `-`, so one hex
sha256 fits in one label value and the file name becomes the key.

## Step 4 · The hardened setup

```bash
make check-hardened
make hardened
```

- `make check-hardened`: same as `python3 checker.py hardened`
- `make hardened`: same as `python3 evaluate.py hardened`

```output
[MEDIUM] GC15-17 (15.2) org policy doesn't enforce ainotebooks.restrictPublicIp, ainotebooks.disableRootAccess, ainotebooks.disableTerminal, ainotebooks.disableFileDownloads: today's instances are fine, but the next one anybody creates gets the defaults (challenge 1)
[MEDIUM] GC15-25 (15.3) no promotion gate: nothing checks formats, hashes, licence and reviewer before the prod alias moves (challenge 2)

0 HIGH, 2 MEDIUM, 0 LOW  (2 findings)
```

```output
  A1   blocked  Booby-trapped model file: the weights are a pickle, and loading it runs code in the container
         . no pickle-based weights: nothing ran at load
  A2   blocked  Swap after the scan: a data scientist changes the release folder before models.upload copies it
         . ds-bob writes into gs://example-tsg-models/tsg-summariser/v4/ after the pipeline scanned it: DENIED (no role with storage.objects.create on the bucket or its project)
  A3   blocked  Unreviewed model to production: a hotfix uploaded and deployed straight from a notebook
         . ds-bob models.upload a hotfix from gs://example-tsg-models/bob/experiment/ in example-summariser-prod: DENIED (no role with aiplatform.models.upload on the model or its project)
  A4   blocked  Self-promotion: the author moves the prod alias onto their own version
         . ds-bob moves the prod alias onto version 2, which he trained himself: DENIED (no role with aiplatform.models.update on the model or its project)
  A5   blocked  Data out of the container: code in the serving container posts tickets to the internet
         . code in the serving container posts a ticket to https://collector.example.net: blocked (inside an enforced VPC Service Controls perimeter: the managed environment's default internet access is blocked)
  A6   blocked  Container identity: code in the container reads another team's bucket
         . code in the container reads the analytics team's export as tsg-summariser-runtime: DENIED (no role with storage.objects.get on the bucket or its project)
  A7   blocked  Leaked key file: predict from the internet with the app's service account key
         . tsg-helpdesk-app has no user-managed keys: there is no key file to steal
  A8   blocked  Prompt logs for everyone: request-response logs in a dataset all staff can read
         . ds-bob reads yesterday's prompts and summaries in bq://example-summariser-prod.summariser_audit.requests: DENIED (not a reader of the dataset)
  A9   blocked  Shared notebook identity: a notebook running as the default service account changes production
         . from his notebook (running as tsg-ds-runtime), ds-bob deploys a model to the production endpoint: DENIED (no role with aiplatform.endpoints.deploy on the endpoint or its project)
  A10  blocked  Notebook exfiltration: a Workbench instance uploads data to the internet
         . a notebook uploads a ticket export to https://collector.example.net: blocked (no public IP and no Cloud NAT: no route to the internet)
  A11  blocked  actAs escalation: a data scientist runs a notebook as the pipeline's service account
         . ds-bob acts as tsg-ci-deployer: DENIED (no role with iam.serviceAccounts.actAs on the sa or its project)
  A12  blocked  Secret in the model: models.get shows the Hugging Face token
         . the deployed version's containerSpec.env holds no secrets
  A13  blocked  Unvetted Model Garden model: an open model nobody reviewed is deployed
         . org policy: DENIED (not on the vertexai.allowedModels list)
  A14  WORKED   Defaults come back: a new Workbench instance with external IP, root, terminal and downloads
         . ds-bob creates 'bob-quick' with the console defaults (external IP, root, terminal, downloads): allowed (notebooks.admin on the project example-summariser-dev)
         . no ainotebooks.* constraint is enforced: the instance is created
  A15  WORKED   Promotion in a hurry: the ML lead promotes a version that fails every check
         . the ML lead moves the prod alias onto version 2 in a hurry (pickle weights, no licence, no hashes): allowed (tsgModelApprover on the project example-summariser-prod)
         . no promotion gate: the alias moves, and the pipeline's next deploy of tsg-summariser@prod serves version 2

  N1   works    The Helpdesk gets a ticket summary
  N2   works    The pipeline uploads and deploys a release
  N3   works    The ML lead promotes a clean version
  N4   works    A data scientist opens her own notebook
  N5   works    A data scientist evaluates the approved base model
  N6   works    The endpoint starts

Attacks that worked: 2 of 15  (A14, A15)   |   normal requests that work: 6 of 6
```

Ask the twin the same questions again:

```bash
python3 twin.py container hardened
python3 twin.py decide hardened tsg-helpdesk-app aiplatform.endpoints.predict --from internet
python3 twin.py decide hardened tsg-helpdesk-app aiplatform.endpoints.predict --from vpc
```

```output
{
  "endpoint_kind": "psc",
  "container": {
    "internet": false,
    "identity": "tsg-summariser-runtime",
    "why": "inside an enforced VPC Service Controls perimeter: the managed environment's default internet access is blocked"
  },
  "workbench": {
    "alice-wb": {
      "internet": false,
      "why": "no public IP and no Cloud NAT: no route to the internet"
    },
    "bob-wb": {
      "internet": false,
      "why": "no public IP and no Cloud NAT: no route to the internet"
    }
  }
}
DENY: VPC Service Controls: request from outside the perimeter tsg_ai
ALLOW: tsgPredictOnly on the endpoint
```

**What stopped what**, one line each: A1 safetensors-only versions; A2 a release bucket only the pipeline writes, plus
a hash check before `models.upload`; A3 and A4 data scientists hold no roles in production; A5 the perimeter blocks
the serving environment's default internet access; A6 a runtime service account with no project roles; A7 no
user-managed keys (and the perimeter would stop one from the internet anyway); A8 a request-response sample in a
dataset only the platform admin reads; A9 and A11 single-user instances that run as a dev-only service account, and
`actAs` only on that account; A10 no external IP and no Cloud NAT; A12 no secrets in `containerSpec.env`; A13
`vertexai.allowedModels`.

## Step 5 · Hunt

```bash
make hunt
```

Same as `python3 hunt.py`.

```output
Q1. Uploads and deploys not made by the pipeline
   2027-01-28T09:12:40Z  UploadModel  by ds-bob    gs://example-tsg-models/bob/experiment/
   2027-01-28T09:16:30Z  DeployModel  by ds-bob    projects/example-summariser-prod/locations/us-central1/models/tsg-summariser@prod

Q2. Self-promotion: prod alias moved by the principal who uploaded that version
   2027-01-28T09:14:03Z  version 5 promoted to prod by ds-bob, who uploaded it

Q3. New user-managed service account keys
   2027-01-28T10:40:22Z  ds-bob created a key for tsg-helpdesk-app: 1f2e3d4c5b6a79880000lab

Q4. Predict calls from outside ExampleCo's network (challenge 3)
   not written yet: challenge 3: write find_outside_predictions()
```

The story: two days after ExampleCo turned on Data Access audit logs for `aiplatform.googleapis.com`, before the
perimeter was enforced, Bob uploads his experiment as version 5, moves `prod` onto it himself and deploys it, then
creates a key file for the Helpdesk app's service account. Q1 to Q3 use Admin Activity audit logs, which are always
written. Q4 is yours (challenge 3).

## Step 6 · Break the hardened setup on purpose

Google says endpoints "must be created after the project is added to the service perimeter", and deploying to one
created before "will fail". Open `setups/hardened/endpoint.json`, change `"_created": "2027-01-12"` to
`"_created": "2027-01-05"` (before the perimeter's `_enforced_since`), then:

```bash
make hardened
```

The attack lines don't change. The normal requests do (the end of the output):

```output
  N1   BROKEN   The Helpdesk gets a ticket summary
         . the Helpdesk asks for a ticket summary (psc path, from ExampleCo's VPC): allowed (tsgPredictOnly on the endpoint); endpoint: the endpoint was created on 2027-01-05, before the project joined the perimeter on 2027-01-10: deploying to it fails
  N2   works    The pipeline uploads and deploys a release
  N3   works    The ML lead promotes a clean version
  N4   works    A data scientist opens her own notebook
  N5   works    A data scientist evaluates the approved base model
  N6   BROKEN   The endpoint starts
         . the endpoint starts and loads its model: the endpoint was created on 2027-01-05, before the project joined the perimeter on 2027-01-10: deploying to it fails

Attacks that worked: 2 of 15  (A14, A15)   |   normal requests that work: 4 of 6
```

Put the date back to `2027-01-12` before you go on. The lesson: perimeter first, endpoint second.

## Step 7 · Prove it

```bash
make test
```

Same as `python3 run_tests.py`.

```output
[PASS] first draft: 35 findings, 15 HIGH (perimeter, identities, keys, notebooks, public endpoint, pickle, prompt logs)
[PASS] hardened: 0 HIGH; only the two challenge findings are left (GC15-17 Workbench constraints, GC15-25 promotion gate)
[PASS] first draft: 15 of 15 attacks work, and 6 of 6 normal requests work (that's why it shipped)
[PASS] hardened: only A14 and A15 still work (the challenge), and 6 of 6 normal requests still work
[PASS] scanner: the pickle's builtins.print import is flagged; the PyTorch import on the allow-list is not
[PASS] scanner: works with pickle.load and pickle.loads disabled (it only parses opcodes)
[PASS] hashes: version 3's files match its sha256-* labels; a swapped folder does not; every label fits in 64 characters
[PASS] registry: models.upload copies the folder at upload time; a hash check before upload refuses a swap (A2)
[PASS] VPC-SC: inside an enforced perimeter the serving environment has no internet; without one it does
[PASS] VPC-SC: an endpoint created before the project joined the perimeter can't take a deployment (Google)
[PASS] VPC-SC: even with a leaked key file, predict from the internet is denied by the perimeter; from the VPC it works
[PASS] identity: the deployed model's serviceAccount decides what the container can reach; hardened has no project roles
[PASS] IAM: a project binding applies to every bucket, model and endpoint in it; a resource binding only to that resource
[PASS] Workbench: an external IP reaches the internet; no IP and no NAT doesn't; enforced constraints refuse the defaults
[PASS] vertexai.allowedModels: no policy allows everything; an allow list allows only its entries; deny wins
[PASS] 15.4: prompt logs readable by all staff, Data Access logs off, access logging off, prompts in container logs: all flagged
[PASS] checker: exits 1 on any HIGH finding (so it can fail a pipeline), 0 on the hardened setup
[PASS] hunt: finds Bob's upload and deploy, his self-promotion of version 5 and the key he made for the app
[PASS] hunt: Predict entries are in the data_access log, every other entry in activity
[PASS] safety: the lab's token is a labelled placeholder, and the lab's pickle only names builtins.print
----------------------------------------------------------------------
Ran 20 tests in 0.030s

OK

ALL TESTS PASSED (20 run)
```

## Step 8 · Challenge (no solution included)

```bash
make challenge
```

Same as `python3 run_tests.py --challenge`.

Before you start, 6 of 27 fail (test 22 is a guard that already passes):

```output
[PASS] first draft: 35 findings, 15 HIGH (perimeter, identities, keys, notebooks, public endpoint, pickle, prompt logs)
[PASS] hardened: 0 HIGH; only the two challenge findings are left (GC15-17 Workbench constraints, GC15-25 promotion gate)
[PASS] first draft: 15 of 15 attacks work, and 6 of 6 normal requests work (that's why it shipped)
[PASS] hardened: only A14 and A15 still work (the challenge), and 6 of 6 normal requests still work
[PASS] scanner: the pickle's builtins.print import is flagged; the PyTorch import on the allow-list is not
[PASS] scanner: works with pickle.load and pickle.loads disabled (it only parses opcodes)
[PASS] hashes: version 3's files match its sha256-* labels; a swapped folder does not; every label fits in 64 characters
[PASS] registry: models.upload copies the folder at upload time; a hash check before upload refuses a swap (A2)
[PASS] VPC-SC: inside an enforced perimeter the serving environment has no internet; without one it does
[PASS] VPC-SC: an endpoint created before the project joined the perimeter can't take a deployment (Google)
[PASS] VPC-SC: even with a leaked key file, predict from the internet is denied by the perimeter; from the VPC it works
[PASS] identity: the deployed model's serviceAccount decides what the container can reach; hardened has no project roles
[PASS] IAM: a project binding applies to every bucket, model and endpoint in it; a resource binding only to that resource
[PASS] Workbench: an external IP reaches the internet; no IP and no NAT doesn't; enforced constraints refuse the defaults
[PASS] vertexai.allowedModels: no policy allows everything; an allow list allows only its entries; deny wins
[PASS] 15.4: prompt logs readable by all staff, Data Access logs off, access logging off, prompts in container logs: all flagged
[PASS] checker: exits 1 on any HIGH finding (so it can fail a pipeline), 0 on the hardened setup
[PASS] hunt: finds Bob's upload and deploy, his self-promotion of version 5 and the key he made for the app
[PASS] hunt: Predict entries are in the data_access log, every other entry in activity
[PASS] safety: the lab's token is a labelled placeholder, and the lab's pickle only names builtins.print
[FAIL] challenge 1: a new instance with the console defaults breaks four enforced constraints (A14 blocked)
[PASS] challenge 1: alice-wb and bob-wb still comply, and Alice can still open hers (N4)
[FAIL] challenge 2: version 2 is refused, with a reason for the pickle file, the missing licence and the missing hashes
[FAIL] challenge 2: clean version 4 passes for the ML lead; refused for its trainer, for the uploader, or with a swapped file
[FAIL] challenge 2: "approval_gate": true in setups/hardened/app.json; A15 blocked and N3 (clean promotion) still works
[ERROR] challenge 3: three Predict calls from 203.0.113.50 with the app's new key, none from ExampleCo's network
[FAIL] all three: the hardened setup has 0 findings, 0 of 15 attacks work, 6 of 6 normal requests work
  why test_21_defaults_refused: AssertionError: 'restrictPublicIp' not found in ''
  why test_23_gate_refuses_version_2: AssertionError: 'pytorch_model.bin' not found in ''
  why test_24_gate_passes_a_clean_version_only: AssertionError: [] is not true
  why test_25_gate_is_switched_on: AssertionError: False is not true
  why test_27_everything: Diff is 685 characters long. Set self.maxDiff to None to see it.
  why test_26_outside_predictions: NotImplementedError: challenge 3: write find_outside_predictions()
----------------------------------------------------------------------
Ran 27 tests in 0.032s

FAILED (failures=5, errors=1)

6 of 27 TESTS FAILED (27 run)
```

1. **15.2, Workbench constraints.** In `setups/hardened/orgpolicy.json`, enforce the constraints that refuse a new
   instance with the console defaults (A14), without breaking `alice-wb` and `bob-wb`.
2. **15.3, the promotion gate.** Write `check_before_promotion()` in `gate.py` (formats, hashes, licence, and a
   promoter who is neither the trainer nor the uploader), then set `"approval_gate": true` in
   `setups/hardened/app.json` (A15).
3. **15.4, the hunt.** Write `find_outside_predictions()` in `hunt.py`: the Predict entries whose
   `requestMetadata.callerNetwork` isn't ExampleCo's VPC. Report the caller IP and the
   `authenticationInfo.serviceAccountKeyName`.

When all three are right, `make check-hardened` prints 0 findings and `make hardened` prints 0 of 15.

## Step 9 · Optional: build it in your sandbox project (costs money)

[`GUIDED-BUILD.md`](GUIDED-BUILD.md): a CPU-only custom container serving a small open model you download, scan and
upload yourself, on a **Private Service Connect** endpoint with a dedicated service account, CMEK, access logging and
Data Access audit logs, and a **Cloud Scheduler job that undeploys the model 60 minutes after you deploy it**,
created first. `make cost` prints the hourly cost from the list prices we read; `make cloud-down` deletes everything.

## How faithful is the twin?

| Behaviour | Twin | Google source |
|---|---|---|
| Inside an enforced perimeter, "all public internet access to your Agent Platform instance is automatically blocked". The serving environment "has its default internet access blocked". The perimeter "blocks access from Agent Platform to third-party APIs and services on the internet" | Same | [VPC Service Controls with Agent Platform](https://docs.cloud.google.com/gemini-enterprise-agent-platform/machine-learning/general/vpc-service-controls) |
| Outside a perimeter the serving container can reach the internet | **Twin choice**, inferred from "default internet access" on the same page | same page |
| Endpoints created before the project joined the perimeter can't take a deployment | Same | same page |
| The deployed model runs as `deployedModel.serviceAccount`; without one, a service account Agent Platform manages that can read the model artifacts ("Do not rely on the service account to have any other permissions") | Same | [Custom service account](https://docs.cloud.google.com/vertex-ai/docs/general/custom-service-account) |
| The container serves "a copy of your model artifact directory" made when the `Model` is created | Same: a swap after upload doesn't reach the copy; a swap before upload does | [Custom container requirements](https://docs.cloud.google.com/vertex-ai/docs/predictions/custom-container-requirements) |
| IAM allow policies are inherited from the project to its resources; groups contain members; deploying as a service account needs `iam.serviceAccounts.actAs` | Same, for the roles in `roles.json` (a subset of each role). No deny policies, no conditions, no folders | [Access control](https://docs.cloud.google.com/vertex-ai/docs/general/access-control) |
| `vertexai.allowedModels`: no policy allows everything, deny wins, only Model Garden models are covered | Same | [Control model access](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/control-model-access) |
| Workbench: an external IP by default; root, terminal and downloads enabled by default; the `ainotebooks.*` constraints refuse non-compliant instances | Same for the four boolean constraints and `accessMode` | [Create an instance](https://docs.cloud.google.com/vertex-ai/docs/workbench/instances/create), [metadata](https://docs.cloud.google.com/vertex-ai/docs/workbench/instances/manage-metadata), [best practices](https://docs.cloud.google.com/docs/security/security-best-practices-catalog/tools-inference) |
| A VM with no external IP and no Cloud NAT can't reach the internet | **Twin choice** (ordinary VPC routing; Private Google Access only reaches Google APIs) | - |
| Moving an alias (`mergeVersionAliases`) needs `aiplatform.models.update` | **Twin choice**: the method page names no permission | [mergeVersionAliases](https://docs.cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.models/mergeVersionAliases) |
| What a framework does with a pickle-based weights file | **Twin choice:** the worst case (it unpickles it) | not documented (it varies by framework and version) |

The audit log entries in `data/incident/` follow the field names of Google's
[AuditLog reference](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)
(`authenticationInfo.serviceAccountKeyName`, `requestMetadata.callerIp`, `requestMetadata.callerNetwork`); the values
are ours, and `response._lab_version_id` is a lab simplification.

## Troubleshooting

- `python3: command not found` or a syntax error: you need Python 3.11+. On Windows use `py -3` instead of `python3`.
- `make: command not found` (Windows): run the `python3 ...` command shown next to each `make` line.
- Challenge tests still fail after you edited a JSON file: check it's still valid JSON (`python3 -m json.tool setups/hardened/orgpolicy.json`).
- You changed a setup and `make test` fails: `make test` pins the shipped hardened setup only for the challenge
  files. Undo other edits (`git checkout setups/`).
