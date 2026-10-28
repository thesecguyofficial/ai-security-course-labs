# Lab AZ15: a private endpoint for an open model on Azure Machine Learning

Companion to lessons **15.0 to 15.5** of *AI Security Engineer* (The Sec Guy), Azure stream. About 70 minutes for
Steps 1 to 8, **$0**, all on your laptop: **Python 3.11+ only**, no packages, no Azure subscription, no model download.
Step 9 is optional and **costs money every hour**: [`GUIDED-BUILD.md`](GUIDED-BUILD.md) builds a private endpoint for
an open model in **your own** sandbox subscription, with an auto-teardown timer created before the endpoint.

You are the cloud security engineer at **Contoso** (fictional; "Contoso" is the placeholder name Microsoft uses in its
documentation). The TSG Helpdesk now summarises tickets with an **open-weights model** that the data science team
fine-tunes. Tickets must stay in Contoso's subscription, so the platform team hosts the model on an
**Azure Machine Learning managed online endpoint** instead of calling Foundry Models. Data scientists work in a dev
workspace, production runs in another, and a **registry** exists but nobody uses it yet. The pull request says
"endpoint up, summaries work". That is the **first draft**. Your job: break it, then prove the hardened version holds.

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Review the first draft: 31 findings, 15 HIGH | 15.1 to 15.4 |
| **Break** | 15 attacks and 6 normal requests: 15 of 15 attacks work, and every normal request works too | 15.2, 15.3 |
| **Files** | Scan the model files: a pickle-based weights file vs safetensors, and the hashes recorded as tags | 15.3 |
| **Harden** | The same suite against the hardened setup: 13 of 15 stopped, 6 of 6 normal requests still work | 15.2, 15.3 |
| **Hunt** | Investigate a morning of Activity Log and endpoint traffic log rows | 15.4 |
| **Prove** | `make test`: 21 tests | 15.5 |
| **Challenge** | Azure Policy in Deny, a promotion gate, a hunt query. No solution included | 15.2, 15.3, 15.4 |
| **Cloud (optional, costs money)** | [`GUIDED-BUILD.md`](GUIDED-BUILD.md): a private endpoint for an open model, from zero (CLI, plus studio clicks), five requests, one setting changed, auto-teardown and teardown | 15.2 to 15.4 |

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/az15`.

## What's in this folder

| File | What it is |
|---|---|
| `setups/first-draft/` | The pull request. Production workspace in **allow internet outbound** mode with public access on; the dev workspace in approved-outbound mode but with FQDN rules for Hugging Face and PyPI. The endpoint uses **key** auth with public access on, a system-assigned identity with Storage Blob Data Reader on the whole subscription, a vLLM image from Docker Hub by `:latest`, a Hugging Face token in `environment_variables`, pickle-based weights, and Bob's `debug` deployment at 0% traffic. Data scientists hold AzureML Data Scientist on production and can write its storage. A datastore with an account key. Releases deploy whatever is tagged `stage=Prod` |
| `setups/hardened/` | The fixed version. Both workspaces in approved-outbound mode with **no FQDN rules**, private endpoints, public access off and a customer-managed key. `aad_token` auth, public access off, a user-assigned endpoint identity that reads only the registry's storage. Deployments only from `contoso-ml-registry`, promoted by the approvers, safetensors with sha256 tags the deploy step checks, and an Azure Policy that denies other registries. Identity-based datastores, no secrets, scoped custom roles, logs and alerts on |
| `*/workspace.json`, `endpoint.json`, `deployments.json`, `models.json` | What `az ml workspace show`, `az ml online-endpoint show`, `az ml online-deployment show` and `az ml model show` return, cut to the security settings. Keys that start with `_` are lab notes |
| `*/rbac.json`, `policy.json`, `datastores.json`, `monitoring.json`, `app.json` | Role assignments and custom roles; Azure Policy assignments with the built-in rules copied from the Azure/azure-policy repo; datastores; what is logged and alerted; how the team runs it |
| `setups/hardened/policy-challenge.json` | Where your challenge 1 assignments go |
| `contoso.json`, `environments.json` | The lab's facts (people, object IDs, the standard) and its environment catalog (fictional versions and dates) |
| `twin.py` | The **offline stand-in for Azure Machine Learning**: Azure RBAC, a subset of Azure Policy, the managed VNet's three modes, inbound flags, endpoint auth and routing, model loading. Read "How faithful is the twin?" below |
| `model_files.py` | Builds the lab's model files and **scans** any model folder (the lab's or a real download): file formats, pickle imports read without loading, sha256 hashes |
| `evaluate.py` | 15 attacks and 6 normal requests; prints which attacks worked AND which normal requests still work |
| `checker.py` | 28 review rules, `AZ15-01` to `AZ15-28` |
| `hunt.py`, `data/incident/` | Three hunting questions over Activity Log and endpoint traffic log rows, plus challenge 3 |
| `gate.py` | The promotion gate you write in challenge 2 |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 21 tests for the lab, 8 for the challenge |
| `data/policy-definitions/` | One more built-in policy rule, used by a test |
| `cloud/` | Optional: `cloud.sh` (the guided build's commands), `endpoint.yml`, `deployment.yml`, `teardown-timer.json` (the Logic App that deletes the endpoint), `scorer-role.json`, `request.json` |

## Needs

- Python **3.11 or newer**: `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 9 only: the Azure CLI with the `ml` extension, your own sandbox subscription (lesson 0.7) with a
  budget alert, and quota for one small CPU VM for managed online endpoints.

## Step 1 · Review the first draft

```bash
cd labs/az15
make setup
make check
```

- `make setup`: checks your Python, installs nothing
- `make check`: same as `python3 checker.py first-draft`

You should see (long lines cut here):

```output
[HIGH  ] AZ15-01 (15.1) deployment 'blue' runs docker.io/vllm/vllm-openai:latest: a public image by a moving tag. ...
[HIGH  ] AZ15-03 (15.2) workspace tsg-ml managed network is 'AllowInternetOutbound': code in deployments and notebooks can send data to the internet
[HIGH  ] AZ15-05 (15.2) workspace tsg-ml has public network access enabled: a stolen token works from anywhere
[HIGH  ] AZ15-05 (15.2) workspace tsg-ml-dev has public network access enabled: a stolen token works from anywhere
[HIGH  ] AZ15-06 (15.2) endpoint tsg-summariser has public_network_access enabled (the default): scoring requests are accepted from the internet
[HIGH  ] AZ15-07 (15.2) endpoint identity tsg-summariser-sai has Storage Blob Data Reader at sub: anything in the container can use it far beyond the model's own files
[HIGH  ] AZ15-08 (15.2) datastore tsg-ml/ticket_exports stores a credential (account_key) in the workspace key vault: other workspace users with enough permissions can retrieve it
[HIGH  ] AZ15-09 (15.2) secret-looking value in deployment 'blue' environment_variables (HF_TOKEN): Microsoft says secrets in the deployment definition are exposed there
[HIGH  ] AZ15-11 (15.3) endpoint tsg-summariser uses auth_mode 'key': keys don't expire, need no role to use, and the traffic log records no identity
[HIGH  ] AZ15-12 (15.3) ds-alice, ds-bob, tsg-ci-deployer, tsg-reporting can call listKeys on tsg-summariser: anyone holding a key can call the endpoint, no role needed
[HIGH  ] AZ15-13 (15.3) ds-alice, ds-bob can write production deployments: a model can go from a notebook to the live endpoint without review
[HIGH  ] AZ15-14 (15.3) deployment 'blue' runs workspace model tsg-summariser:1, not a version promoted into contoso-ml-registry: nobody's approval is part of what runs
[HIGH  ] AZ15-15 (15.3) the release process deploys by tag ('deploy the newest version tagged stage=Prod from tsg-ml'): tags are writable by anyone who can write the model, including its author
[HIGH  ] AZ15-16 (15.3) the deployed model files are not safetensors-only: pytorch_model.bin (pickle: imports builtins.print)
[HIGH  ] AZ15-17 (15.3) ds-alice, ds-bob may overwrite the files the deployment loads (storage:sttsgml/azureml-blobstore/models/tsg-summariser/1/): ...
[MEDIUM] AZ15-02 (15.1) deployment 'debug' pins curated environment version 9 (2026-10-06); version 14 (2027-01-19) is out. Patched images get a new version: nothing updates yours
[MEDIUM] AZ15-04 (15.2) workspace tsg-ml-dev has FQDN outbound rules (huggingface.co, *.huggingface.co, pypi.org, *.pythonhosted.org): they deploy a billed Azure Firewall (Standard), ...
[MEDIUM] AZ15-18 (15.3) no file hashes recorded on the deployed version, or the deploy step doesn't compare them: nobody can prove the files running are the ones approved
[MEDIUM] AZ15-18 (15.3) licence not recorded on the deployed version: Microsoft says complying with a model's licence terms is your job
[MEDIUM] AZ15-19 (15.3) deployment(s) debug at 0% traffic on the production endpoint: the azureml-model-deployment header still routes to them
[MEDIUM] AZ15-20 (15.3) no Azure Policy denies registry models from outside contoso-ml-registry: a catalog or Hugging Face model can be deployed straight from its public registry
[MEDIUM] AZ15-21 (15.3) model files are not scanned in CI before registration and Defender's AI model security scans once a week, after the upload
[MEDIUM] AZ15-22 (15.3) no promotion gate: nothing checks formats, hashes, licence and who registered it before a version is approved (challenge 2)
[MEDIUM] AZ15-23 (15.2) no Azure Policy in Deny for the managed network mode and public network access: an admin's quick test can still create an open workspace (challenge 1)
[MEDIUM] AZ15-24 (15.4) no diagnostic setting sends AmlOnlineEndpointTrafficLog for tsg-summariser to Log Analytics: no record of who called which deployment
[MEDIUM] AZ15-25 (15.4) payload collection (full requests and responses) goes to storage:stanalytics/shared read by analytics-team, expiry None: ...
[LOW   ] AZ15-10 (15.2) workspace tsg-ml uses Microsoft-managed keys; Contoso's standard asks for a customer-managed key (in a vault with purge protection)
[LOW   ] AZ15-10 (15.2) workspace tsg-ml-dev uses Microsoft-managed keys; Contoso's standard asks for a customer-managed key (in a vault with purge protection)
[LOW   ] AZ15-26 (15.4) no alerts on 4xx responses, request volume or listKeys: probing and abuse show up there first
[LOW   ] AZ15-27 (15.4) the monitoring plan relies on Azure Machine Learning model monitoring, which doesn't support the AllowOnlyApprovedOutbound mode Contoso's standard requires
[LOW   ] AZ15-28 (15.4) the Activity Log isn't exported: Azure keeps it for 90 days, and listKeys or deployment writes older than that are gone

15 HIGH, 11 MEDIUM, 5 LOW  (31 findings)
```

Start with `setups/first-draft/endpoint.json`, the shortest file. Three lines carry most of the risk:
`"auth_mode": "key"`, `"public_network_access": "enabled"` and `"traffic": {"blue": 100, "debug": 0}`. Then open
`workspace.json` and find `AllowInternetOutbound`.

## Step 2 · Attack the first draft

```bash
make attack
```

Same as `python3 evaluate.py first-draft`.

```output
  A1   WORKED   Booby-trapped model file: the weights are a pickle, and loading it runs code in the container
         . the endpoint identity (tsg-summariser-sai) downloads tsg-summariser:1 from storage:sttsgml/azureml-blobstore/models/tsg-summariser/1/
         . container: loading pytorch_model.bin ran builtins.print (LAB-PLACEHOLDER: a real payload runs here)
         . loaded the files from storage:sttsgml/azureml-blobstore/models/tsg-summariser/1/
  A2   WORKED   Approval by tag: the author marks his own model for release
  A3   WORKED   Notebook to production: a data scientist points the live deployment at his own model
  A4   WORKED   A swap underneath: a data scientist overwrites the files behind the released version
  A5   WORKED   Data out of the container: code in the deployment posts tickets to the internet
         . code in the deployment's container (a booby-trapped file, a bad package) posts a ticket to https://collector.example.net: sent (managed VNet in allow internet outbound mode)
  A6   WORKED   A wide endpoint identity: code in the container reads another team's storage
  A7   WORKED   A leaked key, used from the internet
  A8   WORKED   The scoring role that hands out keys: listKeys by a job that only needed numbers
  A9   WORKED   The hidden deployment: a 0% deployment still answers when you name it
  A10  WORKED   Notebook exfiltration through an allowed FQDN: an upload to a personal Hugging Face repo
  A11  WORKED   Keys in the datastore: another workspace user retrieves the storage account key
  A12  WORKED   Secret in the deployment: the Hugging Face token in environment_variables
  A13  WORKED   A workspace on the internet: a stolen data scientist token used from anywhere
  A14  WORKED   Isolation dropped: an admin's quick-test workspace with internet outbound and public access
  A15  WORKED   Approval in a hurry: the approver approves a version that fails every check

  N1   works    The Helpdesk gets a ticket summary
  N2   works    The pipeline deploys the released version
  N3   works    The approver approves a clean version (v4)
  N4   works    A data scientist runs and registers an experiment in the dev workspace
  N5   works    A data scientist reads the production deployment's settings
  N6   works    The platform team creates a new, correctly configured workspace

Attacks that worked: 15 of 15  (A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15)   |   normal requests that work: 6 of 6
```

All six normal requests work too: nothing *looks* broken. `python3 evaluate.py first-draft -v` prints every step.
Three of the attacks need a closer look.

**A1 and A5 together are the real story.** A model file is code if it's a pickle (M9). In allow internet outbound
mode, the code that runs at load time can send data anywhere. In approved-outbound mode, outbound traffic is limited to
"private endpoints, FQDN outbound rules, and service tag outbound rules"
([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/concept-secure-online-endpoint)).

**A8 is the one reviewers miss.** Microsoft's own sample scoring role grants `onlineEndpoints/*/action`, and the
wildcard covers `listKeys`. Ask the twin:

```bash
python3 twin.py decide first-draft tsg-reporting Microsoft.MachineLearningServices/workspaces/onlineEndpoints/listKeys/action endpoint:tsg-ml/tsg-summariser
python3 twin.py decide hardened tsg-reporting Microsoft.MachineLearningServices/workspaces/onlineEndpoints/listKeys/action endpoint:tsg-ml/tsg-summariser
```

```output
ALLOW: Custom role for scoring - online endpoint at endpoint:tsg-ml/tsg-summariser  [/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-tsg-ml/providers/Microsoft.MachineLearningServices/workspaces/tsg-ml/onlineEndpoints/tsg-summariser]
DENY: no role assignment grants it  [/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-tsg-ml/providers/Microsoft.MachineLearningServices/workspaces/tsg-ml/onlineEndpoints/tsg-summariser]
```

**A9 is the one nobody plans for.** Microsoft documents that "A request can bypass the configured traffic load
balancing by including an HTTP header of `azureml-model-deployment`"
([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online?view=azureml-api-2)):

```bash
python3 twin.py invoke first-draft tsg-helpdesk-app vnet key debug
```

```output
200 OK: key auth: no role needed, the key is enough; routed by azureml-model-deployment: debug (traffic share 0%) to 'debug'
```

## Step 3 · Look at the model files

```bash
make scan
```

- `make scan`: builds the lab's files in artifacts/, then: python3 model_files.py scan artifacts/v1-pickle ...

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

The scanner never loads a file. It reads the pickle's opcodes with Python's `pickletools` and checks every import
against an allow-list of what a PyTorch state dict needs. `builtins.print` isn't on it. (The lab's file only prints a
line if something ever unpickled it; it stands in for the real payloads you met in M9.) Then print the hashes the
registry version records:

```bash
python3 model_files.py manifest artifacts/v2-safe
```

```output
{
  "sha256/config.json": "2239240893aab4434347887491ba9de3a390cac0d0e5192b465089f8ae067f36",
  "sha256/model.safetensors": "e4f168a317b4ec264ba876970665810f5ef53dcb2381525789e230712dd8c49a",
  "sha256/tokenizer.json": "ea991de3c734d41384ad6b47bf781c803c1550b381b435823b9232ec03ee380d"
}
```

In the hardened setup, registry version 2 carries these as tags (`setups/hardened/models.json` says `SET-BY-BUILD`;
the twin fills in the real values when it loads). Tags are the one part of a model version anyone with write access can
change, so the deploy step compares the files with them instead of trusting a "stage" tag.

Why scan here and not rely on Defender for Cloud? Its AI model security (preview) says "Workspaces and registries that
use a private link aren't supported" ([Microsoft](https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-model-security)),
and the hardened workspaces use one.

## Step 4 · The hardened setup

```bash
make check-hardened
make hardened
```

- `make check-hardened`: 0 HIGH, 2 MEDIUM (AZ15-22, AZ15-23: the challenge)
- `make hardened`: same as `python3 evaluate.py hardened`

```output
  A1   blocked  Booby-trapped model file: the weights are a pickle, and loading it runs code in the container
         . the endpoint identity (id-tsg-summariser) downloads tsg-summariser:2 from storage:stcontosomlreg/assets/tsg-summariser/2/
         . loaded the files from storage:stcontosomlreg/assets/tsg-summariser/2/
         . no pickle-based weights: nothing ran at load
  A2   blocked  Approval by tag: the author marks his own model for release
         . ds-bob tags his version for release, but releases come from contoso-ml-registry only; he tries to create version 3 there: DENIED (no role assignment grants it)
  A3   blocked  Notebook to production: a data scientist points the live deployment at his own model
         . ds-bob updates the live 'blue' deployment to azureml:bob-experiment:1: DENIED (no role assignment grants it)
         . Azure Policy: nothing to deny (the registry-model rules only fire for models from a registry)
  ...
  A7   blocked  A leaked key, used from the internet
         . a key found in an old notebook, used from the internet: refused at the network: public network access is disabled
  A8   blocked  The scoring role that hands out keys: listKeys by a job that only needed numbers
         . tsg-reporting (it only needed usage numbers) calls listKeys: listKeys DENIED (no role assignment grants it)
  A9   blocked  The hidden deployment: a 0% deployment still answers when you name it
         . a caller adds the header azureml-model-deployment: debug: no deployment named debug
  A10  blocked  Notebook exfiltration through an allowed FQDN: an upload to a personal Hugging Face repo
         . a notebook on ci-bob uploads a ticket export to https://huggingface.co/bob-lab-placeholder/scratch: BLOCKED (approved-outbound mode: no outbound rule allows it)
  ...
  A14  WORKED   Isolation dropped: an admin's quick-test workspace with internet outbound and public access
  A15  WORKED   Approval in a hurry: the approver approves a version that fails every check

  N1   works    The Helpdesk gets a ticket summary
  ...
Attacks that worked: 2 of 15  (A14, A15)   |   normal requests that work: 6 of 6
```

Look at A3's second line. The registry Deny policy is on, and it still says "nothing to deny": its rule only fires when
the deployment's model comes from a registry, so a workspace model (`azureml:bob-experiment:1`) passes it. RBAC is what
stopped Bob.

Which change stopped which attack:

| Attack | Stopped by (hardened file) | Lesson |
|---|---|---|
| A1 pickle weights | `models.json`: registry version 2 is safetensors only; `deployments.json` deploys that version | 15.3 |
| A2 approval by tag | `app.json`: releases come from the registry; `rbac.json`: only `tsg-ml-approver` can write registry assets | 15.3 |
| A3 notebook to production | `rbac.json`: data scientists are Reader on `tsg-ml`; only `tsg-ci-deployer` writes deployments | 15.3 |
| A4 a swap underneath | `rbac.json`: nobody but the endpoint identity reads, and nobody writes, the registry's storage; `app.json` `deploy_verifies_hashes` | 15.3 |
| A5 data out of the container | `workspace.json`: `AllowOnlyApprovedOutbound`, no FQDN rules | 15.2 |
| A6 a wide endpoint identity | the same, plus `rbac.json`: `id-tsg-summariser` reads only `stcontosomlreg` | 15.2 |
| A7 a leaked key | `endpoint.json`: `aad_token`, `public_network_access: disabled` | 15.3 |
| A8 listKeys | `rbac.json`: `tsg-reporting` gets a read-only custom role; the app gets `score/action` only | 15.3 |
| A9 the hidden deployment | `endpoint.json` and `deployments.json`: no deployment without traffic in production | 15.3 |
| A10 notebook exfiltration | `workspace.json`: the dev workspace in approved-outbound with no FQDN rules; packages from Contoso's own mirror | 15.2 |
| A11 datastore keys | `datastores.json`: identity-based datastores | 15.2 |
| A12 secret in the deployment | `deployments.json`: no secrets in `environment_variables` | 15.2 |
| A13 workspace on the internet | `workspace.json`: `publicNetworkAccess: Disabled` and a private endpoint | 15.2 |

## Step 5 · Hunt

```bash
make hunt
```

Same as `python3 hunt.py`.

```output
Q1. Deployment writes not made by the pipeline (AzureActivity)
   2027-01-28T09:44:52Z  tsg-summariser/debug    by ds-bob         from 198.51.100.23

Q2. Endpoint keys listed by someone outside the platform team (AzureActivity)
   2027-01-28T09:12:44Z  tsg-summariser-legacy  by ds-bob         from 198.51.100.23
   2027-01-28T09:13:02Z  tsg-summariser         by tsg-reporting  from 192.0.2.44

Q3. Calls served by a deployment with 0% traffic (AmlOnlineEndpointTrafficLog)
   2027-01-28T09:52:10Z  tsg-summariser/debug    identity: ds-bob         agent: python-requests/2.32.3
   2027-01-28T09:53:44Z  tsg-summariser/debug    identity: ds-bob         agent: python-requests/2.32.3
   2027-01-28T09:55:02Z  tsg-summariser/debug    identity: ds-bob         agent: python-requests/2.32.3

Q4. Calls made with a key (challenge 3)
   not written yet: challenge 3: write find_key_calls()
```

The story: last week the team moved `tsg-summariser` to Entra auth, and the old key-auth endpoint
`tsg-summariser-legacy` was meant to be deleted. Q1 and Q2 come from the Activity Log, which records writes and actions
such as `listKeys` and keeps them for 90 days
([Microsoft](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log)). Q3 comes from
`AmlOnlineEndpointTrafficLog`, which only exists if a diagnostic setting sends it to Log Analytics. Its `AuthType` and
`IdentityData` columns tell you how each caller signed in and who they were; it has no client IP column and no request
body ([table reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/amlonlineendpointtrafficlog)).
The rows use the tables' column names; every value is invented.

## Step 6 · Break the hardened setup on purpose

Each of these takes one edit. Run `make check-hardened` and `make hardened` after each, then undo it with
`git checkout setups/`.

1. In `setups/hardened/workspace.json`, set the production workspace's `"isolationMode"` to `"AllowInternetOutbound"`.
   AZ15-03 is HIGH, and A5 comes back. A6 stays blocked only because the endpoint identity is scoped.
2. In the same file, delete the production workspace's `contoso-ml-registry` outbound rule. No attack comes back, but
   **N1 and N2 break**: the endpoint can't download its model from the registry. Approved-outbound mode creates
   private endpoint rules for the workspace's own storage, key vault and container registry automatically
   ([Microsoft](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-managed-network?view=azureml-api-2));
   anything else needs a rule you add.
3. Put Bob's test back: in `setups/hardened/endpoint.json` add `"debug": 0` to `traffic`, copy the first draft's `debug`
   deployment into `deployments.json`, and copy its model (`"bob-experiment:1"`, under `"workspace:tsg-ml"`) into
   `models.json`. A9 comes back, and the checker adds AZ15-02 (an old environment) and AZ15-19 (a 0% deployment).
4. In `setups/hardened/deployments.json`, add `"HF_MODEL_ID": "Qwen/Qwen3-0.6B"` to `blue`'s `environment_variables`
   (the container would download the model from the Hub at start). N1 breaks: an approved-outbound workspace without
   FQDN rules can't reach the Hub. That's the point. Bring the files in yourself, through the registry, where you can
   scan and hash them.

## Step 7 · Prove it

```bash
make test
```

Same as `python3 run_tests.py`.

```output
[PASS] first draft: 31 findings, 15 HIGH (network, public access, identity, keys, deployments, registry, pickle weights)
[PASS] hardened: 0 HIGH; only the two challenge findings are left (AZ15-22 promotion gate, AZ15-23 Azure Policy)
...
[PASS] traffic log: no client IP and no payload columns; key calls carry no identity
[PASS] README Step 6: no registry outbound rule, or a model pulled from the Hub at start, and the summariser breaks
----------------------------------------------------------------------
Ran 21 tests in 0.055s

OK

ALL TESTS PASSED (21 run)
```

`make test` pins the hardened setup as shipped (it ignores `policy-challenge.json` and the gate switch), so your
challenge work doesn't break it.

## Step 8 · Challenge (no solution included)

```bash
make challenge
```

You should see:

```text
7 of 29 TESTS FAILED (29 run)
```

They fail until you finish.

1. **15.2: Azure Policy in Deny.** Add assignments to `setups/hardened/policy-challenge.json` (same shape as
   `policy.json`) so that creating a workspace is DENIED when its managed network isn't in approved-outbound mode, and
   when public network access isn't disabled. Start from the built-in rules in `policy.json`. Read `ml-approved-outbound`
   closely: its `isolationMode` parameter is left at the default, and `make check-hardened` tells you what that does. A
   correctly configured workspace (N6) must still be created.
2. **15.3: write the promotion gate.** Write `check_before_promotion()` in `gate.py` (the docstring lists the four
   checks), then set `"approval_gate": true` in `setups/hardened/app.json`. Version 3 must be refused with reasons;
   clean version 4 must pass for the approver, and fail if its own registrant promotes it or a file was swapped.
3. **15.4: write a hunt query.** Write `find_key_calls()` in `hunt.py`: the scoring requests made with a key, on any
   endpoint. Then look at Q2 again and decide what you can and can't say about who made them.

Finished, `make check-hardened` shows 0 findings and `make hardened` shows 0 of 15 attacks with 6 of 6 normal requests.

## Step 9 · Optional: build it in your sandbox subscription (costs money)

Follow [`GUIDED-BUILD.md`](GUIDED-BUILD.md). A managed online endpoint bills for its VM every hour it exists, so the
guide creates a Logic App timer that deletes the endpoint **before** it creates the endpoint. Short version:

```bash
make cloud-up
MODEL_ID=azureml://registries/azureml/models/<name>/versions/<version> make cloud-deploy
make cloud-ask
make cloud-down
```

- `make cloud-up`: resource group, approved-outbound workspace, private endpoint, client VM, Log Analytics
- `make cloud-ask`: five requests
- `make cloud-down`: delete everything, today

## How faithful is the twin?

| Behaviour | Twin | Microsoft source |
|---|---|---|
| Managed VNet modes; approved outbound allows only private endpoint, FQDN and service tag rules; required private endpoint rules for the workspace's storage, key vault and container registry are created automatically; an FQDN rule deploys an Azure Firewall; exfiltration protection isn't guaranteed to FQDN destinations | Same | [Managed network](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-managed-network?view=azureml-api-2) |
| Endpoint `public_network_access: disabled`: inbound only through the workspace private endpoint; control-plane calls (listKeys included) go to Azure Resource Manager | Same | [Secure online endpoint](https://learn.microsoft.com/en-us/azure/machine-learning/concept-secure-online-endpoint) |
| Auth modes: a key needs no role; `aad_token` needs `score/action`; keys don't expire | Same. **Twin choice:** an `aad_token` endpoint refuses keys and `listKeys` returns no usable key | [Auth concepts](https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online-auth?view=azureml-api-2), [authenticate clients](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-authenticate-online-endpoint) |
| The `azureml-model-deployment` header routes to a named deployment, bypassing the traffic split | Same | [Online endpoints](https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online?view=azureml-api-2) |
| A system-assigned endpoint identity gets AcrPull, Storage Blob Data Reader and AzureML Metrics Writer automatically; for a user-assigned one, you assign the roles | Same, for the workspace's own storage | [Auth concepts](https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online-auth?view=azureml-api-2) |
| Credential-based datastores keep keys in the workspace key vault, retrievable by other workspace users with enough permissions | Same. **Twin choice:** the operation is called `datastores/listSecrets/action`, granted by AzureML Data Scientist's `workspaces/*/action` | [Managed identities](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-use-managed-identities?view=azureml-api-2) |
| Model versions: only `description` and `tags` can change | Same | [Manage models](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-models?view=azureml-api-2) |
| Azure RBAC: Actions minus NotActions, DataActions minus NotDataActions, scope inheritance, `*` wildcards; AzureML Data Scientist and AzureML Registry User as Microsoft lists them | Same, for the operations the lab uses. No deny assignments, no conditions, no PIM | [Built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/ai-machine-learning) |
| Azure Policy: the built-in rules in `policy.json`, parameters with defaults, Deny and Audit | Same rules, a subset of the language; case-insensitive comparisons | [Azure/azure-policy](https://github.com/Azure/azure-policy/tree/master/built-in-policies/policyDefinitions/Machine%20Learning) |
| Where a registry keeps its files, and the private endpoint rule a workspace needs to reach a registry | **Twin choice:** the registry's files sit in `stcontosomlreg`, reached through a private endpoint outbound rule (registries are a supported private endpoint target) | [Managed network](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-managed-network?view=azureml-api-2) |
| What a serving container does with a pickle-based weights file | **Twin choice:** the worst case (it unpickles it) | not documented (it varies by framework and version) |

Nothing in `cloud/` has been run by us yet: see GUIDED-BUILD.md.

## Troubleshooting

- **`make challenge` exits with an error.** Expected until you finish: the last line tells you how many tests fail.
- **`make test` fails after you edited a setup.** `git diff setups/` shows what you changed; `git checkout setups/` undoes it.
- **Windows:** `python run_tests.py`, `python checker.py first-draft`, and so on.
