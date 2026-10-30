# Lab M15: a private endpoint for an open model on SageMaker AI

Companion to lessons **15.0 to 15.5** of *AI Security Engineer* (The Sec Guy). About 70 minutes for Steps 1 to 8,
**$0**, all on your laptop: **Python 3.11+ only**, no packages, no AWS account, no model download. Step 9 is optional
and **costs money every hour**: [`GUIDED-BUILD.md`](GUIDED-BUILD.md) builds a private, network-isolated endpoint for an
open model in **your own** sandbox account, with an auto-teardown schedule created before the endpoint.

You are still the cloud security engineer at **AnyCompany** (fictional; "AnyCompany" is the placeholder name AWS uses
in its documentation). The TSG Helpdesk now summarises tickets with an **open-weights model** that the data science
team fine-tunes. Tickets must stay in AnyCompany's account, so the platform team hosts the model on an
**Amazon SageMaker AI** real-time endpoint instead of calling a managed model on Bedrock. The data scientists work in a
**SageMaker Studio** domain and register versions in the **Model Registry**. The pull request says "endpoint up,
summaries work". That is the **first draft**. Your job: break it, then prove the hardened version holds.

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Review the first draft: 35 findings, 19 HIGH | 15.1 to 15.4 |
| **Break** | 15 attacks and 6 normal requests: 15 of 15 attacks work, and every normal request works too | 15.2, 15.3 |
| **Files** | Scan the model files: a pickle-based weights file vs safetensors, and the hashes the registry recorded | 15.3 |
| **Harden** | The same suite against the hardened setup: 13 of 15 stopped, 6 of 6 normal requests still work | 15.2, 15.3 |
| **Hunt** | Investigate a morning of CloudTrail records | 15.4 |
| **Prove** | `make test`: 20 tests | 15.5 |
| **Challenge** | An SCP, an approval gate, a hunt query. No solution included | 15.2, 15.3, 15.4 |
| **Cloud (optional, costs money)** | [`GUIDED-BUILD.md`](GUIDED-BUILD.md): a private endpoint for an open model, from zero (CLI, plus Studio console clicks), five requests, one setting changed, auto-teardown and teardown | 15.2 to 15.4 |

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m15`.

## What's in this folder

| File | What it is |
|---|---|
| `setups/first-draft/` | The pull request. The model has no network isolation and no VPC, and loads a fine-tuned export with pickle-based weights straight from S3. Old image by tag, a Hugging Face token in the environment, SSM access on the production variant. A Studio domain with internet access and one shared security group. Data scientists with `sagemaker:*` and `iam:PassRole` on everything. An app role that works from anywhere, a runtime VPC endpoint with the default policy, data capture into the analytics bucket |
| `setups/hardened/` | The fixed version. An approved registry version with safetensors and recorded hashes. Network isolation plus a VPC with an S3 gateway endpoint and no internet route; an image pinned by digest. A VpcOnly domain with a key and one security group per profile. Scoped roles, and a bucket policy that only lets the pipeline write released models. An app role tied to the VPC endpoint and an endpoint policy for this account and endpoint. Encrypted capture in its own bucket, data events and alarms |
| `*/model.json`, `endpoint-config.json`, `domain.json`, `registry.json` | The real request bodies (`CreateModel`, `CreateEndpointConfig`, `CreateDomain`, `CreateModelPackage`). Keys that start with `_` are lab notes |
| `*/iam.json`, `scp.json`, `network.json`, `app.json` | Identity policies, the runtime VPC endpoint policy and bucket policies; SCPs; subnets, routes and VPC endpoints; how the team runs it |
| `images.json` | The lab's image catalog: release dates and the AWS support rule (end of patch) |
| `twin.py` | The **offline stand-in for SageMaker AI**: an IAM evaluator (identity, SCP, VPC endpoint and bucket policies), what a model container can reach, model downloads, what a Studio notebook can reach. Read "How faithful is the twin?" below |
| `model_files.py` | Builds the lab's model files and **scans** any model folder (the lab's or a real download): file formats, pickle imports read without loading, sha256 hashes |
| `evaluate.py` | 15 attacks and 6 normal requests; prints which attacks worked AND which normal requests still work; `--only A5` shows one case, every step |
| `explore.py` | Step 1b: shows each SageMaker AI piece on its own (`pieces`, `endpoint`, `patch`, `reach`, `call`, `role`, `record`). Read-only: it reads the lab's files and asks `twin.py`; nothing is sent anywhere |
| `checker.py` | 27 review rules, `M15-01` to `M15-27` |
| `hunt.py`, `data/incident/` | Three hunting questions over CloudTrail records, plus challenge 3 |
| `gate.py` | The approval gate you write in challenge 2 |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 20 tests for the lab, 8 for the challenge |
| `cloud/` | Optional: `base.yaml` (CloudFormation for the private network, keys, buckets, roles, the app Lambda and a trail), `requests/` (CLI request bodies with placeholders) and `render.py` (fills them in) |

## Needs

- Python **3.11 or newer**: `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 9 only: the AWS CLI v2, your own sandbox account (lesson 0.7) with a budget alarm, a GPU quota for
  SageMaker AI endpoints, and about 2 GB free disk for the model download.

## Step 1b · Before you attack: look at each piece (about 10 minutes)

New to SageMaker AI? Do this before Step 1 (lesson 15.5 and its videos call it Step 1b). `explore.py` shows AnyCompany's
setup one piece at a time. Real output below is from a fresh Ubuntu machine (recording run 41116260706).

**What it really runs.** Nothing that changes anything: `explore.py` reads the JSON files in `setups/` and
`data/incident/` and prints what it finds. `reach`, `call` and `role` ask `twin.py`, the lab's offline stand-in for
SageMaker AI. No network, no AWS account.

**0. Look before you run.** `make -n setup` prints what `make setup` would run, without running it:

```bash
make -n setup
make setup
```

```text
python3 ../../tools/check_python.py 3.11
```

Other labs make a *virtual environment* here (a private folder for that lab's Python packages, so versions don't
clash; it keeps versions apart, it isn't a security sandbox) and run `pip install`. This lab uses only Python's
standard library, so `make setup` just checks your Python version and says "Nothing to install for this lab".

**1. The pieces.** Every SageMaker AI piece AnyCompany uses, in one list:

```bash
python3 explore.py pieces first-draft
```

```text
AnyCompany's SageMaker AI pieces, setup first-draft (fictional; AWS documentation example IDs)

  Studio domain    tsg-data-science: where the data scientists work in notebooks
                   user profiles: alice, bob   network: PublicInternetOnly
  Training job     none in this lab: the team fine-tunes in a notebook and exports the files
  Model files      in S3: s3://amzn-s3-demo-tsg-models/tsg-summariser/v1/
  Model Registry   group tsg-summariser: one entry per version, each with an approval status
                   version 1  Approved               registered by ds-alice
                   version 3  PendingManualApproval  registered by ds-bob
                   version 4  PendingManualApproval  registered by tsg-ci-deployer
  Model            tsg-summariser-v1: image + files + execution role + network settings
                   image djl-inference:0.30.0-lmi12.0.0-cu124
  Endpoint config  tsg-summariser-v1-cfg: 1 x ml.g5.xlarge, data capture on
  Endpoint         tsg-summariser: the address the Helpdesk app calls
  Execution roles  tsg-summariser-exec (the endpoint), tsg-ds-exec (notebooks and jobs)
  Where models come from   huggingface.co/Qwen/Qwen3-0.6B (an open model; JumpStart is AWS's catalog, not used here)
```

A Studio domain is where the data scientists work; the Model Registry holds versions with an approval status; the
model, the endpoint configuration and the endpoint serve the Helpdesk; the execution roles are what SageMaker AI acts as.

**2. An endpoint is three objects.** The real request bodies, field by field, and what happens at start:

```bash
python3 explore.py endpoint first-draft
```

```text
One real-time endpoint is three objects (setup first-draft). The request bodies are in setups/first-draft/.

1. CreateModel           model.json
   Image                   djl-inference:0.30.0-lmi12.0.0-cu124
   model files             s3://amzn-s3-demo-tsg-models/tsg-summariser/v1/
   ExecutionRoleArn        arn:aws:iam::111122223333:role/tsg-summariser-exec
   EnableNetworkIsolation  false
   VpcConfig               none
   Environment             OPTION_ROLLING_BATCH, HF_TOKEN

2. CreateEndpointConfig  endpoint-config.json
   InstanceType x count    ml.g5.xlarge x 1
   DataCaptureConfig       prompts and answers to s3://amzn-s3-demo-tsg-analytics/tsg-summariser/

3. CreateEndpoint        name tsg-summariser, config tsg-summariser-v1-cfg

When it starts, SageMaker AI (AWS's documented contract for inference containers):
   copies the model files from S3 to /opt/ml/model (read-only for the container)
   runs the image as: docker run <image> serve
   sends requests to a web server in the container on port 8080: POST /invocations, GET /ping
```

**3. Who patches what.** AWS patches the endpoint instances; the image is yours, and it has an end-of-patch date:

```bash
python3 explore.py patch first-draft
```

```text
Who patches what for AnyCompany's endpoint (setup first-draft)

  AWS   the hosts, and the endpoint instances ("automatically patches endpoints")
  You   the image your model names, the model files, the network settings, the execution role, keys, buckets

  image          djl-inference:0.30.0-lmi12.0.0-cu124
  pinned by      tag (a tag can move to other bytes)
  released       2025-09-15   (a lab value; read real dates in the image's GitHub release)
  support rule   DLC: end of patch 365 days after release
  end of patch   2026-09-15
  lab today      2027-02-01   -> PAST end of patch: no more security fixes

  A newer image reaches the endpoint only when you deploy a model that names it.
```

**4. What code can reach.** Run it for both setups and compare:

```bash
python3 explore.py reach first-draft
python3 explore.py reach hardened
```

```text
What code can reach (setup first-draft), from twin.py

  Model container   EnableNetworkIsolation false, VpcConfig none
     internet       yes
     AWS credentials (the execution role)  yes
     why            no network isolation and no VpcConfig: SageMaker AI provides external network access
     model files    SageMaker AI downloads the files with the execution role
     S3 gateway endpoint   none

  Studio notebook   AppNetworkAccessType PublicInternetOnly
     internet       yes
     why            PublicInternetOnly (the default): direct internet access through a SageMaker-managed VPC

  VPC endpoints (private doors to AWS services): sagemaker.runtime

What code can reach (setup hardened), from twin.py

  Model container   EnableNetworkIsolation true, VpcConfig yes
     internet       no
     AWS credentials (the execution role)  no
     why            network isolation: no outbound calls, no AWS credentials in the container
     model files    SageMaker AI downloads the files with the execution role
     S3 gateway endpoint   vpce-0a1b2c3d4e5f60002 with a policy

  Studio notebook   AppNetworkAccessType VpcOnly
     internet       no
     why            VpcOnly: no route to the internet

  VPC endpoints (private doors to AWS services): sagemaker.runtime, sagemaker.api, aws.sagemaker.us-east-1.studio
```

**5. One call.** The request the Helpdesk app sends, its path, and the IAM checks. Over the internet, the first draft
allows it and the hardened setup doesn't:

```bash
python3 explore.py call first-draft tsg-helpdesk-app
python3 explore.py call hardened tsg-helpdesk-app
```

```text
One InvokeEndpoint call (setup first-draft). Nothing is sent: twin.py answers.

  POST https://runtime.sagemaker.us-east-1.amazonaws.com/endpoints/tsg-summariser/invocations
  body: the ticket text; signed with SigV4 by the caller's credentials
  caller   arn:aws:iam::111122223333:role/tsg-helpdesk-app
  target   arn:aws:sagemaker:us-east-1:111122223333:endpoint/tsg-summariser
  path     over the internet (no VPC endpoint: aws:SourceVpce is missing)

  IAM checks, in order:
   1. caller's identity policy        ALLOW
   2. VPC endpoint policy             not on the path

  result   ALLOW: allowed by the identity policy

One InvokeEndpoint call (setup hardened). Nothing is sent: twin.py answers.

  POST https://runtime.sagemaker.us-east-1.amazonaws.com/endpoints/tsg-summariser/invocations
  body: the ticket text; signed with SigV4 by the caller's credentials
  caller   arn:aws:iam::111122223333:role/tsg-helpdesk-app
  target   arn:aws:sagemaker:us-east-1:111122223333:endpoint/tsg-summariser
  path     over the internet (no VPC endpoint: aws:SourceVpce is missing)

  IAM checks, in order:
   1. caller's identity policy        no Allow
   2. VPC endpoint policy             not on the path

  result   DENY: no identity policy allows it (implicit deny)
```

Add `--vpce` to send the call through AnyCompany's runtime VPC endpoint, and try `collector-role` (someone else's
account): that is attack A8 in Step 2.

**6. An execution role.** Who may wear it, what it may do, and who may hand it out:

```bash
python3 explore.py role first-draft
```

```text
Execution role tsg-summariser-exec (setup first-draft)

  who may wear it    sagemaker.amazonaws.com (sts:AssumeRole): SageMaker AI, on your behalf
  managed policies   AmazonSageMakerFullAccess
  what it may do
     Allow  s3:*                               on *
     Allow  kms:Decrypt                        on *
  who may pass it    ds-alice, ds-bob, tsg-ci-deployer, tsg-platform-admin
                     (iam:PassRole: hand this role to a model, job or notebook)
```

**7. One CloudTrail record.** The lab's fake records use CloudTrail's field names:

```bash
python3 explore.py record InvokeEndpoint
```

```text
One CloudTrail record from data/incident/cloudtrail.json (fake values in CloudTrail's field names)

  who      AssumedRole  tsg-helpdesk-app  in account 111122223333
  what     sagemaker.amazonaws.com  InvokeEndpoint
           on arn:aws:sagemaker:us-east-1:111122223333:endpoint/tsg-summariser
  kind     eventCategory Data  (a data event: logged only if the trail selects AWS::SageMaker::Endpoint)
  where    us-east-1, from 10.0.1.77, through vpce-0a1b2c3d4e5f60001
  when     2027-01-28T10:01:12Z
  error    none
  request  {} (AWS: InvokeEndpoint does not log its request parameters: no prompt)
```

**8. Read one result from the top.** `evaluate.py --only` shows one case with every step:

```bash
python3 evaluate.py first-draft --only N1
```

```text
setup: first-draft   (twin.py, offline: nothing is sent to AWS)
group: normal request (it must keep working)

  N1   works    The Helpdesk gets a ticket summary
         . the Helpdesk asks for a ticket summary through the VPC endpoint: allowed (allowed by the identity policy (through the VPC endpoint)); endpoint: SageMaker AI downloads the files with the execution role
```

The setup and a reminder that nothing is sent to AWS; the group (a normal request, which must keep working); the case
and its verdict; then the **why** line: the call through the VPC endpoint is allowed by the identity policy, and the
endpoint starts because SageMaker AI downloads the files with the execution role. `--only` takes `A1` to `A15` and `N1`
to `N6`.

## Step 1 · Review the first draft

```bash
cd labs/m15
make check
```

- `make check`: same as `python3 checker.py first-draft`

You should see (long lines cut here):

```output
[HIGH  ] M15-01 (15.1) the inference image reached end of patch on 2026-09-15 (dlc: 365 days after release): it gets no more security fixes, ...
[HIGH  ] M15-03 (15.2) the model container runs without network isolation: code in it can call out to the internet and use the execution role's credentials
[HIGH  ] M15-05 (15.2) Studio notebooks can reach the internet (PublicInternetOnly (the default): direct internet access through a SageMaker-managed VPC): ...
[HIGH  ] M15-08 (15.2) execution role tsg-summariser-exec has AmazonSageMakerFullAccess (AWS: 'fairly broad'); s3:* on *: ...
[HIGH  ] M15-10 (15.2) ds-alice may pass tsg-summariser-exec to SageMaker AI: a job or notebook they start runs with the production role
[HIGH  ] M15-11 (15.2) ds-bob may create a presigned Studio URL for alice: they sign in as that profile, with its files and execution role
[HIGH  ] M15-12 (15.2) secret-looking value in the container Environment (HF_TOKEN): DescribeModel returns it to ds-alice, ds-bob
[HIGH  ] M15-14 (15.3) tsg-helpdesk-app may call InvokeEndpoint from anywhere (no aws:SourceVpce condition): stolen keys work from the internet
[HIGH  ] M15-15 (15.3) the sagemaker.runtime interface endpoint has the default policy (full access): credentials from any AWS account can use your private path ...
[HIGH  ] M15-16 (15.3) EnableSSMAccess on a production variant: shell access into the inference container for ds-alice, ds-bob; ...
[HIGH  ] M15-17 (15.3) the endpoint's model points straight at an S3 path, not at an approved Model Registry version: nobody's approval is part of what runs
[HIGH  ] M15-18 (15.3) ds-bob may call UpdateModelPackage: a data scientist can approve their own model version (no four-eyes)
[HIGH  ] M15-19 (15.3) the deployed model files are not safetensors-only: pytorch_model.bin (pickle: imports builtins.print)
[HIGH  ] M15-20 (15.3) ds-alice, ds-bob may overwrite the files the endpoint loads (s3://amzn-s3-demo-tsg-models/tsg-summariser/v1/): ...
...
[MEDIUM] M15-02 (15.1) the image is pinned by tag, not by digest: the same tag can point at different bytes over time
[MEDIUM] M15-04 (15.2) the model has no VpcConfig: model downloads don't go through your VPC, so your S3 endpoint policy and flow logs never see them
[MEDIUM] M15-06 (15.2) sg-0a1b2c3d4e5f60031 allows inbound from itself and is shared by alice, bob: AWS warns users in the VPC could reach other profiles' apps ...
[MEDIUM] M15-07 (15.2) the Studio domain has no KmsKeyId: notebooks' EFS and EBS volumes use an AWS managed key, whose key policy you can't edit
[MEDIUM] M15-09 (15.2) tsg-summariser-exec trust policy has no aws:SourceArn: any SageMaker AI resource, in any account, could be the one assuming it ...
[MEDIUM] M15-21 (15.3) no file hashes recorded for the deployed model: nobody can prove the files running are the ones approved
[MEDIUM] M15-21 (15.3) licence not recorded: AWS says reviewing model licences is your job
[MEDIUM] M15-22 (15.3) no approval gate: nothing checks formats, hashes, licence and approver before a version becomes Approved (challenge 2)
[MEDIUM] M15-23 (15.2) no SCP requires network isolation and a VPC on CreateModel: an admin's quick test can still ship a container that calls out (challenge 1)
[MEDIUM] M15-24 (15.4) data capture (full prompts and answers) is written without a KmsKeyId of yours
[MEDIUM] M15-24 (15.4) data capture goes to amzn-s3-demo-tsg-analytics, a bucket other teams read: ...
[MEDIUM] M15-25 (15.4) no CloudTrail data events for AWS::SageMaker::Endpoint: InvokeEndpoint is a data event, and trails don't log data events by default
[LOW   ] M15-13 (15.2) KmsKeyId on an endpoint with ml.g5.xlarge (NVMe instance storage): AWS says you can't use a KMS key on an instance type with local storage, ...
[LOW   ] M15-26 (15.4) no alarm on Invocation4XXErrors or invocation volume: probing and abuse show up there first
[LOW   ] M15-27 (15.4) the monitoring plan relies on SageMaker Model Monitor or Clarify: both are no longer open to new customers

19 HIGH, 13 MEDIUM, 3 LOW  (35 findings)
```

Start with `setups/first-draft/model.json`, the shortest file. Three lines carry most of the risk:
`"EnableNetworkIsolation": false`, an `S3Uri` that points at a folder anyone on the team can write, and `HF_TOKEN`.

## Step 2 · Attack the first draft

```bash
make attack
```

Same as `python3 evaluate.py first-draft`.

```output
  A1   WORKED   Booby-trapped model file: the weights are a pickle, and loading it runs code in the container
         . SageMaker AI downloads the files with the execution role
         . container: loading pytorch_model.bin ran builtins.print (LAB-PLACEHOLDER: a real payload runs here)
  A2   WORKED   Artifact swap after approval: a data scientist overwrites the files the endpoint loads
  A3   WORKED   Unapproved model to production: a hotfix model straight from a notebook onto the live endpoint
  A4   WORKED   Self-approval: the author approves their own model version
  A5   WORKED   Data out of the container: code in the model container posts tickets to the internet
         . code in the container posts a ticket to https://collector.example.net: sent (no network isolation and no VpcConfig: SageMaker AI provides external network access)
  A6   WORKED   Container credentials: code in the container reads another team's bucket with the execution role
  A7   WORKED   Stolen app keys: InvokeEndpoint from the internet
  A8   WORKED   Outsider through the private endpoint: someone else's account sends data out via AnyCompany's VPC endpoint
  A9   WORKED   Shell into the endpoint: SSM access on the production container
  A10  WORKED   Studio exfiltration: a notebook uploads data to the internet
  A11  WORKED   Studio impersonation: a presigned URL for someone else's profile
  A12  WORKED   PassRole escalation: a job started by a data scientist runs as the production role
  A13  WORKED   Secret in the model definition: DescribeModel shows the Hugging Face token
  A14  WORKED   Isolation dropped: an admin's quick test creates a model with no isolation and no VPC
  A15  WORKED   Approval in a hurry: the approver approves a version that fails every check
  ...
Attacks that worked: 15 of 15  (A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15)   |   normal requests that work: 6 of 6
```

All six normal requests work too: nothing *looks* broken. Two of the attacks need a closer look.

**A1 and A5 together are the real story.** A model file is code if it's a pickle (M9). Without network isolation, the
code that runs at load time can call out and use the role. AWS describes network isolation in one sentence: "your
training and inference containers can't make any outbound network calls to any service, including Amazon S3. No AWS
credentials are made available to the container runtime environment"
([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html)).

**A8 is the one reviewers miss.** Ask the twin directly:

```bash
python3 twin.py decide first-draft collector-role sagemaker:InvokeEndpoint arn:aws:sagemaker:us-east-1:444455556666:endpoint/collector --vpce
python3 twin.py decide hardened collector-role sagemaker:InvokeEndpoint arn:aws:sagemaker:us-east-1:444455556666:endpoint/collector --vpce
```

```output
ALLOW: allowed by the identity policy (through the VPC endpoint)
DENY: the sagemaker.runtime VPC endpoint policy does not allow it
```

`collector-role` lives in someone else's account. Its own policy lets it call its own endpoint. AnyCompany's private
path to SageMaker AI carried the call because nobody wrote an endpoint policy.

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
line; it stands in for the real payloads you met in M9.) Then print the hashes the registry recorded for version 2:

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

Compare them with `CustomerMetadataProperties` in `setups/hardened/registry.json`, version 2. The hardened deploy step
refuses to start an endpoint whose files don't match.

## Step 4 · The hardened setup

```bash
make check-hardened
make hardened
```

- `make check-hardened`: 0 HIGH, 2 MEDIUM (M15-22, M15-23: the challenge)
- `make hardened`: same as `python3 evaluate.py hardened`

```output
  A1   blocked  Booby-trapped model file: the weights are a pickle, and loading it runs code in the container
         . no pickle-based weights: nothing ran at load
  A2   blocked  Artifact swap after approval: a data scientist overwrites the files the endpoint loads
         . ds-bob writes into s3://amzn-s3-demo-tsg-models/tsg-summariser/v2/: DENIED (explicit Deny in the bucket policy of amzn-s3-demo-tsg-models)
  ...
  A8   blocked  Outsider through the private endpoint: someone else's account sends data out via AnyCompany's VPC endpoint
         . someone in the VPC uses their OWN account's keys, through AnyCompany's runtime endpoint, to send tickets to their endpoint: DENIED (the sagemaker.runtime VPC endpoint policy does not allow it)
  ...
  A14  WORKED   Isolation dropped: an admin's quick test creates a model with no isolation and no VPC
  A15  WORKED   Approval in a hurry: the approver approves a version that fails every check

  N1   works    The Helpdesk gets a ticket summary
  ...
Attacks that worked: 2 of 15  (A14, A15)   |   normal requests that work: 6 of 6
```

Which change stopped which attack:

| Attack | Stopped by (hardened file) | Lesson |
|---|---|---|
| A1 pickle weights | `registry.json` version 2 is safetensors only; `model.json` deploys that version | 15.3 |
| A2 artifact swap | `iam.json` bucket policy: only `tsg-ci-deployer` writes `tsg-summariser/*`; `app.json` `deploy_verifies_hashes` | 15.3 |
| A3 notebook to production | `iam.json`: data scientists act only on `ds-*` resources; the pipeline deploys | 15.3 |
| A4 self-approval | `iam.json`: an explicit Deny on `UpdateModelPackage` for data scientists; only `tsg-model-approver` approves | 15.3 |
| A5 data out of the container | `model.json` `EnableNetworkIsolation: true` (and no internet route in `network.json`) | 15.2 |
| A6 container credentials | the same: no credentials in an isolated container; the execution role is scoped anyway | 15.2 |
| A7 stolen app keys | `iam.json`: the app may invoke only with `aws:SourceVpce` = the runtime VPC endpoint | 15.3 |
| A8 outsider through the VPC endpoint | `iam.json` `runtime_endpoint_policy`: this account, this endpoint | 15.3 |
| A9 SSM shell | `endpoint-config.json`: no `EnableSSMAccess`; with isolation on, SSM can't start anyway | 15.3 |
| A10 Studio exfiltration | `domain.json` `VpcOnly`; `network.json`: no NAT route | 15.2 |
| A11 Studio impersonation | `iam.json`: `CreatePresignedDomainUrl` on your own user profile only | 15.2 |
| A12 PassRole escalation | `iam.json`: data scientists may pass `tsg-ds-exec` only | 15.2 |
| A13 secret in the model | `model.json` has no secrets; the registry version's `Environment` has none | 15.2 |

## Step 5 · Hunt

```bash
make hunt
```

Same as `python3 hunt.py`.

```output
Q1. Models created outside the pipeline
   2027-01-28T09:41:07Z  tsg-summariser-hotfix    by ds-bob     from registry: False   network isolation: False

Q2. Self-approvals
   2027-01-28T09:05:02Z  version 3 approved by ds-bob, who registered it

Q3. Presigned Studio URLs for someone else's profile
   2027-01-28T10:15:26Z  ds-bob (own profile: bob) signed in as alice

Q4. InvokeEndpoint calls that skipped the private endpoint (challenge 3)
   not written yet: challenge 3: write find_outside_invocations()
```

Q1 to Q3 come from management events, which CloudTrail keeps by default. Q4 needs data events for
`AWS::SageMaker::Endpoint`, which a trail records only when you select them, and even then AWS says `InvokeEndpoint`
"don't log the request parameters" ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/logging-using-cloudtrail.html)):
you see who called and from where, never the prompt. The records use CloudTrail's field names; every value is invented.

## Step 6 · Break the hardened setup on purpose

Each of these takes one edit. Run `make check-hardened` and `make hardened` after each, then undo it with `git checkout setups/`.

1. In `setups/hardened/model.json`, set `"EnableNetworkIsolation": false`. M15-03 is HIGH, but A5 still says blocked:
   the VPC has no route out. Now add `"nat"` to the routes of the two app subnets in `network.json`
   (`subnet-0a1b2c3d4e5f60011` and `...12`). A5 comes back. A6 stays blocked only because the execution role is scoped.
2. In `setups/hardened/network.json`, set `"s3_gateway_endpoint": null`. No attack comes back, but **N1 and N6 break**:
   the endpoint can't download its model. AWS: models in a VPC without internet access "can't connect to the Amazon S3
   buckets that contain your data unless you create a VPC endpoint that allows access"
   ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/host-vpc.html)).
3. In `setups/hardened/iam.json`, set `"runtime_endpoint_policy": null`. A8 comes back (M15-15 HIGH).
4. In `setups/hardened/registry.json`, version 2, delete `ModelDataSource` and add `"HF_MODEL_ID": "Qwen/Qwen3-0.6B"`
   to its `Environment` (the container would download the model from the Hub at start). M15-19 is HIGH, and N1 and N6
   break: an isolated container can't reach the Hub. Network isolation forces you to bring the files yourself,
   through S3, where you can scan and hash them.

## Step 7 · Prove it

```bash
make test
```

Same as `python3 run_tests.py`.

```output
[PASS] first draft: 35 findings, 19 HIGH (isolation, Studio, roles, endpoint paths, SSM, registry, pickle weights)
[PASS] hardened: 0 HIGH; only the two challenge findings are left (M15-22 approval gate, M15-23 SCP)
...
[PASS] hunt: the InvokeEndpoint data events carry no request parameters (AWS: InvokeEndpoint doesn't log them)

ALL TESTS PASSED (20 run)
```

`make test` pins the hardened setup as shipped (it ignores your `scp.json` statements and the gate switch), so your
challenge work doesn't break it.

## Step 8 · Challenge (no solution included)

```bash
make challenge
```

You should see:

```text
7 of 28 TESTS FAILED (28 run)
```

They fail until you finish.

1. **15.2: write an SCP.** Add `Deny` statements to `setups/hardened/scp.json` so `CreateModel` fails when network
   isolation is left out or false, and when there is no VPC. The keys are `sagemaker:NetworkIsolation` and
   `sagemaker:VpcSubnets` (both listed for `CreateModel` in the Service Authorization Reference). Watch out: a request
   that leaves a parameter out may not carry the key at all. The pipeline's own isolated, in-VPC deploy (N2) must
   still work.
2. **15.3: write the approval gate.** Write `check_before_approval()` in `gate.py` (the docstring lists the four
   checks), then set `"approval_gate": true` in `setups/hardened/app.json`. Version 3 must be refused with reasons;
   clean version 4 must pass for the approver, and fail if its own registrant approves it or a file was swapped.
3. **15.4: write a hunt query.** Write `find_outside_invocations()` in `hunt.py`: `InvokeEndpoint` data events on
   AnyCompany's endpoint that didn't come through the runtime VPC endpoint (`vpcEndpointId`).

Finished, `make check-hardened` shows 0 findings and `make hardened` shows 0 of 15 attacks with 6 of 6 normal requests.

## Step 9 · Optional: build it in your sandbox account (costs money)

Follow [`GUIDED-BUILD.md`](GUIDED-BUILD.md). It runs a GPU endpoint, which bills for every hour it exists, so the guide
creates an EventBridge Scheduler one-time schedule that deletes the endpoint **before** it creates the endpoint.
Short version:

```bash
make cloud-base
```

- `make cloud-base`: private VPC, VPC endpoints with policies, KMS key, buckets, roles, app Lambda, trail

GUIDED-BUILD Parts B to E: download and scan the model, register and approve it, deploy, five requests.

```bash
make cloud-down
```

- `make cloud-down`: delete everything, today

## How faithful is the twin?

| Behaviour | Twin | AWS source |
|---|---|---|
| Network isolation: no outbound calls, "No AWS credentials are made available to the container"; S3 downloads done by SageMaker AI with the execution role, through your subnets when the model has a VPC | Same | [Internet-free mode](https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html) |
| Without isolation and without `VpcConfig`, SageMaker AI provides external network access ("If you do not want SageMaker AI to provide external network access ... you can enable network isolation") | Same | same page |
| Without isolation, code in the container can use the execution role | **Twin choice**, inferred: AWS documents that isolation removes the credentials, and that LMI containers can fetch `s3://` model IDs themselves | same page; [LMI deploy guide](https://docs.djl.ai/master/docs/serving/serving/docs/lmi/deployment_guide/deploying-your-endpoint.html) |
| A model in a VPC with no internet route needs an S3 VPC endpoint; the default gateway endpoint policy allows full access | Same | [Host models in a VPC](https://docs.aws.amazon.com/sagemaker/latest/dg/host-vpc.html), [gateway endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html) |
| `CreateModel` with `ModelPackageName` runs the registry version's container | Same | CreateModel / ContainerDefinition API reference |
| Studio `PublicInternetOnly` (the default) has direct internet access; `VpcOnly` sends all traffic through your subnets | Same | CreateDomain API reference, [Studio and internet access](https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-and-internet-access.html) |
| SSM access: not possible on a network-isolated container; AWS recommends dev/test only | Same | [Access containers through SSM](https://docs.aws.amazon.com/sagemaker/latest/dg/ssm-access.html) |
| A KMS key can't be used on an instance type with local storage | Flagged by the checker | [Encryption at rest](https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest-nbi.html), [instance storage table](https://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/) |
| IAM: explicit Deny wins; SCPs and VPC endpoint policies filter; negated condition operators are true when the key is missing; `...IfExists` and `Null` | Same, for the operators the lab uses. No permission boundaries or sessions. No resource-based policies on SageMaker AI resources (AWS: SageMaker AI doesn't support them) | [Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html), [SageMaker AI and IAM](https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_service-with-iam.html) |
| What a framework does with a pickle-based weights file | **Twin choice:** the worst case (it unpickles it) | not documented (it varies by framework and version) |
| Model Registry approval | A status anyone with `UpdateModelPackage` can set; nothing checks the files | [Update approval status](https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html) |

The request bodies in `setups/` and the rendered `cloud/requests/` were checked against the botocore 1.43.118 service
models (`sagemaker`, `scheduler`): required members, unknown members, enums, lengths. `cloud/base.yaml` passes
`cfn-lint` 1.58.0. Nothing in `cloud/` has been deployed by us: see GUIDED-BUILD.md.

## Troubleshooting

- **`make challenge` exits with an error.** Expected until you finish: the last line tells you how many tests fail.
- **`make test` fails after you edited a setup.** `git diff setups/` shows what you changed; `git checkout setups/` undoes it.
- **Windows:** `python run_tests.py`, `python checker.py first-draft`, and so on.
