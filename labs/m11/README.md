# Lab M11: review TSG Helpdesk's Bedrock Terraform before it ships, then deploy the hardened version

Companion to lessons **11.1 to 11.6** of *AI Security Engineer* (The Sec Guy). About 60 minutes for Steps 1 to 6,
**$0**, all on your laptop: **Python 3.11+ only**, no packages, no AWS account, no Terraform. Step 7 is optional: it
deploys the hardened Helpdesk into **your own** sandbox account with Terraform, costs roughly $0.02 an hour while it
runs, and ends with `make down`.

**Guided build (your own account, optional):** [`GUIDED-BUILD.md`](GUIDED-BUILD.md) builds the same hardened Helpdesk by
hand, console and CLI, then proves each control with five requests, one changed setting, cost and teardown.

You are still the cloud security engineer at **AnyCompany** (fictional; "AnyCompany" is the placeholder name AWS uses
in its own documentation). After M10, the platform team wants to ship **TSG Helpdesk v2** to production on Amazon
Bedrock, deployed with Terraform. A developer opened a pull request on Friday: "it works, ship it". That is the
**first draft**. You review its plan, show what it would let an attacker do, and compare it with a **hardened**
version that passes every control from this module.

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Run a plan checker over the first draft's Terraform plan: 15 findings | 11.1 to 11.5 |
| **Break** | Replay 7 attacks and mistakes against the first draft, and see which ones AnyCompany would even notice | 11.1 to 11.5 |
| **Fix** | Read the hardened Terraform, check its plan (0 findings) and replay: 0 of 7, the Helpdesk still works | 11.1 to 11.5 |
| **Prove** | `make test`: one test per control | 11.6 |
| **Challenge** | Tighten the org's Region guard, write next sprint's bedrock-mantle endpoint policy, write a checker rule. No solution included | 11.2, 11.4, 11.5 |
| **Deploy (optional)** | `make up` the hardened Helpdesk in your sandbox, ask it a question, find the prompt in the encrypted log, `make down` | 11.6 |

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m11`.

## What's in this folder

| File | What it is |
|---|---|
| `terraform/first-draft/` | The pull request: Lambda in a VPC with a NAT gateway, a bedrock-runtime endpoint with no policy, `bedrock:*` on `*`, a global inference profile, logging to an unencrypted log group kept forever. **Review only: don't deploy it** |
| `terraform/hardened/` | The version that passes: no internet path, a custom endpoint policy, one model through one US profile, two KMS keys, invocation logging with retention, a trail for Bedrock data events and endpoint network activity |
| `twin/first-draft.plan.json`, `twin/hardened.plan.json` | The **offline twin**: each folder's real `terraform show -json` plan, made with mock credentials and no AWS calls (`make twin`) |
| `checker.py` | 16 rules (`M11-01` to `M11-16`) over a plan, plus `M11-17`, which you write |
| `attack.py` | 7 attacks and mistakes, 2 legitimate requests, checked against the policies **in the plan**, the org SCPs and the network; and for each one, what AnyCompany's logs would show |
| `iam_eval.py` | The M10 **teaching model** of AWS policy evaluation, now with VPC endpoint policies (see below) |
| `plan.py` | Reads a plan JSON (values, and what each attribute references) |
| `anycompany.json` | The company: principals, approved models, and the residency rule: Helpdesk data is processed in US Regions only |
| `org/` | Org SCPs: `FullAWSAccess`, the first draft's Region guard, and the current one (`scp-region-guard.json`: challenge) |
| `policies/endpoint-policy-mantle.json` | Next sprint's bedrock-mantle endpoint policy, copied from the AWS example (challenge) |
| `policies/ops-tools-mantle-role.json` | Next sprint's ops tool role: `bedrock-mantle:*` on `*` for now (challenge) |
| `package.py` | Zips `lambda/handler.py` for Terraform |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 15 tests for the lab, 7 for the challenge |

**About the twin.** Terraform can tell you what it is *about* to build: `terraform plan -out tfplan` then
`terraform show -json tfplan`. That JSON holds every policy, flag and setting before anything exists, which is the
cheapest moment to catch a mistake. The two plans in `twin/` were made from the two folders here with OpenTofu
1.13.2 and AWS provider 6.70.0 (OpenTofu writes the same JSON format as Terraform). To make policies readable at
plan time, the Terraform builds ARNs from `var.account_id` instead of from resources that don't exist yet. You can
run the checker on **your own** plans too: `python3 checker.py my-plan.json`.

**About `iam_eval.py`.** It is not the AWS policy engine. On top of the M10 rules (implicit deny, explicit deny wins,
SCPs only limit, missing condition keys), it adds what lesson 11.2 needs: a request through a VPC endpoint must
**also** be allowed by the endpoint policy, the default endpoint policy "grants full access to the endpoint", and a
bare account ID as an endpoint-policy principal means that account's root user only
([AWS docs](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)). It does not model other
resource-based policies, RCPs, permissions boundaries or session policies. For real policies, use IAM Access Analyzer
and test in a sandbox.

**About cross-Region checks.** For a geographic profile AWS "evaluates authorization for the inference profile
resource, the foundation model in the source Region, and the foundation model in each candidate destination Region",
and the model checks "carry the destination Regions"; for a global profile the last check is the Region-less ARN
`arn:aws:bedrock:::foundation-model/...`, "for which `aws:RequestedRegion` is `unspecified`"
([geographic](https://docs.aws.amazon.com/bedrock/latest/userguide/geographic-cross-region-inference.html),
[global](https://docs.aws.amazon.com/bedrock/latest/userguide/global-cross-region-inference.html)). `attack.py` builds
its checks exactly that way. The `us.` Claude Haiku 4.5 profile called from `us-east-1` can route to `us-east-1`,
`us-east-2` and `us-west-2` ([model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-haiku-4-5.html)).

**About the data and safety.** Account IDs (`111122223333`, `444455556666`, `777788889999`, `123456789012`), the org
ID `o-a1b2c3d4e5` and every ARN are AWS documentation example values. Model IDs are from the AWS model cards (checked
22 Oct 2026); models retire, so check the current list. Nothing in Steps 1 to 6 contacts AWS or anything else. Test
15 fails if a real-looking account ID or access key creeps in.

## Needs

- Python **3.11 or newer**. Check with `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 7 only: Terraform 1.6+ (or OpenTofu), the AWS CLI v2, and your own sandbox account (lesson 0.7).

## Step 1 · Check the first draft's plan

```bash
cd labs/m11
make check
```

- `cd labs/m11`: or wherever you put this folder
- `make check`: same as `python3 checker.py twin/first-draft.plan.json`

Real output (Linux, Python 3.13):

```text
--- M11 plan checker · twin/first-draft.plan.json ---

  HIGH    M11-01  aws_iam_role_policy.app_invoke [LetTheAppUseBedrock]
          The Helpdesk role allows bedrock:*, bedrock-mantle:*: every model, every setting, both endpoints.
          fix: List only bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream (lesson 11.1).
  HIGH    M11-02  aws_iam_role_policy.app_invoke [LetTheAppUseBedrock]
          Can invoke ANY model, through any route, in any Region (Resource "*").
          fix: Name the profile ARN, plus the model ARN in each destination Region with a bedrock:InferenceProfileArn condition (AWS's geographic example policy).
  HIGH    M11-05  aws_vpc_endpoint.bedrock_runtime
          No endpoint policy, so the default applies: any principal, any action, any resource. Credentials from ANY AWS account work through this endpoint.
          fix: Attach a policy: only your account or org (aws:PrincipalAccount / aws:PrincipalOrgID), only the invoke actions (lesson 11.2).
  HIGH    M11-06  aws_nat_gateway.nat, aws_internet_gateway.igw
          The app's VPC can reach the internet: it can call bedrock-mantle or any other public endpoint, and the endpoint policy never sees those calls.
          fix: Remove the NAT/internet route; add an interface endpoint for each AWS service the app needs.
  HIGH    M11-08  aws_cloudwatch_log_group.prompts
          Prompt logs (every question and answer) are not encrypted with a key you control: logs read access in IAM is all anyone needs to read them.
          fix: Set kms_key_id to a customer managed key whose policy limits who can decrypt (lesson 11.3).
  HIGH    M11-12  aws_iam_role.bedrock_logging
          Bedrock's service principal may assume this role with no check of which account or resource it acts for (no aws:SourceAccount and aws:SourceArn): confused deputy.
          fix: Add both conditions, as in AWS's invocation-logging example (lesson 11.4).
  HIGH    M11-15  aws_lambda_function.helpdesk
          MODEL_ID global.anthropic.claude-haiku-4-5-20251001-v1:0 is a GLOBAL profile: requests can be processed in any supported commercial Region. Residency rule: Helpdesk prompts and answers may only be processed in US Regions.
          fix: Use the geographic profile (us.) and allow-list only its destination Regions.
  MEDIUM  M11-03  aws_iam_role_policy.app_invoke
          An app role that can also: CreateInference, PutAccountDataRetention, CreateModelCustomizationJob, CreateModelInvocationJob, CreateProvisionedModelThroughput, DeleteModelInvocationLoggingConfiguration, PutModelInvocationLoggingConfiguration, PutUseCaseForModelAccess.
          fix: Remove them. Logging belongs to the security admin; Marketplace subscriptions to the platform team, once per approved model (lesson 11.1).
  MEDIUM  M11-07  aws_security_group.endpoint
          Endpoint accepts HTTPS from 10.20.0.0/16: anything in that range can use it.
          fix: Allow 443 only from the app's security group.
  MEDIUM  M11-09  aws_cloudwatch_log_group.prompts
          Prompt logs never expire (no retention set).
          fix: Set retention_in_days to what investigations need, and an S3 lifecycle rule (lesson 11.4).
  MEDIUM  M11-10  aws_bedrock_model_invocation_logging_configuration.this
          CloudWatch only: request or response bodies over 100 KB, and binary data, can only go to S3, so they are not logged.
          fix: Add large_data_delivery_s3_config (an encrypted bucket).
  MEDIUM  M11-12  aws_iam_role_policy.bedrock_logging
          The logging role can do far more than write one log stream.
          fix: logs:CreateLogStream + logs:PutLogEvents on the log group's aws/bedrock/modelinvocations stream only.
  MEDIUM  M11-14  account
          No customer managed keys: nothing but IAM decides who can read the prompt logs.
          fix: Create keys for prompt logs and for audit logs, with separate readers (lesson 11.3).
  MEDIUM  M11-16  account
          No CloudTrail trail: management events stay 90 days in event history; data events (including bedrock-mantle inference) and endpoint network activity are not recorded at all.
          fix: Add a trail with log file validation and KMS, selecting the Bedrock data events you need.
  LOW     M11-11  aws_bedrock_model_invocation_logging_configuration.this
          Also logs image, embedding, video data, for every model in the account and Region.
          fix: Log only the modalities you need: logging applies to all models that use them.

7 HIGH, 7 MEDIUM, 1 LOW  (15 findings)
```

Read the seven HIGH findings as one story:

- **11.1** (`M11-01`, `M11-02`): the role was copied from the old Helpdesk: `bedrock:*` and `bedrock-mantle:*` on `*`.
- **11.2** (`M11-05`, `M11-06`): there *is* a bedrock-runtime endpoint, but with no policy, so the default applies;
  and a NAT gateway means the function can reach every public endpoint anyway, including bedrock-mantle.
- **11.3** (`M11-08`): every question and answer lands in a log group no key of yours protects.
- **11.4** (`M11-12`): the role Bedrock uses to write logs trusts *any* Bedrock request, not just your account's.
- **11.5** (`M11-15`): `MODEL_ID` is a `global.` profile: about 10% cheaper, and requests may be processed in any
  supported commercial Region, against AnyCompany's "US only" rule.

The checker exits with code 1 when it finds anything HIGH, so it can fail a pull request in CI
(`terraform show -json tfplan > plan.json && python3 checker.py plan.json`).

## Step 2 · Break it: what would this let happen, and who would notice?

```bash
make attack
```

Same as `python3 attack.py --plan first-draft`.

Real output:

```text
--- M11 lab · FIRST-DRAFT · twin/first-draft.plan.json ---
    org SCPs: FullAWSAccess, scp-region-guard.first-draft.json · endpoint policy: aws_vpc_endpoint.bedrock_runtime (default policy)
    (iam_eval.py: a teaching model of AWS policy evaluation; nothing is sent to AWS)

Attacks and mistakes
  [X1] ALLOWED  Outsider's own AWS keys, used from inside the VPC through AnyCompany's endpoint
         why:  every check passed: bedrock:InvokeModel
         seen: CloudTrail: the API call is recorded in THEIR account's CloudTrail, not AnyCompany's
         seen: AnyCompany: nothing (no trail records network activity on its endpoint)
  [X2] ALLOWED  Stolen Helpdesk role: Converse with a model nobody approved (Claude Opus 4.7)
         why:  every check passed: bedrock:InvokeModel
         seen: CloudTrail event history: management event (90 days, free)
         seen: Prompt log: question + answer in /tsg-helpdesk/bedrock/model-invocations (no KMS key of yours, kept FOREVER)
  [X3] ALLOWED  Stolen Helpdesk role: the approved model, called directly in us-west-2 (no profile)
         why:  every check passed: bedrock:InvokeModel
         seen: CloudTrail event history: management event (90 days, free)
         seen: Prompt log: question + answer in /tsg-helpdesk/bedrock/model-invocations (no KMS key of yours, kept FOREVER)
  [X4] ALLOWED  Stolen Helpdesk role: the GLOBAL profile (may run outside the US)
         why:  every check passed: bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel
         seen: CloudTrail event history: management event (90 days, free)
         seen: Prompt log: question + answer in /tsg-helpdesk/bedrock/model-invocations (no KMS key of yours, kept FOREVER)
  [X5] ALLOWED  Stolen Helpdesk role: DeleteModelInvocationLoggingConfiguration
         why:  every check passed: bedrock:DeleteModelInvocationLoggingConfiguration
         seen: CloudTrail event history: management event (90 days, free)
  [X6] ALLOWED  Stolen Helpdesk role: CreateProvisionedModelThroughput (billed by the hour)
         why:  every check passed: bedrock:CreateProvisionedModelThroughput
         seen: CloudTrail event history: management event (90 days, free)
  [X7] ALLOWED  A code change: the function calls bedrock-mantle (Anthropic SDK) from inside the VPC
         why:  every check passed: bedrock-mantle:CreateInference
         seen: CloudTrail: NOTHING (mantle inference is a data event, and no trail selects it)
         seen: Prompt log: NOT captured (invocation logging covers bedrock-runtime only)

Legitimate traffic · must keep working
  [L1] ALLOWED  Helpdesk function: Converse via its configured profile (global.anthropic.claude-haiku-4-5-20251001-v1:0)
         why:  every check passed: bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel
         seen: CloudTrail event history: management event (90 days, free)
         seen: Prompt log: question + answer in /tsg-helpdesk/bedrock/model-invocations (no KMS key of yours, kept FOREVER)
  [L2] ALLOWED  Security admin: GetModelInvocationLoggingConfiguration
         why:  every check passed: bedrock:GetModelInvocationLoggingConfiguration
         seen: CloudTrail event history: management event (90 days, free)

7 of 7 attacks and mistakes allowed; 2 of 2 legitimate requests allowed.
```

Three lines deserve a second look:

- **X1, the outsider.** Someone inside the VPC (an insider, or malware on a build box) uses keys from **their own**
  AWS account. The default endpoint policy lets them through. Their call is recorded in *their* CloudTrail, and if
  they switched on invocation logging, their account keeps every prompt they send. AnyCompany's account records
  nothing. That is a quiet way to move data out through your own private endpoint.
- **X4, the global profile.** Allowed because the org Region guard lists `unspecified`, which is AWS's own first
  suggestion for making global profiles work ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/global-cross-region-inference.html)).
  It now works for every team in the organization.
- **X7, the second door.** One SDK change and the function talks to bedrock-mantle through the NAT gateway. No
  CloudTrail record (inference there is a data event, and there is no trail), and no prompt log: invocation logging
  covers bedrock-runtime only ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)).

## Step 3 · Read the fix: the hardened Terraform

Open `terraform/hardened/`. Every file starts with a comment saying which lesson it implements.

| Control | First draft | Hardened | File |
|---|---|---|---|
| 11.1 Role | `bedrock:*`, `bedrock-mantle:*` on `*` | `InvokeModel` + `InvokeModelWithResponseStream` on one profile, and the model in its 3 destination Regions only with `bedrock:InferenceProfileArn` | `app.tf` |
| 11.2 Network | NAT gateway; endpoint SG open to the VPC CIDR | No internet or NAT route; endpoint SG accepts 443 from the function's SG only | `network.tf` |
| 11.2 Endpoint policy | none (default: full access) | only `aws:PrincipalAccount` = AnyCompany **and** `aws:PrincipalArn` = the Helpdesk role; invoke actions only | `network.tf` |
| 11.3 Keys | none | `prompts` key (logs) and `audit` key (trail), rotation on, service statements with `aws:SourceAccount`/`aws:SourceArn` or encryption context, the logging role only via CloudWatch Logs (`kms:ViaService`), decrypt for an MFA-only investigator role | `kms.tf` |
| 11.4 Prompt logs | CloudWatch only, all modalities, no key, kept forever | text only, KMS, 30 days; S3 bucket for bodies over 100 KB with KMS, lifecycle, TLS-only, ACLs off, public access blocked | `logging.tf` |
| 11.4 Logging role | trusts any Bedrock request; `logs:*` on `*` | `aws:SourceAccount` + `aws:SourceArn`; one log stream | `logging.tf` |
| 11.4 Trail | none | multi-Region trail, log file validation, KMS; Bedrock mantle data events, endpoint network activity, guardrail data events only (management events: 90-day event history, or your org trail) | `trail.tf` |
| 11.5 Residency | `global.` profile | `us.` profile | `variables.tf` |
| Cost | `MAX_TOKENS` 4096 | 300 (LLM06:2026) | `variables.tf` |

Then check and replay it:

```bash
make check-hardened
make attack-safe
```

- `make check-hardened`: same as `python3 checker.py twin/hardened.plan.json`
- `make attack-safe`: same as `python3 attack.py --plan hardened`

Real output:

```text
--- M11 plan checker · twin/hardened.plan.json ---


0 HIGH, 0 MEDIUM, 0 LOW  (0 findings)
No findings: every M11 control this checker knows about is in the plan.
```

```text
--- M11 lab · HARDENED · twin/hardened.plan.json ---
    org SCPs: FullAWSAccess, scp-region-guard.json · endpoint policy: aws_vpc_endpoint.bedrock_runtime
    (iam_eval.py: a teaching model of AWS policy evaluation; nothing is sent to AWS)

Attacks and mistakes
  [X1] DENIED   Outsider's own AWS keys, used from inside the VPC through AnyCompany's endpoint
         why:  the endpoint policy aws_vpc_endpoint.bedrock_runtime doesn't allow it  [check: bedrock:InvokeModel on arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-7]
         seen: CloudTrail: the API call is recorded in THEIR account's CloudTrail, not AnyCompany's
         seen: AnyCompany trail: network activity event, as the endpoint owner, refused at the endpoint (filter: errorCode VpceAccessDenied)
  [X2] DENIED   Stolen Helpdesk role: Converse with a model nobody approved (Claude Opus 4.7)
         why:  no identity policy allows it (implicit deny)  [check: bedrock:InvokeModel on arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-7]
         seen: CloudTrail event history: management event, with an access-denied errorCode (90 days, free)
  [X3] DENIED   Stolen Helpdesk role: the approved model, called directly in us-west-2 (no profile)
         why:  no identity policy allows it (implicit deny)  [check: bedrock:InvokeModel on arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0]
         seen: CloudTrail event history: management event, with an access-denied errorCode (90 days, free)
  [X4] DENIED   Stolen Helpdesk role: the GLOBAL profile (may run outside the US)
         why:  no identity policy allows it (implicit deny)  [check: bedrock:InvokeModel on arn:aws:bedrock:us-east-1:111122223333:inference-profile/global.anthropic.claude-haiku-4-5-20251001-v1:0]
         seen: CloudTrail event history: management event, with an access-denied errorCode (90 days, free)
  [X5] DENIED   Stolen Helpdesk role: DeleteModelInvocationLoggingConfiguration
         why:  no identity policy allows it (implicit deny)  [check: bedrock:DeleteModelInvocationLoggingConfiguration on *]
         seen: CloudTrail event history: management event, with an access-denied errorCode (90 days, free)
  [X6] DENIED   Stolen Helpdesk role: CreateProvisionedModelThroughput (billed by the hour)
         why:  no identity policy allows it (implicit deny)  [check: bedrock:CreateProvisionedModelThroughput on arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-7]
         seen: CloudTrail event history: management event, with an access-denied errorCode (90 days, free)
  [X7] DENIED   A code change: the function calls bedrock-mantle (Anthropic SDK) from inside the VPC
         why:  no network path: no NAT or internet gateway, and no bedrock-mantle endpoint in this VPC
         seen: nothing: the request never left the VPC

Legitimate traffic · must keep working
  [L1] ALLOWED  Helpdesk function: Converse via its configured profile (us.anthropic.claude-haiku-4-5-20251001-v1:0)
         why:  every check passed: bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel
         seen: CloudTrail event history: management event (90 days, free)
         seen: Prompt log: question + answer in /tsg-helpdesk/bedrock/model-invocations (your KMS key, kept 30 days)
  [L2] ALLOWED  Security admin: GetModelInvocationLoggingConfiguration
         why:  every check passed: bedrock:GetModelInvocationLoggingConfiguration
         seen: CloudTrail event history: management event (90 days, free)

0 of 7 attacks and mistakes allowed; 2 of 2 legitimate requests allowed.
```

Notice two things. Each attack on the role is refused by the **role alone** (test 06 checks this with only
`FullAWSAccess` above it): defence in depth means each layer holds by itself. And X1 is now visible to AnyCompany: the
trail records network activity on its endpoint, and AWS says these events "can help VPC endpoint owners detect when
credentials from outside their organization attempt to access their VPC endpoints"; `errorCode` can be filtered on
`VpceAccessDenied` ([AWS docs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-network-events-with-cloudtrail.html)).
One caveat: that page lists "Amazon Bedrock" (event source `bedrock.amazonaws.com`) without saying which Bedrock
endpoint services it covers, and lists no `bedrock-mantle` source. That the runtime endpoint's refusals show up is
our reading of it; if you do Step 7, check it.

## Step 4 · Prove it: `make test`

```bash
make test
```

Same as `python3 run_tests.py`.

Real output:

```text
[PASS] first draft: the checker flags 7 HIGH controls (wildcards, any model, default endpoint policy, NAT, no key, deputy, global)
[PASS] first draft: all 7 attacks and mistakes are allowed
[PASS] first draft: an outsider's own keys work through the endpoint, and AnyCompany has no record of it
[PASS] first draft: a bedrock-mantle call from the VPC works and leaves no CloudTrail record and no prompt log
[PASS] hardened: the checker finds nothing
[PASS] 11.1 hardened: the stolen role can't pick another model, Region, setting or purchase
[PASS] 11.2 hardened: the endpoint refuses outsiders, the VPC has no way out, a mantle call can't leave
[PASS] 11.3 hardened: prompt logs, both buckets and the trail use customer managed keys with rotation on
[PASS] 11.4 hardened: text logging with a large-data bucket, 30-day retention, a guarded role, a trail with network activity
[PASS] 11.5 hardened: the app uses the us. profile; every Region its call can touch is a US Region
[PASS] both plans: the Helpdesk's own call and the security admin's check are allowed
[PASS] 11.5 org SCP: even a team allowed to call any model can't use a global profile (unspecified is not allowed)
[PASS] iam_eval: the default endpoint policy lets anyone through; a bare account ID means its root user only
[PASS] checker: remove the endpoint policy from the hardened plan and M11-05 fires (it reads values, not names)
[PASS] safety: only AWS documentation account IDs, no access keys, no real-looking secrets in the lab
----------------------------------------------------------------------
Ran 15 tests in 0.023s

OK

ALL TESTS PASSED (15 run)
```

## Step 5 · The SCP gotcha, by hand (5 minutes)

Before the challenge, read `org/scp-region-guard.json`. It allows `us-east-1`, `us-east-2` and `us-west-2`, for
**every** service, because the Helpdesk's US profile can route to all three. AWS documents this trade-off: with a
Region allow-list you "must either allow access to all destination Regions listed in the Geographic cross-Region
inference profile for your source Region or add an inference-profile exception"
([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/geographic-cross-region-inference.html)). AnyCompany
runs everything else in `us-east-1` only, so two extra Regions are open to every team for every service, just so the
model can be routed there. The exception is the better tool: the destination-Region model checks carry
`bedrock:InferenceProfileArn`, so "you can use `bedrock:InferenceProfileArn` in a Region-deny SCP to exempt
cross-Region routing without adding those destination Regions to the Region allowlist for other services and actions",
and "This exemption can't bypass the Region restriction on the originating call" (same page).

Try it in your head with `python3 attack.py --plan hardened --verbose`: the `L1` checks show `aws:RequestedRegion`
set to each destination Region, with `bedrock:InferenceProfileArn` set.

## Step 6 · Your turn: `make challenge`

```bash
make challenge
```

Same as `python3 run_tests.py --challenge`.

Real output before your fix (last lines):

```text
[PASS] safety: only AWS documentation account IDs, no access keys, no real-looking secrets in the lab
[FAIL] challenge 11.5: outside us-east-1, AnyCompany can't create buckets or call models directly
[PASS] challenge 11.5: the Helpdesk's us. profile still routes to us-east-2 and us-west-2
[PASS] challenge 11.5: a global profile is still refused
[FAIL] challenge 11.2: outsiders are refused at the mantle endpoint; the ops role alone refuses unapproved models
[PASS] challenge 11.2: AnyCompany's ops tool can still use the approved mantle model
[FAIL] challenge 11.4: M11-17 flags the first draft, and a hardened plan whose trail lost its mantle selector
[PASS] challenge 11.4: M11-17 stays quiet on the hardened plan
  why test_16_region_guard_us_east_1_only: AssertionError: True is not false : s3:CreateBucket in us-west-2 is still allowed
  why test_19_mantle_endpoint_policy: AssertionError: True is not false : an outsider's keys still work through the mantle endpoint
  why test_21_rule_m11_17_flags_missing_mantle_events: + ['M11-17'] : rule_trail_covers_mantle() finds nothing in the first draft, which has no trail at all
----------------------------------------------------------------------
Ran 22 tests in 0.020s

FAILED (failures=3)

3 of 22 TESTS FAILED (22 run)
```

Three gaps, three fixes. Each test's message is a hint.

1. **Region guard (lesson 11.5).** Rewrite `org/scp-region-guard.json` so that everything outside `us-east-1` is
   denied, **except** requests that carry the Helpdesk's approved US profile in `bedrock:InferenceProfileArn`. Use
   `ArnNotLike` (a negated operator: with no profile in the request it is *true*, so the deny applies). Keep the
   global profile blocked and the Helpdesk working (tests 17 and 18).
2. **Next sprint's mantle access (lesson 11.2).** The ops team will call Claude Haiku 4.5 on bedrock-mantle from this
   VPC with the Anthropic SDK (on mantle, this model supports the Messages API only, per its model card). Two files:
   - `policies/endpoint-policy-mantle.json` is AWS's example, which "grants access to the listed Amazon Bedrock Mantle
     actions for all principals on all resources"
     ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html)). Limit it to
     AnyCompany's organization: the identity perimeter, as for the runtime endpoint.
   - `policies/ops-tools-mantle-role.json` is the ops tool's role, `bedrock-mantle:*` on `*`. Limit it to
     `bedrock-mantle:CreateInference` on the approved mantle model (`anthropic.claude-haiku-4-5`, in `anycompany.json`;
     mantle model IDs aren't the runtime IDs). Hint: the Service Authorization Reference lists the condition key
     `bedrock-mantle:Model` for `CreateInference`. AWS doesn't say whether a VPC endpoint policy evaluates that key, so
     test 19 checks the model rule in the role alone.
3. **Rule M11-17 (lesson 11.4).** Write `rule_trail_covers_mantle()` in `checker.py`. The docstring says what to
   return. It must flag a plan with no trail **and** a plan whose trail lost its mantle selector, and stay quiet on the
   hardened plan.

Done when `make challenge` says `ALL TESTS PASSED (22 run)` and `make check` shows 16 findings (8 HIGH). No solution
is included.

## Step 7 (optional) · Deploy the hardened Helpdesk in your own sandbox account

Everything above runs offline. This step builds the real thing. **Only in your own sandbox account** (lesson 0.7),
never in a work account without permission (lesson 0.8). We wrote and validated this Terraform offline
(`terraform validate` and an offline plan) but did not apply it in a live account for this README, so read every
prompt before you type `yes`.

**What it costs (us-east-1, October 2026 prices).**

| Item | Price | Source |
|---|---|---|
| bedrock-runtime interface endpoint, 2 network interfaces | $0.01 per hour each, "Each partial VPC endpoint-hour consumed is billed as a full hour"; data $0.01 per GB | [PrivateLink pricing](https://aws.amazon.com/privatelink/pricing/) |
| 2 KMS keys | "$1/month (prorated hourly)" each; "no charge" while scheduled for deletion; 20,000 requests a month free | [KMS pricing](https://aws.amazon.com/kms/pricing/) |
| Trail: data events and network activity events | $0.10 per 100,000 events delivered | [CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/) |
| Lambda, CloudWatch Logs, S3 | per request and per GB; this step sends 3 requests and writes a few KB | AWS pricing pages |
| Claude Haiku 4.5 tokens | per token, "billed through AWS Marketplace", shown "under the model provider (not under Amazon Bedrock)" in Cost Explorer; 3 questions, at most 300 output tokens each | [model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-haiku-4-5.html), [Bedrock pricing](https://aws.amazon.com/bedrock/pricing/) |

So roughly **$0.02 an hour** for the endpoint plus the keys' hourly share, and the per-use items. Set
`availability_zones = ["us-east-1a"]` to halve the endpoint cost. Create the $5 budget from M10 (Step 8b) **first**,
and run `make down` the same day.

**7a · Enable the model once, as an admin (lesson 11.1).** The Helpdesk role has no AWS Marketplace permissions, on
purpose. AWS: "If you can't assume AWS Marketplace permission, someone with AWS Marketplace permissions must enable
the model for the account as a one-time step", and Anthropic models need the first-time use form first
([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html)). From your own admin session:

```bash
aws bedrock-runtime converse --region us-east-1 --model-id us.anthropic.claude-haiku-4-5-20251001-v1:0 \
  --messages '[{"role":"user","content":[{"text":"hello"}]}]' --inference-config maxTokens=20
```

If that returns `AccessDeniedException` about the use case, submit the Anthropic form from the model catalog in the
Bedrock console, wait a few minutes, and retry.

**7b · Deploy.** If your sandbox already has a Bedrock invocation logging configuration in us-east-1, this
**replaces** it (one per account and Region), and `make down` deletes it.

```bash
make up
make smoke
make verify
```

- `make up`: terraform init + apply, with account_id from `aws sts get-caller-identity`; type yes
- `make smoke`: asks the Helpdesk "How do I reset my VPN token?" through the VPC endpoint
- `make verify`: the logging configuration, then the newest prompt log event

What to look for:

- In the prompt log event: `"operation": "Converse"`, `"modelId"` (the profile), `identity.arn` with
  `tsg-helpdesk-app`, `requestMetadata` with `"app": "tsg-helpdesk"`, and your question in `input.inputBodyJson`.
  "Every field in the record is populated by Amazon Bedrock automatically, with one exception: `requestMetadata` is
  the only field supplied by the caller" ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)).
  Don't trust it for attribution; trust `identity.arn`.
- In CloudTrail event history (console, event source `bedrock.amazonaws.com`): the `Converse` management event, with
  no prompt text in it. For a cross-Region call CloudTrail logs the request "in your source Region"; look for
  `inferenceRegion` to see where it ran ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html)).
- Try reading the log group as a plain admin without `kms:Decrypt` on the prompts key: CloudWatch Logs says a principal
  calling `GetLogEvents`, `FilterLogEvents` or `StartQuery` on a log group with a customer managed key "needs
  additional AWS KMS permissions" ([AWS docs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)).
  The key's first statement delegates to IAM, so an identity with `kms:Decrypt` on `*` still gets in: search your
  IAM policies for that.

**7c · Re-check your real plan with the checker** (optional): `cd terraform/hardened && terraform plan -out tfplan
-var account_id=<yours> && terraform show -json tfplan > ../../my-plan.json`, then `python3 checker.py my-plan.json`.

**Teardown** (today, not later):

```bash
make down
```

- `make down`: terraform destroy; type yes

The two KMS keys go into a 7-day waiting period (the minimum AWS allows: "a waiting period of 7 – 30 days",
[AWS docs](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html)), with no charge while scheduled
for deletion. The logs in the buckets are deleted with them (`force_destroy`, lab only).

## Troubleshooting

| Problem | Fix |
|---|---|
| `make: command not found` (Windows) | Run the `python` command shown next to each `make` step |
| `SyntaxError` or `TypeError` on start | You need Python 3.11+: `python3 --version` |
| `json.decoder.JSONDecodeError` after editing a policy | A typo, often a trailing comma. `python3 -m json.tool org/scp-region-guard.json` shows where |
| A legitimate request (L1, L2, test 17 or 20) turns DENIED | Your statement is too wide. Run `python3 attack.py --plan hardened --verbose` and read the **why** line |
| Test 15 fails | You added a real-looking account ID or key. Use the documentation values |
| `make twin` fails | It needs Terraform or OpenTofu (`make twin TF=tofu`) and internet once, to download the AWS provider |
| `make up`: the endpoint "does not support the availability zone" | Some zones don't offer every endpoint. List them: `aws ec2 describe-vpc-endpoint-services --service-names com.amazonaws.us-east-1.bedrock-runtime --query 'ServiceDetails[0].AvailabilityZones'` and set `availability_zones` |
| `make up`: `MalformedPolicyDocumentException` on a KMS key | IAM hadn't finished creating the investigator role. Run `make up` again |
| `make smoke` returns `AccessDeniedException` | Do Step 7a (enable the model once as an admin), then retry |
| `make smoke` times out | The function can only reach the bedrock-runtime endpoint. Check the endpoint is `available` and private DNS is on |

## What to write in your findings notebook (lesson 0.5)

Three lines: what you found (a first-draft Bedrock deployment with a wildcard role, a default VPC endpoint policy plus
a NAT path, unencrypted prompt logs kept forever, a confused-deputy logging role and a global inference profile against
a US residency rule), how you fixed it (least-privilege role pinned to one profile, a custom endpoint policy and no
internet path, two customer managed keys, retention, a guarded logging role, a data-event and network-activity trail,
a geographic profile and a Region guard with an inference-profile exception), and how you'd spot it (plan checks in
CI, `VpceAccessDenied` network activity events, `AWS::BedrockMantle::Project` data events, invocation logs filtered by
`identity.arn`, `inferenceRegion` in CloudTrail).

## Sources

- VPC interface endpoints for Amazon Bedrock: <https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html>
- Control access to VPC endpoints using endpoint policies: <https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html>
- IAM data perimeters: <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_data-perimeters.html> · global condition keys: <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html>
- Model invocation logging: <https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html>
- CloudTrail for Bedrock: <https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html> · for bedrock-mantle: <https://docs.aws.amazon.com/bedrock/latest/userguide/logging-cloudtrail-mantle.html> · network activity events: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-network-events-with-cloudtrail.html>
- CloudTrail bucket policy: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html> · KMS key policy: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html>
- CloudWatch Logs encryption with KMS: <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html>
- Cross-Region inference: <https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html> · geographic: <https://docs.aws.amazon.com/bedrock/latest/userguide/geographic-cross-region-inference.html> · global: <https://docs.aws.amazon.com/bedrock/latest/userguide/global-cross-region-inference.html>
- Claude Haiku 4.5 model card (IDs, profiles, Regions, Marketplace): <https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-haiku-4-5.html>
- Model access and Marketplace subscriptions: <https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html>
- Lambda VPC internet access: <https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc-internet.html>
- Pricing: PrivateLink <https://aws.amazon.com/privatelink/pricing/> · KMS <https://aws.amazon.com/kms/pricing/> · CloudTrail <https://aws.amazon.com/cloudtrail/pricing/> · KMS key deletion: <https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html>
