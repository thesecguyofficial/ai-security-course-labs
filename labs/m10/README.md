# Lab M10: find the over-broad AI permissions, write the SCPs that stop LLMjacking, then hunt it in CloudTrail

Companion to lessons **10.3, 10.4 and 10.5** of *AI Security Engineer* (The Sec Guy). About 60 minutes, **$0**, all on
your laptop. **Nothing to install** (Python standard library only) and **no AWS account needed**. An optional last
step runs the same policies through free AWS tools in your own sandbox account.

You are the new cloud security engineer at **AnyCompany** (a fictional company; "AnyCompany" is the placeholder name
AWS uses in its own documentation). It runs the TSG Helpdesk chatbot on Amazon Bedrock in a production account, and
lets staff try models in a sandbox account. In one sitting you will:

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Run a small policy checker over AnyCompany's IAM policies, SCPs and Bedrock API key inventory, and read why each finding matters | 10.3, 10.4 |
| **Break** | Replay what a thief could do with a leaked long-term Bedrock API key and with the chatbot's stolen role: 10 of 11 requests work | 10.3 to 10.5 |
| **Fix** | Add three SCPs (model allow-list, API-key rules, audit-trail and spend protection) and replay: legitimate traffic still works | 10.3 to 10.5 |
| **Hunt** | Search five days of sample CloudTrail for the LLMjacking timeline: recon, probe, logging switched off, unapproved models, new source, volume | 10.5 |
| **Challenge** | Close two gaps the "safe" setup still has, and write one detection. No solution included | 10.3 to 10.5 |

## What's in this folder

| File | What it is |
|---|---|
| `policy_checker.py` | The checker: 13 rules (`M10-01` to `M10-13`) for AI-specific IAM, SCP and API-key mistakes |
| `attack.py` | 20 requests (11 attacker, 9 legitimate) checked against AnyCompany's policies, `--mode vulnerable` or `--mode safe` |
| `iam_eval.py` | A **teaching model** of AWS policy evaluation (see below). The checker and `attack.py` use it |
| `hunt.py` | Nine CloudTrail hunting rules (`H01` to `H09`; `H09` is yours to write), plus `--naive` |
| `anycompany/` | The company: `principals.json` (accounts, roles, users, API keys), `identity/` policies, `scps/`, `approved-models.json`, and `aws-managed/AmazonBedrockLimitedAccess-v9.json` (the AWS managed policy, copied from the AWS docs) |
| `fixes/` | Three SCPs and a least-privilege policy for the chatbot role |
| `examples/blunt-allowlist-scp.json` | A model allow-list written the blunt way, to show what it breaks |
| `cloudtrail/anycompany-2026-10-09_14.json` | 226 **fake** CloudTrail records: two normal days, a key created on 9 Oct, and two intrusions on 14 Oct |
| `aws-twin/` | Budget files for the optional AWS step |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 17 tests for the lab, 5 for the challenge |

**About `iam_eval.py`.** It is not the AWS policy engine. It models the rules this lab depends on, each from the IAM
documentation: no matching Allow means denied; any matching Deny wins; an SCP never grants anything, it only limits;
SCPs don't apply to the management account; and a condition key missing from the request makes a normal condition
operator false, a negated one true, and `Null` tests presence. It does not model resource-based policies, resource
control policies, permissions boundaries, session policies or VPC endpoint policies. For real policies, use IAM Access
Analyzer (Step 8) and test in a sandbox.

**About multi-check requests.** Some calls are authorized more than once, and `attack.py` checks each one:

- A call through a cross-Region **inference profile** checks the profile **and** the foundation model in every
  destination Region, with the `bedrock:InferenceProfileArn` condition key set
  ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-prereq.html)). In this lab
  a `us.` profile called from `us-east-1` can route to `us-east-1`, `us-east-2` and `us-west-2` (as on the AWS model
  cards for the two approved models); for a `global.` profile the lab checks the model in the caller's Region and
  with an empty Region, the two foundation-model ARNs in AWS's own global-profile example. A real profile lists its
  own Regions.
- A call made with a **Bedrock API key** is also authorized as `bedrock:CallWithBearerToken` (or
  `bedrock-mantle:CallWithBearerToken`), with the key type in the `BearerTokenType` condition key
  ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-permissions.html)).
- `Converse` is authorized as `bedrock:InvokeModel`, and `ConverseStream` as `bedrock:InvokeModelWithResponseStream`
  ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-prereq.html)).
- The **bedrock-mantle** endpoint (OpenAI-compatible and Anthropic Messages APIs) is a separate IAM namespace:
  `bedrock-mantle:CreateInference` on a **project**, with the model in the `bedrock-mantle:Model` condition key
  ([Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock-mantle.html)).

**About the data and safety.** Every account ID (`111122223333`, `444455556666`, `123456789012`), key ID
(`...EXAMPLE`) and ARN is an AWS documentation example value; every IP address is from the documentation ranges in
[RFC 5737](https://www.rfc-editor.org/rfc/rfc5737). Model IDs are copied from the AWS model cards (checked 21 Oct 2026); models retire, so check the current list. The attacker
steps follow Sysdig TRT's published LLMjacking research; nothing here contacts AWS or any other system. Test 17 fails
if a real-looking account ID, IP or access key ever creeps in.

## Needs

- Python **3.11 or newer** (tested on 3.13). Check with `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 8 only: the AWS CLI v2 and credentials for **your own** sandbox account (lesson 0.7).

## Step 1 · Check: find the over-broad permissions

```bash
cd labs-export/m10          # or wherever you put this folder
make check                  # same as: python3 policy_checker.py
```

Real output (Linux, Python 3.13):

```text
--- M10 policy checker · AnyCompany today ---

  HIGH    M10-01  identity/helpdesk-app-role.json [LetTheAppUseBedrock]
          Allows every bedrock action on every resource: any model, delete invocation logging, buy Provisioned Throughput.
          fix: List only the actions the workload calls, on the exact model/profile ARNs (lesson 10.3).
  HIGH    M10-01  identity/helpdesk-app-role.json [LetTheAppUseTheNewEndpointToo]
          Allows every bedrock-mantle action on every resource: any model on the OpenAI-compatible endpoint, plus projects, files and fine-tuning.
          fix: List only the actions the workload calls, on the exact model/profile ARNs (lesson 10.3).
  HIGH    M10-03  identity/platform-admin-role.json [ManageBedrockUsersAndKeys]
          Can create long-term API keys (service-specific credentials) with no service or expiry limit.
          fix: Add conditions on iam:ServiceSpecificCredentialServiceName and iam:ServiceSpecificCredentialAgeDays, and cap them org-wide with an SCP (lesson 10.4).
  HIGH    M10-05  BedrockAPIKey-x7k2 key ACCA1234EXAMPLE1234
          Long-term Bedrock API key that NEVER expires.
          fix: Deactivate it, move the caller to short-term keys or IAM roles; cap expiry with an SCP.
  HIGH    M10-06  BedrockAPIKey-x7k2 key ACCA1234EXAMPLE1234
          Long-term Bedrock API key in account 111122223333, which is not the sandbox.
          fix: AWS: long-term keys are for exploration; use short-term keys or roles in production (lesson 10.4).
  MEDIUM  M10-02  identity/data-science-role.json [TryAnyModelAnywhere]
          Can invoke ANY model in ANY Region, including the most expensive ones.
          fix: Name the approved model and inference-profile ARNs, and back it with an org SCP allow-list.
  MEDIUM  M10-04  identity/helpdesk-app-role.json [LetTheAppUseBedrock]
          Can change or delete Bedrock model invocation logging: attackers check and switch it off.
          fix: Remove it from workload roles; deny it org-wide except your security admin role (SCP).
  MEDIUM  M10-07  BedrockAPIKey-x7k2
          The key's IAM user can invoke any model in any Region and buy Provisioned Throughput (AmazonBedrockLimitedAccess is the console default).
          fix: Replace the managed policy with one that names the approved model ARNs only.
  MEDIUM  M10-07  sandbox-explorer
          The key's IAM user can invoke any model in any Region and buy Provisioned Throughput (AmazonBedrockLimitedAccess is the console default).
          fix: Replace the managed policy with one that names the approved model ARNs only.
  MEDIUM  M10-08  org root
          No SCP allow-lists models: every model AWS adds is usable on day one.
          fix: Add an SCP that denies bedrock:InvokeModel* with NotResource = approved model + profile ARNs.
  MEDIUM  M10-10  org root
          Nothing at org level stops a workload role from deleting Bedrock invocation logging.
          fix: SCP: deny Delete/PutModelInvocationLoggingConfiguration except for the security admin role.
  MEDIUM  M10-11  org root
          No SCP limits long-term Bedrock API keys (creation, expiry or use).
          fix: SCP: deny bedrock:CallWithBearerToken for LONG_TERM keys outside the sandbox; cap key age.
  LOW     M10-09  scps/deny-deepseek.json [DenyDeepseekEverywhere]
          A deny-list: it blocks the models it names and allows every model released later.
          fix: Prefer an allow-list (Deny with NotResource = approved models). Keep deny-lists as a second layer.

5 HIGH, 7 MEDIUM, 1 LOW, 0 WARNING  (13 findings)
```

How to read it, highest first:

- **M10-01**: the chatbot's role allows `bedrock:*` and `bedrock-mantle:*` on `*`. That's every model, deleting the
  invocation logs, and buying Provisioned Throughput. Someone wrote it "just to get it working".
- **M10-03, M10-05, M10-06, M10-07**: the Bedrock API key story (lesson 10.4). The platform role can mint long-term
  keys with no limits; one was made on 9 October in the **production** account, it **never expires**, and its IAM
  user carries `AmazonBedrockLimitedAccess`, the policy the console attaches. Open
  `anycompany/aws-managed/AmazonBedrockLimitedAccess-v9.json`: `bedrock:InvokeModel` on `"Resource": "*"`, plus
  `bedrock:CreateProvisionedModelThroughput` and `bedrock-mantle:CreateInference`.
- **M10-02**: data science can invoke any foundation model in any Region.
- **M10-08 to M10-11**: nothing at the organization level backs any of this up. The only SCP is a deny-list for one
  model family.

Lint your own policies the same way: `python3 policy_checker.py --policy my-role.json` or `--scp my-scp.json`.

## Step 2 · Break it: what can a thief do today?

```bash
make attack                 # same as: python3 attack.py --mode vulnerable
```

Real output:

```text
--- M10 lab · VULNERABLE · SCPs on the org root: FullAWSAccess, deny-deepseek ---
    (iam_eval.py: a teaching model of AWS policy evaluation; nothing is sent to AWS)

Attacker 1 · a long-term Bedrock API key for IAM user BedrockAPIKey-x7k2 leaked (prod account, never expires)
  [A1] ALLOWED  ListFoundationModels: which models can I reach?
         why: every check passed: bedrock:CallWithBearerToken; bedrock:ListFoundationModels
  [A2] ALLOWED  GetModelInvocationLoggingConfiguration: is anyone logging prompts?
         why: every check passed: bedrock:CallWithBearerToken; bedrock:GetModelInvocationLoggingConfiguration
  [A3] ALLOWED  Converse with an expensive model nobody approved (Claude Opus 4.7)
         why: every check passed: bedrock:CallWithBearerToken; bedrock:InvokeModel
  [A4] ALLOWED  Same model through the OpenAI-compatible bedrock-mantle endpoint
         why: every check passed: bedrock-mantle:CallWithBearerToken; bedrock-mantle:CreateInference
  [A5] ALLOWED  CreateProvisionedModelThroughput: buy capacity billed by the hour
         why: every check passed: bedrock:CallWithBearerToken; bedrock:CreateProvisionedModelThroughput

Attacker 2 · stolen temporary credentials of HelpdeskAppRole (identity policy: bedrock:* and bedrock-mantle:* on *)
  [B1] ALLOWED  DeleteModelInvocationLoggingConfiguration: switch off prompt logging
         why: every check passed: bedrock:DeleteModelInvocationLoggingConfiguration
  [B2] ALLOWED  Converse through the GLOBAL Claude Opus 4.7 profile (not approved)
         why: every check passed: bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel
  [B3] DENIED   InvokeModel on a DeepSeek model (the old deny-list catches this one)
         why: explicit Deny in SCP deny-deepseek (DenyDeepseekEverywhere)  [check: bedrock:InvokeModel on arn:aws:bedrock:us-east-1::foundation-model/deepseek.r1-v1:0]
  [B4] ALLOWED  bedrock-mantle CreateInference with an unapproved model (no API key: plain SigV4)
         why: every check passed: bedrock-mantle:CreateInference

Attacker 3 · a sandbox admin session used to mint long-lived keys
  [C1] ALLOWED  CreateServiceSpecificCredential for Bedrock with NO expiry (never expires)
         why: every check passed: iam:CreateServiceSpecificCredential
  [C2] ALLOWED  CreateServiceSpecificCredential for Bedrock valid for 365 days
         why: every check passed: iam:CreateServiceSpecificCredential

Legitimate traffic · must keep working after the fixes
  [L1] ALLOWED  Helpdesk chatbot: Converse via the approved US cross-Region profile
         why: every check passed: bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel
  [L2] ALLOWED  Helpdesk chatbot: ApplyGuardrail on its guardrail
         why: every check passed: bedrock:ApplyGuardrail
  [L3] ALLOWED  Helpdesk chatbot: Retrieve from its knowledge base
         why: every check passed: bedrock:Retrieve
  [L4] ALLOWED  Helpdesk chatbot: approved model (Claude Haiku 4.5) on the bedrock-mantle endpoint
         why: every check passed: bedrock-mantle:CreateInference
  [L5] ALLOWED  Data science: InvokeModel on approved Nova Lite in us-west-2
         why: every check passed: bedrock:InvokeModel
  [L6] ALLOWED  Security admin: PutModelInvocationLoggingConfiguration (turn logging on)
         why: every check passed: bedrock:PutModelInvocationLoggingConfiguration
  [L7] ALLOWED  Sandbox admin: a Bedrock API key that expires in 30 days
         why: every check passed: iam:CreateServiceSpecificCredential
  [L8] ALLOWED  Sandbox user: Converse on Nova Lite with their 30-day API key
         why: every check passed: bedrock:CallWithBearerToken; bedrock:InvokeModel
  [L9] ALLOWED  Platform admin: CreateProvisionedModelThroughput (approved purchase)
         why: every check passed: bedrock:CreateProvisionedModelThroughput

10 of 11 attacker requests allowed; 9 of 9 legitimate requests allowed.
```

Read the **why** lines. Attacker 1 is the leaked key: listing models, checking whether prompts are logged, running
an expensive unapproved model on **both** endpoints, and buying capacity all pass, because `AmazonBedrockLimitedAccess`
allows them on `*`. Attacker 2 is the chatbot's role, stolen from the server it runs on: it can switch off invocation
logging and send traffic through a **global** inference profile to whatever Region AWS picks. The DeepSeek deny-list
(B3) works, for exactly the one family it names. Add `--verbose` to see every authorization check.

## Step 3 · Read the fixes

Open the three SCPs in `fixes/`:

| File | Statement | What it stops | Lesson |
|---|---|---|---|
| `scp-model-allowlist.json` | `DenyUnapprovedModelsOnBedrockRuntime`: deny `bedrock:InvokeModel*` on everything **except** the approved foundation-model **and** inference-profile ARNs (`NotResource`) | Any model nobody approved, by ARN or through a profile (A3, B2). Covers `Converse`/`ConverseStream`, which are authorized as InvokeModel actions | 10.3 |
| `scp-bedrock-api-keys.json` | No long-term keys outside the sandbox (creation and use, on both endpoints); sandbox keys may live 30 days at most | The leaked prod key (A1 to A5), 365-day keys (C2) | 10.4 |
| `scp-protect-ai-logging-and-spend.json` | Only `SecurityAdmin` may change Bedrock invocation logging or CloudTrail; only `PlatformAdminRole` may buy Provisioned Throughput | B1, and a stolen identity committing you to capacity | 10.5 |

Three design points:

- **Allow-list, not deny-list.** A `Deny` with `NotResource` lists what's *approved*; every model AWS adds later is
  refused until someone approves it. The deny-list did the opposite.
- **Scope the action.** The allow-list denies `bedrock:InvokeModel*` only, so Guardrails, Knowledge Bases and the
  model catalogue keep working. Step 5 shows the alternative.
- **SCPs are a ceiling, not the fix.** Run `make check-fixed`: the org-level findings are gone, but every identity
  finding is still there. The real fix for the chatbot is `fixes/helpdesk-app-role.least-privilege.json` (zero
  findings: `python3 policy_checker.py --policy fixes/helpdesk-app-role.least-privilege.json`). You want both: the
  least-privilege role, and the SCP that holds when someone gets a role wrong.

## Step 4 · Fix it: replay with the SCPs

```bash
make attack-safe            # same as: python3 attack.py --mode safe
```

Real output:

```text
--- M10 lab · SAFE · SCPs on the org root: FullAWSAccess, deny-deepseek, scp-model-allowlist, scp-bedrock-api-keys, scp-protect-ai-logging-and-spend ---
    (iam_eval.py: a teaching model of AWS policy evaluation; nothing is sent to AWS)

Attacker 1 · a long-term Bedrock API key for IAM user BedrockAPIKey-x7k2 leaked (prod account, never expires)
  [A1] DENIED   ListFoundationModels: which models can I reach?
         why: explicit Deny in SCP scp-bedrock-api-keys (NoLongTermKeyUseOutsideSandbox)  [check: bedrock:CallWithBearerToken on *]
  [A2] DENIED   GetModelInvocationLoggingConfiguration: is anyone logging prompts?
         why: explicit Deny in SCP scp-bedrock-api-keys (NoLongTermKeyUseOutsideSandbox)  [check: bedrock:CallWithBearerToken on *]
  [A3] DENIED   Converse with an expensive model nobody approved (Claude Opus 4.7)
         why: explicit Deny in SCP scp-bedrock-api-keys (NoLongTermKeyUseOutsideSandbox)  [check: bedrock:CallWithBearerToken on *]
  [A4] DENIED   Same model through the OpenAI-compatible bedrock-mantle endpoint
         why: explicit Deny in SCP scp-bedrock-api-keys (NoLongTermKeyUseOutsideSandboxMantle)  [check: bedrock-mantle:CallWithBearerToken on *]
  [A5] DENIED   CreateProvisionedModelThroughput: buy capacity billed by the hour
         why: explicit Deny in SCP scp-bedrock-api-keys (NoLongTermKeyUseOutsideSandbox)  [check: bedrock:CallWithBearerToken on *]

Attacker 2 · stolen temporary credentials of HelpdeskAppRole (identity policy: bedrock:* and bedrock-mantle:* on *)
  [B1] DENIED   DeleteModelInvocationLoggingConfiguration: switch off prompt logging
         why: explicit Deny in SCP scp-protect-ai-logging-and-spend (OnlySecurityAdminTouchesAiAuditTrail)  [check: bedrock:DeleteModelInvocationLoggingConfiguration on *]
  [B2] DENIED   Converse through the GLOBAL Claude Opus 4.7 profile (not approved)
         why: explicit Deny in SCP scp-model-allowlist (DenyUnapprovedModelsOnBedrockRuntime)  [check: bedrock:InvokeModel on arn:aws:bedrock:us-east-1:111122223333:inference-profile/global.anthropic.claude-opus-4-7]
  [B3] DENIED   InvokeModel on a DeepSeek model (the old deny-list catches this one)
         why: explicit Deny in SCP deny-deepseek (DenyDeepseekEverywhere)  [check: bedrock:InvokeModel on arn:aws:bedrock:us-east-1::foundation-model/deepseek.r1-v1:0]
  [B4] ALLOWED  bedrock-mantle CreateInference with an unapproved model (no API key: plain SigV4)   <-- still open: make challenge
         why: every check passed: bedrock-mantle:CreateInference

Attacker 3 · a sandbox admin session used to mint long-lived keys
  [C1] ALLOWED  CreateServiceSpecificCredential for Bedrock with NO expiry (never expires)   <-- still open: make challenge
         why: every check passed: iam:CreateServiceSpecificCredential
  [C2] DENIED   CreateServiceSpecificCredential for Bedrock valid for 365 days
         why: explicit Deny in SCP scp-bedrock-api-keys (SandboxKeysExpireWithin30Days)  [check: iam:CreateServiceSpecificCredential on arn:aws:iam::444455556666:user/sandbox-explorer]

Legitimate traffic · must keep working after the fixes
  [L1] ALLOWED  Helpdesk chatbot: Converse via the approved US cross-Region profile
         why: every check passed: bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel; bedrock:InvokeModel
  [L2] ALLOWED  Helpdesk chatbot: ApplyGuardrail on its guardrail
         why: every check passed: bedrock:ApplyGuardrail
  [L3] ALLOWED  Helpdesk chatbot: Retrieve from its knowledge base
         why: every check passed: bedrock:Retrieve
  [L4] ALLOWED  Helpdesk chatbot: approved model (Claude Haiku 4.5) on the bedrock-mantle endpoint
         why: every check passed: bedrock-mantle:CreateInference
  [L5] ALLOWED  Data science: InvokeModel on approved Nova Lite in us-west-2
         why: every check passed: bedrock:InvokeModel
  [L6] ALLOWED  Security admin: PutModelInvocationLoggingConfiguration (turn logging on)
         why: every check passed: bedrock:PutModelInvocationLoggingConfiguration
  [L7] ALLOWED  Sandbox admin: a Bedrock API key that expires in 30 days
         why: every check passed: iam:CreateServiceSpecificCredential
  [L8] ALLOWED  Sandbox user: Converse on Nova Lite with their 30-day API key
         why: every check passed: bedrock:CallWithBearerToken; bedrock:InvokeModel
  [L9] ALLOWED  Platform admin: CreateProvisionedModelThroughput (approved purchase)
         why: every check passed: bedrock:CreateProvisionedModelThroughput

2 of 11 attacker requests allowed; 9 of 9 legitimate requests allowed.
```

Nine attacks stopped, and all nine legitimate requests still pass, including the chatbot's call through the approved
US profile (four checks: the profile and the model in three Regions). Two attacks still get through. That's Step 7.

## Step 5 · Why "scope the action" matters

The AWS Organizations documentation shows an allow-list that denies `bedrock:*` with `NotResource` set to approved
models. Try that shape with AnyCompany's models:

```bash
make blunt                  # same as: python3 attack.py --mode safe --allowlist examples/blunt-allowlist-scp.json
```

Real output (last lines):

```text
Legitimate traffic · must keep working after the fixes
  [L1] DENIED   Helpdesk chatbot: Converse via the approved US cross-Region profile
         why: explicit Deny in SCP blunt-allowlist-scp (PermittedModels)  [check: bedrock:InvokeModel on arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0]
  [L2] DENIED   Helpdesk chatbot: ApplyGuardrail on its guardrail
         why: explicit Deny in SCP blunt-allowlist-scp (PermittedModels)  [check: bedrock:ApplyGuardrail on arn:aws:bedrock:us-east-1:111122223333:guardrail/gr-helpdesk-example]
  [L3] DENIED   Helpdesk chatbot: Retrieve from its knowledge base
         why: explicit Deny in SCP blunt-allowlist-scp (PermittedModels)  [check: bedrock:Retrieve on arn:aws:bedrock:us-east-1:111122223333:knowledge-base/KBHELPDESK1]
  [L4] ALLOWED  Helpdesk chatbot: approved model (Claude Haiku 4.5) on the bedrock-mantle endpoint
         why: every check passed: bedrock-mantle:CreateInference
  [L5] ALLOWED  Data science: InvokeModel on approved Nova Lite in us-west-2
         why: every check passed: bedrock:InvokeModel
  [L6] DENIED   Security admin: PutModelInvocationLoggingConfiguration (turn logging on)
         why: explicit Deny in SCP blunt-allowlist-scp (PermittedModels)  [check: bedrock:PutModelInvocationLoggingConfiguration on *]
  [L7] ALLOWED  Sandbox admin: a Bedrock API key that expires in 30 days
         why: every check passed: iam:CreateServiceSpecificCredential
  [L8] DENIED   Sandbox user: Converse on Nova Lite with their 30-day API key
         why: explicit Deny in SCP blunt-allowlist-scp (PermittedModels)  [check: bedrock:CallWithBearerToken on *]
  [L9] ALLOWED  Platform admin: CreateProvisionedModelThroughput (approved purchase)
         why: every check passed: bedrock:CreateProvisionedModelThroughput

2 of 11 attacker requests allowed; 4 of 9 legitimate requests allowed.
```

Why, from the AWS docs: a `Deny` with `NotResource` "denies services and resources that are not explicitly listed"
([IAM docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html)), and the
[Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrock.html)
authorizes `bedrock:ApplyGuardrail` on a `guardrail` resource, `bedrock:Retrieve` on a `knowledge-base` resource,
`InvokeModel` through a profile on the `inference-profile` resource, and `PutModelInvocationLoggingConfiguration` and
`CallWithBearerToken` on no resource type at all. None of those is a model ARN, so the Deny matches every one of them.
Using a guardrail during `InvokeModel`/`Converse` also needs `bedrock:ApplyGuardrail` on the guardrail
([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions.html)), so attached guardrails
break too, not just direct `ApplyGuardrail` calls. Five legitimate requests break. This is the teaching model's answer
from documented rules; test it in a sandbox before you rely on it. `python3 policy_checker.py --scp
examples/blunt-allowlist-scp.json` flags it as `M10-12`.

## Step 6 · Hunt: find the LLMjacking timeline in CloudTrail

```bash
make hunt-naive             # same as: python3 hunt.py --naive
```

Real output:

```text
--- M10 LLMjacking hunt · NAIVE rule only · 226 CloudTrail records ---

  HIGH   NAIVE  2026-10-14T02:11:22Z  user/BedrockAPIKey-x7k2
         InvokeModel of unapproved model anthropic.claude-opus-4-7

1 finding. Attacker events covered by a finding: 1 of 117 (20 on bedrock-mantle.amazonaws.com, 96 on bedrock.amazonaws.com, 1 on sts.amazonaws.com).
Not covered: 20 x bedrock-mantle.amazonaws.com CreateInference; 60 x bedrock.amazonaws.com Converse; 30 x bedrock.amazonaws.com ConverseStream; 1 x bedrock.amazonaws.com DeleteModelInvocationLoggingConfiguration; 1 x bedrock.amazonaws.com GetFoundationModelAvailability; 1 x bedrock.amazonaws.com GetModelInvocationLoggingConfiguration; 1 x bedrock.amazonaws.com ListFoundationModels; 1 x bedrock.amazonaws.com PutUseCaseForModelAccess; 1 x sts.amazonaws.com GetCallerIdentity
```

A rule that watches `InvokeModel` only sees **one** of 117 attacker events. The attackers used `Converse` and
`ConverseStream`, which CloudTrail records under their own names (Sysdig noticed attackers using the Converse API
within 30 days of its launch), and the bedrock-mantle endpoint, whose events have a different `eventSource`. Now run
every rule:

```bash
make hunt                   # same as: python3 hunt.py
```

Real output:

```text
--- M10 LLMjacking hunt · all rules · 226 CloudTrail records ---

  LOW    H01  2026-10-09T15:02:10Z  role/PlatformAdminRole
         console-style API-key user created: BedrockAPIKey-x7k2
  HIGH   H01  2026-10-09T15:02:12Z  role/PlatformAdminRole
         long-term Bedrock API key created for user BedrockAPIKey-x7k2
         - credentialAgeDays: missing -> the key NEVER expires
  HIGH   H02  2026-10-14T02:11:03Z  user/BedrockAPIKey-x7k2
         model and logging reconnaissance by a principal that never did this before
         - GetFoundationModelAvailability, GetModelInvocationLoggingConfiguration, ListFoundationModels
         - from 203.0.113.50  UA: Python/3.11 aiohttp/3.9.5
  MEDIUM H03  2026-10-14T02:11:22Z  user/BedrockAPIKey-x7k2
         invalid-request probe (ValidationException) from a new invoker
         - InvokeModel anthropic.claude-opus-4-7 from 203.0.113.50
  HIGH   H06  2026-10-14T02:11:22Z  user/BedrockAPIKey-x7k2
         61 invocation(s) of unapproved model anthropic.claude-opus-4-7
         - events: ['Converse', 'InvokeModel']  from ['203.0.113.50']
  HIGH   H07  2026-10-14T02:11:22Z  user/BedrockAPIKey-x7k2
         61 invocation(s) from a new source 203.0.113.50 using Bedrock API key (bearer token)
         - baseline IPs: none: never seen before
  MEDIUM H08  2026-10-14T02:11:22Z  user/BedrockAPIKey-x7k2
         61 invocations in the hour 2026-10-14T02:00Z (limit 20)
         - baseline peak: 0 per hour
  MEDIUM H05  2026-10-14T02:12:40Z  user/BedrockAPIKey-x7k2
         PutUseCaseForModelAccess: someone is enabling models
         - from 203.0.113.50
  HIGH   H04  2026-10-14T03:05:40Z  role/HelpdeskAppRole
         DeleteModelInvocationLoggingConfiguration: audit trail changed by a non-security principal
         - from 198.51.100.77  UA: Python/3.11 aiohttp/3.9.5
  HIGH   H06  2026-10-14T03:10:00Z  role/HelpdeskAppRole
         30 invocation(s) of unapproved model global.anthropic.claude-opus-4-7
         - events: ['ConverseStream']  from ['198.51.100.77']
  HIGH   H07  2026-10-14T03:10:00Z  role/HelpdeskAppRole
         30 invocation(s) from a new source 198.51.100.77 using SigV4 credentials
         - baseline IPs: 192.0.2.10
  MEDIUM H08  2026-10-14T03:10:00Z  role/HelpdeskAppRole
         30 invocations in the hour 2026-10-14T03:00Z (limit 20)
         - baseline peak: 4 per hour

12 findings. Attacker events covered by a finding: 96 of 117 (20 on bedrock-mantle.amazonaws.com, 96 on bedrock.amazonaws.com, 1 on sts.amazonaws.com).
Not covered: 20 x bedrock-mantle.amazonaws.com CreateInference; 1 x sts.amazonaws.com GetCallerIdentity
```

| Rule | Looks for | Why |
|---|---|---|
| H01 | `CreateServiceSpecificCredential` for `bedrock.amazonaws.com` (no `credentialAgeDays` = never expires), `CreateUser` named `BedrockAPIKey...` | AWS Security Blog: track long-term key creation and console-made key users |
| H02 | 2+ different recon calls in 30 minutes from a principal that never made them before | Sysdig: attackers list models and check invocation logging first |
| H03 | `ValidationException` on an invocation from a principal with no successful invocations | Sysdig: a deliberately invalid request tells the attacker the key works |
| H04 | invocation-logging or CloudTrail changes by anyone but the security admin | Sysdig: `DeleteModelInvocationLoggingConfiguration` |
| H05 | `PutUseCaseForModelAccess`, `CreateFoundationModelAgreement`, `PutFoundationModelEntitlement` | Sysdig: attackers enabled models themselves |
| H06 | invocations of models not in `approved-models.json` | your allow-list, as a detection |
| H07 | invocations from an IP the principal never used before; API-key use called out | AWS: `additionalEventData.callWithBearerToken` marks key use |
| H08 | invocations per hour above 3 times the principal's baseline peak (minimum 20) | volume is the bill |

Look at test 16 as well: the security admin calls `GetModelInvocationLoggingConfiguration` every morning, and no
rule fires on it. A detection that pages you every day gets switched off.

CloudTrail records cross-Region inference in the source Region, with `additionalEventData.inferenceRegion` showing
where the request ran ([AWS docs](https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html)).
Attacker 2's requests ran in three different Regions through the global profile. Extra credit: add a rule that flags
an `inferenceRegion` outside the Regions your data may go to. (Token counts aren't in CloudTrail: use the
`AWS/Bedrock` CloudWatch metrics or invocation logs for those.)

## Step 7 · Your turn: `make challenge`

```bash
make challenge              # same as: python3 run_tests.py --challenge
```

Real output before your fix (last lines):

```text
[FAIL] challenge: the stolen chatbot role can't run an unapproved model on bedrock-mantle
[PASS] challenge: the chatbot's approved model on bedrock-mantle still works
[FAIL] challenge: a sandbox Bedrock API key with no expiry at all is refused
[FAIL] challenge: rule_mantle_inference flags the 20 unapproved CreateInference data events
[PASS] challenge: the chatbot's hourly approved-model mantle calls are not flagged
  why test_18_mantle_unapproved_model_denied: AssertionError: True is not false : B4 is still ALLOWED: the allow-list ignores bedrock-mantle
  why test_20_never_expiring_key_denied: AssertionError: True is not false : C1 is still ALLOWED: NumericGreaterThan is false when the age key is missing
  why test_21_hunt_sees_mantle: AssertionError: 0 != 20 : 0 of 20 unapproved mantle events flagged
----------------------------------------------------------------------
Ran 22 tests in 0.073s

FAILED (failures=3)

3 of 22 TESTS FAILED (22 run)
```

Three gaps, three fixes. Each test's message is a hint.

1. **B4: the bedrock-mantle gap.** Add a statement to `fixes/scp-model-allowlist.json` that refuses
   `bedrock-mantle:CreateInference` for unapproved models (the approved mantle ID is in `approved-models.json`:
   mantle model IDs aren't always the runtime IDs). Mantle authorizes inference on a *project*, not a model
   ARN, so `NotResource` can't help: you need the `bedrock-mantle:Model` condition key.
2. **C1: keys that never expire.** `SandboxKeysExpireWithin30Days` uses `NumericGreaterThan`. When the request has
   no age at all, the key is missing, and the IAM docs say a missing key makes that operator **false**. Add a
   statement that catches "no age". (`python3 iam_eval.py` demonstrates the rule.)
3. **H09.** Write `rule_mantle_inference()` in `hunt.py` (the docstring says what to return).

Done when `make challenge` says `ALL TESTS PASSED (22 run)`, `make attack-safe` says `0 of 11`, and `make hunt`
leaves only the STS call uncovered. No solution is included.

## Step 8 (optional) · The AWS twin, in your own sandbox account

Everything above runs locally. If you have your own AWS sandbox account (lesson 0.7), these steps use only free
features. **Expected cost: $0.** IAM Access Analyzer policy validation is "provided at no additional charge"
([pricing](https://aws.amazon.com/iam/access-analyzer/pricing/)); "AWS Organizations is offered at no additional charge" ([AWS](https://docs.aws.amazon.com/organizations/latest/userguide/pricing.html));
"You can monitor and receive notifications on your budgets free of charge"
([AWS Budgets pricing](https://aws.amazon.com/aws-cost-management/aws-budgets/pricing/)); a request refused by an SCP
runs no model. Never run these in a work account without permission (lesson 0.8). We wrote these commands from the AWS
CLI reference but did not run them against a live account for this README, so your output will differ.

**8a · Validate the SCPs with IAM Access Analyzer** (any account, no Organization needed):

```bash
make validate
# runs, for each fixes/scp-*.json:
aws accessanalyzer validate-policy --policy-type SERVICE_CONTROL_POLICY --policy-document file://fixes/scp-model-allowlist.json
```

It reports `ERROR`, `SECURITY_WARNING`, `WARNING` and `SUGGESTION` findings
([CLI reference](https://docs.aws.amazon.com/cli/latest/reference/accessanalyzer/validate-policy.html)). An empty list
means the grammar is fine; it does not prove the policy does what you meant. That's what Steps 2 to 5 are for.

**8b · A budget with alerts** (replace `111122223333` with your account ID and `you@example.com` with your email):

```bash
aws budgets create-budget --account-id 111122223333 \
  --budget file://aws-twin/budget.json \
  --notifications-with-subscribers file://aws-twin/notifications-with-subscribers.json
```

A $5 monthly cost budget that emails you at 80% of actual spend and at 100% of forecast. Remember lesson 10.5: AWS
Budgets data is "updated up to three times a day", so an alert is a smoke detector, not a sprinkler.

**8c · Attach the model allow-list SCP to a sandbox member account** (only if you run an AWS Organization with a
separate sandbox account; SCPs never affect the management account). First edit the approved model IDs in the file to
models you use, then, from the management account:

```bash
aws organizations create-policy --name m10-model-allowlist --type SERVICE_CONTROL_POLICY \
  --description "M10 lab: approved Bedrock models only" --content file://fixes/scp-model-allowlist.json
# note the policy ID in the output (p-...), then:
aws organizations attach-policy --policy-id p-examplepolicyid111 --target-id 444455556666
```

Then, **in the sandbox account**, ask for a model that is not on the list. You should get `AccessDeniedException`, and
no model runs:

```bash
aws bedrock-runtime converse --region us-east-1 --model-id anthropic.claude-opus-4-7 \
  --messages '[{"role":"user","content":[{"text":"hello"}]}]'
```

**Teardown** (do it today, not later):

```bash
aws organizations detach-policy --policy-id p-examplepolicyid111 --target-id 444455556666
aws organizations delete-policy --policy-id p-examplepolicyid111
aws budgets delete-budget --account-id 111122223333 --budget-name m10-ai-sandbox-monthly
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `make: command not found` (Windows) | Run the `python` command shown next to each `make` step |
| `SyntaxError` or `TypeError` on start | You need Python 3.11+: `python3 --version` |
| `json.decoder.JSONDecodeError` after editing a fix | Your JSON has a typo (often a trailing comma). `python3 -m json.tool fixes/<file>.json` shows where |
| A legitimate request (L1 to L9) turns DENIED after your change | Your statement is too wide. Re-read the **why** line: it names the SCP, the Sid and the exact check |
| Test 17 fails | You added a real-looking account ID, IP or key. Use the documentation values |
| `aws: command not found` (Step 8) | Install the AWS CLI v2, or skip Step 8: it's optional |

## What to write in your findings notebook (lesson 0.5)

Three lines: what you found (a chatbot role with `bedrock:*`, a never-expiring long-term key in production with a
policy that can run any model and buy capacity, and no org-level guardrail), how you fixed it (a least-privilege role,
plus SCPs for a model allow-list on both endpoints, API-key limits and audit-trail protection), and how you'd spot it
(recon calls from a new principal, `ValidationException` probes, `DeleteModelInvocationLoggingConfiguration`,
`callWithBearerToken` from a new IP, unapproved model IDs, mantle `CreateInference` data events, volume spikes).

## Sources

- Amazon Bedrock API keys: <https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html> · permissions: <https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-permissions.html>
- AWS Security Blog, Securing Amazon Bedrock API keys (17 Oct 2025): <https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management>
- AWS Security Blog, Simplified model access in Amazon Bedrock (15 Oct 2025): <https://aws.amazon.com/blogs/security/simplified-amazon-bedrock-model-access/>
- Inference profile permissions: <https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-prereq.html> · inference prerequisites: <https://docs.aws.amazon.com/bedrock/latest/userguide/inference-prereq.html>
- Service Authorization Reference: Amazon Bedrock <https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrock.html> · Bedrock Mantle <https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock-mantle.html>
- AmazonBedrockLimitedAccess (v9): <https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonBedrockLimitedAccess.html>
- CloudTrail for bedrock-runtime: <https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html> · for bedrock-mantle: <https://docs.aws.amazon.com/bedrock/latest/userguide/logging-cloudtrail-mantle.html>
- Example SCPs for Amazon Bedrock: <https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_bedrock.html> · SCPs: <https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html>
- IAM condition operators (missing keys, Null): <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html>
- IAM NotResource: <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html> · Guardrails permissions: <https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions.html>
- Bedrock model cards (model IDs, endpoints, profile Regions): <https://docs.aws.amazon.com/bedrock/latest/userguide/model-cards.html> · cross-Region inference: <https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html>
- Sysdig TRT, LLMjacking (6 May 2024): <https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/> · The growing dangers of LLMjacking (18 Sep 2024): <https://sysdig.com/blog/growing-dangers-of-llmjacking/>
- Provisioned Throughput billing: <https://docs.aws.amazon.com/bedrock/latest/userguide/prov-throughput.html>
- RFC 5737, documentation IP ranges: <https://www.rfc-editor.org/rfc/rfc5737>
