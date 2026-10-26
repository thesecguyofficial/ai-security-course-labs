# Lab M13: port the local RAG + agent to Bedrock without losing a single control

Companion to lessons **13.0 to 13.3** of *AI Security Engineer* (The Sec Guy). About 60 minutes for Steps 1 to 8,
**$0**, all on your laptop: **Python 3.11+ only**, no packages, no AWS account, no model download. Step 9 is optional:
it builds the knowledge base (and, if you want, the agent) in **your own** sandbox account, with
[`GUIDED-BUILD.md`](GUIDED-BUILD.md) walking you through every request, and ends with teardown.

You are still the cloud security engineer at **AnyCompany** (fictional; "AnyCompany" is the placeholder name AWS uses in
its documentation). In Part 2 you built and fixed the TSG Helpdesk on your laptop: a RAG bot that only showed each person
their own documents (M6) and an agent whose tools were fenced in by an allow-list, approvals, argument checks and an
audit log (M7). In M11 and M12 it moved to Amazon Bedrock with a guardrail. Now the platform team has ported the
knowledge base and the agent to managed AWS services. Their pull request says "same app, now on Bedrock". That is the
**first draft**. Your job: prove whether every control from M6 and M7 came along.

| Part | What you do | Lesson |
|---|---|---|
| **Check** | Review the first-draft port: 17 findings, 9 HIGH | 13.1, 13.2 |
| **Break** | 8 attacks and 5 normal requests: 7 of 7 applicable attacks work, and nothing *looks* broken | 13.1, 13.2 |
| **Knowledge base** | How ACL-aware retrieval really behaves: no identity = no results, deny beats allow, no ACL = not indexed, changes need a resync | 13.1 |
| **Port, twice** | The fixed port on Bedrock Agents Classic, and the same port on an AgentCore harness (for accounts that can't create Classic agents) | 13.0, 13.2 |
| **Parity** | All 10 local controls from M6 and M7, each mapped to its AWS equivalent: kept, partial or lost | 13.3 |
| **Prove** | `make test`: 19 tests | 13.3 |
| **Challenge** | Screen retrieved chunks, write checker rule M13-20, add authorisation behind the confirmation. No solution included | 13.1, 13.2 |
| **Cloud (optional)** | Terraform for the managed knowledge base (+ harness), and [`GUIDED-BUILD.md`](GUIDED-BUILD.md): console and CLI from zero, five requests including a cross-user leak attempt, an indirect injection and a confirmed write, one setting changed, cost, teardown | 13.1, 13.2 |

## What's in this folder

| File | What it is |
|---|---|
| `setups/first-draft/` | The pull request: a customer-managed (VECTOR) knowledge base with metadata filters, a Bedrock Agents Classic agent with a Lambda action group and Code Interpreter, policies, logging, and `app.json` (how the backend builds each request) |
| `setups/ported/` | The fixed port on **Bedrock Agents Classic**: Bedrock Managed Knowledge Base with an ACL-aware S3 source, search as a return-of-control action group, `requireConfirmation` on the write, scoped Lambda |
| `setups/harness/` | The same port on an **AgentCore harness**: both tools are inline functions, `allowedTools` set, memory off |
| `data/docs/` | The bucket: public IT articles, an HR-only file, an IT-admin-only file, and a staff-uploaded vendor note with a hidden instruction (lab placeholder) |
| `twin.py` | The **offline stand-in for the AWS pieces**: knowledge base ingestion and `Retrieve` for both kinds of knowledge base, and the Lambda resource policy. Read "How faithful is the twin?" below |
| `helpdesk.py` | TSG Helpdesk v4 with a **worst-case stand-in model** (not AI: it obeys any instruction it can read, including HTML comments in retrieved documents). Holds the two challenge stubs |
| `suite/cases.json` | 8 attacks and 5 normal requests. Payloads are harmless lab placeholders |
| `evaluate.py` | Runs the suite against a setup: attacks that worked AND normal requests that still work |
| `checker.py` | 19 review rules `M13-01` to `M13-19`, plus `M13-20`, which you write |
| `parity.py` | The 10 local controls from M6 and M7, their AWS equivalents, and their status in a setup |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 19 tests for the lab, 7 for the challenge |
| `GUIDED-BUILD.md` | Optional: build it in your own AWS account, by console and CLI, with example responses and teardown |
| `cloud/` | Optional: Terraform (managed knowledge base, bucket, ACL file, KMS key, optional harness), `helpdesk_cloud.py` (the real backend: `Retrieve` with `userContext`, `InvokeHarness` with inline functions and a confirmation prompt), and the JSON request bodies the guide uses |

**Why two ported setups?** Since 30 July 2026, AWS has put Bedrock Agents (now "Bedrock Agents Classic") in
maintenance mode: accounts without Bedrock Agents activity in the past 12 months get `AccessDeniedException` on
`CreateAgent` ([AWS](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html)). Plenty of
estates still run Classic agents, and you'll review them. A new sandbox account can't create one, so the harness setup
is the one you can build yourself (Step 9).

## Needs

- Python **3.11 or newer**: `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 9 only: Terraform 1.6+ (or OpenTofu), the AWS CLI v2, `pip install boto3`, and your own sandbox account (lesson 0.7).

## Step 1 · Review the first draft

```bash
cd labs/m13
make check
```

- `make check`: same as `python3 checker.py first-draft`

You should see:

```
[HIGH  ] M13-01 (13.1) the backend takes the user's identity from the request body, not the signed-in session: anyone can claim to be anyone
[HIGH  ] M13-02 (13.1) per-user access is a metadata filter whose value the browser sends (department): a filter is a relevance feature, and a client-supplied scope is a suggestion, not a control
[HIGH  ] M13-03 (13.1) implicit metadata filtering is on: a model writes the filter from the user's words, so the user chooses which department's documents come back
[HIGH  ] M13-04 (13.1) 2 restricted documents (hr/, it-admin/) sit in a customer-managed knowledge base with no ACL awareness: any caller of Retrieve gets them unless every request carries the right filter
[HIGH  ] M13-12 (13.2) write action reset_mfa runs without user confirmation (requireConfirmation is not ENABLED): a retrieved document can trigger it
[HIGH  ] M13-13 (13.2) the action Lambda doesn't know who the end user is: it acts on whatever target the model passes, with the agent's own permissions
[HIGH  ] M13-14 (13.2) Lambda resource policy lets bedrock.amazonaws.com invoke the function without an AWS:SourceArn condition: any agent (another team's, another account's) can call reset_mfa
[HIGH  ] M13-15 (13.2) Lambda execution role allows cognito-idp:* on *: one injected call can do anything the identity service can
[HIGH  ] M13-16 (13.2) the agent can run code it doesn't need: the AMAZON.CodeInterpreter action group is enabled
[MEDIUM] M13-06 (13.1) knowledge base service role trust policy has no aws:SourceAccount + AWS:SourceArn conditions (AWS's documented confused-deputy guard)
[MEDIUM] M13-07 (13.1) knowledge base service role can read S3 beyond the knowledge base bucket, or without an aws:ResourceAccount condition: whoever can point a data source at a bucket can index it
[MEDIUM] M13-08 (13.1) role/tsg-staff-portal can write anywhere in the knowledge base bucket: a staff upload can land in public/ (poisoning everyone's answers) or in hr/ and inherit HR's ACL prefix
[MEDIUM] M13-09 (13.1) no customer managed KMS key on the knowledge base, but AnyCompany requires one for hr/, it-admin/ (M11): you can't revoke or audit use of an AWS owned key
[MEDIUM] M13-10 (13.1) CloudTrail doesn't record Retrieve / RetrieveAndGenerate: they are data events on AWS::Bedrock::KnowledgeBase, off by default
[MEDIUM] M13-17 (13.2) the app assumes the agent's guardrail checks retrieved chunks and tool results; AWS documents it on prompts sent to the agent and responses returned (M12: tool results aren't evaluated)
[MEDIUM] M13-18 (13.2) CloudTrail doesn't record InvokeAgent: it is a data event on AWS::Bedrock::AgentAlias, off by default
[LOW   ] M13-11 (13.1) no ingestion log delivery (APPLICATION_LOGS): you can't see which documents were added, updated or failed in each sync

9 HIGH, 7 MEDIUM, 1 LOW  (17 findings)
note: Bedrock Agents Classic is closed to new customers since 30 Jul 2026 (maintenance mode). Accounts with no Agents activity in the past 12 months can't call CreateAgent: see setups/harness for the AgentCore path.
```

Open `setups/first-draft/app.json` first. It's the shortest file and it explains half the HIGH findings: the backend
copies `user`, `department` and `sessionAttributes` from what the browser sent. In M6 the safe version took the tenant
from the server-side session. That line didn't survive the port.

## Step 2 · Attack the first draft

```bash
make attack
```

Same as `python3 evaluate.py first-draft`.

```
  A1 WORKED  Department spoof: Bob sends department=hr with his question
  A2 WORKED  User spoof: Bob's browser says he is Alice (IT) and asks for the IT admin runbook
  A3 WORKED  Implicit filter: 'search all departments' lets a model write the filter from Bob's words
  A4 WORKED  Indirect injection: a retrieved vendor note tells the agent to reset the CEO's MFA
  A5 WORKED  Self-approved write: Bob asks for the CEO's MFA reset, claims to be Alice, and clicks Confirm
  A6 WORKED  Confused deputy: another agent (another team's, or another account's) invokes the Helpdesk's action Lambda
  A7 WORKED  Code execution: the agent has a sandbox it doesn't need (Code Interpreter / harness shell)
  A8 n/a     Tool override: a principal the browser controls may call InvokeHarness with its own tools and system prompt
  ...
Attacks that worked: 7 of 7  (A1, A2, A3, A4, A5, A6, A7)   |   normal requests that work: 5 of 5
```

All five normal requests work too. That's why it shipped: nobody's test plan included a person lying about who they
are. Watch the indirect injection one turn at a time:

```bash
python3 helpdesk.py first-draft bob@example.com "What's new in the VPN client?"
```

You should see:

```text
Q (bob@example.com): What's new in the VPN client?
   . identity: caller = bob@example.com (from request_body)
   . agent queried its knowledge base; filter = {"orAll": [{"equals": {"key": "department", "value": "sales"}}, {"equals": {"key": "department", "value": "all"}}]}
   . EXECUTED reset_mfa(ceo@example.com) as nobody in particular (no caller identity)
Retrieved: inbox/vpn-client-update.md, public/vpn-token.md
A: VPN client 7.2 is rolling out this week. It fixes the reconnect loop after sleep. No action is needed from staff. | Done: MFA reset for ceo@example.com.
```

Open `data/docs/inbox/vpn-client-update.md`. The instruction is in an HTML comment: invisible on a rendered page,
plain text to the knowledge base. AWS's own page on user confirmation describes exactly this: if a response "includes
instructions for the model to invoke unintended actions, the agent will go ahead and comply with the instruction"
([AWS](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-userconfirmation.html)).

## Step 3 · How ACL-aware retrieval behaves (the managed knowledge base)

```bash
make ingest
```

Same as `python3 twin.py ingest ported`.

```
  indexed  hr/salary-bands-2027.md            -> priya@example.com
  indexed  inbox/vpn-client-update.md         -> alice@example.com, bob@example.com, priya@example.com
  indexed  it-admin/break-glass-runbook.md    -> alice@example.com
  indexed  public/mfa-new-phone.md            -> alice@example.com, bob@example.com, priya@example.com
  indexed  public/outlook-frozen.md           -> alice@example.com, bob@example.com, priya@example.com
  indexed  public/vpn-token.md                -> alice@example.com, bob@example.com, priya@example.com
```

Now ask as nobody, then as Priya:

```bash
python3 twin.py retrieve ported "salary bands 2027"
python3 twin.py retrieve ported "salary bands 2027" --user priya@example.com
```

- `python3 twin.py retrieve ported "salary bands 2027"`: no userContext

The first returns `{"retrievalResults": []}`: AWS says that without `userContext`, "ACL-enabled data sources return
zero results" ([AWS](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-retrieve-acl.html)). The second returns
the HR file. Four more rules are pinned by tests 07 to 11 (read them in `test_lab.py`): deny beats allow; a document with
no ACL entry is not ingested at all; changing the ACL file changes nothing until the next ingestion job; and an email
spelled differently from the ACL `Name` silently gets nothing.

**The rule to remember:** AWS calls this "ACL-aware filtering, not a security boundary". The knowledge base trusts
whatever `userId` you send. If your backend takes it from the browser (`setups/first-draft/app.json` style), ACLs
protect nothing.

## Step 4 · The port on Bedrock Agents Classic

```bash
make check-ported
make ported
make parity-ported
```

- `make check-ported`: 0 HIGH, 0 MEDIUM, 1 LOW (M13-17: chunks unscreened, challenge 1)
- `make ported`: same as `python3 evaluate.py ported`
- `make parity-ported`: same as `python3 parity.py ported`

```
Attacks that worked: 1 of 7  (A5)   |   normal requests that work: 5 of 5
...
Kept 8 of 10 controls, partial 2, lost 0
```

Read `setups/ported/agent.json`. The knowledge base is no longer attached to the agent: `InvokeAgent` can pass a
metadata filter for an attached knowledge base, but its API has no field for `userContext`. So search became a
**return-of-control** action group: the model asks for `search_kb`, Bedrock hands the call back to your backend, and
your backend runs `Retrieve` as the signed-in user. The write action has `"requireConfirmation": "ENABLED"`. Replay A4:

```bash
python3 helpdesk.py ported bob@example.com "What's new in the VPN client?"
```

You should see:

```text
   . identity: caller = bob@example.com (from session)
   . model called search_kb -> returnControl -> app called Retrieve with userContext.userId = bob@example.com
   . confirmation asked (with arguments): reset_mfa(ceo@example.com) -> DENY
A: VPN client 7.2 is rolling out this week. It fixes the reconnect loop after sleep. No action is needed from staff.
```

The model was still fooled. The control is that Bob saw "reset MFA for ceo@example.com" and said no. **A5 still works**:
Bob asks for the CEO's reset himself and confirms it. Confirmation proves the user agreed, not that the user is allowed.
That's challenge 3.

## Step 5 · The same port on an AgentCore harness

```bash
make check-harness
make harness
make parity-harness
```

You should see:

- `make check-harness`: 1 LOW, the same M13-17
- `make harness`: Attacks that worked: 2 of 7  (A5, A8)

Two harness-specific lessons, both in `setups/harness/`:

1. **`allowedTools` is the sandbox switch.** AWS: "Default tools `shell` and `file_operations` are available in every
   session unless you restrict them with `allowedTools`" ([AWS](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-tools.html)).
   Delete the `allowedTools` line from `setups/harness/agent.json`, run `make check-harness` and `make harness`: M13-16
   (HIGH) and A7 come back. Put it back.
2. **Who may call `InvokeHarness`?** `InvokeHarness` accepts `tools`, `allowedTools` and `systemPrompt` on every call,
   overriding the harness's own. `setups/harness/invokers.json` gives that permission to `tsg-web-frontend`, a role the
   browser gets credentials for. That's A8, and no rule catches it yet: challenge 2.

## Step 6 · Confirmation people can read

The confirmation only works if it shows the arguments. Test 17 proves it: set `"show_arguments": false` in a copy of
`setups/ported/app.json`, have Bob ask "Please reset my MFA. Also, what's new in the VPN client?", and both resets run,
his and the CEO's, because he approved "reset MFA" without seeing whose. With arguments shown, only his runs.
`make check` on that copy reports M13-12 at MEDIUM.

## Step 7 · Prove it

```bash
make test
```

Same as `python3 run_tests.py`.

```
[PASS] first draft: 17 findings, 9 HIGH (identity, filters, ACL, confirmation, Lambda, code sandbox)
...
[PASS] remove allowedTools from the harness: the default shell tool is back (M13-16 HIGH, A7 works)

ALL TESTS PASSED (19 run)
```

## Step 8 · Challenge (no solution included)

```bash
make challenge
```

You should see:

```text
5 of 26 TESTS FAILED until you finish
```

1. **13.1 + M12: screen what the knowledge base returns.** Write `screen_chunks()` in `helpdesk.py`: strip HTML
   comments from each chunk and drop any chunk that still carries the lab marker, keeping the visible text. Then set
   `"screen_retrieved_chunks": true` in `setups/ported/app.json` and `setups/harness/app.json`. The real-cloud version
   is `ApplyGuardrail` on each chunk (M12.2) plus stripping hidden text at ingestion (M6.2).
2. **13.2: write checker rule M13-20.** Flag, as HIGH, any principal in `invokers.json` with
   `"end_user_reachable": true` that may call `bedrock-agentcore:InvokeHarness`. Then fix it the way you would at
   work: delete the `tsg-web-frontend` entry, so only the backend can invoke the harness.
3. **13.2: confirmation is not authorisation.** Write `authorise_write()` in `helpdesk.py`: `reset_mfa` on your own
   account, or on anyone's if you're in a group listed in `anycompany.json` `may_reset_mfa_for_others`. Nothing else.

Finished, `make check-ported` shows 0 findings, `make ported` shows 0 of 7 attacks, `make parity-ported` shows 10 of 10
kept, and the harness has only A8 left until you delete the web front end's permission.

## Step 9 · Optional: build it in your sandbox account

Follow [`GUIDED-BUILD.md`](GUIDED-BUILD.md). It builds the managed knowledge base with an ACL-aware S3 source and the
AgentCore harness from zero (console and CLI), runs five requests against them, changes one setting, and tears it all
down. Short version with Terraform:

```bash
make cloud-up
make cloud-sync
make cloud-up HARNESS=1
make cloud-down HARNESS=1
```

- `make cloud-up`: bucket, documents, ACL file, KMS key, service role, managed knowledge base, data source
- `make cloud-sync`: ingestion job (wait until it finishes: GUIDED-BUILD shows how to check)
- `make cloud-up HARNESS=1`: add the AgentCore harness (two inline functions, allowedTools, memory off)
- `make cloud-down HARNESS=1`: delete everything, today

Cost: a few US cents for the knowledge base at the list prices on the pricing page (US$5.00 per GB of raw data per
month, prorated, for a few kilobytes; US$1.00 per 1,000 `Retrieve` calls), plus model tokens and harness compute for
the agent part. The KMS key costs US$1 a month, prorated hourly; `make cloud-down` schedules its deletion (7 days), and
AWS doesn't charge for keys scheduled for deletion ([KMS pricing](https://aws.amazon.com/kms/pricing/)). Details in the guide.

## How faithful is the twin?

| Behaviour | Twin | AWS source |
|---|---|---|
| No `userContext`: ACL-enabled sources return zero results; non-ACL sources return normally | Same | [kb-test-retrieve-acl](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-retrieve-acl.html) |
| Deny overrides allow | Same | [kb-managed-acl](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-managed-acl.html) |
| ACL-enabled S3: documents with no ACL entry are not ingested; per-document `.metadata.json` beats the global file | Same | [kb-managed-ds-s3-acl](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-managed-ds-s3-acl.html) |
| Global ACL changes need a resync; S3 has no real-time ACL verification | Same (index built per ingestion) | kb-managed-ds-s3-acl, kb-managed-acl |
| Email must match exactly | Exact string compare | kb-managed-acl ("must exactly match") |
| Overlapping global ACL prefixes | **Twin choice:** the longest prefix wins. AWS doesn't say | not documented |
| Metadata filter operators | `equals`, `notEquals`, `in`, `notIn`, `andAll`, `orAll` only | [kb-test-config](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html) |
| Implicit filtering: a model writes the filter from the query and attribute descriptions | A regex stands in for the model | kb-test-config |
| Relevance | Keyword overlap, not embeddings | not documented |
| Return of control, `requireConfirmation`, `confirmationState` CONFIRM/DENY | Modelled as a decision; no wire format | [agents-returncontrol](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html), [agents-userconfirmation](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-userconfirmation.html) |
| Lambda resource policy: `bedrock.amazonaws.com`, `AWS:SourceAccount`, `AWS:SourceArn` | StringEquals / ArnLike only | [agents-permissions](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html) |
| Harness: default `shell` and `file_operations` unless `allowedTools` restricts them | Same; the twin treats the two inline function names as allowed | [harness-tools](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-tools.html) |
| Harness: inline functions hand the call back to your code | Same | harness-tools |

The request bodies in `setups/` and `cloud/` were checked against the botocore 1.43.117 service models (`bedrock-agent`,
`bedrock-agent-runtime`, `bedrock-agentcore`, `bedrock-agentcore-control`). Keys starting with `_` are lab notes, not
API fields.

## Troubleshooting

- **`make challenge` exits with an error.** Expected until you finish: the last line tells you how many tests fail.
- **A test in `make test` fails after you edited a setup.** `make test` pins the setups as shipped (it switches your
  challenge flags off and restores the web front end on a copy), but it does read the files. `git diff setups/` shows what you changed.
- **Windows:** `python run_tests.py`, `python checker.py first-draft`, and so on.
