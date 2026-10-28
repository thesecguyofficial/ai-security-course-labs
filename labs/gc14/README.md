# Lab GC14: who decides each tool call? Agent Runtime, Agent Identity and Agent Gateway

Companion to lessons **14.0 to 14.8** of *AI Security Engineer* (The Sec Guy), Google Cloud stream. About 45 minutes,
**$0**, all on your laptop. **Nothing to install** (Python 3.11+ standard library only) and **no Google Cloud account
needed**. An optional guided build ([GUIDED-BUILD.md](GUIDED-BUILD.md)) deploys a small version for real in your own
project: an agent with its own Agent Identity, behind an Agent Gateway, with one access policy rule you first run in
dry-run and then enforce.

You are still the cloud security engineer at **ExampleCo** (fictional, on the documentation domain `example.com`). The
Helpdesk agent now runs on **Agent Runtime** in `example-agents-prod`. It has its own **Agent Identity**, its tool
calls leave through an **Agent Gateway** (Agent-to-Anywhere) that checks an **IAM Unified Access Policy**, it remembers
things in **Memory Bank**, and its tools are MCP servers listed in **Agent Registry**. The team says "it's deployed
and the gateway is on". Your job: review the setup like an auditor, then ask every control what it decides for eight
tool calls.

| Part | What you do | Command |
|---|---|---|
| **Review** | An auditor's checker over today's deployment: 14 findings, 9 HIGH | `make check` |
| **Decide** | Eight proposed tool calls (6 hijacked, 2 legitimate) against today's deployment: 6 of 6 go through | `make decide` |
| **Compare** | The same table hardened (0 of 6), in dry run (2 of 6), after a rug pull (1 of 6) and during a Model Armor outage (0 of 6) | `make decide-fixed`, `make decide-dry`, `make rugpull`, `make outage` |
| **Logs** | The gateway's decisions as log lines: what a dry run looks like | `make logs` |
| **Prove** | 25 tests | `make test` |
| **Challenge** | Rule GC14-18 and the rug-pull fix. No solution included | `make challenge` |
| **Guided build** (optional) | [GUIDED-BUILD.md](GUIDED-BUILD.md): the real services in your own project | |

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/gc14`.

## What this lab is (and isn't)

It's **decision-only**. There is no model in here, no prompt, and no attack text. Each case in `data/cases.json` is
a tool call that the agent's model has *already proposed*, plus one line about where the proposal came from (for
example "proposed after reading untrusted ticket text"). The lab then asks each control, in order, "do you allow
this?", and prints who said no. That is the question a reviewer has to answer for a real agent: if the model gets
talked into something, **which deterministic control stops it, and who owns that control?**

## What's in this folder

| File | What it is |
|---|---|
| `checker.py` | 17 review rules (`GC14-01` to `GC14-17`) plus 4 notes no setting can fix. `GC14-18` is your challenge |
| `decide.py` | The decision table: every case through Model Armor, Memory Bank, your app's approval queue, the gateway and IAM |
| `twin.py` | **Teaching stand-ins** for Agent Identity, IAM, Model Armor on the gateway, Agent Gateway and Memory Bank (see below) |
| `cel.py` | A small evaluator for the part of CEL the access policy conditions use. Anything else is an error |
| `data/cases.json` | The eight proposed calls: `L1`, `L2` legitimate; `C1` to `C6` hijacked |
| `data/directory.json` | Two fake users and the ID tokens your front end has already verified |
| `data/memories.json` | One memory already in Memory Bank (Bob's, with a canary value) |
| `twin/today/deployment.json` | Today's deployment: agent, IAM bindings, gateway, access policy, Memory Bank, sandbox, audit logs |
| `twin/hardened/deployment.json` | The same after a security review. One gap left on purpose (your challenge) |
| `twin/registry.json`, `twin/registry-rugpull.json` | Agent Registry entries for the MCP servers, before and after the tickets team re-registers theirs |
| `twin/requirements.json` | ExampleCo's rules for this agent (what it must never reach, which roles count as data access) |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 25 tests for the lab, 4 for the challenge |
| `cloud/` | Optional, for the guided build: Terraform (`cloud/terraform/`) and the agent's code (`cloud/agent/`) |

**About `twin.py`.** It is not Google Cloud. It copies only the decisions this lab needs, each from Google's
documentation (October 2026):

- **Agent Identity.** With `identity_type` `AGENT_IDENTITY`, the agent gets its own principal,
  `principal://agents.global.org-ORG_ID.system.id.goog/resources/aiplatform/projects/PROJECT_NUMBER/locations/REGION/reasoningEngines/AGENT_ID`.
  A `principalSet://.../attribute.platformContainer/aiplatform/projects/PROJECT_NUMBER` grant covers **every** agent
  in the project, including ones deployed later. Without Agent Identity, the agent runs as a service account.
- **Agent Gateway.** "By default, all connections are blocked unless an explicit IAM policy grants access." Destinations
  are either registered in Agent Registry or unregistered (matched by host and path). When an agent uses an egress
  gateway, Agent Identity is required.
- **Unified Access Policy.** Rules have an `effect` (`ALLOW` or `DENY`), `principals`, the permission
  `iap.googleapis.com/resources.egressViaIAP` and a CEL condition under `iap.googleapis.com`; "deny rules override
  allow rules". The twin checks deny rules first, then allow rules, then applies the default deny.
- **Dry run.** With `iamEnforcementMode: "DRY_RUN"` on the IAP authorization extension, IAP logs what it would deny
  and blocks nothing.
- **Model Armor on the gateway.** A `CONTENT_AUTHZ` extension screens MCP `tools/call` requests and responses, with
  `failOpen` deciding what happens when Model Armor can't be reached. The twin doesn't contain any text to screen:
  each case says how a prompt-injection filter would classify the response it came from.
- **Memory Bank.** Memories belong to a `scope` (for example `{app_name, user_id}`); only enabled topics are
  generated; Google's default is no TTL.

It doesn't model networking, tokens, latency, real CEL, real Model Armor verdicts or Google's error messages.

## Needs

- Python **3.11 or newer**: run `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step (use `py` if
  `python3` isn't found).
- A terminal in this folder:

```bash
cd labs/gc14
```

## Step 1 · Review today's deployment (`make check`)

```bash
make check
```

Same as `python3 checker.py --twin today`.

You should see (shortened):

```output
--- GC14 checker · today ---

  HIGH    GC14-02  env_vars
          GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES is false: the agent is opted out of the
          default Context-Aware Access policy that binds its tokens. Google calls this 'strongly discouraged'.
  HIGH    GC14-03  example-agents-prod
          roles/bigquery.dataViewer is granted project-wide to every agent in the project (a principalSet). Any
          agent, including ones deployed later, can read all data in the project.
  HIGH    GC14-05  helpdesk-egress
          The gateway's IAP authorization runs in DRY_RUN: denials are logged, nothing is blocked.
  HIGH    GC14-06  pilot
          An ALLOW rule with no condition: every destination, registered or not, is allowed.
  HIGH    GC14-07  mail.send_email
          The policy allows a tool this agent must never use (pilot).
  HIGH    GC14-09  helpdesk-egress
          No Model Armor on the gateway: tool responses (ticket text, articles) reach the model unscreened.
  HIGH    GC14-11  Memory Bank
          Memory scope (user_id) comes from the request body: a caller can read or write another user's
          memories.
  HIGH    GC14-14  helpdesk-browser
          A sandbox template with internet_access: true, for an agent whose job needs no browser.
  HIGH    GC14-17  agent front end
          The end user is taken from the request body (user_id), which any caller can set.
  MEDIUM  GC14-04  IAM
  MEDIUM  GC14-12  Memory Bank
  MEDIUM  GC14-13  Memory Bank
  MEDIUM  GC14-15  TICKETS_API_TOKEN
  MEDIUM  GC14-16  telemetry
  NOTE    Agent Gateway's Model Armor screens MCP tools/call and prompts/get, not tools/list, resources/* or
          Streamable HTTP/SSE: tool descriptions from a server are not screened.
  NOTE    IAM Unified Access Policies: Google's page says the feature doesn't support VPC Service Controls.
  NOTE    Security Command Center's Agent Engine Threat Detection isn't available for an agent with Agent
          Gateway enabled (Google's routing page): plan detection from the gateway and IAP logs instead.
  NOTE    ADK tool confirmation isn't supported with VertexAiSessionService: keep approvals in your own app.

14 findings (9 HIGH), 4 notes.
```

Each finding has a `fix:` line (left out above). Read the HIGH ones in four groups: **who the agent is and what it
can touch** (GC14-02, GC14-03), **where it can connect** (GC14-05, 06, 07, 09, 14), **who it thinks it's working
for** (GC14-11, GC14-17), and the MEDIUM housekeeping (stale grants, no TTL, a secret in plain text, prompts in traces).

Two rules are worth a closer look. **GC14-07** doesn't trust a rule's name or description: it asks the gateway twin
"would you let this agent call `mail.send_email`?" and reports the rule that said yes. **GC14-05** is the one teams
forget: dry run is the right way to *start*, and the wrong way to stay.

The same review on the hardened deployment:

```bash
make check-fixed
```

Same as `python3 checker.py --twin hardened`.

```output
  HIGH    GC14-08  allow-ticket-reads
          An ALLOW rule trusts tool annotations (readOnlyHint, destructiveHint...). Whoever registers the MCP
          server declares them in its toolspec; a new tool with a wrong hint is allowed automatically.
          fix: Allow tools by name: destination.agent_registry.mcp_server.tool.name in [...].
...
1 finding (1 HIGH), 4 notes.
```

One left, on purpose. You'll see why in Step 3.

## Step 2 · Ask every control (`make decide`)

```bash
make decide
```

Same as `python3 decide.py --twin today`.

```output
--- GC14 decision table · today ---
agent principal: principal://agents.global.org-100000000099.system.id.goog/resources/aiplatform/projects/100000000014/locations/europe-west4/reasoningEngines/1400000000000000002

  L1  legit  alice asks how to fix a VPN                          completed
      for alice@example.com; the user's own question
      Agent Gateway   ALLOWED              tickets.search_kb: pilot
  ...
  C1  hijack email a ticket to an outside mailbox                 WENT THROUGH
      for alice@example.com; proposed after reading untrusted ticket text
      Model Armor     NOT_SCREENED         tools/call response of get_ticket: no Model Armor on this gateway
      Agent Gateway   ALLOWED              mail.send_email: pilot
  ...
  C3  hijack read another team's dataset                          WENT THROUGH
      for alice@example.com; proposed after reading untrusted ticket text
      Model Armor     NOT_SCREENED         tools/call response of get_ticket: no Model Armor on this gateway
      Agent Gateway   ALLOWED              bigquery.execute_sql_readonly: pilot
      IAM (BigQuery)  ALLOWED              dataset finance_exports: roles/bigquery.dataViewer on example-agents-prod via principalSet://agents.global.org-1000000...
  ...
  C6  hijack read another user's memories (user_id says bob)      WENT THROUGH
      for bob@example.com; the request body names a different user than the verified token
      Memory Bank     retrieve scope user_id=bob@example.com 1 memories returned, belonging to bob@example.com

6 of 6 hijacked calls went through; 2 of 2 legitimate calls completed.
```

### How to read the decision table

Each case is three lines or more:

1. **The case**: its ID (`L` = legitimate, `C` = hijacked), what the call would do, and the verdict. For a
   legitimate call the verdict is `completed` or `BROKEN`; for a hijacked one it's `stopped` or `WENT THROUGH`.
2. **For whom, and why it was proposed**: the user the agent believes it's working for, and where the proposal came
   from. "For bob" under C6 is the problem: the signed-in user is alice, but today's app believes the request body.
3. **One line per control that looked at the call**, in the order a real request meets them:

| Column 1 (control) | Column 2 (its decision) | Column 3 (why) |
|---|---|---|
| `Model Armor` | `BLOCKED`, `ALLOW`, `NOT_SCREENED` (no Model Armor) or `PASSED_UNSCREENED` (unreachable, fail open) | which tool response it screened. Blocked means the model never read that text, so the proposal never happens |
| `Memory Bank` | `retrieve scope ...`, `CREATED` or `SKIPPED` | which user's scope was used, which topic, when the memory expires |
| `your app` | `PAUSED` | the approval queue in your own code for write tools |
| `Agent Gateway` | `ALLOWED`, `DENIED`, `DRY_RUN would deny` or `NOT ATTACHED` | the destination and the **rule** that decided (or "default deny") |
| `IAM (BigQuery)` | `ALLOWED` or `DENIED` | which binding granted the data read, or that none did |

The **last line** of a stopped case is the control that stopped it. A case with no line that says no went through.
Read C3 again: the gateway allowed the tool (the policy allows everything), and IAM allowed the data, because a
`principalSet` grant gives **every agent in the project** Data Viewer on the whole project.

## Step 3 · Compare four setups

### The hardened deployment (`make decide-fixed`)

```bash
make decide-fixed
```

Same as `python3 decide.py --twin hardened`.

```output
0 of 6 hijacked calls went through; 2 of 2 legitimate calls completed.
```

Scroll up to see which control stopped each one:

| Case | Stopped by | The setting in `twin/hardened/deployment.json` |
|---|---|---|
| C1 email a ticket outside | **Model Armor** (the ticket text is flagged, the model never sees it) | `model_armor_authz_extension` with `failOpen: false` |
| C2 unregistered outside host | **Agent Gateway**, default deny | no rule allows unregistered hosts |
| C3 another team's dataset | **IAM (BigQuery)**: the gateway allows `execute_sql_readonly`, the dataset says no | Data Viewer on `helpdesk` only, for this agent's own principal |
| C4 ticket copy to an outside mailbox | **Agent Gateway**, rule `deny-mail` | a DENY rule for the mail server |
| C5 instruction stored as a memory | **Model Armor** (and the topic isn't enabled either) | `EXPLICIT_INSTRUCTIONS` removed, TTL 30 days |
| C6 another user's memories | **Memory Bank** scope from the verified token: 0 memories | `_lab_memory_scope_from: verified_token` |

L2 (bob closes a ticket) also stops in `your app` for a person to approve it: ADK's tool confirmation isn't supported
with Agent Runtime's session service, so the hardened app keeps its own approval queue.

### Dry run (`make decide-dry`)

The hardened deployment, with `iamEnforcementMode: "DRY_RUN"` on the gateway's IAP extension.

```bash
make decide-dry
```

Same as `python3 decide.py --twin hardened --dry-run`.

```output
  C2  hijack call an unregistered outside host                    WENT THROUGH
      ...
      Agent Gateway   DRY_RUN would deny   https://status.example.net/report: default deny (no rule grants access) (logged, not blocked)
  ...
  C4  hijack send a ticket copy to an outside mailbox             WENT THROUGH
      ...
      Agent Gateway   DRY_RUN would deny   mail.send_email: deny-mail (logged, not blocked)
  ...
2 of 6 hijacked calls went through; 2 of 2 legitimate calls completed.
```

The policy was **right** both times, and nothing happened, because dry run logs instead of blocking. C2 and C4 are
the cases where the gateway is the only control that says no. Dry run is how you find out which legitimate calls
your policy would break before you enforce it; it is not a place to stay.

### Rug pull (`make rugpull`)

The tickets team re-registers its MCP server in Agent Registry with a new tool, `export_ticket`, that sends a ticket
to an address in its arguments. Its toolspec says `readOnlyHint: true`. Nobody on the agent team reviews the change.

```bash
make rugpull
```

Same as `python3 decide.py --twin hardened --rugpull`.

```output
  C4  hijack send a ticket copy to an outside mailbox             WENT THROUGH
      for alice@example.com; proposed after reading untrusted ticket text
      Model Armor     ALLOW                tools/call response of get_ticket: NO_MATCH_FOUND
      Agent Gateway   ALLOWED              tickets.export_ticket: allow-ticket-reads
  ...
1 of 6 hijacked calls went through; 2 of 2 legitimate calls completed.
```

The `deny-mail` rule still works; the proposal simply uses a different tool. The `allow-ticket-reads` rule allows
any tool on the tickets server whose annotation says read-only, and **whoever registers the server writes the
annotations**: Agent Registry "doesn't automatically introspect the server" when you register it manually. That's
GC14-08, and it's your challenge.

### Model Armor outage (`make outage`)

```bash
make outage
```

Same as `python3 decide.py --twin hardened --outage`.

```output
  C2  hijack call an unregistered outside host                    stopped
      for alice@example.com; proposed after reading an untrusted knowledge-base article
      Model Armor     BLOCKED              tools/call response of search_kb: Model Armor unreachable, failOpen: false; the model never saw it
  ...
0 of 6 hijacked calls went through; 2 of 2 legitimate calls completed.
```

With `failOpen: false`, a screening failure blocks the tool response, so every case that depends on a tool response
stops at Model Armor. Write down what the helpdesk does during an outage (here: questions that need a ticket or an
article fail). The tests also run the `failOpen: true` variant: C1 and C5 then reach the model unscreened, and the
gateway rule and the disabled memory topic still stop them. That's why you want more than one control per path.

## Step 4 · The gateway's log lines (`make logs`)

```bash
make logs
```

```output
--- gateway decisions · hardened (one JSON line each; 'lab' holds our own fields) ---
{"logName": "projects/example-agents-prod/logs/networkservices.googleapis.com%2Fgateway_requests", "resource": {"type": "networkservices.googleapis.com/Gateway"}, "httpRequest": {"requestUrl": "https://status.example.net/report"}, "jsonPayload": {"authzPolicyInfo": {"result": "ALLOWED"}, "agentGatewayInfo": {}}, "lab": {"case": "C2", "target": "https://status.example.net/report", "policy_says": "DENIED", "rule": "default deny (no rule grants access)", "dry_run": true}}
```

(One line shown; the first half of the output is today's deployment.) The field names outside `lab` come from the
queries in Google's Agent Gateway codelab: the `gateway_requests` log, `jsonPayload.authzPolicyInfo.result`, and
`jsonPayload.agentGatewayInfo.agentRegistryResource`, which is **empty for an unregistered destination**. In a dry run
the request went through, so the twin writes `ALLOWED`; IAP's own audit log (`protoPayload.serviceName="iap.googleapis.com"`)
is where Google says the would-be denials are recorded. The guided build shows both on a real gateway.

## Step 5 · Prove it (`make test`)

```bash
make test
```

Same as `python3 run_tests.py`.

```output
[PASS] decide: today, 6 of 6 hijacked calls go through and 2 of 2 legitimate calls complete
[PASS] decide-fixed: hardened, 0 of 6 go through, 2 of 2 complete, each stopped by the control the README names
[PASS] decide-dry: DRY_RUN lets C2 and C4 through; the gateway still says what it would deny, and logs it
[PASS] rugpull: with an annotation-based allow rule, a re-registered tool marked readOnlyHint goes through (C4)
[PASS] rugpull: the same rule written with tool NAMES stops the new tool at the default deny
[PASS] outage: Model Armor down with failOpen false: 0 of 6, every screened response is blocked, legit still works
[PASS] outage with failOpen true: C1 and C5 text reaches the model unscreened; the gateway and topics still stop them
[PASS] fail closed: an agent without Agent Identity behind the gateway is denied, legitimate calls too
[PASS] fail closed: a typo in a policy condition stops decide.py with CelError instead of allowing traffic
[PASS] C6: today the body's user_id (bob) picks the memory scope; hardened uses the verified token (alice)
[PASS] C3: the gateway allows execute_sql_readonly; IAM on the dataset decides (and a project-wide grant leaks)
[PASS] logs: Google's gateway log field names; an unregistered host has an empty agentGatewayInfo
[PASS] check: 14 findings on today's deployment, 9 of them HIGH (15 once you've written GC14-18)
[PASS] check-fixed: nothing left on the hardened deployment but GC14-08 (your challenge)
[PASS] check: each rule GC14-01..17 fires on one wrong setting and stays quiet when it's right (18 cases)
[PASS] check: GC14-07 doesn't trust a deny rule's name; it asks the gateway twin what it would decide
[PASS] check --ci: HIGH findings would fail a pipeline; the notes never count
[PASS] CEL: Google's example conditions evaluate as written (registry, tool + annotation, unregistered host/path)
[PASS] CEL: in, !=, !, ( ), && before ||, and ! binds tighter than ==
[PASS] CEL: unsupported syntax raises CelError (unknown attribute, numbers, >, in on a hint, methods, lists)
[PASS] CEL: every condition in today's and the hardened deployment is inside the supported subset
[PASS] files: access policy rules use Google's v3 field names; the IAP extension uses V2 metadata
[PASS] safety: every hijack case only says where the proposal came from; no model, no attack text in the lab
[PASS] safety: only documentation domains, placeholder IDs, no keys or tokens
[PASS] cloud: Terraform starts in DRY_RUN with one DENY rule, grants go to the agent's own principal, audit logs on

ALL TESTS PASSED (25 run)
```

Two of these are about failing **closed**. If an agent behind the gateway has no Agent Identity, everything is denied,
legitimate calls included. And if you mistype an attribute in a policy condition (`tool.nmae`), `cel.py` stops with an
error instead of treating the rule as "doesn't match". For a DENY rule, "doesn't match" would quietly allow traffic.

## Step 6 · Change one thing and re-run

The deployment files are plain JSON. Pick one hardened setting, change it, and re-run `make decide-fixed` and
`make check-fixed`. Three to try (undo each one afterwards, or `git checkout twin/`):

- In `twin/hardened/deployment.json`, set `"_lab_memory_scope_from"` to `"request_body"`: C6 goes through and
  GC14-11 comes back.
- Delete the whole `deny-mail` rule: C4 is still stopped, by the **default deny**, and GC14-07 stays quiet. Why is the
  explicit deny rule still worth having? (Hint: what happens the day someone adds a broad allow rule?)
- Set `"failOpen": true` on `model_armor_authz_extension` and run `make outage`.

`python3 -m json.tool twin/hardened/deployment.json` finds a JSON typo if you make one.

## Step 7 · Your challenge (no solution included)

Two changes. `make challenge` runs the 25 lab tests plus 4 challenge tests; all 4 fail until you're done.

1. **Rule GC14-18: Data Access audit logs for Memory Bank** (`checker.py`, at the `TODO`). Cloud Audit Logs records
   admin activity by default, but "Data Access audit logs are disabled by default for all services but some BigQuery
   services". A Memory Bank retrieve is a data read, so with `DATA_READ` off nobody can later answer "who read
   Bob's memories, and when?". Report a **MEDIUM** finding `GC14-18` when `"DATA_READ"` is missing from
   `dep["audit_logs"]["aiplatform.googleapis.com"]`, including when there's no `audit_logs` section at all. It must
   fire on today's deployment and stay quiet on the hardened one.
2. **The rug-pull fix** (`twin/hardened/deployment.json`). Rewrite the condition of the `allow-ticket-reads` rule so
   it names the tools the helpdesk reads, with `destination.agent_registry.mcp_server.tool.name in [...]`, instead of
   trusting `read_only_hint`. Then `make rugpull` should stop `export_ticket` at the default deny, and both
   legitimate calls should still complete. Keep the server name in the condition too.

```bash
make challenge
```

Real output before you start:

```output
[PASS] cloud: Terraform starts in DRY_RUN with one DENY rule, grants go to the agent's own principal, audit logs on
[FAIL] challenge: checker reports GC14-18 on today's deployment (memories.retrieve isn't in any audit log)
[FAIL] challenge: GC14-18 is quiet when DATA_READ is on, and fires when only DATA_READ is removed
[FAIL] challenge: make rugpull shows 0 of 6 hijacked calls and 2 of 2 legitimate calls
[FAIL] challenge: checker.py --twin hardened reports nothing
  why test_26_gc14_18_today: AssertionError: write rule GC14-18 in checker.py
  why test_27_gc14_18_reads_the_setting: AssertionError: GC14-18 must look for DATA_READ itself, not just any audit config
  why test_28_rugpull_stopped: AssertionError: went through: ['C4'], broken: []: name the tools in allow-ticket-reads instead of trusting readOnlyHint
  why test_29_checker_clean: AssertionError: still reported: GC14-08

4 of 29 TESTS FAILED (29 run)
```

Done when `make challenge` ends with `ALL TESTS PASSED (29 run)`, `make check` shows 15 findings (GC14-18 is new),
`make check-fixed` shows 0, and `make rugpull` shows 0 of 6. Then think about the process, not just the rule: who is
told when someone re-registers an MCP server your agent uses?

## Step 8 · The guided build (optional, your project)

[GUIDED-BUILD.md](GUIDED-BUILD.md) builds a small version for real, with console steps, `gcloud` and Terraform: an ADK
agent deployed with **Agent Identity**, bound to an **Agent Gateway** whose registry lists only the Google endpoints
it needs, Google's **BigQuery MCP server** as its tool, one **DENY rule** run first in dry-run and then enforced,
**Data Access logs** and a **TTL** for Memory Bank, four requests, one setting changed, cost and teardown.

## Troubleshooting

- `python3: command not found` on Windows: use `py` instead, for example `py decide.py --twin today`.
- `make: command not found`: run the Python command shown next to each `make` line.
- `cel.CelError: unknown attribute ...` after you edited a policy: check the attribute name against the list at the
  top of `cel.py` (it's Google's table). The lab refuses to guess what a misspelt condition means.
- `json.decoder.JSONDecodeError`: `python3 -m json.tool twin/hardened/deployment.json` shows the line.
- A test fails after your edits and you want the original files back: `git checkout twin/ checker.py`.
- The lab is tested on Python 3.11 and 3.13. If you see a `SyntaxError` in a lab file, check `python3 --version` first.

## Cost

**$0.** The offline lab runs on your laptop and talks to nothing. The guided build has its own cost section.

## Safety rules

- The lab is **decision-only**: no model, no prompts, no attack payloads, no code that makes anything follow text it
  read. `test_lab.py` checks that the four lab programs import no network or model library.
- Every address and host is on a reserved documentation domain (`example.com`, `example.net`, RFC 2606). Project
  numbers, org IDs and agent IDs are placeholders. The one "token" is the string `PLACEHOLDER-NOT-A-REAL-TOKEN`.
- The guided build runs only in **your own sandbox project**, never a work project, and tears everything down.
- Use what you learn here to review and defend agents you are responsible for.

## Sources

- [IAM Unified Access Policies overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/iam-overview-uap),
  [configure them](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/configure-iam-policies-uap),
  [CEL attributes](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/cel-attributes-uap)
- [Set up Agent Gateway](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/set-up-agent-gateway),
  [delegate authorization (IAP and Model Armor extensions, DRY_RUN)](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/delegate-authorization),
  [route Agent Runtime traffic through Agent Gateway](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/agent-gateway-runtime-deploy)
- [Agent Identity](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/agent-identity)
- [Register MCP servers in Agent Registry](https://docs.cloud.google.com/agent-registry/register-mcp-servers)
- [Set up Memory Bank](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/setup)
- [Configure Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access)
- [ADK tool confirmation, known limitations](https://adk.dev/tools-custom/confirmation/)
- [Google's Agent Gateway codelabs (code)](https://github.com/GoogleCloudPlatform/cloud-networking-solutions/tree/main/codelabs)
