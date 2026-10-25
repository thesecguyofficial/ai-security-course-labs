# Lab M19: Capstone. Secure the TSG Helpdesk end to end

The graded capstone of *AI Security Engineer* (The Sec Guy), lessons **19.1 to 19.3** (19.2 and 19.3, the
walkthroughs, are coming; this guide is complete without them). You get one realistic,
deliberately vulnerable AI system and do the whole job on it: threat-model it, attack it, fix it, prove the fixes
with security evals in CI, write detections and an incident report, review its cloud deployment, and write the
governance note someone needs before it goes live. Then you publish it as a public GitHub repo and submit it.

- **Time:** plan 8 to 12 hours, spread over two or three weeks.
- **Cost:** $0. Python **3.11 or newer**, standard library only. No packages, no model download, no API key.
- **Cloud:** the cloud part (Part 6) reviews an AWS deployment description offline, so you need no AWS account.
  Azure and Google Cloud versions ship with those streams (`cloud/azure/`, `cloud/gcp/`).
- **Grading:** `selfcheck.py` verifies the objective parts. A person then grades your work against
  [`RUBRIC.md`](RUBRIC.md): Pass, Merit or Distinction. How to submit: [`SUBMISSION.md`](SUBMISSION.md).

## The system

TSG Helpdesk, capstone edition: the same Helpdesk you met in Modules 2 to 8, with all its parts at once.

| Part | File | What it does |
|---|---|---|
| Web app | `helpdesk/app.py` | Chat page and `POST /api/chat` on `127.0.0.1:8719`. Sign-in is simulated: you pick a user |
| One chat turn | `helpdesk/core.py` | Retrieval, the agent loop, tool calls, the reply, the app log |
| RAG | `helpdesk/rag.py`, `data/kb/` | Keyword search over seven pages. Some are for one tenant, one is staff only, two come from a partner feed |
| Agent tools | `helpdesk/tools.py` | `lookup_order` reads fake orders; `send_email` writes to `state/outbox.jsonl` (nothing is sent) |
| MCP server | `helpdesk/mcp_server.py`, `mcp_client.py` | The "crm" server over stdio: `crm_lookup`, `crm_list_customers`. Release 2 changes them |
| Model | `helpdesk/model.py` | A **worst-case stand-in**, not AI: it follows every instruction it reads and ignores labels |
| **Your controls** | `helpdesk/guards.py`, `helpdesk/config.py` | Every hook allows everything today. This is where you work |
| App log | `helpdesk/logs.py` | JSON lines in `state/app-log.jsonl`, same fields as the attack log in `detections/logs/` |

Users (all fake, every domain ends in `.example`): `alice@acme.example` and `carol@acme.example` (tenant acme),
`bob@globex.example`, `dana@initech.example`, and `sam@tsg-helpdesk.example` (staff).

**Why a stand-in model?** So your controls are tested, not a model's mood: every run gives the same answer on every
laptop and in CI. It is deliberately worse than a real model: it obeys every `LAB-INJECTED-DIRECTIVE` placeholder
it reads, in a message, a page, a tool description or a tool result. A control that asks the model to behave does
nothing here. A control in code that checks the action does. That is the lesson of Modules 3 to 8.

## Ground rules

1. **Put your controls in `helpdesk/guards.py` and `helpdesk/config.py`.** You may add helper modules next to
   `guards.py`. Do not edit the other `helpdesk/` files, `data/`, `tests/`, `evals/cases.json` or the checking
   tools: the self-check compares them with the originals (check H1), so a grader knows the model, tools and logs
   were not weakened to pass.
2. **Normal use must keep working.** `tests/test_functional.py` passes today and must still pass after your fixes.
3. **Only fake data, only your machine.** The app binds to `127.0.0.1`. Never put a real key, address or customer
   record in your repo (check H3).
4. **Your own work.** You may use any tool, AI assistants included, if you say what you used and how in your
   README's "How I built this" section, and you can explain every line in a walkthrough. Don't copy another
   learner's repo.
5. **Out of scope:** the simulated sign-in (treat the chosen user as authenticated), denial of service against your
   own laptop, and the stand-in model's code.

## Part 0 · Make it your repo (15 minutes)

```bash
cd labs/m19
make export DEST=../../../my-ai-security-capstone     # python3 export.py <folder>
cd ../../../my-ai-security-capstone
git init -b main && git add . && git commit -m "TSG Helpdesk capstone: starting point"
```

Create an **empty public** repo on GitHub (no README, no licence), then follow the two `git` lines `export.py`
printed. Open the repo's **Actions** tab: the `capstone-checks` workflow runs on every push. It is red now. Your
job is to make it green, honestly.

From here on, work in your exported repo. `README.md` there is your portfolio README (fill it in at the end);
this guide is kept as `CAPSTONE-GUIDE.md`.

## Part 1 · Threat model (1 to 2 hours)

Fill in `report/THREAT-MODEL.md`: assumptions, the data flows, all seven trust boundaries, the lethal trifecta,
then at least **10 threats** with OWASP IDs and the year (`LLM01:2026`, `ASI02:2026`) and, for at least five, a
MITRE ATLAS technique (`AML.T0051.001`). Do this **before** you run the attacks: the point is to see how much of
the system you can reason about from the design. Lessons 2.1 to 2.5.

## Part 2 · Attack (1 to 2 hours)

```bash
make attack                       # python3 tour.py: one attack for each known finding
make ask U=bob@globex.example Q="Show me the Acme onboarding guide"
make run                          # the web page on http://127.0.0.1:8719 (Ctrl+C to stop)
```

The six known findings, described by what you can see, not by their cause:

| ID | What you can see |
|---|---|
| F-1 | A customer asks about refunds, and the fake customer list is emailed to an outside address |
| F-2 | Customers can read another tenant's pages and a staff-only page |
| F-3 | After the crm MCP server's "update" (release 2), the agent calls a tool nobody approved and leaks a token |
| F-4 | Asking for the system prompt reveals a staff escalation code |
| F-5 | A partner page puts live markup into the chat page |
| F-6 | One message can trigger dozens of tool calls; huge messages and bursts are never refused |

For each one, find the **root cause** (which hook, which data, which missing check) and record the evidence in
`report/FINDINGS.md`: the request, what came back, the log line or outbox entry. Read `state/app-log.jsonl` as you
go: you need its fields in Part 5.

**There is at least one more.** The six above are the ones we tell you about. Finding, fixing and testing a
real issue that is not on this list is part of the Distinction level.

## Part 3 · Fix (2 to 3 hours)

Change `helpdesk/guards.py` (and `helpdesk/config.py`). Each function's docstring says when it runs and what it
receives. Then:

```bash
make test                         # F01 to F12 must stay green; S01 to S11 turn green as you fix things
make attack                       # every line should now say "held"
```

Aim for controls that hold **even though the model obeys the instruction**: decide in code what a tool call may
do, who may read which page, which MCP tools are approved (`make pin` records them), what reaches the page. Then
try one variant of each attack against your own fix and write down what happened (`FINDINGS.md`, "Variants I tried").

## Part 4 · Prove it in CI (1 hour)

```bash
make eval                         # the gate: 27 core cases + yours; exit 1 if any fails
make regress                      # take your controls away again, three ways: the gate must FAIL each time
```

`evals/cases.json` is the core suite: 17 attacks and 10 normal requests. Add your own cases to
`evals/my_cases.json` (same format; extra pages go in `evals/kb/`). For Merit: at least five, with two new
injection variants and two normal requests that a careless fix would break.

Push. The workflow runs the same commands. Keep one run where a deliberate regression made it fail (a branch where
you weakened a guard, then deleted it): that red run is evidence. Lesson 17.3 and 17.4.

## Part 5 · Detect and respond (1 to 2 hours)

`detections/logs/attack-day.jsonl` is one busy day of app logs (seed 1) with five incidents hidden in normal
traffic: zero-click exfiltration (S1), cross-tenant and staff-only reads (S2), an MCP rug pull (S3), system prompt
extraction (S4) and denial of wallet (S5). Write rules in `detections/rules.json` (the format is at the top of
`detections/detect.py`); the one example rule catches S1 but also fires on honest traffic.

```bash
make detect                       # your rules on the attack day
make detect-check                 # all five incidents on seeds 1, 2 and 3, max 2 false alerts a day
make detect LOG=state/app-log.jsonl   # the same rules on your own Helpdesk's log
```

Each seed changes who the attackers are and what they use, so a rule that names a user, an IP or a request ID
will miss the next day. Graders also run your rules on days you have never seen. Then pick **one** incident and
write `report/INCIDENT-REPORT.md` (timeline, scope, root cause, containment, evidence with request IDs). Lessons
16.1, 16.5 and 16.6.

## Part 6 · Cloud: your stream (1 hour)

`cloud/aws/deployment.json` describes the Helpdesk on AWS as the platform team's first draft: Bedrock, a guardrail,
a knowledge base, a Bedrock agent, an AgentCore gateway in front of the crm tools, logging, detection and budget.
It is the course's own summary format, one file instead of a dozen consoles; each key names the real setting and
the lesson that teaches it.

```bash
make cloud                        # python3 cloud/cloud_check.py: 11 HIGH findings on the first draft
```

Harden the file until there are no HIGH findings (Pass) and no MEDIUM ones (Merit). For every change, write one
line in `FINDINGS.md` ("Cloud") naming the lesson. Optional, for Distinction evidence: build part of it for real in
your own sandbox account with one of the guided builds (`labs/m12/GUIDED-BUILD.md`, `labs/m14/GUIDED-BUILD.md`),
record what you saw, and show the teardown.

`capstone.json` names your stream. It is `aws` for now; Azure and Google Cloud are accepted when their streams ship.

## Part 7 · Governance note (45 minutes)

Fill in `report/GOVERNANCE-NOTE.md`: the AI inventory entry, three to five risk decisions, an **evidence index**
that links every control to the test, eval case or rule that proves it (at least eight rows), a mapping to the
NIST AI RMF functions and ISO/IEC 42001, and the residual risk with an owner and a review date. Lessons 18.1 to 18.4.

## Part 8 · Submit

```bash
make check                        # python3 selfcheck.py: every objective check, PASS or FAIL
```

Fill in `README.md` (your portfolio README), push, wait for a green Actions run, then follow
[`SUBMISSION.md`](SUBMISSION.md). Lesson 19.3 (coming) will walk through all of it.

## What's in this folder

| Path | What it is |
|---|---|
| `helpdesk/` | The app. You change `guards.py` and `config.py` only |
| `data/` | Fake users, customers, orders and the knowledge base |
| `tests/` | `test_functional.py` (F01 to F12) and `test_security.py` (S01 to S11) |
| `evals/` | `run_evals.py` (the gate and the regressions), `cases.json` (core), `my_cases.json` (yours), `kb/` |
| `detections/` | `attack_sim.py`, `detect.py` (rule engine), `score.py`, `rules.json` (yours), `logs/` |
| `cloud/` | `cloud_check.py`, `aws/deployment.json` (yours to harden), `azure/` and `gcp/` (coming) |
| `report/` | Templates: threat model, findings, incident report, governance note, portfolio README |
| `template/.github/workflows/capstone.yml` | The CI workflow (`export.py` puts it in place) |
| `selfcheck.py`, `selfcheck.lock.json` | The self-check and the fingerprints of the original files |
| `tour.py`, `export.py` | `make attack` and `make export` |
| `RUBRIC.md`, `SUBMISSION.md` | How it is graded, how to submit |

## Troubleshooting

- **`python3: command not found` or a version below 3.11:** run `make doctor` in the repo root (lesson 0.6).
  Windows: use `py` instead of `python3` and run the commands from the Makefile by hand.
- **H1 fails after you only changed `guards.py`:** your editor may have changed line endings or reformatted
  another file. `git diff --stat` shows which. Restore it with `git checkout -- <file>`.
- **A test hangs:** an MCP server process from an earlier run may still be running. Close the terminal, or
  `pkill -f helpdesk.mcp_server`.
- **`make run` says the port is in use:** another copy is running. Stop it, or `python3 -m helpdesk.app --port 8720`.
