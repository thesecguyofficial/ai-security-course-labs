# Capstone rubric: TSG Helpdesk

Published with the capstone so you know exactly what earns each grade. Version **2026.10**. A person grades every
submission against this page; `selfcheck.py` only checks the objective parts.

## How the grade is decided

1. **Automated checks.** `python3 selfcheck.py` must end with `OBJECTIVE CHECKS PASSED` on the commit you submit,
   and the grader re-runs the course's own copy against your repo (with other simulated days for detections).
   If any required check fails, the submission is returned with the failing lines; nothing else is graded yet.
   On the grader's other days, a missed incident returns the submission; more than 2 false alerts a day there
   limits criterion 5 to Pass.
2. **Eight criteria**, each scored 0 to 3: 0 = not met, 1 = Pass, 2 = Merit, 3 = Distinction. A level includes
   everything in the levels below it.
3. **Overall grade:**

| Grade | Rule |
|---|---|
| **Pass** | Automated checks pass, and every criterion scores at least 1 |
| **Merit** | Every criterion at least 1, and at least five criteria at 2 or more |
| **Distinction** | Every criterion at least 2, and at least four criteria at 3, one of which is criterion 2 or 3 |
| Not yet | Anything else. You get written feedback per criterion and may resubmit as often as you like |

The certificate needs a Pass. Merit and Distinction are shown to you with the feedback.

## Automated checks (selfcheck.py)

| Check | What must be true |
|---|---|
| H1 | The core Helpdesk files, data, tests, core eval cases and checking tools match the originals |
| H2 | The app listens on 127.0.0.1 only |
| H3 | No real-looking secrets anywhere in the repo |
| H4 | A workflow in `.github/workflows/` runs `selfcheck.py`, with `permissions: contents: read`, no `pull_request_target`, every action pinned to a full commit SHA |
| T1, T2 | Functional tests F01 to F12 and security tests S01 to S11 pass |
| E1 | The eval gate passes: all core cases and all of yours |
| E2 | The gate fails on each of the three regressions (injection, retrieval, output) |
| D1 | Your rules raise at least one alert for each of S1 to S5 on three simulated days, with at most 2 false alerts a day |
| C1 | The cloud check for your stream has no HIGH findings |
| R1 to R5 | The four reports and your README have every section, no placeholders or TODO, and the minimum content listed in each template |

## The eight criteria

### 1. Threat model (`report/THREAT-MODEL.md`)

| Level | What it looks like |
|---|---|
| Pass (1) | Data flows and all seven trust boundaries; at least 10 threats as actor, path, outcome, each with an OWASP ID and year; risk scored; a control named for every threat rated 4 or more |
| Merit (2) | Threats cover the MCP server, the partner feed, identity and the web page, not only the chat box; ATLAS techniques where they fit; the top 5 are justified; residual risk stated |
| Distinction (3) | The model predicted issues before the attacks did, and is honestly updated afterwards (what it missed and why); includes at least one threat beyond the six known findings, tested in Part 2 |

### 2. Attack and findings (`report/FINDINGS.md`)

| Level | What it looks like |
|---|---|
| Pass (1) | All six known findings reproduced, each with evidence (request, response, log or outbox line), root cause and severity |
| Merit (2) | Root causes named as the missing control, not the symptom; at least one variant per finding tried against your own fix, with the result |
| Distinction (3) | At least one real issue that is **not** in the list of six, found, explained, fixed and covered by a test or eval case of yours |

### 3. Fixes (`helpdesk/guards.py`, `helpdesk/config.py`)

| Level | What it looks like |
|---|---|
| Pass (1) | S01 to S11 and F01 to F12 pass; every fix is in code outside the model |
| Merit (2) | Defence in depth: at least two independent layers on the injection path (for example a tool policy and a data scope), each explained with its trade-off; no secret left in any prompt |
| Distinction (3) | Least privilege by design: per-role tools, per-turn data scope and fail-closed behaviour (unpinned MCP tools, unknown roles) shown with your own tests; the code is small enough for a reviewer to read in ten minutes |

### 4. Security evals in CI (`evals/`, `.github/workflows/`)

| Level | What it looks like |
|---|---|
| Pass (1) | A green CI run on the submitted commit; the gate fails on all three regressions |
| Merit (2) | At least 5 cases of your own: 2 or more new injection variants and 2 or more normal requests that a careless fix would break; the workflow stays hardened |
| Distinction (3) | A linked CI run where the gate blocked a real regression you introduced on a branch, with a short note on what it caught and why that case exists |

### 5. Detection and response (`detections/rules.json`, `report/INCIDENT-REPORT.md`)

| Level | What it looks like |
|---|---|
| Pass (1) | D1 passes; the incident report has a timeline, scope, root cause, containment and at least three request IDs as evidence |
| Merit (2) | No false alerts on seeds 1 to 3; every rule carries ATLAS IDs where one fits; rules also pass on the grader's unseen days |
| Distinction (3) | The same rules run on your own app's log after you replay attacks and catch them (show the output), and the report names a detection gap and the rule or log field that closes it |

### 6. Cloud, your stream (`cloud/<stream>/deployment.json`)

| Level | What it looks like |
|---|---|
| Pass (1) | No HIGH findings; every change listed in `FINDINGS.md` with the lesson that teaches it |
| Merit (2) | No MEDIUM findings either, and each change says what attack or failure it prevents in this system |
| Distinction (3) | Evidence from your own sandbox account for at least one control, such as a guardrail from a guided build. Show the cost and the teardown. No account IDs, keys or personal data in screenshots or text |

### 7. Governance and evidence (`report/GOVERNANCE-NOTE.md`)

| Level | What it looks like |
|---|---|
| Pass (1) | Inventory entry, risk decisions and an evidence index of at least 8 rows that point to real files, tests, cases or rules |
| Merit (2) | Controls mapped to the NIST AI RMF functions and ISO/IEC 42001 activities accurately (only what you did); residual risk with an owner and a review date |
| Distinction (3) | A reader who has never seen the code could approve or reject go-live from this page alone |

### 8. Communication (`README.md`)

| Level | What it looks like |
|---|---|
| Pass (1) | Runs in three commands from a clean clone; says what it is, what you found and fixed, and how you built it, including any AI assistance |
| Merit (2) | A stranger understands the project in one screen of reading: a diagram, numbers you can prove, links to the evidence |
| Distinction (3) | It reads like a professional security review summary: precise, short, no claims without evidence |

## What graders never reward

- Length for its own sake. A short, exact report beats a long one.
- Claims without evidence ("fully secure", "all attacks blocked"). Say what you tested and what held.
- Controls that ask the model to behave and nothing else.
- Rules or fixes tuned to one log line, one user or one case ID.

## Academic honesty

Your repo is public, which makes it a portfolio piece and also means others can read it. Reading other people's
public work for ideas is fine; copying it is not. A grader may ask you to walk through any part of your work.
Submissions that copy another learner's repo are not graded.
