# Capstone rubric: TSG Helpdesk

Published with the capstone so you know exactly how the grade is decided. Version **2026.10.26**. Grading is
automatic and the same for everyone: no person and no AI model reads or scores your reports.

## How the grade is decided

You submit your public repo URL and the full commit SHA on the course's capstone page. The grader then re-runs the
course's own copy of `selfcheck.py` against your repo at that commit, in a sandbox. On top of what `make check`
does on your laptop, it runs your detection rules on three more simulated days you have never seen, sends HTTP
probes to your running app, and cross-checks that the results agree with each other.

The grade comes from the **required automated checks** below (H1 to H4, T1, T2, E1, E2, D1, C1, R1 to R5). You need
to pass them to get a Pass.

| Grade | Rule |
|---|---|
| **Pass** | Your submission passes the required automated checks, and there is no integrity hold |
| **Not yet** | Anything else. The capstone page lists the checks that failed. Fix them, push, and submit the new SHA |

- **Integrity hold.** If the grader finds that the checking tools were changed, or that results contradict each
  other (for example the self-check reports a pass that the separate test run or the probes do not confirm), the
  submission is not passed automatically. It is held for the course owner to look at, and you see "Not yet" with a
  note until then.
- **Resubmitting.** Submit as often as the page allows: up to 3 times a day, at least 30 minutes apart. Only the
  commit you submit is graded; later pushes are not, until you submit again.
- **Overrides.** The course owner can change a grade by hand, for example after an integrity hold turns out to be
  a false alarm. Every change is logged.
- **What a Pass earns.** The certificate needs a Pass on this capstone. There are no higher grades: a Pass is a Pass.

Run `make check` before you submit: it shows you every failing line. Each check stands for something an employer
will look for in your repo.

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

R1 to R5 are the only part of the grade that looks at your reports, and they check structure: every section is
there, nothing is left as a placeholder or TODO, and each template's minimum content is met. They do not judge how
good the writing is. The next section is for that.

## What good looks like

Nobody scores this section. It describes what a strong capstone contains, so your repo is worth showing to an
employer and not only enough to pass. Use it as a checklist while you write.

### 1. Threat model (`report/THREAT-MODEL.md`)

- Data flows and all seven trust boundaries; at least 10 threats written as actor, path, outcome, each with an
  OWASP ID and year; risk scored; a control named for every threat rated 4 or more.
- Threats cover the MCP server, the partner feed, identity and the web page, not only the chat box. ATLAS
  techniques where they fit. The top 5 are justified and the residual risk is stated.
- The model predicted issues before the attacks did, and you updated it honestly afterwards: what it missed and
  why. It includes at least one threat beyond the six known findings, tested in Part 2.

### 2. Attack and findings (`report/FINDINGS.md`)

- All six known findings reproduced, each with evidence (request, response, log or outbox line), root cause and
  severity.
- Root causes named as the missing control, not the symptom. At least one variant per finding tried against your
  own fix, with the result.
- At least one real issue that is **not** in the list of six, found, explained, fixed and covered by a test or
  eval case of yours.

### 3. Fixes (`helpdesk/guards.py`, `helpdesk/config.py`)

- S01 to S11 and F01 to F12 pass, and every fix is in code outside the model.
- Defence in depth: at least two independent layers on the injection path (for example a tool policy and a data
  scope), each explained with its trade-off. No secret left in any prompt.
- Least privilege by design: per-role tools, per-turn data scope and fail-closed behaviour (unpinned MCP tools,
  unknown roles), shown with your own tests. The code is small enough to read in ten minutes.

### 4. Security evals in CI (`evals/`, `.github/workflows/`)

- A green CI run on the submitted commit, and the gate fails on all three regressions.
- At least 5 cases of your own: 2 or more new injection variants and 2 or more normal requests that a careless fix
  would break. The workflow stays hardened.
- A linked CI run where the gate blocked a real regression you introduced on a branch, with a short note on what
  it caught and why that case exists.

### 5. Detection and response (`detections/rules.json`, `report/INCIDENT-REPORT.md`)

- D1 passes. The incident report has a timeline, scope, root cause, containment and at least three request IDs as
  evidence.
- No false alerts on seeds 1 to 3, and every rule carries ATLAS IDs where one fits. Rules written for behaviour,
  not for one user or IP, also hold on the grader's unseen days.
- The same rules run on your own app's log after you replay attacks and catch them (show the output), and the
  report names a detection gap and the rule or log field that closes it.

### 6. Cloud, your stream (`cloud/<stream>/deployment.json`)

- No HIGH findings, and every change listed in `FINDINGS.md` with the lesson that teaches it.
- No MEDIUM findings either, and each change says what attack or failure it prevents in this system.
- Evidence from your own sandbox account for at least one control, such as a guardrail from a guided build. Show
  the cost and the teardown. No account IDs, keys or personal data in screenshots or text.

### 7. Governance and evidence (`report/GOVERNANCE-NOTE.md`)

- Inventory entry, risk decisions and an evidence index of at least 8 rows that point to real files, tests, cases
  or rules.
- Controls mapped to the NIST AI RMF functions and ISO/IEC 42001 activities accurately (only what you did), and
  residual risk with an owner and a review date.
- A reader who has never seen the code could approve or reject go-live from this page alone.

### 8. Communication (`README.md`)

- Runs in three commands from a clean clone. Says what it is, what you found and fixed, and how you built it,
  including any AI assistance.
- A stranger understands the project in one screen of reading: a diagram, numbers you can prove, links to the
  evidence.
- It reads like a professional security review summary: precise, short, no claims without evidence.

## What weakens a capstone

- Length for its own sake. A short, exact report beats a long one.
- Claims without evidence ("fully secure", "all attacks blocked"). Say what you tested and what held.
- Controls that ask the model to behave and nothing else.
- Rules or fixes tuned to one log line, one user or one case ID. The unseen days and the probes exist to catch
  these.

## Academic honesty

Your repo is public, which makes it a portfolio piece and also means others can read it. Reading other people's
public work for ideas is fine; copying it is not. When you submit, you confirm the work is your own. The course
owner may ask you to walk through any part of it, and a submission that copies another learner's repo loses its
Pass.
