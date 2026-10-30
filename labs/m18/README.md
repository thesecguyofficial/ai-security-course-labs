# Lab M18: run an AI risk assessment on TSG Helpdesk and build the evidence pack

Companion to lessons **18.0 to 18.4** of *AI Security Engineer* (The Sec Guy). About 75 minutes, **$0**, all on your
laptop: **Python 3.11+ only**, no packages, no model, no cloud account, no network.

It is **24 October 2026**. TSG Helpdesk, the course's support bot (chat, RAG, refund and email tools, a ticketing MCP
server, memory), has been in production since May for customers in India and the EU. Over Modules 3 to 17 the team
added real controls. Now the business wants a sign-off, and the team has written a first-draft AI risk assessment.
Your job: review the draft the way an auditor would, then write the assessment properly, close one legal gap in
the product itself, and hand over an evidence pack that proves what it claims.

| Part | What you do | Lesson |
|---|---|---|
| **Inventory** | The AI inventory rows for the Helpdesk; one component has a gap | 18.3 |
| **Triage** | EU AI Act role, risk tier and dates; then the same system re-used for hiring | 18.2 |
| **Audit the draft** | 22 errors of 15 kinds, each one a real governance mistake | 18.0, 18.1 |
| **Your assessment** | A risk register for 13 required risk sources, with owners, treatments and residual risk | 18.1, 18.4 |
| **Fix the product** | The Helpdesk never says it is an AI. Change that, and prove it | 18.2 |
| **Crosswalk** | Which NIST AI RMF, ISO/IEC 42001, EU AI Act and OWASP items your proven controls support | 18.1, 18.2 |
| **Evidence pack** | A folder an auditor can verify with one command | 18.3, 18.4 |
| **Prove** | `make test` (15 tests) and `make challenge` (5 more, on your work) | 18.4 |

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m18`.

## What's in this folder

| File | What it is |
|---|---|
| `govlab.py` | The toolkit: `inventory`, `triage`, `check`, `crosswalk`, `evidence`, `pack`, `verify-pack`, `start` |
| `explore.py` | The read-only helper for Step 1b: one idea at a time (kinds of document, an inventory entry, a risk row, a control, an evidence item). It writes no file and runs nothing |
| `Makefile` | Short commands for Mac and Linux (`make check`, `make inventory` ...); `make -n <target>` shows what one would run |
| `helpdesk/system-card.json` | TSG Helpdesk 2.0: components, tools, data, features, EU AI Act facts, and the status of every course control |
| `helpdesk/chat-widget.html` | The chat widget; `id="greeting"` is the first message every customer sees |
| `catalog/controls.json` | The 32 controls this course teaches (C01 to C27, G01 to G05), where each was taught, what proves it, and its mapping to NIST AI RMF, the EU AI Act, ISO/IEC 42001 and OWASP 2026 |
| `catalog/risk-library.json` | 16 risk sources for a GenAI app with tools, RAG, memory and MCP, with the system feature that makes each one required |
| `catalog/frameworks.json` | The framework items the crosswalk uses, with their sources |
| `first-draft/` | The team's first draft: `assessment.json`, `risk-register.csv`, `evidence-index.csv` |
| `evidence/` | Evidence files. Three are real `make test` output from labs m03, m05 and m07; the rest are illustrative samples, labelled as such |
| `templates/` | Lesson 18.3's templates: one-page AI policy, AI inventory, model and vendor review, AI incident report, plus the assessment files |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 15 tests for the toolkit, 5 for your assessment |

**About the EU AI Act triage.** `govlab.py triage` is a simplified decision aid built from the official texts as of
24 Oct 2026 (Regulation (EU) 2024/1689 as amended by the Digital Omnibus on AI in 2026). It covers the questions
this system raises, not every case in the Act. It is not a legal determination: in real life, your legal team
confirms the result, and you record who confirmed it.

## Needs

- Python **3.11 or newer**: `python3 --version`, or `make check` (Windows: `py --version`). No packages, no internet.
  There is no setup step: the lab uses only Python's standard library, so there is nothing for `pip` to install and
  no virtual environment to create.
- Mac or Linux for the `make` shortcuts. Windows: run the `py govlab.py ...` command shown under each step (or
  `python` instead of `py`).
- A text editor, and a spreadsheet app if you prefer editing CSV files in a grid (save as CSV, UTF-8).

## Step 1 · The AI inventory (18.3)

**Mac / Linux:**

```bash
cd labs/m18
make inventory
```

**Windows (PowerShell):**

```powershell
cd labs/m18
py govlab.py inventory
```

```output
AI inventory: TSG Helpdesk 2.0 (production), owner Head of Customer Support
type             component                                                  flags
application      Helpdesk chat app (Python)                                 ok
model            Gemma 3, 1B (local twin, via Ollama)                       ok
model            Managed model in your cloud stream (Bedrock, Foundry or Ag ok
embedding_model  Local embedding model (Module 6)                           licence unknown
vector_store     Qdrant (Module 6)                                          ok
mcp_server       Ticketing MCP server                                       ok
memory           Customer memory summaries                                  ok

7 components, 1 with gaps. Full rows: out/ai-inventory.csv (columns as in templates/AI-INVENTORY.csv)
```

An inventory lists **components**, not just "the chatbot": two models, an embedding model, a vector store, an MCP
server and a memory store. Each can change on its own, and each has its own supply-chain risk (Module 9). One gap
already: nobody has checked the embedding model's licence. Open `out/ai-inventory.csv` to see the full rows. This is
NIST AI RMF **GOVERN 1.6** ("mechanisms are in place to inventory AI systems").

## Step 1b · Look at each governance idea on its own (about 10 minutes)

New to governance? Do this first. `explore.py` shows, one at a time, the ideas `govlab.py` is built on. It only
reads the lab's files: it writes nothing, starts no program and uses no network. Windows: `py explore.py ...`.
The output below is from a fresh Ubuntu machine (recording run 41008583415).

**1. Four kinds of document.** A framework is voluntary advice, a standard can be certified, a law binds, and the
OWASP lists are community checklists. The lab maps every control to all four:

```bash
python3 explore.py kinds
```

```output
Four kinds of document this lab maps controls to (catalog/frameworks.json)

framework  NIST AI RMF 1.0 (NIST AI 100-1, Jan 2023) subcategories
           voluntary: guidance you choose from; nobody has to use it
           28 items in this lab's catalogue · https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf

standard   ISO/IEC 42001:2023, AI management system (clause level; Annex A reference controls come from your licensed copy)
           certifiable: an accredited auditor can certify an organisation against it
           7 items in this lab's catalogue · https://www.iso.org/standard/42001
...
```

**2. One inventory entry.** An inventory lists every part of a system, not just "the chatbot":

```bash
python3 explore.py inventory
```

```output
AI inventory entry 4 of 7 (helpdesk/system-card.json, "components")

  system     TSG Helpdesk 2.0, production since 2026-05-01
  owners     business: Head of Customer Support · technical: Platform engineering lead
  type       embedding_model                what kind of part it is
  name       Local embedding model (Module 6)
  version    pinned by hash                 which exact build runs
  hosting    self-hosted                    where it runs
  licence    unknown                        <- a gap: nobody has checked what this licence allows

One row per part, not one per app: 7 parts here (application, embedding_model, mcp_server, memory, model, vector_store).
```

**3. One risk register row, scored.** Risk = likelihood × impact, each 1 to 3. *Inherent* is the score before any
control; *residual* is the score after the controls really in place. The grid marks both:

```bash
python3 explore.py risk R1
```

```output
Risk R1 from first-draft/risk-register.csv, column by column

  title       Injected ticket text makes the bot refund or email
  source      RS01: Injected text (chat, ticket, document) steers a tool call: refunds, emails, tickets
  owner       Platform engineering lead
  likelihood  3    how likely, 1 to 3
  impact      3    how bad, 1 to 3
  inherent    3 x 3 = 9    likelihood x impact, before any control
  treatment   mitigate     one of mitigate, transfer, avoid, accept (NIST AI RMF MANAGE 1.3)
  controls    C01 implemented, C02 implemented, C03 implemented, C04 implemented, C05 implemented
  residual    1 x 2 = 2    after the controls really in place
  accepted by (blank)      needed above 3 (the AI policy's risk appetite)
  review      2027-01-24 (92 days after the assessment on 2026-10-24)
  owasp       LLM01;LLM03:2026;ASI02
  notes       M7 controls in place

  Likelihood x impact, I = inherent, R = residual (status of each control: helpdesk/system-card.json)
  impact 3 |  .    .    I
  impact 2 |  R    .    .
  impact 1 |  .    .    .
            L1   L2   L3
```

Notice `LLM01` without a year: Step 3's checker flags it (REG-06). Try `risk R5` and `risk R6` too: they are two of
the draft's worst rows.

**4. One control, many rulebooks.** A crosswalk maps each control to the items it supports in each framework:

```bash
python3 explore.py control C24
```

```output
Control C24 (catalog/controls.json): Tell people they are chatting with an AI, from the first message
  taught in   lesson 18.2
  status      planned in TSG Helpdesk (helpdesk/system-card.json)
  proved by   the live greeting text (or a screenshot of it)

  maps to
  nist_ai_rmf  MEASURE 2.8  Risks associated with transparency and accountability are examined and documented.
  iso_42001    Clause 8     Operation (running the controls)
  eu_ai_act    Art. 50      Transparency obligations for providers and deployers of certain AI systems
  owasp        (none mapped)
```

**5. One evidence item, checked.** Evidence is a dated, owned file. Its SHA-256 hash, written in the index when it
was collected, proves it is still the same file:

```bash
python3 explore.py evidence E01
```

```output
Evidence row E01 from first-draft/evidence-index.csv

  control      C01
  file         evidence/2026-10-20-m07-agent-controls-test.txt
  owner        AppSec lead
  collected    2026-10-20
  sha256 then  cff000aa90b51c655c9d6b4f16ad73ac36b1559795a98156080b775b046ddccd   (written in the index)
  sha256 now   cff000aa90b51c655c9d6b4f16ad73ac36b1559795a98156080b775b046ddccd   (same: unchanged since it was indexed)
  age          4 days before the assessment on 2026-10-24 (the lab allows 90)
...
```

Now try `python3 explore.py evidence E03`: the two hashes differ. Step 3 shows why that matters.

## Step 2 · EU AI Act triage (18.2)

**Mac / Linux:**

```bash
make triage
```

**Windows (PowerShell):**

```powershell
py govlab.py triage
```

```output
EU AI Act triage: TSG Helpdesk (as of 2026-10-24)
Triage only: confirm the result with your legal team.

In scope?      yes: offered in the EU = True (markets: IN, EU)
Your role      PROVIDER of the AI system (you build it and run it under your own name, Art. 3(3))
Prohibited?    no Art. 5 practice selected
Risk tier      TRANSPARENCY (Art. 50)

Obligations
  APPLIES NOW       Art. 4      AI literacy: take measures to support it for staff and others who use the system
  APPLIES NOW       Art. 50(1)  Tell people they are interacting with an AI system, at the latest at the first interaction (unless obvious)
  DUE 2026-12-02    Art. 50(2)  Mark generated content in a machine-readable way (text is in scope, with exclusions: confirm with legal)

Note: Arts. 9 to 15, 26, 72 and 73 apply to high-risk systems only: use them here as good practice.

Note: The maker of the general-purpose model you build on has its own duties (since 2025-08-02); ask for its documentation in your vendor review.
```

Three things to notice:

1. **You are the provider**, even though someone else made the model. You built the Helpdesk and run it under your
   own name. The model maker is the provider of the *model*; you are the provider of the *AI system*.
2. **Article 50(1) has applied since 2 August 2026**, and the Helpdesk's greeting
   (`helpdesk/chat-widget.html`) never says it is an AI. That is a live gap. You fix it in Step 6.
3. **Article 50(2) is due on 2 December 2026** for this system, because it was on the market before 2 August 2026.
   The Commission's FAQ says text output is in scope, with exclusions. That one goes to legal with a date on it.

Now change one fact. The shop wants to re-use the Helpdesk to screen job applicants:

**Mac / Linux:**

```bash
make what-if
```

**Windows (PowerShell):**

```powershell
py govlab.py triage --what-if hiring
```

```output
Risk tier      HIGH-RISK (Annex III: Employment, workers' management and access to self-employment)

Obligations
  APPLIES NOW       Art. 4      AI literacy: take measures to support it for staff and others who use the system
  APPLIES NOW       Art. 50(1)  Tell people they are interacting with an AI system, at the latest at the first interaction (unless obvious)
  DUE 2026-12-02    Art. 50(2)  Mark generated content in a machine-readable way (text is in scope, with exclusions: confirm with legal)
  DUE 2027-12-02    Art. 9      Risk management system
  DUE 2027-12-02    Art. 10     Data and data governance
  ...
  DUE 2027-12-02    Art. 16     Obligations of providers of high-risk AI systems (conformity assessment, registration and more)
```

Same code, same model, different **purpose**, and a different law applies. The high-risk date is **2 December 2027**:
the Digital Omnibus on AI moved it from 2 August 2026. Try `py govlab.py triage --as-of 2026-07-01` to see how
the dates read before Article 50 applied.

## Step 3 · Audit the team's first draft (18.0, 18.1)

**Mac / Linux:**

```bash
make draft
```

**Windows (PowerShell):**

```powershell
py govlab.py check first-draft
```

You get 22 errors. Here is what each kind means, and why an auditor (or an incident) would find it:

| Code | What the draft did | Why it matters |
|---|---|---|
| REG-02 | Owner "TBD" | A risk with no owner is a risk nobody treats. NIST **GOVERN 2.1**: roles and responsibilities are documented |
| REG-06 | `LLM01` without a year | `LLM01` means different things in different editions; write `LLM01:2026` (lesson 2.2) |
| REG-07 | "mitigate" with no controls | A treatment with nothing behind it is a wish |
| REG-08 | Control `C99` | It does not exist in the catalogue. Typos in a register become false comfort |
| REG-09 | Residual higher than inherent | Controls cannot make a risk worse; the scoring is wrong |
| REG-11 | Residual lowered by C12 (planned), C07 (stale evidence), C23 (missing file) | **No credit for planned or unproven controls.** The most common mistake in real registers |
| REG-12 | Residual above 3 with nobody accepting it | The policy's risk appetite (`templates/AI-POLICY.md`): above 3 needs a named acceptance. NIST **MANAGE 1.4** |
| REG-13 | "accept" for a risk of 9 | The shared service account: too much work this quarter. The policy never allows accepting a 9 |
| REG-14 | Review date 14 months away | Reviews at least every 6 months. NIST **GOVERN 1.5** |
| COV-01 | No risk for the MCP server, the AI disclosure or incident response | The system card has those features, so those risk sources are required |
| EVD-02 | Evidence file not found | The index points at `grounding-eval-v2.txt`, which nobody saved |
| EVD-03 | Hash mismatch on the refund limits | The file changed after it was indexed (the limit went from 25 to 50 per call under CHG-2026-1017). Re-collect, re-index |
| EVD-04 | Guardrail config from July | 114 days old, and from before the September prompt change. Evidence must be fresh (90 days here) |
| ASM-01 | No approver | An assessment nobody approved is a draft |
| ASM-02 | Recorded as "deployer, minimal" | Triage says provider, transparency. The team misread its own role |

Then look at what the draft can actually prove:

**Mac / Linux:**

```bash
make crosswalk
```

**Windows (PowerShell):**

```powershell
py govlab.py crosswalk first-draft
```

```output
EU AI Act articles that apply to this system: 0 of 2 have a proven control (Art. 4, Art. 50)
  NOT PROVEN  Art. 4       C27 implemented  <- APPLIES
  NOT PROVEN  Art. 50      C24 planned  <- APPLIES
  reference only for this system (high-risk duties): Art. 9, Art. 10, Art. 11, Art. 12, Art. 13, Art. 14, Art. 15, Art. 25, Art. 26, Art. 72, Art. 73
```

(Shown: the EU part. The full run lists NIST, ISO/IEC 42001 and OWASP too, and writes `out/crosswalk.md`.)
"Implemented" in the system card is a claim; **COVERED** needs a control with valid evidence. Training (C27) may well
have happened, but the draft indexed no record of it.

Finally, try to pack it:

**Mac / Linux:**

```bash
make pack-draft
```

**Windows (PowerShell):**

```powershell
py govlab.py pack first-draft
py govlab.py pack first-draft --draft
```

A real pack is refused while errors are open. `--draft` builds one anyway, named `...-DRAFT`, with the open findings
in `CHECK.txt`. A draft is fine to share for review; it is not something anyone signs.

## Step 4 · Start your own assessment

**Mac / Linux:**

```bash
make start
```

**Windows (PowerShell):**

```powershell
py govlab.py start
```

This copies the templates into `my-assessment/` (git ignores that folder, so your work never conflicts with
updates): `assessment.json`, an empty `risk-register.csv` and `evidence-index.csv`, plus your own copies of
`system-card.json` and `chat-widget.html`. Keep the assessment date **2026-10-24**; the lab's evidence was collected
in the weeks before it.

## Step 5 · Write the risk register (18.1, 18.4)

Open `my-assessment/risk-register.csv`. One row per risk. The checker requires a row for each of these 13 sources
(from `catalog/risk-library.json`, chosen by the features in the system card):

| Source | Risk | Usual controls |
|---|---|---|
| RS01 | Injected text steers a tool call (refunds, emails, tickets) | C01 to C07 |
| RS02 | Answers leak data through Markdown images and links | C05, C08 |
| RS03 | Poisoned or hidden-instruction articles reach the knowledge base | C11, C06, C19 |
| RS04 | One customer gets another customer's data | C10, C01 |
| RS05 | A memory summary carries instructions into later chats | C12, C19 |
| RS06 | An MCP server update changes tool descriptions or behaviour | C13, C14, C26 |
| RS07 | A malicious or swapped model file | C15, C16 |
| RS08 | One shared service account turns any injection into full access | C17, C01 |
| RS09 | Scripted use runs up the model bill | C18, C19 |
| RS10 | Personal data in prompts, logs or traces | C09, C19 |
| RS11 | The bot states a policy or refund rule that does not exist | C23 |
| RS12 | People are not told they are chatting with an AI | C24 |
| RS14 | An AI incident is not detected, contained or reported in time | C19, C20, C21, G05 |

RS13, RS15 and RS16 are optional; add them if you think they matter here (they do).

**How to fill a row:**

- `owner`: a named role ("Platform engineering lead"), never "TBD" or "team".
- `likelihood` and `impact`: 1 to 3 each. Inherent risk = likelihood × impact, before your controls. Write a reason
  in `notes` for anything you score 3.
- `treatment`: `mitigate` (controls), `transfer` (contract or insurance, still with a control), `avoid` (stop doing the
  risky thing), or `accept` (a named person signs). These are NIST **MANAGE 1.3**'s four response options.
- `controls`: IDs from `catalog/controls.json`, separated by `;`. Check each one's status in your
  `system-card.json`: **only implemented or partial controls with valid evidence earn credit**.
- `res_likelihood`, `res_impact`: the residual risk after the controls that are really in place. Above 3? Fill
  `accepted_by` with the role allowed to accept it, and say why in `notes`.
- `review_date`: after 2026-10-24 and within 6 months.
- `owasp`: IDs with the year (`LLM01:2026`, `ASI02`). `nist_genai`: one of the 12 risks of NIST AI 600-1 (see
  `catalog/frameworks.json`).

One worked row, so you can see the level of detail (yours can differ):

```text
R01,Injected text in a chat or ticket steers a refund or email,RS01,LLM01:2026;LLM03:2026;ASI02,Information Security,Platform engineering lead,3,3,mitigate,C01;C02;C03;C04;C05;C06,1,2,,2027-01-24,M7 and M3 suites pass
```

Three rows need a decision, not just typing:

- **RS05 memory:** C12 is only planned. You may not lower the risk with it. Choose: keep the residual and get it
  accepted, or **avoid** the risk (switch memory off until C12 is built, and say so in `notes`).
- **RS08 shared service account:** C17 is partial (the ticketing MCP server still uses the shared account; see
  `evidence/2026-10-18-identity-map.json`). Score what is left, and decide who accepts it until the split lands.
- **RS03 knowledge base:** the new review procedure only covers new imports (read
  `evidence/2026-10-17-kb-import-procedure.md`). What is the residual risk from the old articles?

Check as you go:

**Mac / Linux:**

```bash
make mine
```

**Windows (PowerShell):**

```powershell
py govlab.py evidence my-assessment --fill
py govlab.py check my-assessment
```

## Step 6 · Fix the product: tell people it's an AI (18.2)

The greeting in `my-assessment/chat-widget.html` says "Hello, welcome to TSG Shop support." It never says an AI is
answering. Under Article 50(1), people must be told at the latest at the first interaction, unless it is obvious, and
the Commission says that exception is read narrowly. Fix it in three moves:

1. Change the text inside `id="greeting"` so it says plainly that the customer is talking to an AI assistant (for
   example, that it is an automated AI assistant and how to reach a person).
2. In `my-assessment/system-card.json`, set `"C24"` to `"implemented"`.
3. Add an evidence row for C24 to `my-assessment/evidence-index.csv`, pointing at the widget file itself:

   ```text
   E23,C24,my-assessment/chat-widget.html,,2026-10-24,Head of Customer Support,live greeting text
   ```

   Leave `sha256` blank; `make mine` fills it. If you edit the greeting again later, the hash no longer matches
   (EVD-03): delete the old value and run `make mine` again. That is the point: evidence is a snapshot.

If you mark C24 implemented but the greeting does not mention an AI, the checker says so (DIS-01).

## Step 7 · Index the evidence and read your crosswalk (18.1, 18.2)

For every control your register leans on, add a row to `my-assessment/evidence-index.csv`: an ID, the control, the
file (path from `labs/m18`, for example `evidence/2026-10-20-m07-agent-controls-test.txt`), a blank hash, the date
in the file name as `collected`, and an owner. One file can prove several controls (the M7 test output covers C01,
C02, C04, C05 and C21). Read each file before you use it: some are partial on purpose.

**Mac / Linux:**

```bash
make mine
make mine-crosswalk
```

**Windows (PowerShell):**

```powershell
py govlab.py evidence my-assessment --fill
py govlab.py check my-assessment
py govlab.py crosswalk my-assessment
```

How to read the crosswalk:

- **COVERED**: a control mapped to that item is in place and has valid evidence. It is something to show an auditor,
  not a verdict that you comply.
- **NOT PROVEN**: a mapped control exists but is planned, or has no valid evidence. Either fix the evidence or stop
  claiming it. (G03, periodic review, is a good example: the system card says implemented, and no file proves it.)
- **NO CONTROL**: nothing in the course maps there. For ASI05 (code execution), ASI07 and ASI08 (multi-agent) that
  is fine: the Helpdesk has no code tool and is a single agent. Write that reasoning down; "not applicable,
  because..." is an answer, a blank is not.
- EU articles marked **reference only** are high-risk duties. They do not apply to this system today. They are still
  a good checklist, and they become law for it the day someone re-purposes it (Step 2).

## Step 8 · Build and verify the evidence pack (18.3, 18.4)

Fill in `my-assessment/assessment.json`: `assessor`, `approved_by` (who signs; in the lab you decide, for example
"Chief Operating Officer"), `next_review` (within 12 months), and the `eu_ai_act` decision from Step 2 with
`decided_by`. Then:

**Mac / Linux:**

```bash
make mine-pack
```

**Windows (PowerShell):**

```powershell
py govlab.py pack my-assessment
py govlab.py verify-pack out/evidence-pack-tsg-helpdesk-2026-10-24
```

```output
Built out/evidence-pack-tsg-helpdesk-2026-10-24/ with 21 evidence file(s) and MANIFEST.sha256
Open out/evidence-pack-tsg-helpdesk-2026-10-24/README.md first.
pack verified: every file matches MANIFEST.sha256
```

(Your number of evidence files depends on your index.) Open the pack's `README.md`, `RISK-REGISTER.md` and
`CROSSWALK.md`. Then play the auditor: add one line to the pack's `RISK-REGISTER.md` and run `verify-pack` again. It
names the changed file. Rebuild the pack to get back to a clean one.

## Step 9 · Prove it

**Mac / Linux:**

```bash
make test
```

**Windows (PowerShell):**

```powershell
py run_tests.py
```

```output
[PASS] catalog: every control maps only to framework items that exist; every risk source's controls exist
[PASS] check: the team's first draft fails with exactly the 15 kinds of problem the README walks through
[PASS] check: lowering a risk with a planned control (C12) is refused; 'avoid' or an accepted residual is allowed
...
ALL TESTS PASSED (15 run)
```

## Challenge

**Mac / Linux:**

```bash
make challenge
```

**Windows (PowerShell):**

```powershell
py run_tests.py --challenge
```

Five more tests run against `my-assessment/`: every file is there, `check` is clean, all 13 required sources are
covered, C24 is implemented and proven (and the greeting really says it is an AI), and the pack builds and verifies.
They fail until you finish Steps 4 to 8. There is no single right register: two good assessments of the same system
differ in scores and wording. A worked sample answer, with the reasoning behind each decision, is in the course
(lesson 18.4).

Stretch goals, no tests:

- Fill `templates/MODEL-VENDOR-REVIEW.md` for the local embedding model whose licence is "unknown", and decide what
  happens if the licence does not allow your use.
- Fill `templates/AI-INCIDENT-REPORT.md` for Module 16's hijacked-agent scenario, including the notification-clock
  table. Which clocks apply to the Helpdesk today, and which only apply if it were high-risk?
- Write your own one-page `AI-POLICY.md` for a team you know. Keep it to one page.

## Troubleshooting

- **`no such assessment folder: my-assessment`**: run `make start` first.
- **EVD-06 "no sha256 yet"**: run `make mine` (it fills blank hashes and never overwrites existing ones).
- **EVD-03 after you edited a file on purpose**: delete that row's `sha256` value and run `make mine` again.
- **EVD-02 "evidence file not found"**: paths are relative to `labs/m18`, for example `evidence/...` or
  `my-assessment/chat-widget.html`.
- **The CSV looks broken after saving from a spreadsheet**: save as "CSV UTF-8 (comma delimited)", keep the header
  row, and do not use commas inside a cell (use `;` to separate IDs).
- **Windows line endings**: git keeps the files in `evidence/` byte-for-byte (see `.gitattributes`), so their hashes
  match on every system.
