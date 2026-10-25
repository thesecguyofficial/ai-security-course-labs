# Submitting your advanced capstone

## What you submit

A **public GitHub repository** made with `make export` (Part 0) that contains:

| Path | What |
|---|---|
| `README.md` | Your portfolio README (from `report/README-TEMPLATE.md`) |
| `report/THREAT-MODEL.md` | Part 1 |
| `report/FINDINGS.md` | Parts 2, 3 and 6 (findings, variants, cloud changes) |
| `report/INCIDENT-REPORT.md` | Part 5 |
| `report/GOVERNANCE-NOTE.md` | Part 7 |
| `crew/guards.py`, `crew/config.py` (+ any helper modules) | Part 3 |
| `crew/mcp_pins.json` | Part 3 (from `make pin`) |
| `evals/my_cases.json` | Part 4 |
| `detections/rules.json` | Part 5 |
| `cloud/<stream>/deployment.json`, `capstone.json` | Part 6 |
| `.github/workflows/capstone.yml` | The CI workflow, unchanged or hardened further |

Everything else stays as `export.py` wrote it (self-check H1).

## Before you submit

1. `make check` ends with `OBJECTIVE CHECKS PASSED`.
2. The latest Actions run on `main` is green, and it ran on the exact commit you submit.
3. Search your repo for anything real: keys, account IDs, email addresses, screenshots with names. Everything in it
   must be fake or yours to publish. If a real secret was ever committed, rotate it first, then remove it from the
   history (deleting the file in a new commit is not enough).
4. Your README's "How I built this" says which tools you used, AI assistants included.

## How to submit

1. Sign in to the course and open the capstone page: **learn.thesecguy.com/capstone**.
2. Paste:
   - your **public repo URL**, for example `https://github.com/your-name/my-ai-security-capstone`;
   - the **full 40-character commit SHA** you want graded. Get it with `git rev-parse HEAD`, or copy it from the
     commit page on GitHub. A short 7-character SHA is not accepted. Later commits are not graded unless you
     submit again.
3. Tick the box that confirms the work is your own, and submit.

Your stream comes from `capstone.json` (`aws` for now). You do not need to email anything or paste any output.

## What happens next

The grader runs the course's own checks against your repo at that commit (see [`RUBRIC.md`](RUBRIC.md)). This
usually takes a few minutes; the capstone page shows the status and then the result:

- **Pass:** your submission passed the required automated checks and nothing was held for an integrity check.
- **Not yet:** the page lists the checks that failed. Fix them, push, wait for a green Actions run, and submit the
  new SHA. You can submit up to 3 times a day, at least 30 minutes apart.
- **Held:** if an integrity check needs a look (for example the checking tools were changed), the course owner
  reviews it, usually within a day, and the page then shows the result.

If the grader itself has a problem, the page says "Try again" and that attempt does not count.

## After a Pass

You earn the **Advanced capstone** badge, and your certificate and its public verify page gain an "Advanced
capstone" line. (The certificate itself comes from the M19 capstone; this one adds to it.) The verify page also
lists the skills you completed. This capstone demonstrates **multi-agent system security design**: per-agent
identity, deterministic tool authorization, trust boundaries and containment between agents, supply-chain
controls, security evals in CI, and detection. Keep the repo public if you want employers to see it; it is your
work.
