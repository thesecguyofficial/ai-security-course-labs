# Submitting your capstone

## What you submit

A **public GitHub repository** made with `make export` (README, Part 0) that contains:

| Path | What |
|---|---|
| `README.md` | Your portfolio README (from `report/README-TEMPLATE.md`) |
| `report/THREAT-MODEL.md` | Part 1 |
| `report/FINDINGS.md` | Parts 2, 3 and 6 (findings, variants, cloud changes) |
| `report/INCIDENT-REPORT.md` | Part 5 |
| `report/GOVERNANCE-NOTE.md` | Part 7 |
| `helpdesk/guards.py`, `helpdesk/config.py` (+ any helper modules) | Part 3 |
| `evals/my_cases.json`, `evals/kb/` | Part 4 |
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

Email **hello@thesecguy.com** from the address you use for the course, subject `Capstone submission`, with:

- the repo URL,
- the full commit SHA you want graded (later commits are not graded unless you resubmit),
- your stream (`aws` for now),
- the last lines of `make check` pasted as text.

You get feedback per criterion of [`RUBRIC.md`](RUBRIC.md) by email. "Not yet" comes with what to change; fix it,
push, and resubmit with the new SHA. There is no limit on resubmissions.

## After a Pass

Your certificate's public verify page lists the skills you completed in the course. Lesson 19.6 shows how to add
the certificate and your capstone repo to LinkedIn, and lesson 19.4 how to turn the repo into portfolio projects.
Keep the repo public if you want employers to see it; it is your work.
