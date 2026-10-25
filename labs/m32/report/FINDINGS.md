# Findings: TSG Ops Crew security review

> Fill in every `<...>` and delete every TODO line. One section per finding: the six known ones (G-1 to G-6)
> and any you found yourself (G-7 onwards). Every finding names the test or eval case that proves the fix.

## Summary

<Four or five sentences for a manager: what you tested, the worst thing you found, what is fixed, what is left.>

## Findings

| ID | Title | Severity | OWASP (with year) | Status | Proof (test / eval IDs) |
|---|---|---|---|---|---|
| G-1 | <injection across a hand-off> | <...> | <ASI07:2026 / LLM01:2026> | <fixed / open> | <S01, inj-01, ...> |
| TODO | one row per finding (G-1 to G-6, plus yours) | | | | |

### G-1 <title>

- **Severity and why:** <...>
- **Where:** <agent, guard, data>
- **Evidence (before):** <the request, the hand-off, the tool call, the outbox line; paste short excerpts>
- **Root cause:** <the missing control, not the symptom>
- **Fix:** <what you changed and where; why it holds even though every agent obeys the instruction>
- **Proof (after):** <test and eval IDs that now pass; the command you ran>
- **Trade-off:** <what normal use could break, and how test_functional shows it did not>

TODO: copy the block above for G-2 to G-6, and for every finding of your own (G-7 onwards).

## Variants I tried

<At least one variant per finding that you tried against your own fix: what it was, and whether it held.>

## Cloud (stream: <aws>)

<What cloud_check.py reported on the first draft, what you changed in cloud/aws/deployment.json and why, with the
lesson for each change. If you deployed anything in your own sandbox account, link the evidence and the teardown.>
