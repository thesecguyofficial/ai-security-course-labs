# Incident report: <fill in a short name>

Copy this file to `report/INCIDENT-REPORT.md`, replace every `<...>` and TODO, then run
`python3 report.py check report/INCIDENT-REPORT.md --scenario S1` (or `make report-check`).
Write for two readers: the engineer who fixes it tomorrow and the manager who signs off. Short sentences, UTC times,
facts with the record that proves them.

## Summary

<Three sentences: what happened, what it cost or exposed, and whether it is contained.>

## Severity and status

<Severity (and why), status (open, contained, closed), who owns the next step.>

## Timeline (UTC)

<One line per event: 2026-10-20Thh:mm what happened (source). At least five lines. Start with the first malicious
event you can find, not the first alert. Use `python3 report.py pivot <entity>`.>

## Scope

<Which identities, keys, models, regions, end users and data were involved. Which logs you checked and what each one
could and could not show (for example: request-response logging was on for the Gemini models only).>

## Root cause

<How it started and which control was missing or switched off. Name the control, not a person.>

## Containment

<What was done to stop it, with the exact command or console action and the time. Lesson 16.5 has the playbook.>

## Eradication and recovery

<What was removed or rotated, what was restored, and how you checked it is gone.>

## Evidence

<At least three record IDs from the telemetry (audit insertId, request-response request_id, SCC finding ID, gateway
insertId or app request_id), each with one line on what it proves.>

## Detection gaps and new rules

<Which alert fired first, which should have fired earlier, and the rule or log you add so it does next time.>

## Lessons learned

<Two or three changes, each with an owner and a date. TODO>
