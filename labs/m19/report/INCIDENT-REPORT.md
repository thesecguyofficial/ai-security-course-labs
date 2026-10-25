# Incident report: <short name>

> Pick ONE incident from detections/logs/attack-day.jsonl (seed 1) and write it up. Replace every `<...>` and TODO.
> The self-check (R3) wants at least five timeline lines and at least three request IDs that exist in that log.
> Write for two readers: the engineer who fixes it tomorrow and the manager who signs off. UTC times.

## Summary

<Three sentences: what happened, what it exposed or cost, and whether it is contained.>

## Severity and status

<Severity and why, status (open, contained, closed), who owns the next step.>

## Timeline (UTC)

<One line per event, in this form: 2027-01-20T09:14:03Z what happened (request ID). At least five lines. Start with
the first malicious event you can find, not the first alert.>

## Scope

<Which users, sessions, documents, tools and data were involved. Which records you checked and what each one could
and could not show.>

## Root cause

<How it started and which control was missing. Name the control, not a person.>

## Containment

<What you would do in the first hour, in order, with the exact change (for example the guard or the config line).>

## Eradication and recovery

<What is removed, rotated or restored, and how you check it is gone.>

## Evidence

<At least three request IDs from the log, each with one line on what it proves.>

## Detection gaps and new rules

<Which of your rules fired first, which would have fired earlier with better logging, and what you added.>

## Lessons learned

<Two or three changes, each with an owner and a date.>
