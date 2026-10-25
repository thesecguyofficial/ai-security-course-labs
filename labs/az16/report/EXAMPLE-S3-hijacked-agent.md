# Incident report: helpdesk agent emailed ticket data out and deleted the ticket

A worked example for scenario S3, written from the lab's hardened telemetry. It passes
`python3 report.py check report/EXAMPLE-S3-hijacked-agent.md --scenario S3`. Yours, for S1, follows the same shape.

## Summary

On 20 Oct 2026 at 11:20 UTC the helpdesk agent, working for Bob, read ticket 5120, followed a hidden instruction in
it, emailed a ticket export to archive@ticket-export.example.net and deleted the ticket. Nobody was asked to approve
either call: a rollback at 11:12 had set the helpdesk-tools toolbox back to version 1, where the actions server has
require_approval never. Contained at 11:41 by promoting version 2 again.

## Severity and status

High: ticket data left the company and a record was destroyed. Status: contained; ticket 5120 restored from the
ticketing system's backup; the export's contents are being reviewed by the data protection lead.

## Timeline (UTC)

- 2026-10-20T08:40 Pipeline run agent-run-311 by sp-agent-deploy sets toolbox default version 2, require_approval always (deploy log).
- 2026-10-20T11:12 Rollback run agent-run-312 by sp-agent-deploy sets default version 1: require_approval never, no allowed_tools (deploy log).
- 2026-10-20T11:12 D03 fires: toolbox default version runs write tools without approval.
- 2026-10-20T11:20 Bob asks the agent about ticket 5120 in conversation conv-7f3a5120 (app log, invoke_agent span).
- 2026-10-20T11:20 search_tickets returns T-5120 with an injected vendor note; send_email to archive@ticket-export.example.net and delete_ticket T-5120 run with approval not_required (execute_tool spans).
- 2026-10-20T11:26 Defender for AI services raises "Anomalous tool invocation" (Low).
- 2026-10-20T11:41 Toolbox default version set back to 2; the same turn replayed in staging stops at the approval step.

## Scope

One conversation (conv-7f3a5120), one signed-in user (bob), two write tool calls without approval. The execute_tool
spans for 11:12 to 11:41 show no other write tool calls, so no other conversation was affected. Checked: deploy log,
Foundry traces, app log, gateway LLM log, SecurityAlert.

## Root cause

The rollback restored a toolbox version from before approval was required on the actions server. Nothing stopped a
pipeline from promoting a version with require_approval never, and the only defence against the instruction in
ticket 5120 was that approval step. Model behaviour is not a control.

## Containment

- 11:41 Default version of helpdesk-tools set back to 2 (Foundry portal, the toolbox, Versions, promote).
- 11:44 The agent's tool connection paused while the review ran.
- 11:50 Ticket 5120's vendor note quarantined in the ticketing system.

## Eradication and recovery

Ticket 5120 restored. The external address blocked at the mail gateway. The rollback pipeline now refuses a
toolbox version whose write servers lack require_approval always and an allowed_tools list.

## Evidence

- a650fca6-ebc5-4002-b3e5-56c469d313ec: deploy record, agent-run-312 promotes version 1 with require_approval never.
- 12ec1b5848c54b08: execute_tool span, send_email to the outside address, approval not_required.
- 2988aa30bead4262: execute_tool span, delete_ticket T-5120, approval not_required.
- 9c93672d-7643-4c49-95f7-594a8d4d4ab4: SecurityAlert, Anomalous tool invocation (Low).

## Detection gaps and new rules

D03 fired at 11:12 but sat in the queue as a change record. It now pages as High. D08 and D09 fired at 11:20. The
Defender alert is Low, so the default email to subscription owners (High only) never sent it. Without Foundry
tracing none of the 11:20 tool records would exist.

## Lessons learned

- Pipelines check require_approval and allowed_tools before promoting a toolbox version (platform team, 31 Oct 2026).
- Toolbox promotions page the on-call engineer (SOC, 24 Oct 2026).
- Re-run the AZ14 attack suite against staging after every rollback (platform team, 7 Nov 2026).
