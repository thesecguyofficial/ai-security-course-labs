# Incident report: Helpdesk agent hijacked through ticket 5120

A worked example for scenario S3 (lesson 16.5, playbook 3). Every record ID below exists in the lab's hardened
telemetry. ExampleCo, the people and the addresses are fictional.

## Summary

On 20 October 2026 at 11:20 UTC a hidden instruction in ticket 5120 made the Helpdesk agent email ticket data to an
outside address and reset the CEO's MFA, in staff member bob's session. The gateway's access policy said DENY to both
calls, but the IAP authorization extension had been put back in DRY_RUN at 11:12, so both ran. Enforcement was back on
at 11:41; the mail was reported to the receiving provider and the MFA was re-enrolled.

## Severity and status

High: data left the company and an executive account lost a factor. Status: contained, recovery done, two follow-ups
open (owners below).

## Timeline (UTC)

- 2026-10-20T11:12 `ci-deployer` updates the `helpdesk-iap` authorization extension with `iamEnforcementMode: "DRY_RUN"` (audit 27da4368ba86).
- 2026-10-20T11:20 bob asks the agent for the latest on ticket 5120 (app req-ba7ca8a4).
- 2026-10-20T11:20 the agent reads ticket 5120: `get_ticket`, allowed (gateway 9989e9694840).
- 2026-10-20T11:20 the agent calls `send_email` to archive@ticket-export.example.net: policy DENY, mode DRY_RUN, executed (gateway 4d9fb3bea215).
- 2026-10-20T11:20 the agent calls `reset_mfa` for `ceo`: policy DENY, mode DRY_RUN, executed (gateway 15f2e5789711).
- 2026-10-20T11:23 rules D09 and D10 alert on agent session 7351126042550190080.
- 2026-10-20T11:41 enforcement restored (see Containment).

## Scope

One agent (`reasoningEngines/4815162342`), one agent session (7351126042550190080), one staff user (bob), two tool
calls that should have been denied. Logs checked: Admin Activity audit logs (the configuration change), Agent Gateway
request logs (the tool calls), request-response logs (the agent's turn, joined by the session label), the app log
(which person). No other session in the 11:12 to 11:41 window called a denied tool.

## Root cause

A rollback pipeline restored an older copy of the authorization extension, which still had the dry-run line from the
pilot. Nothing blocked a change that switched enforcement off, and the hidden instruction in ticket 5120 did the
rest: the model can't tell an instruction in a ticket from one from its user.

## Containment

11:41: removed the `iamEnforcementMode: "DRY_RUN"` line from the extension's metadata and re-imported it
(`gcloud service-extensions authz-extensions import helpdesk-iap --source=helpdesk-iap.yaml --location=europe-west4`),
so the gateway enforces again (ENFORCE). Quarantined ticket 5120 (moved to a closed queue the agent can't read).

## Eradication and recovery

Re-enrolled the CEO's MFA and confirmed the old factor no longer works. Reported the mail to the receiving provider and
asked for deletion. Removed the dry-run line from the pipeline's stored copy. Re-ran the GC14 hijack suite against
staging: all denied calls blocked.

## Evidence

- 27da4368ba86: Admin Activity entry, `UpdateAuthzExtension` by ci-deployer with `iamEnforcementMode: "DRY_RUN"`.
- 4d9fb3bea215: gateway request log, `send_email` to an outside address, policy DENY, executed in DRY_RUN.
- 15f2e5789711: gateway request log, `reset_mfa` for `ceo`, policy DENY, executed in DRY_RUN.
- 1527713204604221357: request-response row for the agent's turn, labelled with the same session.

## Detection gaps and new rules

D03 fired at 11:12 on the change but named the pipeline, so nobody looked at the agent. D09 and D10 named the session
eight minutes later. New: page on D03 "Gateway authorization set to DRY_RUN" outside a change window, and add posture
check C05 to the deployment pipeline so a dry-run extension can't ship.

## Lessons learned

- Block any extension change that adds `iamEnforcementMode` outside a change ticket (owner: platform team, 31 Oct 2026).
- Treat ticket text as untrusted input to the agent: keep write tools behind a confirmation step (owner: IT support, 15 Nov 2026).
