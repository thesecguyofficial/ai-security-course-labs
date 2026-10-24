# Incident report: Helpdesk agent emailed ticket data out and reset the CEO's MFA

A worked example for scenario S3, written from the lab's hardened telemetry. It passes
`python3 report.py check report/EXAMPLE-S3-hijacked-agent.md --scenario S3`. Yours, for S1, follows the same shape.

## Summary

On 20 Oct 2026 at 11:20 UTC the Helpdesk agent, working for Bob, read ticket 5120, followed a hidden instruction in
it, emailed a ticket export to archive@ticket-export.example.net and reset the CEO's MFA. The gateway's policy engine
said DENY to both calls, but a rollback deploy at 11:12 had put it in LOG_ONLY, so both calls ran. Contained at
11:41 by setting the policy engine back to ENFORCE.

## Severity and status

High: data left the company and a privileged account's MFA was reset. Status: contained; the CEO's MFA was
re-enrolled in person; the export's contents are being reviewed by the data protection lead.

## Timeline (UTC)

- 2026-10-20T08:30 Normal deploy: UpdateGateway by tsg-ci-deployer, policy engine mode ENFORCE (CloudTrail).
- 2026-10-20T11:12 Rollback pipeline run 412: UpdateGateway by tsg-ci-deployer sets the policy engine to LOG_ONLY (CloudTrail).
- 2026-10-20T11:20 Bob asks the agent about ticket 5120; InvokeAgentRuntime for runtime session tsg-5120b0b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6 (app log, CloudTrail data event).
- 2026-10-20T11:20 get_ticket 5120 ALLOW; send_email to archive@ticket-export.example.net DENY in LOG_ONLY, executed (gateway spans).
- 2026-10-20T11:20 reset_mfa for ceo DENY in LOG_ONLY, executed (gateway span).
- 2026-10-20T11:23 Alerts D03 (gateway not in ENFORCE), D09 (DENY not enforced) and D10 (mail out) reach the SOC queue.
- 2026-10-20T11:41 Policy engine set back to ENFORCE; replaying the turn in staging is refused at the gateway.

## Scope

One runtime session (tsg-5120b0b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6), one signed-in user (bob), two tool calls that ran
against policy. The gateway spans for 11:12 to 11:41 show no other DENY decisions, so no other session was affected.
Checked: CloudTrail management and data events, gateway spans, invocation logs, app log.

## Root cause

The rollback pipeline restored a gateway configuration from before the policy engine was switched to ENFORCE.
Nothing stopped a deploy role from changing the mode, and the only defence against the injected instruction in
ticket 5120 was the policy engine. Model behaviour is not a control.

## Containment

- 11:41 `aws bedrock-agentcore-control update-gateway` with `policyEngineConfiguration` mode ENFORCE (console:
  the gateway, Policy, Edit).
- 11:44 `aws bedrock-agentcore stop-runtime-session` for the session, so no cached state continues.
- 11:50 Ticket 5120's vendor comment quarantined in the ticketing system.

## Eradication and recovery

The CEO's MFA device was re-enrolled in person. The external address was blocked at the mail gateway. The rollback
pipeline now refuses any configuration whose policy engine mode is not ENFORCE, and an SCP-style deny on
UpdateGateway for every role except the security admin role is in review.

## Evidence

- c2ddc05b-6e5b-4b97-a245-37b506562e7f: CloudTrail UpdateGateway by tsg-ci-deployer, mode LOG_ONLY.
- 0f8ef1809ddd4567: gateway span, send_email DENY in LOG_ONLY, executed.
- d27d2bfbe7e44d07: gateway span, reset_mfa for ceo DENY in LOG_ONLY, executed.
- bad05720-599e-4756-8eff-4aa3b53e31d3: CloudTrail data event, InvokeAgentRuntime for the session.

## Detection gaps and new rules

D03 fired at 11:12 but sat in the queue as a configuration change. It is now paged as High when the mode leaves
ENFORCE. D09 and D10 fired correctly. New custom Config rule C05 flags a gateway in LOG_ONLY within minutes of the
change. Without gateway tracing and data events none of the 11:20 records would exist.

## Lessons learned

- Deploy pipelines verify the policy engine mode before and after every gateway change (platform team, 31 Oct 2026).
- Gateway mode changes page the on-call engineer (SOC, 24 Oct 2026).
- Re-run the M14 attack suite against staging after every rollback (platform team, 7 Nov 2026).
