# Evidence: AI incident tabletop, 14 Oct 2026 (sample for the M18 lab, fictional)

- **Scenario:** a ticket with hidden instructions makes the Helpdesk email an order history outside (Module 16, playbook "hijacked agent").
- **Who took part:** on-call engineer, AppSec lead, Head of Customer Support, data protection lead.
- **What worked:** the DENY alert on `send_email` reached the SOC queue; the kill switch (C21) stopped tools in one step.
- **What did not:** nobody knew who decides whether the event must be reported to a regulator. Action: add notification clocks to the incident template (owner: data protection lead, due 2026-10-31). Done 2026-10-20, see the AI incident report template.
- **Next exercise:** January 2027.
