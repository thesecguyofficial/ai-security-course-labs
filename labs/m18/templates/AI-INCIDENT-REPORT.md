# AI incident report: <short name>

Template from lesson 18.3. It extends the technical incident report from Module 16 with the parts governance needs:
which AI system, which framework risk, who must be told, and by when. Write for two readers: the engineer who fixes
it tomorrow and the manager who signs off. UTC times; every fact names the record that proves it.

## 1. Summary
<Three sentences: what happened, what it exposed or cost, and whether it is contained.>

## 2. The AI system
- Inventory entry: <system, version>; model and version: <...>; MCP servers and tools involved: <...>
- What the AI did: <answer, tool call, email, refund>, and whether a person approved it.
- Inputs involved: <prompt, retrieved documents (IDs), memory, tool results>. Attach or reference them; do not paste
  personal data into this report.

## 3. Classification
- Severity and why: <...>
- Risk register entry: <R-id>, and whether the incident matches its scenario or is new.
- Mapped to: OWASP <LLM0x:2026 / ASI0x>, MITRE ATLAS <AML.T....>, NIST GenAI risk <...>
- People affected: <customers, staff, how many>; data affected: <categories>.

## 4. Timeline (UTC)
- <time> <event> (<record that proves it>)

## 5. Containment, eradication, recovery
- <time> <action> (<who>)

## 6. Notification clocks (legal decides; record the decision either way)
| Rule | When it can apply | Clock | Decision, who, when |
|---|---|---|---|
| EU AI Act Art. 73 | Serious incident with a **high-risk** AI system | Not later than 15 days after becoming aware; 2 days for a widespread infringement or a critical-infrastructure incident (Art. 3(49)(b)); 10 days if a person died | <...> |
| GDPR Art. 33 | Personal data breach (EU) | Without undue delay and, where feasible, not later than 72 hours after becoming aware | <...> |
| CERT-In Directions (India) | Cyber incidents listed in its Annexure I | Within 6 hours of noticing | <...> |
| Contracts and sector rules | Customer contracts, regulators in your sector | <as written> | <...> |

## 7. Root cause and what changes
- Root cause (not "the model misbehaved": which control was missing or failed?):
- Register updates: <risk IDs whose likelihood, impact, controls or residual change>
- New or changed controls, owners and due dates:
- Detection gaps and new rules:

## 8. Sign-off
Business owner: <name/role, date> · Security: <...> · Legal/data protection: <...>
