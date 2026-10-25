# AI policy (one page)

Template from lesson 18.3 of *AI Security Engineer*. Replace every `<...>`. Keep it to one page: details live in
standards, runbooks and the risk register, which this policy points to. Staff rules for using AI tools (what may be
pasted where) are a separate acceptable use policy: see lesson 4.5.

**Owner:** <role, e.g. Chief Operating Officer> · **Approved:** <date> · **Next review:** <date, 6 months or less>

## 1. Scope
Every AI system we build, buy or run that makes or shapes a decision, talks to people, or acts on our systems or
data. "AI system" includes features inside other products, agents, MCP servers and models we host.

## 2. Before anything goes live
1. It is in the **AI inventory** with a named business owner and technical owner.
2. It has a **risk assessment** (risk register with owners, treatments, residual risk and review dates).
3. Its **legal triage** is recorded (for example EU AI Act role and tier), and legal has confirmed it.
4. Every third-party **model, vendor and MCP server** has passed the model and vendor review.
5. The **approver** below has signed it off.

## 3. Risk appetite
- Likelihood and impact are scored 1 to 3; risk = likelihood × impact.
- A residual risk **above 3** needs a named acceptance by <role>. A risk of **9** is never accepted: mitigate or avoid it.
- No credit for planned controls: residual risk counts only controls that are in place and proven by evidence.

## 4. Baseline controls for every AI system
- Every tool call is authorised in code, never by the model; limits on money and data are enforced outside the model.
- No secrets or internal-only rules in prompts.
- People are told when they are talking to an AI.
- Logs name the user, the retrieved documents and every tool call; personal data is redacted.
- Agents have a kill switch, and money, deletions and outbound messages above a limit need a person's approval.
- Security tests run in CI and fail the build on a regression.

## 5. Roles
| Role | Responsible for |
|---|---|
| Business owner | The purpose, the risk decisions, accepting residual risk within their authority |
| Technical owner | The controls and the evidence that they work |
| Security | The assessment method, testing, detection and incident response |
| Data protection and legal | Legal triage, notification decisions, vendor terms |
| Approver (<role>) | Go-live sign-off and acceptance of residual risk above 3 |

## 6. Review and change
Every AI system is reviewed at least every <6> months, and again before any major change: a new model, tool, data
source, user group or country.

## 7. Incidents
Anyone who sees an AI system behave unsafely reports it to <channel>, without blame. Security opens an AI incident
report (template: `AI-INCIDENT-REPORT.md`), and legal decides on notifications within the clocks listed there.

## 8. Exceptions
Exceptions are written, time-limited (90 days at most), owned and approved by <role>, and listed in the risk register.
