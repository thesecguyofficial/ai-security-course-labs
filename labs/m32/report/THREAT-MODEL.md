# Threat model: TSG Ops Crew (multi-agent)

> Fill in every `<...>` and delete every TODO line. The self-check (R1) fails while any are left.
> Start from your Module 2 method and your Part 5 work (M20 to M24). This system is three agents sharing one turn,
> with hand-offs, shared memory and a crm MCP server. Lessons 2.1 to 2.5, 22.1, 24.1 to 24.2.

- **Author:** <your name or handle>
- **Date:** <YYYY-MM-DD>
- **Version reviewed:** <commit SHA of the vulnerable starting point, and of your fixed version>

## 1. What are we working on?

### 1.1 Assumptions
- <One line each. Example of the kind of thing: "Sign-in is simulated and out of scope.">
- TODO

### 1.2 Data-flow diagram (as text)

**External entities:** <customers, staff, the crm MCP server, planted tickets in shared memory, ...>

**Processes:** <app.py, the triage agent, the billing agent, the analyst agent, the orchestrator loop, ...>

**Data stores:** <data/tickets.json, customers.json, orders.json, shared memory, outbox, app log, ...>

| Flow | From → To | What it carries | Into an agent's context? | Trusted / untrusted |
|---|---|---|---|---|
| F1 | <...> | <...> | <...> | <...> |
| TODO | add a row for every arrow, including each hand-off | | | |

### 1.3 Trust boundaries

| Boundary | Which flows cross it |
|---|---|
| Input | <...> |
| Hand-off (agent to agent) | <...> |
| Tools | <...> |
| Output | <...> |
| Shared memory | <...> |
| Identity (per agent) | <...> |
| Supply chain (crm MCP) | <...> |

## 2. What can go wrong?

> At least 10 threats, each as actor, path, outcome. Every threat needs an OWASP ID with the year
> (LLM01:2026 or ASI07:2026). At least five need a MITRE ATLAS technique (AML.T0051.001). Stamp the ATLAS release.

ATLAS release used: <2026.09>

| ID | Threat (actor, path, outcome) | OWASP (with year) | ATLAS | Likelihood | Impact | Score | Control |
|---|---|---|---|---|---|---|---|
| T01 | <a planted ticket makes triage hand to billing, which emails the customer list out> | <ASI07:2026 / LLM01:2026> | <AML.T0051.001, AML.T0086> | <...> | <...> | <...> | <...> |
| T02 | <...> | <...> | <...> | <...> | <...> | <...> | <...> |
| TODO | at least 10 rows, covering hand-offs, shared memory, per-agent identity, the crm MCP server and the web page | | | | | | |

## 3. What are we going to do about it?

<For every threat you scored 4 or more, name the control and where it lives. The top 5 get a sentence of why.>

## 4. Did we do a good enough job?

<What the model predicted before you ran the attacks, what the attacks showed you missed, and the residual risk you
accept. For Distinction: at least one threat beyond the six known findings, tested in Part 2.>
