# Threat model: TSG Helpdesk, capstone edition

> Fill in every `<...>` and delete every TODO line. The self-check (R1) fails while any are left.
> Start from your Module 2 threat model; this system adds an MCP server and a web page. Lessons 2.1 to 2.5.

- **Author:** <your name or handle>
- **Date:** <YYYY-MM-DD>
- **Version reviewed:** <commit SHA of the vulnerable starting point, and of your fixed version>

## 1. What are we working on?

### 1.1 Assumptions
- <One line each. Example of the kind of thing: "Sign-in is simulated and out of scope.">
- TODO

### 1.2 Data-flow diagram (as text)

**External entities:** <customers, staff, partner feed, crm MCP server, ...>

**Processes:** <app.py, core.py turn, retriever, agent loop, ...>

**Data stores:** <data/kb, customers.json, orders.json, outbox, app log, ...>

| Flow | From → To | What it carries | Into the model? | Trusted / untrusted |
|---|---|---|---|---|
| F1 | <...> | <...> | <...> | <...> |
| TODO | add a row for every arrow | | | |

### 1.3 Trust boundaries

| Boundary | Which flows cross it |
|---|---|
| Input | <...> |
| Model | <...> |
| Tools | <...> |
| Output | <...> |
| Data | <...> |
| Memory | <...> |
| Identity | <...> |

### 1.4 Lethal trifecta check

| Leg | Present? | Which component provides it |
|---|---|---|
| Access to private data | <...> | <...> |
| Exposure to untrusted content | <...> | <...> |
| Ability to communicate externally | <...> | <...> |

## 2. What can go wrong?

At least 10 threats. Threat = actor + path + outcome. Write OWASP IDs with the year (`LLM01:2026`, `ASI02:2026`)
and add the MITRE ATLAS technique where one fits (`AML.T0051.001`). L and I: 1 low, 2 medium, 3 high.

| ID | Component | Boundary | Threat (actor, path, outcome) | STRIDE | OWASP (with year) | ATLAS | L | I | Risk |
|---|---|---|---|---|---|---|---|---|---|
| T01 | <...> | <...> | <...> | <...> | <...> | <...> | <...> | <...> | <...> |
| TODO | add rows T02 to T10 or more | | | | | | | | |

## 3. What are we going to do about it?

For every threat with risk 4 or more: the control, where it lives (file and function), whether it still works if
the model is fooled, and how you would see it in the log.

| ID | Control (what, where) | Works if the model is fooled? | Detection (rule ID or log field) |
|---|---|---|---|
| <T__> | <...> | <...> | <...> |

## 4. Did we do a good enough job?

### 4.1 Top 5 risks, in order, with one line on why
1. <...>

### 4.2 Residual risk
<What stays risky after your fixes, and why you accept it or who should decide.>
