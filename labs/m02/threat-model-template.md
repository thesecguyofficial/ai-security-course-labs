# Threat model: TSG Helpdesk

> Copy this file to `my-threat-model.md` and fill it in. Pen and paper is fine too: copy the headings.
> Guide: `README.md` in this folder. Lessons 2.1–2.5 of *AI Security Engineer*.

- **Author:**
- **Date:**
- **Version of the system reviewed:** (local / Ollama, or AWS / Bedrock)

## 1. What are we working on?

### 1.1 Assumptions
- 
- 

### 1.2 Data-flow diagram (as text)

List the elements, then the flows. Draw it on paper as well if that helps.

**External entities:**
- E1:
- E2:

**Processes:**
- P1:
- P2:

**Data stores:**
- D1:
- D2:

**Data flows** (number every arrow):

| Flow | From → To | What it carries | Into the model? | Trusted / untrusted |
|---|---|---|---|---|
| F1 | | | | |
| F2 | | | | |
| F3 | | | | |

### 1.3 Trust boundaries

| Boundary | Where it sits in your diagram (which flows cross it) |
|---|---|
| Input | |
| Model | |
| Tools | |
| Output | |
| Data | |
| Memory | |
| Identity | |

### 1.4 Where is it on the maps?

- **GenAI Security Scoping Matrix scope (1–5):**  … because …
- **Agentic AI Security Scoping Matrix scope (1–4):**  … because …

### 1.5 Lethal trifecta check

| Leg | Present? (yes/no) | Which component provides it |
|---|---|---|
| Access to private data | | |
| Exposure to untrusted content | | |
| Ability to communicate externally | | |

## 2. What can go wrong?

One row per threat. Threat = **actor + path + outcome**. STRIDE letter: S, T, R, I, D or E.
Likelihood (L) and impact (I): 1 low, 2 medium, 3 high. Risk = L × I.

| ID | Component | Boundary | Threat (actor, path, outcome) | STRIDE | OWASP (with year) | ATLAS | L | I | Risk |
|---|---|---|---|---|---|---|---|---|---|
| T01 | | | | | | | | | |
| T02 | | | | | | | | | |
| T03 | | | | | | | | | |
| T04 | | | | | | | | | |
| T05 | | | | | | | | | |
| T06 | | | | | | | | | |
| T07 | | | | | | | | | |
| T08 | | | | | | | | | |
| T09 | | | | | | | | | |
| T10 | | | | | | | | | |
| T11 | | | | | | | | | |
| T12 | | | | | | | | | |

**Why I rated them this way** (one line each for the highest risks):
- T__:
- T__:

## 3. What are we going to do about it?

For every threat with risk ≥ 4.

| ID | Control (what, and where: code / config / process) | Still works if the model is fooled? | How to detect (log, event, alert) | Log exists today? |
|---|---|---|---|---|
| T__ | | | | |
| T__ | | | | |
| T__ | | | | |

## 4. Did we do a good enough job?

### 4.1 Top 5 risks, in order
1. 
2. 
3. 
4. 
5. 

### 4.2 Checklist
- [ ] Every one of the seven boundaries has at least one threat.
- [ ] At least one threat starts from content other than the chat box.
- [ ] At least one threat is about identity or permissions.
- [ ] At least one threat is about the MCP server itself.
- [ ] Every high risk has a control that still works if the model is fooled.
- [ ] Every OWASP ID has a year.

### 4.3 Questions for the developers
- 
- 

### 4.4 Residual risk (what stays risky even after the controls)
- 
