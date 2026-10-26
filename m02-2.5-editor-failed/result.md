# Threat model: TSG Helpdesk

> Copy this file to `my-threat-model.md` and fill it in. Pen and paper is fine too: copy the headings.
> Guide: `README.md` in this folder. Lessons 2.1–2.5 of *AI Security Engineer*.

- **Author:** The Sec Guy
- **Date:** 27 Oct 2026
- **Version of the system reviewed:** local / OllamaOllama, or AWS / Bedrock)

## 1. What are we working on?

### 1.1 Assumptions
- Customers log in on the shop website; anyone on the internet can create an account.
- Ticket text is written by customers.
- The model sees the system prompt, memory summary, retrieved articles, chat and tool results in one context window.
- One service account is used for orders, refunds, email and tickets.

### 1.2 Data-flow diagram (as text)

List the elements, then the flows. Draw it on paper as well if that helps.

**External entities:**
- E1: Customer (logged in, but anyone can sign up)
- E2: Support staff
- E3: Public package registry (where the MCP server came from)
- E4: Email recipients

**Processes:**
- P1: Chat app (builds the prompt, runs the tools, renders Markdown)
- P2: Model (Ollama, locally)
- P3: Tools: lookup_order, issue_refund (up to 50 per call), send_email
- P4: MCP ticketing server
- P5: Nightly import of resolved tickets

**Data stores:**
- D1: Knowledge base (vector store)
- D2: Memory summaries
- D3: Order database
- D4: Ticketing system
- D5: Logs

**Data flows** (number every arrow):

| Flow | From → To | What it carries | Into the model? | Trusted / untrusted |
|---|---|---|---|---|
| F1 | E1 → P1 | Chat message | Yes | Untrusted |
| F2 | P1 → P2 | System prompt | Yes | Trusted |
| F3 | D2 → P2 | Memory summary (the model wrote it from chat text) | Yes | Untrusted |
| F4 | D1 → P2 | Retrieved articles (include imported tickets) | Yes | Untrusted |
| F5 | P2 → P3, P4 | Tool calls the model chose | No | Untrusted |
| F6 | P3 → D3 | Order lookups and refunds (shared service account) | No | n/a |
| F7 | P3 → P2 | Tool results: order details, addresses | Yes | Untrusted |
| F8 | P4 → P2 | Ticket text from get_ticket and search_tickets | Yes | Untrusted |
| F9 | P3 → E4 | Emails from the support address | No | n/a |
| F10 | P1 → E1 | Answer rendered as Markdown | No | n/a |
| F11 | D4 → P5 → D1 | Resolved tickets imported every night | No | Untrusted |
| F12 | P1 → D2 | Memory summary saved after each chat | No | Untrusted |
| F13 | E3 → P4 | MCP server code and its updates | No | Untrusted |
| F14 | P1 → D5 | Log line: time, customer, model, tokens | No | n/a |

### 1.3 Trust boundaries

| Boundary | Where it sits in your diagram (which flows cross it) |
|---|---|
| Input | F1 |
| Model | F2, F3, F4, F7, F8: all in one context window |
| Tools | F5, F6, F9, F13 |
| Output | F10 (Markdown can load images and links), F9 |
| Data | F4, F11 |
| Memory | F3, F12 |
| Identity | F6, F9: one shared service account behind every tool |

### 1.4 Where is it on the maps?

- **GenAI Security Scoping Matrix scope (1–5):** 3, because it is our own app on a pre-trained model (Ollama here, Bedrock on AWS) with RAG.because …
- **Agentic AI Security Scoping Matrix scope (1–4):** 3, because a customer starts it and it refunds and emails within a limit, with no approval per action.:**  … because …

### 1.5 Lethal trifecta check

| Leg | Present? (yes/no) | Which component provides it |
|---|---|---|
| Access to private data | Yes | lookup_order (addresses, emails), memory, tickets |
| Exposure to untrusted content | Yes | Chat, imported tickets in the knowledge base, MCP ticket text, tool results |
| Ability to communicate externally | Yes | send_email to any address; images and links in Markdown answers |

## 2. What can go wrong?

One row per threat. Threat = **actor + path + outcome**. STRIDE letter: S, T, R, I, D or E.
Likelihood (L) and impact (I): 1 low, 2 medium, 3 high. Risk = L × I.

| ID | Component | Boundary | Threat (actor, path, outcome) | STRIDE | OWASP (with year) | ATLAS | L | I | Risk |
|---|---|---|---|---|---|---|---|---|---|
| T00 (example) | Knowledge base (nightly ticket import) | Data → Model | An attacker files a ticket with hidden instructions; it is imported as an article; the bot later follows it for other customers | T | LLM01:2026, LLM05:2026, ASI06 | AML.T0070, AML.T0051.001 | 3 | 2 | 6 |
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
| T00 | Don't auto-import customer text: staff review and rewrite first; record each article's source (code and process) | Yes | Log the article IDs retrieved for each answer; alert on imported articles with URLs or instruction-like phrases | No: logs have only time, customer, model, tokens |
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
