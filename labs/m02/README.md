# Lab M2.5: threat-model TSG Helpdesk

Companion to lesson **2.5** of *AI Security Engineer*. This folder will move to the public
lab repository as `labs/m02/`. It contains the system description, a step-by-step guide and a blank
template. **It contains no solution** (the worked sample answer is part of the paid course).

- **Time:** 60–90 minutes
- **Cost:** $0. No code, no cloud account. Pen and paper works; so does any Markdown editor.
- **You need:** lessons 2.1–2.4 (the core flaw, the maps, the scoping matrices, trust boundaries).
- **You hand in (to yourself, or to the course community):** a filled-in copy of `threat-model-template.md`.

## Files

| File | What it is |
|---|---|
| `README.md` | This guide, including the system description you will model |
| `threat-model-template.md` | The blank template: copy it to `my-threat-model.md` and fill it in |

## The system you are modelling: TSG Helpdesk

TSG Helpdesk is the course's **deliberately vulnerable** AI app. You will attack it in Module 3, deploy it
on AWS in Module 11 and secure it end to end in the capstone. Today you only look at its design.
All data in it is fake; it binds to `localhost` only.

**What it does:** a customer-support chatbot for a small online shop. Logged-in customers chat with it
about orders, deliveries and refunds.

**Components:**

| # | Component | Details |
|---|---|---|
| 1 | Customer | Logs in to the shop's website, then chats in a web widget. The session carries their `customer_id`. |
| 2 | Chat app | A small Python web app. Builds the prompt, calls the model, runs the tools the model asks for, returns the answer as rendered Markdown. |
| 3 | Model | Locally: a small open model on **Ollama**. AWS version: a model on **Amazon Bedrock**. |
| 4 | Knowledge base (RAG) | Help articles in a vector store. Support staff write articles; **every night, resolved tickets are also imported as articles** so the bot "learns" from past answers. |
| 5 | Tool `lookup_order(order_id)` | Returns status, items, delivery address and email for an order. |
| 6 | Tool `issue_refund(order_id, amount)` | Refunds up to a **limit of 50** (fake currency) per call, with no human approval. |
| 7 | Tool `send_email(to, subject, body)` | Sends an email from the shop's support address. |
| 8 | MCP ticketing server | Connected over MCP. Tools: `create_ticket`, `get_ticket`, `add_comment`, `search_tickets`. Installed from a public package registry. |
| 9 | Memory | After each chat, the app asks the model to summarise "useful facts about this customer" and saves the summary. The saved summary is loaded into the next chat's context. |
| 10 | Support staff | Read and resolve tickets in the ticketing system. |
| 11 | Logs | The chat app writes a log line per request (time, `customer_id`, model, token counts). |
| 12 | Credentials | One service account / API key used for the order database, refunds, email and the ticketing server. |

**Assumptions** (state them in your model too): customers are authenticated by the shop's website;
anyone on the internet can create a shop account; ticket text is written by customers; the model sees
the system prompt, the customer's memory summary, retrieved articles, the chat and tool results, all in one
context window.

## Step by step

### Step 1 · What are we working on? (10 min)
Read the system description twice. On paper or in the template, draw a **data-flow diagram**:
external entities (people and outside systems), processes (chat app, model, tools, MCP server),
data stores (knowledge base, memory, order database, logs) and data flows (arrows).
Tip: number every arrow (F1, F2, …). You will refer to them in the table.

### Step 2 · Draw the trust boundaries (10 min)
Draw a dashed line wherever trust changes. Check all seven from lesson 2.4: **input, model, tools,
output, data, memory, identity**. Then label every arrow that carries text **into the model**:
`trusted` (only your team could have written it) or `untrusted` (anyone else could have written any part of it).
Be strict: a resolved ticket imported into the knowledge base is still customer-written text.

### Step 3 · Place it on the maps (5 min)
- Which **GenAI scope** (1–5) and which **Agentic scope** (1–4) is TSG Helpdesk? Write one sentence of reasoning for each (lesson 2.3).
- **Lethal trifecta check** (lesson 2.4): does it have private data? Untrusted content? An outbound channel? Write down *which component* provides each leg.

### Step 4 · What can go wrong? (25 min)
Walk every boundary crossing and ask the six STRIDE-for-AI questions from lesson 2.4.
Write each threat as **one sentence with an actor, a path and an outcome**, for example:
"An attacker *(actor)* puts instructions in a ticket that is later imported into the knowledge base *(path)*,
so the bot tells other customers to email their card details to a fake address *(outcome)*."
Aim for **at least 12 threats**, covering **all seven boundaries**.

### Step 5 · Map each threat (10 min)
For each threat, add:
- an **OWASP** ID with its year: `LLM01:2026` style from the LLM Top 10 2026, and an `ASI0x` ID from the Agentic Top 10 2026 where it fits;
- a **MITRE ATLAS** technique ID where one fits (for example `AML.T0051` LLM Prompt Injection). Use the ATLAS site's search, or skip it if you're unsure: an empty cell is better than a wrong ID.

### Step 6 · Rate it (5 min)
Score **likelihood** and **impact** from 1 (low) to 3 (high) and multiply them for a **risk** score of 1–9.
Write one short reason for each score. Ratings are judgement calls; the reasons are what make them useful.

### Step 7 · What are we going to do about it? (15 min)
For each threat with risk **4 or more**, write:
- a **control**: prefer deterministic code (authorisation, limits, allow-lists) over "tell the model not to";
- **how to detect** it: which log line or event would show it happening. If no such log exists today, say so: that is a finding too.

### Step 8 · Did we do a good enough job? (5 min)
Pick your **top 5** risks and check your work against this list:

- [ ] Every one of the seven boundaries has at least one threat.
- [ ] At least one threat starts from content *other than the chat box* (knowledge base, ticket, memory, tool result).
- [ ] At least one threat is about identity or permissions (whose account does the tool use?).
- [ ] At least one threat is about the MCP server itself, not just what it returns.
- [ ] Every high risk has a control that would still work **if the model is fooled**.
- [ ] Every OWASP ID has a year.
- [ ] You've written down at least one question you would ask the developers.

## Next

Compare your model with the sample answer in the course (lesson 2.5 solution). Don't worry if yours differs:
two good threat models of the same system are never identical. In Module 3 you will attack TSG Helpdesk
and find out which of your threats are real.

## Safety

This lab is design-only. When you later run TSG Helpdesk, keep it on `localhost`, use only the fake data it
ships with, and never connect it to a real mailbox, payment system or ticketing tenant.
