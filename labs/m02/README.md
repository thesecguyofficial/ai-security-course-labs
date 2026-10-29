# Lab M2.5: threat-model TSG Helpdesk

Companion to lesson **2.5** of *AI Security Engineer* (The Sec Guy). It contains the system description, a
starter data-flow diagram you can open in OWASP Threat Dragon, a small helper that reads that diagram one step at
a time, a step-by-step guide and a blank template. **It contains no solution** (the worked sample answer is part
of the paid course).

- **Time:** 60–90 minutes, plus about 10 minutes for Step 1b
- **Cost:** $0. No cloud account. The threat model itself needs no code: pen and paper works, and so does any Markdown editor.
- **You need:** lessons 2.0–2.4 (how threat modelling works, the core flaw, the maps, the scoping matrices, trust boundaries). For Step 1b: Python 3 (lesson 0.6). One optional package, `pytm`.
- **You hand in (to yourself, or to the course community):** a filled-in copy of `threat-model-template.md`.

## Get the lab files

This folder is part of the free, public course labs repository, [thesecguyofficial/ai-security-course-labs](https://github.com/thesecguyofficial/ai-security-course-labs).

**First time, or you deleted the folder:** download it once.

```bash
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git
cd ai-security-course-labs
```

**Already downloaded it:** go to that folder and get the latest version.

```bash
cd ai-security-course-labs
git pull
```

**No git?** On the [labs page](https://github.com/thesecguyofficial/ai-security-course-labs), click **Code → Download ZIP**, unzip it and open a terminal in that folder (download it again to get updates).

Stay in the `ai-security-course-labs` folder: Step 1b starts with `cd labs/m02`.

## What's in this folder

| File | What it is |
|---|---|
| `README.md` | This guide, including the system description you will model |
| `threat-model-template.md` | The blank template: copy it to `my-threat-model.md` and fill it in |
| `tsg-helpdesk-starter.json` | A starter data-flow diagram of TSG Helpdesk in OWASP Threat Dragon's file format: the chat path and the nightly ticket import, no threats. You add the rest |
| `explore.py` | Reads a Threat Dragon file one step at a time: elements, flows, trust boundaries, STRIDE per element, and what reaches the model. Plain Python; it changes nothing |
| `tm.py` | The same starter written as code for OWASP pytm, which then lists threats from its own library |
| `requirements.txt` | The one package `tm.py` needs: `pytm==1.4.0` (MIT licence) |
| `Makefile` | Short names for long commands: `make pytm` runs `.venv/bin/python tm.py`. Run `make -n <name>` to see a command without running it |

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
New to data-flow diagrams? Do **Step 1b** first: it reads a starter diagram of part of this system with you.

**Optional: draw it in OWASP Threat Dragon.** Threat Dragon is OWASP's free, open-source (Apache-2.0) threat-modelling tool. In local mode it needs no account and sends nothing anywhere.

1. Install the desktop app from the [Threat Dragon releases](https://github.com/OWASP/threat-dragon/releases), or run the official container (Docker): `docker run -d -p 127.0.0.1:3000:3000 -e ENCRYPTION_KEYS='[{"isPrimary": true, "id": 0, "value": "11223344556677889900aabbccddeeff"}]' -e ENCRYPTION_JWT_SIGNING_KEY=change-me -e ENCRYPTION_JWT_REFRESH_SIGNING_KEY=change-me-too -e NODE_ENV=production -e SERVER_API_PROTOCOL=http owasp/threat-dragon:v2.6.2`, then open http://localhost:3000 and choose the local session. The keys in that command are examples; for anything other than this lab, generate your own.
2. **Create a new threat model** called `TSG Helpdesk` and add a **STRIDE** diagram. Or choose **Open an existing threat model** and open `tsg-helpdesk-starter.json`, which already has the chat path and the nightly import; then add the rest.
3. Drag in the **actors**, **processes** and **stores**, and connect them with **data flows**. Name each flow with its number (F1, F2, …).
4. Draw the model as its **own process inside its own trust boundary**, and start the name of every flow into the model with `TRUSTED:` or `UNTRUSTED:`. Threat Dragon has no "model" element and no field for this, so the names carry it.
5. Select an element and add threats. Threat Dragon's own suggestions are web-app threats and won't find AI threats, so add those by hand (lesson 2.5 explains why): pick the closest STRIDE type and put the OWASP and ATLAS IDs in the description.
6. **Save** the model and keep the JSON file next to your `my-threat-model.md`. The scopes and the lethal-trifecta check (Step 3) stay in the template.

### Step 1b · Read the starter model before you start (about 10 minutes)

New to threat modelling? Do this first. `tsg-helpdesk-starter.json` is part of TSG Helpdesk already drawn as a
data-flow diagram: the chat path and the nightly ticket import. `explore.py` reads it one idea at a time, so you
learn to read a diagram before you draw your own. Nothing here changes the file.

```bash
cd labs/m02
python3 explore.py elements
```

**1. Elements.** Every part of the system is one of three kinds: an **external entity** (a person or system
outside your control), a **process** (code that runs and changes data) or a **data store** (where data rests).
The starter has 6:

```text
model: "TSG Helpdesk (starter)"  ->  6 elements

external entity (a person or system outside your control): 1
   Customer           Anyone on the internet can sign up. Writes chats and tickets.

process (code that runs and changes data): 3
   Chat app           Builds the prompt, calls the model, runs its tool calls.
   Model              Local model on Ollama. Reads its whole context as one text.
   Nightly import     Copies resolved tickets into the knowledge base each night.

data store (where data rests): 2
   Ticketing system   Support tickets. Customers write them; staff resolve them.
   Knowledge base     Help articles. Some are imported customer tickets.
```

**2. Data flows.** Every arrow carries data from one element to another. Follow F15, F11 and F4: a customer's
ticket ends up in front of the model.

```bash
python3 explore.py flows
```

```text
8 data flows (arrows). Each one carries data from one element to another.

   F1 chat message                              Customer -> Chat app
   F2 UNTRUSTED: system prompt + chat           Chat app -> Model
   F4 UNTRUSTED: retrieved articles       Knowledge base -> Model
   F5 model output                                 Model -> Chat app
   F10 answer                                   Chat app -> Customer
   F15 ticket text                              Customer -> Ticketing system
   F11 resolved tickets                 Ticketing system -> Nightly import
   F11 new articles                       Nightly import -> Knowledge base
```

**3. Trust boundaries.** A trust boundary is a line where data passes between parts you trust differently. A flow
*crosses* a boundary when one end is inside and the other outside. Crossings are where you look for threats first.

```bash
python3 explore.py boundaries
```

```text
trust boundary: Our servers
   inside:   Chat app, Model, Ticketing system, Nightly import, Knowledge base
   crossing: 3 flows
      F1 chat message
      F10 answer
      F15 ticket text

trust boundary: Model boundary
   inside:   Model
   crossing: 3 flows
      F2 UNTRUSTED: system prompt + chat
      F4 UNTRUSTED: retrieved articles
      F5 model output
```

**4. STRIDE per element.** STRIDE is six questions, one per letter. Not every question fits every element: a
customer can be impersonated (S) or deny what they did (R), but a data flow can only be changed (T), read (I) or
blocked (D). `explore.py stride` prints Threat Dragon's own table for every element of the starter:

```bash
python3 explore.py stride
```

```text
   element                              type             S T R I D E
   Customer                             external entity  S . R . . .
   Chat app                             process          S T R I D E
   Model                                process          S T R I D E
   Ticketing system                     data store       . T R I D .
   ...
   F4 UNTRUSTED: retrieved articles     data flow        . T . I D .
```

Notice what the table can't say: a flow into the model can carry an *instruction*, not just data. That's the gap
lesson 2.5 is about.

**5. What reaches the model.** Everything on these flows lands in one stream of text (lesson 2.1). Both are
untrusted: F2 mixes your system prompt with a stranger's chat, and F4 carries articles that began as customer
tickets.

```bash
python3 explore.py model
```

```text
everything that reaches the model becomes part of one stream of text (lesson 2.1)

   UNTRUSTED         F2 UNTRUSTED: system prompt + chat  (from Chat app)
   UNTRUSTED         F4 UNTRUSTED: retrieved articles  (from Knowledge base)
```

**6. Open it in Threat Dragon (optional).** In Threat Dragon choose **Open an existing threat model**, then
**Open**, and pick `tsg-helpdesk-starter.json`. Open the diagram and click an element: the Properties panel shows
its name and description. The dashed boxes are the trust boundaries.

**7. Let a tool list threats (optional).** OWASP pytm describes the same system as Python code (`tm.py`) and checks
its threat library against facts you set on each element. Look before you run: `make -n setup` prints the two
commands `make setup` will run. `python3 -m venv .venv` makes a *virtual environment*, a private folder for this
lab's packages, so nothing you install touches the rest of your computer. Then `pip`, Python's package installer,
installs `pytm`.

```bash
make -n setup
make setup
make check
make pytm
```

```text
pytm: 121 findings for 13 elements

   Chat app                    34   e.g. INP02 Overflow Buffers
   ...
   Model                        5   e.g. LLM01 Direct Prompt Injection
   ...
all findings for Model:
   LLM01  High       Direct Prompt Injection
   LLM02  High       Indirect Prompt Injection via Retrieved Content
   LLM05  Very High  Excessive Agency via Unauthorized Tool Use
   LLM07  High       Jailbreaking and Safety Bypass
   LLM08  High       Sensitive Information Disclosure Through Output
```

pytm's `LLM01` to `LLM09` are pytm's own rule IDs, not OWASP's. It finds AI threats on the model only because
`tm.py` tells it the model reads untrusted input and uses RAG; the flows into the model still get web threats
(interception, sniffing). A tool gives you a list to judge, not a threat model. Windows: run the commands in
`Makefile` by hand (`py -m venv .venv`, then `.venv\Scripts\python -m pip install -r requirements.txt` and
`.venv\Scripts\python tm.py`).

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
