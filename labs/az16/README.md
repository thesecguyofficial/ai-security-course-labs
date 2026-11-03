# Lab AZ16: build the detections, run the attack simulator, catch it, write the incident report

Companion to lessons **16.0 to 16.6** of the Azure stream of *AI Security Engineer* (The Sec Guy). About 75 minutes
for Steps 1 to 9, **$0**, all on your laptop: **Python 3.11+ only**, no packages, no Azure subscription, no network.
Step 10 is optional: [`GUIDED-BUILD.md`](GUIDED-BUILD.md) turns on Defender for AI services, sends four requests with
user context, changes one setting, adds an alert rule for every AI alert, and ends with teardown, in **your own**
subscription.

You are the cloud security engineer at **Contoso** (fictional; Contoso is the placeholder name Microsoft uses in its
documentation). Over Modules 10 to 14 the company built a customer support bot on Microsoft Foundry (formerly Azure AI
Foundry) behind an API Management AI gateway, a staff helpdesk agent with a Foundry toolbox, and a knowledge base in
Azure AI Search. On **20 October 2026** five things went wrong on the same day. The SOC caught one of them. Your job:
find out why, build the detections and the logging that catch all five, and write the incident report for the
expensive one.

| Part | What you do | Lesson |
|---|---|---|
| **Simulate** | One day of telemetry, normal work plus five incidents, for two logging setups | 16.0, 16.1 |
| **Old SOC** | The SOC's three rules on the old logs: 1 of 5 caught, 1 false alarm | 16.0, 16.2 |
| **Old rules, new logs** | Still 1 of 5: a High-only Defender rule drops 6 of the 8 AI alerts | 16.2 |
| **New rules, old logs** | 1 of 5: you can't detect what you didn't log | 16.1 |
| **Both** | Rules D01 to D10 on the new logs: 3 of 5 caught and named, 2 seen but not named, 0 false alarms | 16.2, 16.4 |
| **Inventory** | Resource Graph, Defender CSPM's AI posture, your own exposure check, and what isn't approved | 16.3 |
| **Posture** | Five built-in Azure Policy definitions for AI services, plus five checks you have to write | 16.4 |
| **Report** | Pivot on an entity, find the tokens nobody logged, read a worked incident report | 16.5 |
| **Prove** | `make test`: 18 tests | 16.6 |
| **Challenge** | Two detections and your own incident report. No solution included | 16.4, 16.5 |
| **Cloud (optional)** | [`GUIDED-BUILD.md`](GUIDED-BUILD.md): portal and CLI from zero, four requests, one setting changed, cost, teardown | 16.1 to 16.4 |

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

Then go to this lab's folder. Every command in this guide runs from there:

```bash
cd labs/az16
```

## What's in this folder

| File | What it is |
|---|---|
| `explore.py` | **Read-only helper** (Step 1b): one idea at a time, from one day's log rows, alerts and incidents to a playbook. It builds the day in memory, sends nothing and writes nothing |
| `data/vnet-flow-logs.json`, `data/dns-query-logs.jsonl` | **Illustrative** virtual network flow log and DNS query log lines in Microsoft's documented shapes, for `explore.py flow` and `explore.py dns` (no other file reads them) |
| `simulate.py` | The **attack simulator**: 20 Oct 2026 at Contoso, normal work plus five incidents (S1 to S5), written as the rows each logging setup would really collect. It replays a scripted day; it never calls Azure |
| `setups/first-draft.json`, `setups/hardened.json` | What each setup collects. First draft: the Activity log, the gateway log and a plain web log. Hardened: lesson 16.1's list (Foundry `RequestResponse` logs, the gateway's LLM log, Defender for AI services with user context, agent traces, blob logs, the agent pipeline's change log, an app log with identities) |
| `detect.py` | Two rule packs: `soc-v1` (three rules a SOC often starts with) and `az16` (D01 to D12). D11 and D12 are your challenge |
| `evaluate.py` | Scores a pack against the five incidents: CAUGHT (an alert names who to act on), SEEN, NOT NAMED, MISSED, and false alarms |
| `inventory.py`, `data/inventory/` | An AI inventory from Azure Resource Graph rows, a Defender CSPM AI posture export and network security group rules |
| `posture.py`, `data/posture/` | Five built-in Azure Policy definitions (display names exactly as Microsoft lists them, conditions copied from each definition) and five custom checks |
| `report.py`, `report/` | Pivot, cost, and the incident report check; `TEMPLATE.md` and a worked example for S3 |
| `queries/` | The same rules as KQL, for your own Log Analytics workspace or Microsoft Sentinel |
| `cloud/` | Files for the guided build: a request body with `user_security_context`, four lab prompts, the alert rule query |
| `contoso.json`, `data/baselines.json` | The company's facts: known addresses, workload identities, the knowledge base publisher, token baselines |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | `make test` and `make challenge` |

Everything is fictional: Contoso, the subscription, the people, the customers. Addresses come from the documentation
ranges (RFC 5737). Attack text is a short, labelled lab placeholder that does nothing outside this folder. Column names
follow Microsoft's table references; each row carries only the columns the lab reads, and identities appear by name
where real rows carry object IDs.

## Needs

- Python 3.11 or newer (`python3 --version`). Nothing to install: `make setup` only checks the version.
- `make` (Mac and Linux have it). Windows: run the `python` commands shown under each step.

## Step 1b · Before you start: look at each idea on its own (about 15 minutes)

New to detection and response? Do this before Step 1 (lesson 16.6 calls it Step 1b; lesson 16.0 explains each idea). `explore.py` shows,
one idea at a time, the records, the rules and the response on Contoso's day, the Azure version of the AWS stream's Module 16.
Real output below is from a fresh Ubuntu machine (recording run 41614948165). Run it from `labs/az16`.

**What it really runs.** Nothing that changes anything: `explore.py` builds the simulated day in memory with
`simulate.py`, runs the lab's own functions on it (`detect.py`, `inventory.py`, `posture.py`, `report.py`) and prints.
It writes no file (not even `out/` or `__pycache__/`), calls no Azure service, runs no `az` command and needs no network.
Windows: `py explore.py day`.

**0. Look before you run.** `make -n` prints what make would run, without running it. This lab needs no virtual environment and no `pip install` (other labs do): only Python's standard library. `make setup` just checks your Python.

```bash
make -n setup simulate
```

```output
python3 ../../tools/check_python.py 3.11
python3 simulate.py
```

**1. One day, in numbers.** Log rows, alerts and incidents: many records, fewer alerts, very few incidents. Each file is one Log Analytics table.

```bash
python3 explore.py day
```

```output
One day at Contoso, 20 Oct 2026 (UTC), with the hardened logging. Fake company, fake values.

LOGS: records of what happened, one row per event (each file = one Log Analytics table)
  activity.jsonl      6  AzureActivity: who changed or read settings (control plane)
  foundry.jsonl     885  AzureDiagnostics: every call to the Foundry resource (resource log)
  gateway.jsonl     735  ApiManagementGatewayLogs: every call through the AI gateway
  llm.jsonl        1464  ApiManagementGatewayLlmLog: prompts, answers, tokens
  alerts.jsonl        8  SecurityAlert: alerts that Defender for AI services raised
  traces.jsonl       64  Foundry agent spans: what the agent did
  blob.jsonl          4  StorageBlobLogs: writes into the knowledge base storage
  deploy.jsonl        2  the agent pipeline's own change log
  metrics.jsonl      10  AzureMetrics: tokens per hour, counted by the Foundry resource
  app.jsonl         585  the web app's own log: which signed-in person
  total            3763

ALERTS: a rule matched, and a message tells a person to look
  detect.py rules    18  from rules D01 to D12 (8 come from D04, which passes on every Defender alert; D11, D12: your challenge)

INCIDENTS: confirmed, someone has to act (the lab's answer key; a real team decides this in triage)
  simulate.py         5  S1 leaked CI secret and Foundry key, S2 jailbroken customer bot, S3 hijacked agent,
                         S4 denial of wallet through the app, S5 poisoned search index

3763 rows, 18 alerts, 5 incidents.
```

**2. The Activity log and a resource log.** The Activity log (who changed or read settings) is on by default and kept 90 days; resource logs (each call to the resource) need a diagnostic setting. AWS keeps both kinds in CloudTrail; Azure splits them.

```bash
python3 explore.py activity
```

```output
Azure keeps two kinds of record about a resource. Both from the hardened setup:

ACTIVITY LOG (table AzureActivity): who changed or read the resource's settings. On by default, kept 90 days
  TimeGenerated        2026-10-20T14:06:00Z               WHEN (UTC)
  OperationNameValue   ACCOUNTS/LISTKEYS/ACTION           WHAT: read the Foundry resource's keys
  Caller               sp-contoso-ci                      WHO: the CI pipeline's service principal
  CallerIpAddress      203.0.113.50                       FROM WHERE: an outside address
  ActivityStatusValue  Succeeded
  _ResourceId          ...accounts/contoso-foundry        WHICH resource

RESOURCE LOG (table AzureDiagnostics, category RequestResponse): every call made TO the resource.
Off until a diagnostic setting sends it to a workspace
  TimeGenerated        2026-10-20T14:10:36Z               WHEN (UTC)
  OperationName        ChatCompletions_Create             WHAT: a chat call (lab placeholder name)
  CallerIPAddress      203.0.113.50                       FROM WHERE: the same outside address
  ResultSignature      200                                200 = the model answered
  WHO                  (no column)                        a key carries no identity: only the address

Hardened today: 6 Activity log rows, 885 resource log rows (735 from the gateway, 150 from elsewhere).
First draft today: 6 Activity log rows, 0 resource log rows.
Neither kind of record holds the prompt or the answer.
```

**3. What was said.** The API Management gateway's LLM log holds the prompt, the answer and the tokens, as two rows per call. The caller is in the gateway log and your app log, joined on `CorrelationId`.

```bash
python3 explore.py llm
```

```output
The API Management AI gateway's LLM log (table ApiManagementGatewayLlmLog): one call, two rows

  TimeGenerated      2026-10-20T08:41:00Z                     WHEN (UTC)
  CorrelationId      853ae47a...                              joins this call's rows in every gateway table
  DeploymentName     helpdesk-chat                            WHICH model deployment
  RequestMessages    "Where is my order 4417?"                row 1, WHAT WAS SAID: the customer
  ResponseMessages   "Order 4417 shipped yesterday...."       row 2: the model's answer
  PromptTokens       628                                      tokens in (you pay per token)
  CompletionTokens   197                                      tokens out
  WHO                (no column)                              the LLM log has no caller column

The caller is in the other tables, joined on CorrelationId:
  ApimSubscriptionId helpdesk-app                             ApiManagementGatewayLogs: WHICH app (its gateway key)
  signed_in_user     cust-1022                                your app log: WHICH PERSON, only if the app writes it

1464 rows today for 735 calls. Not here: the 150 calls that skipped the gateway with a key.
The gateway logs what passes through the gateway. First draft: 0 rows (Log LLM messages was off).
```

**4. Virtual network flow logs.** Who talked to whom, on which port, allowed or not. The lines in `data/vnet-flow-logs.json` are **illustrative**, in Microsoft's documented shape.

```bash
python3 explore.py flow
```

```output
data/vnet-flow-logs.json: virtual network flow logs (version 4), Microsoft's documented shape. ILLUSTRATIVE.

One record covers one VNet (vnet-research) for one minute. Its first flow tuple, field by field:
  rule            UserRule_allow-ollama-demo       the NSG rule that allowed or denied it
  time            1792487523000                    UNIX time in milliseconds
  src / dst       203.0.113.80 -> 10.20.5.4        FROM this address TO this address
  dstport         11434                            on this port
  protocol        6                                6 = TCP
  direction       I                                I = inbound, O = outbound
  state           B                                B = began, C = continuing, E = ended, D = denied
  encryption      NX                               NX = not encrypted (the default inside a VNet)
  packets, bytes  0,0,0,0                          how much, never what: no contents

  from            to              port   dir  state  reading
  203.0.113.80    10.20.5.4       11434  I    B      someone on the internet connected to port 11434 (Ollama) on the GPU VM
  203.0.113.80    10.20.5.4       11434  I    E      the same connection ended: about 48 KB went back to the internet
  198.51.100.9    10.20.5.4       22     I    D      SSH (port 22) from an unknown address: refused by the default deny rule
  10.20.6.8       198.51.100.200  443    O    E      the analytics VM sent HTTPS out: to WHICH service? Not in this line

Flow logs answer: who talked to whom, on which port, allowed or not. Names and contents are not in them.
They land in a storage account. NSG flow logs, the older kind, retire on 30 Sep 2027.
```

**5. DNS query logs.** Which address looked up which name, from a DNS resolver policy. The rows in `data/dns-query-logs.jsonl` are **illustrative**. Azure names the network, not the VM.

```bash
python3 explore.py dns
```

```output
data/dns-query-logs.jsonl: DNS query logs from a DNS resolver policy (table DNSQueryLogs). ILLUSTRATIVE.

One row, field by field:
  TimeGenerated             2026-10-20T11:02:13Z                 WHEN (UTC)
  QueryName                 api.openai.com.                      the NAME the machine looked up
  QueryType                 A                                    A = give me its IPv4 address
  ResponseCode              NOERROR                              the answer: NOERROR = the name exists (lab value)
  SourceIpAddress           10.20.6.8                            the machine's address
  VirtualNetworkId          ...virtualNetworks/vnet-research     WHICH network: no VM name
  ResolverPolicyRuleAction  Allow                                the policy let it through (it can also block)

  network            address      looked up                         times
  vnet-helpdesk      10.20.1.16   contoso-apim.azure-api.net            1  Contoso's own gateway
  vnet-mktg-sandbox  10.20.7.20   api.anthropic.com                     2  outside AI service
  vnet-research      10.20.5.4    huggingface.co                        1  outside AI service
  vnet-research      10.20.6.8    api.openai.com                        3  outside AI service

The flow log said 10.20.6.8 sent HTTPS to 198.51.100.200. The DNS log says which NAME it looked up first.
Azure names the network, not the VM: map the address to its network card with Resource Graph.
```

**6. A detection rule, part by part.** Rule D06 from `detect.py`, then run on the day's app log.

```bash
python3 explore.py rule
```

```output
detect.py, rule D06 "Repeated content-filter blocks for one end user", read part by part

  reads            app.jsonl                            your app's own log (KQL twin: queries/d06-...kql)
  looks for        content_filter_blocked = true        Prompt Shields blocked a message
  groups by        signed_in_user                       the customer, as the app wrote it
  raises an alert  3 or more in 10 minutes              the threshold, from contoso.json
  names            the end user                         the thing you would act on

Run on today's 585 app log rows:
  cust-8841  6 blocked, 10:40 to 10:49  ALERT [HIGH] D06 Repeated content-filter blocks for one end user
  66 other customers: 0 blocked, no alert

A rule asks one question of every row. A yes is an alert, with a name on it. Triage decides if it's an incident.
```

**7. A Defender for AI services alert.** One `SecurityAlert` row field by field, then the day's eight alerts and what a High-only email would send.

```bash
python3 explore.py alert
```

```output
A Defender for AI services alert (table SecurityAlert, cut to the fields the lab reads), from alerts.jsonl

  AlertType            AI.Azure_Jailbreak.ContentFilterin...   WHAT Defender thinks happened
  AlertName            A Jailbreak attempt on an Azure AI...   the name the SOC sees
  AlertSeverity        Medium                                  Low, Medium or High
  Tactics              PrivilegeEscalation, DefenseEvasion     the attacker's goal, in MITRE ATT&CK words
  CompromisedEntity    contoso-foundry                         the Foundry resource
  End user ID          cust-8841                               WHO: only because the app sent user context
  End user source IP   198.51.100.77                           the customer's address, from the same context
  Alert count          6                                       how many blocked attempts
  StartTime / EndTime  10:40:00 / 10:49:20                     WHEN (UTC)

Today's 8 Defender for AI services alerts:
  09:15  High   Corrupted AI application\model\data directed a phishing att... cust-1104
  10:40  Medium A Jailbreak attempt on an Azure AI model deployment was blo... cust-8841
  10:40  Low    (Preview) LLM Reconnaissance Attempt Detected                  cust-8841
  11:20  Low    Anomalous tool invocation                                      contoso-foundry
  14:10  High   Access from suspicious IP                                      contoso-foundry
  14:10  Medium Access anomaly in AI resource                                  contoso-foundry
  14:10  Medium Suspected wallet attack - volume anomaly                       contoso-foundry
  16:00  Medium Suspected wallet attack - recurring requests                   contoso-foundry

Default email notifications go out for High only: 2 of 8 would reach a person that way.
```

**8. An AI inventory.** One asset from each of the three signals, then the register check.

```bash
python3 explore.py inventory
```

```output
An AI inventory, built from three signals, then checked against the approved register

Signal 1  Azure Resource Graph row  ->  an AI resource that exists in Azure
          type microsoft.cognitiveservices/accounts   kind AIServices   name mktg-hackathon-ai
          tags {"owner": "marketing", "purpose": "hackathon"}
          -> microsoft.cognitiveservices/accounts  mktg-hackathon-ai  NOT on the register

Signal 2  Defender CSPM AI security posture (AI-SPM)  ->  AI in a connected AWS or Google Cloud account
          AWS: Amazon Bedrock, account 111122223333 us-east-1
          -> Amazon Bedrock  account 111122223333 us-east-1  approved

Signal 3  a network security group rule (your own check)  ->  a model server you run on a VM
          vm-gpu-lab01: nsg-gpu-lab01/allow-ollama-demo allows Internet to port 11434
          -> self-hosted model server (Ollama)  vm-gpu-lab01  NOT on the register

10 AI assets found; 4 are not on data/inventory/sanctioned.json, the approved register.
Agents: 2 agent records not shown (agent discovery needs a Microsoft Agent 365 licence).
```

**9. Azure Policy and your own check.** A built-in definition the Foundry resource passes, and a custom check it fails.

```bash
python3 explore.py policy
```

```output
Azure Policy checks one setting on each resource. Result: Compliant or NON_COMPLIANT. First-draft setup:

Built-in definition (Microsoft wrote it): Diagnostic logs in Azure AI services resources should be enabled [1.0.0]
  contoso-foundry     Compliant      a diagnostic setting with logs exists (it doesn't look at WHICH logs)

Custom check (you write it): C01 Foundry diagnostic setting sends Audit, RequestResponse and Trace to a workspace
  contoso-foundry     NON_COMPLIANT  sends no RequestResponse, Trace
  mktg-hackathon-ai   NON_COMPLIANT  sends no Audit, RequestResponse, Trace

The Foundry resource passes the built-in and fails yours. This lab: 5 built-in definitions, 5 custom checks.
```

**10. A hunting query.** The KQL from `queries/`, the same question asked of the day, and the tokens the gateway never saw.

```bash
python3 explore.py query
```

```output
queries/d05-token-spike-per-subscription.kql: KQL for a Log Analytics workspace (first lines)

  ApiManagementGatewayLlmLog
  | where TimeGenerated > ago(1d)
  | summarize Tokens = max(TotalTokens) by CorrelationId, bin(TimeGenerated, 1h)   // one value per call
  | join kind=inner (ApiManagementGatewayLogs | project CorrelationId, ApimSubscriptionId) on CorrelationId
  | summarize HourTokens = sum(Tokens) by ApimSubscriptionId, TimeGenerated
  | join kind=leftouter baseline on ApimSubscriptionId
  ...

The same question, asked of today's LLM log (top 5 of 19 rows):
  ApimSubscriptionId  hour    HourTokens  calls
  helpdesk-app        16:00    2,829,467    320
  ds-batch            13:00      112,628    150
  helpdesk-app        10:00       38,809     50
  helpdesk-app        13:00       29,584     36
  helpdesk-app        09:00       27,243     34

The Foundry resource's own TotalTokens metric counted 4,836,357 tokens today; the LLM log holds 3,180,011.
The gap, 1,656,346 tokens, is calls that skipped the gateway. Nobody's log says who sent them.

Hunting: you ask a question across the logs because you suspect something, not because an alert fired.
```

**11. A playbook.** The leaked secret's first steps. Printed only: nothing runs.

```bash
python3 explore.py playbook
```

```output
A playbook: the steps for one kind of incident, written before the day. Leaked CI secret, then a Foundry key.
Printed only: nothing runs, nothing is sent.

  TRIGGER   D01 alert at 14:05: sp-contoso-ci used from an unknown address (203.0.113.50)
  1 KEEP    copy the evidence before anything changes: 5 records mention sp-contoso-ci, 79 mention 203.0.113.50 (report.py pivot)
  2 CONTAIN the secret: remove it from the service principal (not the whole identity)
            az ad sp credential delete --id <object ID of sp-contoso-ci> --key-id <key id>
  3 CONTAIN the keys it listed: regenerate both (a key carries no name, so you can't tell which was used)
            az cognitiveservices account keys regenerate -n contoso-foundry -g rg-helpdesk-prod --key-name Key1
            az cognitiveservices account keys regenerate -n contoso-foundry -g rg-helpdesk-prod --key-name Key2
  4 ASK     what did the key do? The resource log has the calls, the metric has the tokens (query)
  5 RECOVER move every caller to Microsoft Entra ID and set disableLocalAuth to true; find how the secret leaked
  6 WRITE   the incident report: report/TEMPLATE.md

Containment stops the damage growing. The report says what happened, and what changes so it can't again.
```

**12. Read one run from the top.** `make simulate` is the lab's first real step. Each number is how many rows of that table the setup collected.

```bash
make simulate
```

```output
python3 simulate.py
first-draft  activity 6 foundry 0 gateway 735 llm 0 alerts 0 traces 0 blob 0 deploy 0 metrics 0 app 585  -> out/first-draft/
hardened     activity 6 foundry 885 gateway 735 llm 1464 alerts 8 traces 64 blob 4 deploy 2 metrics 10 app 585  -> out/hardened/
```

## Step 1 · The day of the five incidents

```bash
make setup
make simulate
python3 simulate.py --list
```

- `make simulate`: same as `python3 simulate.py`
- `python3 simulate.py --list`: the five stories

```output
Nothing to install for this lab: Python 3.13 and its standard library are all it needs.
python3 simulate.py
first-draft  activity 6 foundry 0 gateway 735 llm 0 alerts 0 traces 0 blob 0 deploy 0 metrics 0 app 585  -> out/first-draft/
hardened     activity 6 foundry 885 gateway 735 llm 1464 alerts 8 traces 64 blob 4 deploy 2 metrics 10 app 585  -> out/hardened/
```

Same day, two logging setups. The first draft has 6 Activity log rows, 735 gateway rows and a web log that doesn't
say who anyone is. The hardened setup adds 885 Foundry resource-log rows, 1,464 LLM log rows with prompts and token
counts, 8 Defender alerts, 64 agent spans and the rest.

| | Incident | Who you'd act on |
|---|---|---|
| S1 | A CI build log printed the pipeline's client secret. Someone signs in as `sp-contoso-ci`, lists the Foundry keys, fails to delete the diagnostic setting, then calls the model directly with a key for 90 minutes, skipping the gateway | `sp-contoso-ci` |
| S2 | A signed-in customer tries nine jailbreaks in 12 minutes; Prompt Shields blocks six; one answer leaks the system prompt's canary | `cust-8841` |
| S3 | A rollback sets the helpdesk toolbox back to version 1 (`require_approval` never); a hidden instruction in ticket 5120 makes the agent email ticket data out and delete the ticket | `conv-7f3a5120` |
| S4 | A scripted account sends 300 near-maximum chats in 50 minutes, all through the app's own gateway subscription | `cust-2290` |
| S5 | A contractor account writes a fake "VPN support update" into the knowledge base container; the indexer picks it up; the bot sends customers to an outside "support line" | `carol@contoso.com` |

## Step 2 · The SOC's old rules on the old logs

```bash
make old
```

Same as `python3 evaluate.py first-draft --pack soc-v1`.

```output
Pack soc-v1 on first-draft telemetry: 3 alerts

  S1  CAUGHT           Leaked CI secret and Foundry key   N2                       named sp-contoso-ci
  S2  MISSED           Jailbroken customer bot                                     
  S3  MISSED           Hijacked agent                                              
  S4  SEEN, NOT NAMED  Denial of wallet through the app   N1                       named 10.20.1.16
  S5  MISSED           Poisoned search index                                       
  false alarm: N1 High call volume at the gateway (10.20.1.17: 150 calls in hour 13:00)

Caught 1 of 5 | seen but not named 1 | missed 3 | false alarms 1
```

The one catch is luck: the attacker tried to delete the diagnostic setting. The gateway volume rule (N1) can't see
S1 at all, because the key calls never touched the gateway. It sees S4 as one busy app server, and it pages on the
data science team's batch job.

## Step 3 · Old rules, new logs

```bash
make old-rules
```

Same as `python3 evaluate.py hardened --pack soc-v1`.

```output
Pack soc-v1 on hardened telemetry: 5 alerts

  S1  CAUGHT           Leaked CI secret and Foundry key   N2                       named contoso-foundry, sp-contoso-ci
  S2  MISSED           Jailbroken customer bot                                     
  S3  MISSED           Hijacked agent                                              
  S4  SEEN, NOT NAMED  Denial of wallet through the app   N1                       named 10.20.1.16
  S5  SEEN, NOT NAMED  Poisoned search index              N3                       named contoso-foundry
  false alarm: N1 High call volume at the gateway (10.20.1.17: 150 calls in hour 13:00)

Caught 1 of 5 | seen but not named 2 | missed 2 | false alarms 1
```

Defender for AI services raised eight alerts. The old rule N3 forwards High only, the same threshold Defender for
Cloud's email uses by default ("By default, subscription owners receive email notifications for high-severity alerts
and attack paths", [Microsoft](https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications)).
Two get through. The jailbreak (Medium), the wallet attacks (Medium) and the anomalous tool invocation (Low) don't.

## Step 4 · New rules, old logs

```bash
make old-logs
```

Same as `python3 evaluate.py first-draft`.

```output
Pack az16 on first-draft telemetry: 2 alerts

  S1  CAUGHT           Leaked CI secret and Foundry key   D01 D03                  named sp-contoso-ci
  S2  MISSED           Jailbroken customer bot                                     
  S3  MISSED           Hijacked agent                                              
  S4  MISSED           Denial of wallet through the app                            
  S5  MISSED           Poisoned search index                                       

Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 0
```

The Activity log is the only source with real content in the first draft, so the control-plane half of S1 is all
the new rules can see. What the key did next is in resource logs the first draft never sent.

## Step 5 · Both: this module's rules on lesson 16.1's logs

```bash
make detect
```

Same as `python3 detect.py hardened`, then `python3 evaluate.py hardened`.

```output
Pack az16 on hardened telemetry: 18 alerts

[MEDIUM] 09:15 D10 Answer links to an unknown domain
         entity domain: vpn-helpdesk-support.example.net   (5 answers)
[HIGH  ] 09:21 D04 Corrupted AI application\model\data directed a phishing attempt at a user
         entity end-user: cust-1104   (AI.Azure_MaliciousUrl.ModelResponse (High), count 1)
[HIGH  ] 10:40 D06 Repeated content-filter blocks for one end user
         entity end-user: cust-8841   (6 blocked calls)
[HIGH  ] 10:48 D07 System prompt canary in an answer
         entity end-user: cust-8841   (the answer contains CANARY-AZ16-SYSPROMPT)
[MEDIUM] 10:55 D04 A Jailbreak attempt on an Azure AI model deployment was blocked by Azure AI Content Safety Prompt Shields
         entity end-user: cust-8841   (AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt (Medium), count 6)
[LOW   ] 10:58 D04 (Preview) LLM Reconnaissance Attempt Detected
         entity end-user: cust-8841   (AI.Azure_LLMReconnaissance (Low), count 9)
[HIGH  ] 11:12 D03 Toolbox default version runs write tools without approval
         entity principal: sp-agent-deploy   (helpdesk-tools default_version=1 (agent-run-312))
[HIGH  ] 11:20 D08 Write tool ran without approval
         entity conversation: conv-7f3a5120   (send_email (toolbox v1), delete_ticket (toolbox v1))
[HIGH  ] 11:20 D09 Agent emailed outside the company
         entity conversation: conv-7f3a5120   (to=archive@ticket-export.example.net)
[LOW   ] 11:26 D04 Anomalous tool invocation
         entity resource: contoso-foundry   (AI.Azure_AnomalousToolInvocation (Low), count 2)
[HIGH  ] 14:05 D01 Workload identity used from an unknown address
         entity service-principal: sp-contoso-ci   (3 operations from ['203.0.113.50']: ACCOUNTS/READ, ACCOUNTS/LISTKEYS/ACTION, DIAGNOSTICSETTINGS/DELETE)
[HIGH  ] 14:07 D03 Defence change: DIAGNOSTICSETTINGS/DELETE
         entity principal: sp-contoso-ci   (status Failed)
[HIGH  ] 14:10 D02 Foundry calls that skip the gateway (keys in use?)
         entity resource-keys: contoso-foundry   (150 calls from ['203.0.113.50', '203.0.113.51']; the logs don't say which key: rotate both)
[HIGH  ] 14:24 D04 Access from suspicious IP
         entity resource: contoso-foundry   (AI.Azure_AccessFromSuspiciousIP (High), count 14)
[MEDIUM] 14:31 D04 Access anomaly in AI resource
         entity resource: contoso-foundry   (AI.Azure_AccessAnomaly (Medium), count 25)
[MEDIUM] 15:08 D04 Suspected wallet attack - volume anomaly
         entity resource: contoso-foundry   (AI.Azure_DOWVolumeAnomaly (Medium), count 87)
[MEDIUM] 16:00 D05 Model token spike
         entity apim-subscription: helpdesk-app   (2,829,467 tokens in hour 16:00 (113x the baseline of 25,000))
[MEDIUM] 16:36 D04 Suspected wallet attack - recurring requests
         entity resource: contoso-foundry   (AI.Azure_DOWDuplicateRequests (Medium), count 180)

python3 evaluate.py hardened
Pack az16 on hardened telemetry: 18 alerts

  S1  CAUGHT           Leaked CI secret and Foundry key   D01 D03                  named contoso-foundry, sp-contoso-ci
  S2  CAUGHT           Jailbroken customer bot            D04 D06 D07              named cust-8841
  S3  CAUGHT           Hijacked agent                     D08 D09                  named contoso-foundry, conv-7f3a5120, sp-agent-deploy
  S4  SEEN, NOT NAMED  Denial of wallet through the app   D04 D05                  named contoso-foundry, helpdesk-app
  S5  SEEN, NOT NAMED  Poisoned search index              D04 D10                  named cust-1104, vpn-helpdesk-support.example.net

Caught 3 of 5 | seen but not named 2 | missed 0 | false alarms 0
```

Read three things in that list:

- **Defender names the customer only because the app told it.** The jailbreak alert names `cust-8841` because the
  app sends `user_security_context` on every chat call. The wallet and key alerts name only the Foundry resource:
  nothing in a key call says who holds the key.
- **The phishing alert names a victim, not the attacker.** `cust-1104` received the bad link. The person to act on
  is whoever wrote the document, and that's in the blob log (challenge 1).
- **D05 names the app's gateway subscription.** One customer's 300 chats look like one busy app until you join the
  app log (challenge 2).

## Step 6 · The AI inventory (16.3)

```bash
make inventory
```

Same as `python3 inventory.py`.

```output
AI inventory: 10 AI assets

  sanctioned   Azure  microsoft.cognitiveservices/accounts           contoso-foundry                  owner: platform   (Resource Graph)
  sanctioned   Azure  microsoft.cognitiveservices/accounts/projects  contoso-foundry/helpdesk         owner: platform   (Resource Graph)
  sanctioned   Azure  microsoft.search/searchservices                contoso-search                   owner: platform   (Resource Graph)
  sanctioned   Azure  microsoft.apimanagement/service                contoso-apim                     owner: platform   (Resource Graph)
  sanctioned   Azure  microsoft.machinelearningservices/workspaces   mlw-research                     owner: data-science   (Resource Graph)
  UNSANCTIONED Azure  microsoft.cognitiveservices/accounts           mktg-hackathon-ai                owner: marketing   (Resource Graph)
  UNSANCTIONED Azure  microsoft.cognitiveservices/accounts           contoso-oai-legacy               owner: (no owner tag)   (Resource Graph)
  sanctioned   AWS    Amazon Bedrock                                 account 111122223333 us-east-1   owner: (connector owner)   (Defender CSPM AI-SPM)
  UNSANCTIONED GCP    Google Vertex AI                               project contoso-analytics        owner: (connector owner)   (Defender CSPM AI-SPM)
  UNSANCTIONED Azure  self-hosted model server (Ollama)              vm-gpu-lab01                     owner: data-science   (your NSG check)

Agents: 2 agent records not shown. From 1 July 2026 agent-level discovery needs a Microsoft Agent 365 licence;
  Defender CSPM still lists the Foundry accounts and projects. Not confirmed: helpdesk-agent (on the register).

Internet exposure AI-SPM reports: contoso-foundry, mktg-hackathon-ai, contoso-oai-legacy
Your check: vm-gpu-lab01 allows the internet to port 11434 (Ollama's default) in nsg-gpu-lab01/allow-ollama-demo. A model server on a VM isn't an AI service AI-SPM lists.

4 of 10 AI assets are not on the approved register.
```

"Unsanctioned" only means something because `data/inventory/sanctioned.json` exists. Without a register every row is
just a row.

## Step 7 · Posture: what Azure Policy can and can't tell you (16.4)

```bash
make posture
make posture-hardened
```

- `make posture`: same as `python3 posture.py first-draft`
- `make posture-hardened`: same as `python3 posture.py hardened`

```output
Posture of the first-draft setup

Built-in Azure Policy definitions (version in brackets)
  NON_COMPLIANT contoso-foundry    Azure AI Services resources should have key access disabled (disable local authentication) [1.1.0]  disableLocalAuth is not true
  NON_COMPLIANT mktg-hackathon-ai  Azure AI Services resources should have key access disabled (disable local authentication) [1.1.0]  disableLocalAuth is not true
  NON_COMPLIANT contoso-search     Azure AI Services resources should have key access disabled (disable local authentication) [1.1.0]  disableLocalAuth is not true
  NON_COMPLIANT contoso-foundry    Azure AI Services resources should restrict network access [3.3.0]  publicNetworkAccess Enabled and networkAcls.defaultAction Allow
  NON_COMPLIANT mktg-hackathon-ai  Azure AI Services resources should restrict network access [3.3.0]  publicNetworkAccess Enabled and networkAcls.defaultAction Allow
  NON_COMPLIANT contoso-search     Azure AI Services resources should restrict network access [3.3.0]  publicNetworkAccess Enabled and no IP rules
  NON_COMPLIANT contoso-foundry    Azure AI Services resources should use Azure Private Link [1.0.0]  no approved private endpoint connection
  NON_COMPLIANT mktg-hackathon-ai  Azure AI Services resources should use Azure Private Link [1.0.0]  no approved private endpoint connection
  NON_COMPLIANT contoso-search     Azure AI Services resources should use Azure Private Link [1.0.0]  no approved private endpoint connection
  NON_COMPLIANT contoso-foundry    Azure AI Services resources should encrypt data at rest with a customer-managed key (CMK) [2.2.0]  encryption.keySource Microsoft.CognitiveServices
  NON_COMPLIANT mktg-hackathon-ai  Azure AI Services resources should encrypt data at rest with a customer-managed key (CMK) [2.2.0]  encryption.keySource Microsoft.CognitiveServices
  Compliant     contoso-foundry    Diagnostic logs in Azure AI services resources should be enabled [1.0.0]  
  NON_COMPLIANT mktg-hackathon-ai  Diagnostic logs in Azure AI services resources should be enabled [1.0.0]  no diagnostic setting with logs
  NON_COMPLIANT contoso-search     Diagnostic logs in Azure AI services resources should be enabled [1.0.0]  no diagnostic setting with logs

Custom checks (no built-in policy: you write these)
  NON_COMPLIANT C01 Foundry diagnostic setting sends Audit, RequestResponse and Trace to a workspace  contoso-foundry sends no RequestResponse, Trace; mktg-hackathon-ai sends no Audit, RequestResponse, Trace
  NON_COMPLIANT C02 Defender for AI services on, with user prompt evidence  Defender for Cloud plan AI (AI services) is not Standard: no AI threat alerts at all
  NON_COMPLIANT C03 API Management LLM logging on for every LLM API  no LLM logging on contoso-apim/helpdesk-openai
  NON_COMPLIANT C04 Tracing to Application Insights for every project with agents  agents without tracing in contoso-foundry/helpdesk
  NON_COMPLIANT C05 Write tools in the toolbox's default version need approval and an allow-list  helpdesk-tools v1 server actions: require_approval never, allowed_tools None

18 NON_COMPLIANT of 19 evaluations
```

The hardened setup ends with `0 NON_COMPLIANT of 14 evaluations` (the hackathon resource was moved to the paved road,
so it's gone). The one green line in the first draft is the lesson: `contoso-foundry` has a diagnostic setting that
sends `Audit` only. The built-in is AuditIfNotExists and checks that a setting with logs exists, not which ones, so
it passes while the logs S1 needed were never collected. C01 catches it.

## Step 8 · From alert to report (16.5)

Pivot on what an alert named. A key carries no identity, so pivot on the addresses as well:

```bash
make pivot
make pivot ENTITY=203.0.113.50
python3 report.py pivot 203.0.113.50 --setup first-draft
make cost
```

- `make pivot`: same as `python3 report.py pivot sp-contoso-ci`
- `make cost`: same as `python3 report.py cost`

```output
2026-10-20T08:30:00Z  activity aaadd6b8-55c6-462b-909e-04924d52bc61  ACCOUNTS/LISTKEYS/ACTION Succeeded by sp-contoso-ci from 10.20.1.30
2026-10-20T08:31:00Z  activity 9a23bef7-be50-4564-b3a1-60712456de76  ACCOUNTS/DEPLOYMENTS/WRITE Succeeded by sp-contoso-ci from 10.20.1.30
2026-10-20T14:05:00Z  activity 11d16259-3c55-4d82-a846-1d3b94fc98b9  ACCOUNTS/READ Succeeded by sp-contoso-ci from 203.0.113.50
2026-10-20T14:06:00Z  activity 836cccf1-faed-4d69-ab88-be116d067e5f  ACCOUNTS/LISTKEYS/ACTION Succeeded by sp-contoso-ci from 203.0.113.50
2026-10-20T14:07:00Z  activity 43293139-c408-4f80-b008-46a2864fc124  DIAGNOSTICSETTINGS/DELETE Failed by sp-contoso-ci from 203.0.113.50

5 records mention sp-contoso-ci in the hardened telemetry
```

```output
79 records mention 203.0.113.50 in the hardened telemetry
3 records mention 203.0.113.50 in the first-draft telemetry
```

```output
  14:00  metric   947,712  LLM log    25,284  not in the LLM log   922,428
  15:00  metric   755,690  LLM log    21,772  not in the LLM log   733,918

1,656,346 tokens reached the model without passing the gateway: $0.66 to $2.65 at the lab's ILLUSTRATIVE prices (contoso.json), not Microsoft's.
```

The pivot on the service principal stops at 14:07: the 150 key calls that follow carry an address, not a name. The
Foundry `TotalTokens` metric counts every call; the gateway's LLM log counts only the calls that went through the
gateway. The difference is the attacker's traffic. Then read `report/EXAMPLE-S3-hijacked-agent.md` and check it:

```bash
python3 report.py check report/EXAMPLE-S3-hijacked-agent.md --scenario S3
```

```output
EXAMPLE-S3-hijacked-agent.md: REPORT COMPLETE
```

## Step 9 · Prove it

```bash
make test
```

Same as `python3 run_tests.py`.

```output
[PASS] the simulator is deterministic: the same day on every computer
[PASS] first draft: Activity log and gateway log only; no prompts, no Defender alerts, no traces, no user IDs
[PASS] hardened: 150 Foundry calls come from outside addresses and have no gateway or LLM log row
[PASS] Defender alerts: types and severities as Microsoft lists them; only two of eight are High
[PASS] LLM log: one request row per call, a response row only when the call wasn't blocked; joins on CorrelationId
[PASS] old rules, old logs: 1 of 5 caught (the diagnostic-delete rule), 1 false alarm (the data science batch)
[PASS] old rules, new logs: the High-only Defender rule passes 2 of 8 AI alerts and catches nothing new
[PASS] new rules, old logs: only S1 is caught (Activity log); everything else is missed
[PASS] new rules, new logs: S1, S2, S3 caught; S4 and S5 seen but not named (the challenge); 0 false alarms
[PASS] with user security context, the Defender jailbreak alert names cust-8841; without it, only the resource
[PASS] without the app log's user ID, D06 and D07 name nobody: S2 drops to seen, not named (no user context either)
[PASS] D02 (calls that skip the gateway) fires only with the Foundry RequestResponse logs on
[PASS] inventory: 10 AI assets, 4 not on the register, 2 agents hidden without Agent 365, Ollama open on a VM
[PASS] posture: 18 of 19 NON_COMPLIANT in the first draft, 0 hardened; the diagnostic built-in is green while broken
[PASS] the worked S3 report passes the check; the empty template does not
[PASS] pivot: 5 records name sp-contoso-ci; the attacker address is in 79 records hardened, 3 in the first draft
[PASS] cost: the Foundry metric counts 1,656,346 tokens the gateway's LLM log never saw (the direct key calls)
[PASS] the rules never read the answer key (truth.json)
----------------------------------------------------------------------
Ran 18 tests in 0.140s

OK

ALL TESTS PASSED (18 run)
```

## Challenge (no solution included)

```bash
make challenge
```

Same as `python3 run_tests.py --challenge`.

```output
[FAIL] challenge 1: D11 names carol@contoso.com, so S5 is CAUGHT
[FAIL] challenge 1: D11 alerts, but never on the nightly knowledge base publisher
[FAIL] challenge 2: D12 names cust-2290, so S4 is CAUGHT
[FAIL] challenge 2: D12 alerts on exactly one end user (no normal customer)
[FAIL] with your rules: 5 of 5 caught on the hardened telemetry, 0 false alarms
[FAIL] challenge 3: report/INCIDENT-REPORT.md for S1 passes the check

6 of 24 TESTS FAILED (24 run)
```

1. **D11, search index poisoning** (16.4, 16.5). In `detect.py`, write `d11_kb_source_write`: an alert when anyone
   other than the knowledge base publisher writes a blob into the knowledge base container (`StorageBlobLogs`,
   `PutBlob`). Name the writer (`RequesterUpn`). The nightly publish must stay quiet.
2. **D12, denial of wallet per end user** (16.1, 16.5). Write `d12_wallet_per_end_user`: one end user above
   `tokens_per_end_user_per_hour` in any hour, from the app log. Defender and D05 can only name the resource or the
   app's gateway subscription; you can name the user.
3. **The S1 incident report** (16.5). `cp report/TEMPLATE.md report/INCIDENT-REPORT.md`, write it from the pivots,
   `make cost` and the playbook in lesson 16.5, then `make report-check`. The check wants every section, five UTC
   timestamps, three real record IDs and the facts a reviewer would ask for: both attacker addresses, the listKeys
   call, regenerating both keys, resetting the service principal's secret, switching key access off, the failed
   diagnostic-setting delete, that the calls skipped the gateway, the cost, and how the secret leaked.

When you're done: `Caught 5 of 5 | seen but not named 0 | missed 0 | false alarms 0`, and `ALL TESTS PASSED (24 run)`.

## Step 10 · Your own subscription (optional)

[`GUIDED-BUILD.md`](GUIDED-BUILD.md): a small Foundry resource that logs, Defender for AI services with prompt
evidence (30-day trial), alerts exported to Log Analytics, four requests with `user_security_context`, Prompt Shields
switched from block to annotate and the same request again, an alert rule for every AI alert, two hunts, the
Resource Graph inventory, and teardown. Cents, if you turn the plan off the same day.

## Troubleshooting

- `no telemetry in out/hardened/`: run `make simulate` (or `python3 simulate.py`) first. `make test` doesn't need it.
- Numbers differ from this page after you changed `simulate.py` or `contoso.json`: `git checkout` them; the tests
  pin the shipped day.
- Windows: `py simulate.py`, `py evaluate.py hardened`, `py run_tests.py`, and so on.
