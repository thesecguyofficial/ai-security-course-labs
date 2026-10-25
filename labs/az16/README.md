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

## What's in this folder

| File | What it is |
|---|---|
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

## Step 1 · The day of the five incidents

```bash
make setup
make simulate                 # python3 simulate.py
python3 simulate.py --list    # the five stories
```

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
make old                      # python3 evaluate.py first-draft --pack soc-v1
```

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
make old-rules                # python3 evaluate.py hardened --pack soc-v1
```

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
make old-logs                 # python3 evaluate.py first-draft
```

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
make detect                   # python3 detect.py hardened, then python3 evaluate.py hardened
```

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
make inventory                # python3 inventory.py
```

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
make posture                  # python3 posture.py first-draft
make posture-hardened         # python3 posture.py hardened
```

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
make pivot                                   # python3 report.py pivot sp-contoso-ci
make pivot ENTITY=203.0.113.50
python3 report.py pivot 203.0.113.50 --setup first-draft
make cost                                    # python3 report.py cost
```

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
make test                    # python3 run_tests.py
```

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
make challenge               # python3 run_tests.py --challenge
```

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
