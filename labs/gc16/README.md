# Lab GC16: build the detections, run the attack simulator, catch it, write the incident report

Companion to lessons **16.0 to 16.6** of the Google Cloud stream of *AI Security Engineer* (The Sec Guy). About 75
minutes for Steps 1 to 9, **$0**, all on your laptop: **Python 3.11+ only**, no packages, no Google Cloud account, no
network. Step 10 is optional: [`GUIDED-BUILD.md`](GUIDED-BUILD.md) turns on Data Access audit logs, Model Armor
logging and three alerts in **your own** sandbox project, and ends with teardown.

You are the cloud security engineer at **ExampleCo** (fictional, on the documentation domain example.com). Over
Modules 10 to 14 the company built a customer support bot on Gemini in Agent Platform (formerly Vertex AI), a staff
Helpdesk agent on Agent Runtime behind Agent Gateway, and a RAG corpus in RAG Engine. On **20 October 2026** five
things went wrong on the same day. The SOC caught one of them. Your job: find out why, build the detections and the
logging that catch all five, and write the incident report for the expensive one.

| Part | What you do | Lesson |
|---|---|---|
| **Simulate** | One day of telemetry, normal work plus five incidents, for two logging setups | 16.0, 16.1 |
| **Old SOC** | The SOC's three rules on the old logs: 1 of 5 caught | 16.0, 16.2 |
| **Old rules, new logs** | Still 1 of 5, plus a false alarm: a "HIGH and CRITICAL" SCC filter drops both AI findings | 16.2 |
| **New rules, old logs** | 1 of 5: you can't detect what you didn't log | 16.1 |
| **Both** | 13 rules (D01 to D13) on the new logs: 3 of 5 caught and named, 2 seen but not named, 0 false alarms | 16.2, 16.4 |
| **Inventory** | What SCC's AI inventory lists, the register diff, and the two checks it leaves to you | 16.3 |
| **Posture** | Four framework controls, six custom checks and two organization policies | 16.3, 16.4 |
| **Report** | Pivot on an entity, estimate the cost, read a worked incident report | 16.5 |
| **Prove** | `make test`: 18 tests | 16.6 |
| **Challenge** | Two detections and your own incident report. No solution included | 16.4, 16.5 |
| **Cloud (optional)** | [`GUIDED-BUILD.md`](GUIDED-BUILD.md): console and gcloud from zero, four requests, one setting changed, cost, teardown | 16.1 to 16.4 |

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
cd labs/gc16
```

## What's in this folder

| File | What it is |
|---|---|
| `simulate.py` | The **attack simulator**: 20 Oct 2026 at ExampleCo, normal work plus five incidents (S1 to S5), written as the files each logging setup would really collect. It replays a made-up day; it never calls Google Cloud |
| `setups/first-draft.json`, `setups/hardened.json` | What each setup collects. First draft: Google Cloud's defaults (Admin Activity, BigQuery Data Access) plus a log exclusion and a plain web log. Hardened: lesson 16.1's list |
| `detect.py` | Two rule packs: `soc-v1` (three rules a SOC often starts with) and `gc16` (D01 to D13). D11 and D12 are your challenge |
| `evaluate.py` | Scores a pack against the five incidents: CAUGHT (an alert names who to act on), SEEN, NOT NAMED, MISSED, and false alarms |
| `inventory.py`, `data/inventory/` | An AI inventory like SCC AI Protection's, an approved-AI register, Cloud DNS logs and firewall rules |
| `posture.py`, `data/posture/` | Settings checks: framework controls (names exactly as Google lists them), custom checks, organization policies |
| `report.py`, `report/` | Pivot, cost, and the incident report check; `TEMPLATE.md` and a worked example for S3 |
| `queries/` | The same rules as Logs Explorer and BigQuery queries, for your own project |
| `cloud/` | Alert policies, a log-based metric filter and an audit config block for the guided build |
| `exampleco.json`, `data/baselines.json` | The company's facts: approved principals, known addresses, the RAG pipeline, token baselines, tuning |

What the telemetry files are, and how close they are to the real thing:

| File | Real source | Field names |
|---|---|---|
| `audit.jsonl` | Cloud Audit Logs (Admin Activity always; Data Access only where enabled) | `protoPayload` as Google documents the `AuditLog` type. Inference `methodName`s come from Google's API definitions: the audit logging page doesn't list `GenerateContent` |
| `requests.jsonl` | Request-response logging (Preview) rows in BigQuery | The table's documented columns (`logging_time`, `request_id`, `model`, `api_method`, `full_request`, `full_response`, ...) |
| `armor.jsonl` | Model Armor sanitize operation logs | `SanitizeOperationLogEntry`, `sanitizationResult`, `filterResults`. Fields starting `lab.` are the lab's own |
| `scc.jsonl` | Security Command Center threat findings (Event Threat Detection) | The fields in Google's example findings (`category`, `severity`, `access`, `sourceProperties.detectionCategory.ruleName`, `evidence`) |
| `gateway.jsonl` | Agent Gateway request logs | `httpRequest`, `trace`, `jsonPayload.mcpInfo`. The policy verdict and mode are `lab.` fields: in a real project a dry-run denial is an IAP entry in Cloud Audit Logs, joined to the request by time and trace |
| `app.jsonl` | Your web app's own log | Yours to design (lesson 16.1) |

## Needs

- Python 3.11 or newer. Check with `make setup` (or `python3 ../../tools/check_python.py 3.11`).
- `make` (Mac/Linux). On Windows run the `python` commands shown under each step.

## Step 1 · The day of the five incidents

```bash
python3 simulate.py --list
python3 simulate.py
```

- `python3 simulate.py`: make simulate

```output
S1  Leaked service account key (LLMjacking)
    A key for the etl-batch service account leaked from a CI log. From 14:05 someone outside the company uses it: three failed model probes, failed attempts to switch off Data Access audit logs and request-response logging, then 120 Gemini calls and 30 Claude calls on ExampleCo's bill.

S2  Jailbroken customer bot
    A signed-in customer spends 12 minutes trying to jailbreak the support bot. Model Armor blocks six attempts at HIGH confidence; one gets through and the answer contains the system prompt's canary.

S3  Hijacked agent
    A rollback pipeline puts the agent gateway's IAP authorization back in DRY_RUN. Eight minutes later a hidden instruction in ticket 5120 makes the agent email ticket data outside the company and reset the CEO's MFA. The access policy said DENY both times; dry run only logged it.

S4  Denial of wallet through the app
    A scripted sign-up account sends 300 maximum-length chats in 50 minutes. Every call is made by the app's own service account, so Google Cloud sees one busy app, not one abusive user.

S5  Poisoned RAG corpus
    At 03:10 a contractor, acting as the contractor-upload service account, writes a fake 'VPN support update' into the RAG source bucket and imports it into the corpus. From 09:15 the support bot sends customers to an outside 'VPN support line'.
```

```output
first-draft  audit 9  requests 0  armor 0  scc 0  gateway 0  app 585   -> out/first-draft/
hardened     audit 903  requests 705  armor 554  scc 2  gateway 33  app 585   -> out/hardened/
```

Look at the first-draft line: no request-response rows, no Model Armor log, no SCC findings, no gateway log. The 9
audit entries are what Google Cloud keeps by default: Admin Activity (always on) and BigQuery's Data Access entries
(on by default for some BigQuery services).

## Step 2 · The SOC's old rules on the old logs

```bash
make old
```

Same as `python3 evaluate.py first-draft --pack soc-v1`.

```output
Pack soc-v1 on first-draft telemetry: 1 alerts

  S1  CAUGHT           Leaked service account key (LLMjacking)  N2                       named etl-batch
  S2  MISSED           Jailbroken customer bot                                           
  S3  MISSED           Hijacked agent                                                    
  S4  MISSED           Denial of wallet through the app                                  
  S5  MISSED           Poisoned RAG corpus                                               

Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 0
```

The one catch comes from Admin Activity, which Google always writes: the attacker tried to remove the Data Access
audit config with `SetIamPolicy` and was denied. The volume rule counts `Predict` only, and the Data Access logs that
would hold the attacker's `GenerateContent` calls were never switched on.

## Step 3 · Old rules, new logs

```bash
make old-rules
```

Same as `python3 evaluate.py hardened --pack soc-v1`.

```output
Pack soc-v1 on hardened telemetry: 2 alerts

  S1  CAUGHT           Leaked service account key (LLMjacking)  N2                       named etl-batch
  S2  MISSED           Jailbroken customer bot                                           
  S3  MISSED           Hijacked agent                                                    
  S4  MISSED           Denial of wallet through the app                                  
  S5  MISSED           Poisoned RAG corpus                                               
  false alarm: N1 High Predict volume (ds-batch: 150 Predict calls in hour 13:00)

Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 1
```

Two SCC findings arrive ("New AI API Method" and "New Geography for AI Service"), both `LOW`, as in Google's example
findings. The old SCC rule forwards `HIGH` and `CRITICAL` only, so neither reaches a person. Meanwhile the volume rule,
now that Data Access logs exist, pages on the data science team's evaluation batch.

## Step 4 · New rules, old logs

```bash
make old-logs
```

Same as `python3 evaluate.py first-draft`.

```output
Pack gc16 on first-draft telemetry: 4 alerts

  S1  CAUGHT           Leaked service account key (LLMjacking)  D01 D03                  named etl-batch
  S2  MISSED           Jailbroken customer bot                                           
  S3  SEEN, NOT NAMED  Hijacked agent                           D03                      named ci-deployer
  S4  MISSED           Denial of wallet through the app                                  
  S5  MISSED           Poisoned RAG corpus                                               

Caught 1 of 5 | seen but not named 1 | missed 3 | false alarms 0
```

The authorization extension change is Admin Activity, so D03 sees the gateway go to `DRY_RUN` and names the pipeline
that did it. What the agent did next is in gateway logs the first draft excluded.

## Step 5 · Both: this module's rules on lesson 16.1's logs

```bash
make detect
```

Same as `python3 detect.py hardened`, then `python3 evaluate.py hardened`.

```output
Pack gc16 on hardened telemetry: 16 alerts

[MEDIUM] 09:15 D13 Answer links to an unknown domain
         entity domain: vpn-helpdesk-support.example.net   (5 answers)
[HIGH  ] 10:40 D07 Repeated blocked prompts from one end user
         entity end-user: cust-8841   (6 Model Armor blocks)
[HIGH  ] 10:48 D08 System prompt canary in an answer
         entity end-user: cust-8841   (the answer contains CANARY-GC16-SYSPROMPT)
[HIGH  ] 11:12 D03 Gateway authorization set to DRY_RUN
         entity principal: ci-deployer   (helpdesk-iap iamEnforcementMode=DRY_RUN)
[HIGH  ] 11:20 D09 Tool call denied by policy but executed (DRY_RUN)
         entity agent-session: 7351126042550190080   (send_email, reset_mfa)
[HIGH  ] 11:20 D10 Agent emailed outside the company
         entity agent-session: 7351126042550190080   (to=archive@ticket-export.example.net; executed=True)
[MEDIUM] 14:00 D06 Model token spike
         entity model: gemini-3.5-flash   (733,572 tokens in hour 14:00 (no baseline))
[HIGH  ] 14:05 D01 Service account key used from an unknown address
         entity service-account: etl-batch   (155 calls from ['203.0.113.50', '203.0.113.51'])
[MEDIUM] 14:05 D02 Failed AI calls (probing)
         entity principal: etl-batch   (GenerateContent 3, RawPredict 7, GenerateContent 5, SetPublisherModelConfig 7)
[HIGH  ] 14:05 D04 Model inference by an unapproved principal
         entity principal: etl-batch   (153 calls; methods ['GenerateContent', 'RawPredict', 'StreamGenerateContent'])
[HIGH  ] 14:07 D03 Defence change: SetIamPolicy
         entity principal: etl-batch   (status code 7)
[HIGH  ] 14:08 D03 Defence change: SetPublisherModelConfig
         entity principal: etl-batch   (status code 7)
[HIGH  ] 14:08 D05 Persistence: New AI API Method
         entity principal: etl-batch   (severity LOW, rule ai_anomalous_behavior_new_api_method; the Google identity, not the end user)
[HIGH  ] 14:12 D05 Persistence: New Geography for AI Service
         entity principal: etl-batch   (severity LOW, rule ai_iam_anomalous_behavior_ip_geolocation; the Google identity, not the end user)
[MEDIUM] 15:00 D06 Model token spike
         entity model: gemini-3.5-flash   (589,959 tokens in hour 15:00 (no baseline))
[MEDIUM] 16:00 D06 Model token spike
         entity model: gemini-3.1-flash-lite   (2,831,760 tokens in hour 16:00 (113x the baseline of 25,000))

Pack gc16 on hardened telemetry: 16 alerts

  S1  CAUGHT           Leaked service account key (LLMjacking)  D01 D02 D03 D04 D05      named etl-batch, gemini-3.5-flash
  S2  CAUGHT           Jailbroken customer bot                  D07 D08                  named cust-8841
  S3  CAUGHT           Hijacked agent                           D09 D10                  named 7351126042550190080, ci-deployer
  S4  SEEN, NOT NAMED  Denial of wallet through the app         D06                      named gemini-3.1-flash-lite
  S5  SEEN, NOT NAMED  Poisoned RAG corpus                      D13                      named vpn-helpdesk-support.example.net

Caught 3 of 5 | seen but not named 2 | missed 0 | false alarms 0
```

Read three things. D05 forwards both SCC findings whatever their severity. D07 names `cust-8841` because the backend
put `end_user` in the request's `labels`; Model Armor and SCC never see the customer. And D06 can only name a model:
request-response rows don't carry the caller, which is why S4 is SEEN, NOT NAMED until you write D12.

## Step 6 · The AI inventory (16.3)

```bash
make inventory
```

Same as `python3 inventory.py` (try: `python3 inventory.py --tier standard`).

```output
AI inventory (SCC Premium): 14 AI assets

  sanctioned   Model          publishers/google/models/gemini-3.1-flash-lite  [example-chatbot-prod, owner: support-platform]
  sanctioned   Model          publishers/google/models/gemini-3.5-flash  [example-chatbot-prod, owner: support-platform]
  sanctioned   Model          publishers/anthropic/models/claude-opus-4-7  [example-chatbot-prod, owner: support-platform]
  sanctioned   Endpoint       endpoints/ticket-classifier  [example-chatbot-prod, owner: data-science]
  sanctioned   Data source    datasets/tickets-2025  [example-chatbot-prod, owner: data-science]
  sanctioned   Data source    ragCorpora/2305843009213693952 (helpdesk-kb)  [example-chatbot-prod, owner: it-support]
  sanctioned   Agent          reasoningEngines/4815162342 (Helpdesk agent)  [example-chatbot-prod, owner: it-support]
  sanctioned   MCP server     mcpServers/tickets-mcp  [example-chatbot-prod, owner: it-support]
  UNSANCTIONED Agent          reasoningEngines/9988776655 (hackathon lead-finder)  [example-marketing-sandbox, owner: (no owner label)]
  UNSANCTIONED App            Gemini Enterprise app sales-assistant  [example-sales, owner: sales-ops]
  UNSANCTIONED MCP server     mcpServers/crm-export-mcp  [example-marketing-sandbox, owner: (no owner label)]
  UNSANCTIONED Model          publishers/google/models/gemini-3.5-pro  [example-marketing-sandbox, owner: (no owner label)]
  UNSANCTIONED Model          models/llama-3-8b-ft (Model Registry)  [example-ds-lab, owner: data-science]
  UNSANCTIONED Outside AI API api.openai.com from build-runner-2  [example-ci, owner: ?]
Finding: Gemini model not protected by Model Armor: publishers/google/models/gemini-3.5-flash in example-chatbot-prod
Finding: Gemini model not protected by Model Armor: publishers/google/models/gemini-3.5-pro in example-marketing-sandbox
Not attributed: 2 DNS queries to api.anthropic.com from 10.20.8.14 in example-marketing-sandbox, with no vmInstanceName (not a Compute Engine VM). Find the owner of that address yourself (GKE pod, Cloud Run, a connector).
Your check: firewall rule allow-ollama-any allows 0.0.0.0/0 to port 11434 (ollama) on gpu-box-1 in example-ds-lab. Software on your own VMs isn't in the AI inventory.

6 of 14 AI assets are not on the approved register.
```

## Step 7 · Posture: framework controls, custom checks, organization policies (16.3, 16.4)

```bash
make posture
make posture-hardened
```

- `make posture`: same as `python3 posture.py first-draft`
- `make posture-hardened`: same as `python3 posture.py hardened`

```output
Posture of the first-draft setup

Framework controls (Google Recommended AI Essentials; lab reading of each control)
  COMPLIANT     Enable Model Armor
  NON_COMPLIANT Enable CMEK for Agent Platform Model Endpoints
                no CMEK on endpoint ticket-classifier
  NON_COMPLIANT Block Public IP Address for Agent Platform Workbench Instances
                public IP on ds-notebook-1
  COMPLIANT     Use labels for Agent Platform agents

Custom checks (no framework control covers these: you write them)
  NON_COMPLIANT C01 Data Access audit logs (DATA_READ, DATA_WRITE) for Agent Platform set at the organization
                aiplatform.googleapis.com missing DATA_READ, DATA_WRITE at the organization (off by default)
  NON_COMPLIANT C02 SCC Premium activated at the organization (Event Threat Detection AI rules)
                SCC STANDARD: no Event Threat Detection AI rules
  NON_COMPLIANT C03 Model Armor sanitize operations logged (template and floor setting)
                logSanitizeOperations off on helpdesk-guard; floor setting Cloud Logging off
  NON_COMPLIANT C04 Request-response logging at sampling rate 1 for every model in use
                request-response logging off or sampled for claude-opus-4-7, gemini-3.1-flash-lite, gemini-3.5-flash
  NON_COMPLIANT C05 Every IAP authorization extension enforces (no iamEnforcementMode DRY_RUN)
                iamEnforcementMode DRY_RUN on helpdesk-iap
  NON_COMPLIANT C06 No log exclusion drops gateway, Data Access or Model Armor logs
                exclusion drops evidence: _Default/drop-gateway-requests

Organization policies (preventive, lesson 16.4)
  NON_COMPLIANT P01 vertexai.allowedModels: an allow-list of models
                vertexai.allowedModels not set: any model, any publisher
  NON_COMPLIANT P02 iam.disableServiceAccountKeyCreation (legacy or managed): no new service account keys
                not enforced (organization created 2021-03-02: before 3 May 2024 it isn't enforced by default)

10 NON_COMPLIANT of 12 checks
```

"Enable Model Armor" passes while Model Armor writes nothing to Cloud Logging, the gateway runs in `DRY_RUN` and the
gateway's logs are excluded. None of the framework's 29 control names covers those settings, so they're yours to
check. The hardened setup still fails C04: request-response logging for Claude needs its own REST call, and nobody
made it. Step 8 shows what that costs you.

```output
Posture of the hardened setup

Framework controls (Google Recommended AI Essentials; lab reading of each control)
  COMPLIANT     Enable Model Armor
  COMPLIANT     Enable CMEK for Agent Platform Model Endpoints
  COMPLIANT     Block Public IP Address for Agent Platform Workbench Instances
  COMPLIANT     Use labels for Agent Platform agents

Custom checks (no framework control covers these: you write them)
  COMPLIANT     C01 Data Access audit logs (DATA_READ, DATA_WRITE) for Agent Platform set at the organization
  COMPLIANT     C02 SCC Premium activated at the organization (Event Threat Detection AI rules)
  COMPLIANT     C03 Model Armor sanitize operations logged (template and floor setting)
  NON_COMPLIANT C04 Request-response logging at sampling rate 1 for every model in use
                request-response logging off or sampled for claude-opus-4-7
  COMPLIANT     C05 Every IAP authorization extension enforces (no iamEnforcementMode DRY_RUN)
  COMPLIANT     C06 No log exclusion drops gateway, Data Access or Model Armor logs

Organization policies (preventive, lesson 16.4)
  COMPLIANT     P01 vertexai.allowedModels: an allow-list of models
  COMPLIANT     P02 iam.disableServiceAccountKeyCreation (legacy or managed): no new service account keys

1 NON_COMPLIANT of 12 checks
```

## Step 8 · From alert to report (16.5)

Pivot on the entity an alert named:

```bash
make pivot
python3 report.py pivot etl-batch --setup first-draft
python3 report.py cost etl-batch
```

- `make pivot`: same as `python3 report.py pivot etl-batch`

```output
2026-10-20T02:30:00Z  audit    daa868d605d4                      bigquery InsertJob from 10.20.1.20
2026-10-20T02:30:15Z  audit    b604a85f68b6                      bigquery InsertJob from 10.20.1.20
2026-10-20T02:30:30Z  audit    3ce4424458b6                      bigquery InsertJob from 10.20.1.20
2026-10-20T02:30:45Z  audit    38f1a28f17d8                      bigquery InsertJob from 10.20.1.20
2026-10-20T14:05:00Z  audit    d554d2f7c9ea                      aiplatform GenerateContent status 3 from 203.0.113.50
2026-10-20T14:05:30Z  audit    3d06fbfa4800                      aiplatform RawPredict status 7 from 203.0.113.50
2026-10-20T14:06:00Z  audit    2a32bae1c332                      aiplatform GenerateContent status 5 from 203.0.113.50
2026-10-20T14:07:00Z  audit    231b5c67846a                      cloudresourcemanager SetIamPolicy status 7 from 203.0.113.50
2026-10-20T14:08:00Z  audit    9100691ed45a                      aiplatform SetPublisherModelConfig status 7 from 203.0.113.50
2026-10-20T14:08:00Z  scc      ca7188f45ab239128bf1e90e5e819537  Persistence: New AI API Method severity LOW
2026-10-20T14:10:00Z  audit    d45636344632                      aiplatform GenerateContent from 203.0.113.51
2026-10-20T14:10:00Z  request  295917249279596887                generateContent gemini-3.5-flash tokens=9905 end=STOP
...
2026-10-20T15:39:15Z  request  1200645806089075545               streamGenerateContent gemini-3.5-flash tokens=11290 end=STOP

281 records mention etl-batch in the hardened telemetry
```

```output
2026-10-20T02:30:00Z  audit    781e5c8cc1ab                      bigquery InsertJob from 10.20.1.20
2026-10-20T02:30:15Z  audit    48f17b00c7f4                      bigquery InsertJob from 10.20.1.20
2026-10-20T02:30:30Z  audit    3a056abd685a                      bigquery InsertJob from 10.20.1.20
2026-10-20T02:30:45Z  audit    017f725ed09d                      bigquery InsertJob from 10.20.1.20
2026-10-20T14:07:00Z  audit    07dc149be7ed                      cloudresourcemanager SetIamPolicy status 7 from 203.0.113.50
2026-10-20T14:08:00Z  audit    9247087ca913                      aiplatform SetPublisherModelConfig status 7 from 203.0.113.50

6 records mention etl-batch in the first-draft telemetry
```

```output
{
 "calls": 120,
 "input_tokens": 902834,
 "output_tokens": 420697,
 "usd_lab_prices": 6.85,
 "claude_calls_not_in_request_response_logs": 30
}
usd_lab_prices uses the ILLUSTRATIVE price list in exampleco.json, not Google's prices.
```

With lesson 16.1's logging the pivot gives you 281 records; with the first draft, 6. The cost covers the 120 Gemini
calls in the request-response table. The 30 Claude calls are only in the audit log: you know they happened, not what
they cost or said.

Then read the worked example and check it:

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
[PASS] first draft: Admin Activity plus BigQuery Data Access only; no prompts, no Model Armor logs, no SCC
[PASS] hardened: Data Access for Agent Platform and the RAG bucket; request-response rows for Gemini only
[PASS] SCC: two Event Threat Detection AI findings, both LOW (as in Google's example findings), with evidence
[PASS] New Geography for AI Service isn't available for project-level activations: one finding fewer
[PASS] one harmless message blocked once by Model Armor makes no alert (D07 needs three in ten minutes)
[PASS] old rules, old logs: 1 of 5 caught (the audit config change, Admin Activity is always on)
[PASS] old rules, new logs: still 1 of 5; the HIGH-and-CRITICAL SCC rule drops both LOW findings, and the
[PASS] new rules, old logs: only S1 is caught (Admin Activity); S3 is seen but not named
[PASS] new rules, new logs: S1, S2, S3 caught; S4 and S5 seen but not named (the challenge); 0 false alarms
[PASS] request-response rows carry no caller: the token rule can only name the model
[PASS] without labels.end_user on the requests, S2 is seen but nobody is named
[PASS] the gateway exclusion: without gateway request logs S3 drops to SEEN, NOT NAMED
[PASS] inventory: 14 AI assets, 6 unsanctioned, 2 Gemini models without Model Armor, one DNS source not
[PASS] posture: 10 of 12 NON_COMPLIANT on the first draft, 1 hardened (Claude's logging); Enable Model Armor
[PASS] the worked S3 report passes the check; the empty template does not
[PASS] pivot on etl-batch: 281 records hardened, 6 first draft; 120 Gemini calls costed, 30 Claude calls that
[PASS] the rules never read the answer key (truth.json)
ALL TESTS PASSED (18 run)
```

## Challenge (no solution included)

```bash
make challenge
```

You should see:

```text
6 of 24 TESTS FAILED (24 run)
```

They fail until you finish.

```output
[FAIL] challenge 1: D11 names contractor-upload, so S5 is CAUGHT
[FAIL] challenge 1: D11 alerts, but never on the nightly RAG pipeline
[FAIL] challenge 2: D12 names cust-2290, so S4 is CAUGHT
[FAIL] challenge 2: D12 alerts on exactly one end user (no normal customer)
[FAIL] with your rules: 5 of 5 caught on the hardened telemetry, 0 false alarms
[FAIL] challenge 3: report/INCIDENT-REPORT.md for S1 passes the check
  why test_c1_rag_poisoning_named: AssertionError: 'contractor-upload' not found in []
  why test_c2_rag_pipeline_quiet: AssertionError: [] is not true : D11 returns no alerts yet
  why test_c3_wallet_named: AssertionError: 'cust-2290' not found in []
  why test_c4_wallet_quiet: + ['cust-2290']
  why test_c5_all_five: ?        ^                           ^
  why test_c6_report: AssertionError: False is not true : write report/INCIDENT-REPORT.md (cp report/TEMPLATE.md report/INCIDENT-REPORT.md)
6 of 24 TESTS FAILED (24 run)
```

1. **D11, RAG corpus poisoning** (16.4, 16.5). In `detect.py`, write `d11_rag_source_write`: an alert when anyone
   other than the RAG pipeline writes into the corpus's source bucket (`storage.objects.create`) or imports files
   into the corpus (`ImportRagFiles`). Name the principal. The nightly pipeline must stay quiet.
   `queries/d11-rag-source-writes.txt` is the Logs Explorer version.
2. **D12, denial of wallet per end user** (16.1, 16.5). Write `d12_wallet_per_end_user`: one end user above
   `tokens_per_end_user_per_hour` in any hour. SCC and D06 can't name the person; the request labels and your app
   log can.
3. **The S1 incident report** (16.5). `cp report/TEMPLATE.md report/INCIDENT-REPORT.md`, write it from the pivot and
   playbook 1 in lesson 16.5, then `make report-check`. The check wants every section, five UTC timestamps, three
   real record IDs and the facts a reviewer would ask for (both attacker addresses, the Claude calls, the command
   that disables the key, the audit config attempt, the cost, how the key leaked).

When you're done: `Caught 5 of 5 | seen but not named 0 | missed 0 | false alarms 0`, and `ALL TESTS PASSED (24 run)`.

## Step 10 · Your own project (optional)

[`GUIDED-BUILD.md`](GUIDED-BUILD.md): Data Access audit logs for Agent Platform, Model Armor sanitize logging with
four requests, three alerts (a Model Armor match, a key used from outside, a request flood from a log-based metric),
hunting with `queries/`, one threshold changed and re-run, what SCC Standard shows, and teardown. A few cents.
Security Command Center Premium stays off: its AI findings are on the module's video and in this lab's simulator.

## Troubleshooting

- `no telemetry in out/hardened/`: run `make simulate` (or `python3 simulate.py`) first. `make test` doesn't need it.
- Numbers differ from this page after you changed `simulate.py`, `exampleco.json` or `data/`: `git checkout` them;
  the tests pin the shipped day.
- Windows: `py simulate.py`, `py evaluate.py hardened`, `py run_tests.py`, and so on.
