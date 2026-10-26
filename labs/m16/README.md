# Lab M16: build the detections, run the attack simulator, catch it, write the incident report

Companion to lessons **16.0 to 16.6** of *AI Security Engineer* (The Sec Guy). About 75 minutes for Steps 1 to 9,
**$0**, all on your laptop: **Python 3.11+ only**, no packages, no AWS account, no network. Step 10 is optional:
[`GUIDED-BUILD.md`](GUIDED-BUILD.md) turns on GuardDuty AI Protection, an alert, a guardrail and the AI inventory in
**your own** sandbox account, makes a real prompt injection finding, and ends with teardown.

You are the cloud security engineer at **AnyCompany** (fictional; "AnyCompany" is the placeholder name AWS uses in its
documentation). Over Modules 10 to 14 the company built a customer support bot on Amazon Bedrock, a staff Helpdesk
agent on Amazon Bedrock AgentCore and a knowledge base. On **20 October 2026** five things went wrong on the same day.
The SOC caught one of them. Your job: find out why, build the detections and the logging that catch all five, and
write the incident report for the expensive one.

| Part | What you do | Lesson |
|---|---|---|
| **Simulate** | One day of telemetry, normal work plus five incidents, for two logging setups | 16.0, 16.1 |
| **Old SOC** | The SOC's three rules on the old logs: 1 of 5 caught, 1 false alarm | 16.0, 16.2 |
| **Old rules, new logs** | Still 1 of 5: a "Medium and above" GuardDuty rule drops every AI Protection finding | 16.2 |
| **New rules, old logs** | 1 of 5: you can't detect what you didn't log | 16.1 |
| **Both** | 13 rules (D01 to D13) on the new logs: 3 of 5 caught and named, 2 seen but not named, 0 false alarms | 16.2, 16.4 |
| **Inventory** | Managed, self-hosted and external AI, and what isn't approved | 16.3 |
| **Posture** | The nine AWS Config managed rules for Bedrock and AgentCore, plus five you have to write | 16.4 |
| **Report** | Pivot on an entity, estimate the cost, read a worked incident report | 16.5 |
| **Prove** | `make test`: 18 tests | 16.6 |
| **Challenge** | Two detections and your own incident report. No solution included | 16.4, 16.5 |
| **Cloud (optional)** | [`GUIDED-BUILD.md`](GUIDED-BUILD.md): console and CLI from zero, four requests, one setting changed, cost, teardown | 16.2 to 16.4 |

## What's in this folder

| File | What it is |
|---|---|
| `simulate.py` | The **attack simulator**: 20 Oct 2026 at AnyCompany, normal work plus five incidents (S1 to S5), written as the files each logging setup would really collect |
| `setups/first-draft.json`, `setups/hardened.json` | What each setup collects. First draft: CloudTrail management events and a plain web log. Hardened: lesson 16.1's list (data events, invocation logs with the end user, GuardDuty AI Protection, gateway spans, an app log with identities) |
| `detect.py` | Two rule packs: `soc-v1` (three rules a SOC often starts with) and `m16` (D01 to D13). D11 and D12 are your challenge |
| `evaluate.py` | Scores a pack against the five incidents: CAUGHT (an alert names who to act on), SEEN, NOT NAMED, MISSED, and false alarms |
| `inventory.py`, `data/inventory/` | An AI inventory from AWS Config items, Inspector software lists and DNS logs, like Security Hub's |
| `posture.py`, `data/posture/` | AWS Config managed rules for Bedrock and AgentCore (names exactly as AWS lists them) and five custom rules |
| `report.py`, `report/` | Pivot, cost, and the incident report check; `TEMPLATE.md` and a worked example for S3 |
| `queries/` | The same rules as CloudWatch Logs Insights queries, for your own account |
| `anycompany.json`, `data/baselines.json`, `data/iam-service-specific-credentials.json` | The company's facts: approved principals, known addresses, the KB pipeline, token baselines, the Bedrock API keys |
| `cloud/` | Files for the guided build: the EventBridge patterns, the guardrail, the SNS topic policy, the inventory filter |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 18 tests for the lab, 6 for the challenge |

**How faithful is the simulation?** Field names follow AWS's documented shapes: CloudTrail records, model invocation
log records (`schemaType` `ModelInvocationLog`), GuardDuty findings (`resource.bedrockGuardrailDetails`,
`resource.modelDetails`), AgentCore gateway span attributes (`aws.agentcore.policy.authorization_decision`,
`aws.agentcore.gateway.policy.mode`), Route 53 Resolver query logs. Values are invented. Three simplifications: each
record carries only the fields the lab reads; GuardDuty's findings are placed where the scenario needs them (AWS
doesn't publish how fast its models react); and the gateway spans carry a few `lab.` fields (tool, input, session) so
you don't have to join three log groups by hand.

## Needs

- Python **3.11 or newer**: `python3 --version`. No packages, no internet.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.
- Optional, Step 10 only: the AWS CLI v2 and your own sandbox account (lesson 0.7).

## Step 1 · The day of the five incidents

```bash
cd labs/m16
python3 simulate.py --list
make simulate
```

- `make simulate`: same as `python3 simulate.py`

```output
first-draft  cloudtrail 865  invocations 0  guardduty 0  spans 0  app 585   -> out/first-draft/
hardened     cloudtrail 930  invocations 855  guardduty 4  spans 33  app 585   -> out/hardened/
```

Same day, same attacks. The first draft collected no invocation logs, no AI findings and no spans, and its 585 web
log lines have no user in them. The five incidents:

| | Incident | Who to act on |
|---|---|---|
| S1 | A long-term Bedrock API key leaked from a CI log and is used to resell model access (LLMjacking) | the key's IAM user, `BedrockAPIKey-q4m8` |
| S2 | A customer jailbreaks the support bot; one answer leaks the system prompt's canary | the customer, `cust-8841` |
| S3 | A rollback puts the agent gateway's policy engine in `LOG_ONLY`; a hidden instruction in a ticket makes the agent mail data out and reset the CEO's MFA | the runtime session |
| S4 | A scripted account burns tokens through the app (denial of wallet) | the customer, `cust-2290` |
| S5 | A contractor role writes a fake page into the knowledge base; the bot sends customers to a phishing site | the role, `ContractorUploadRole` |

## Step 2 · The SOC's old rules on the old logs

```bash
make old
```

Same as `python3 evaluate.py first-draft --pack soc-v1`.

```output
  S1  CAUGHT           Leaked Bedrock API key (LLMjacking)    N2                       named BedrockAPIKey-q4m8
  S2  MISSED           Jailbroken customer bot
  S3  MISSED           Hijacked agent
  S4  MISSED           Denial of wallet through the app
  S5  MISSED           Poisoned knowledge base
  false alarm: N1 High InvokeModel volume (DataScienceRole: 150 InvokeModel calls in hour 13:00)

Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 1
```

S1 was caught by luck: the attacker tried to delete invocation logging, and that one rule fired. The volume rule
counts `InvokeModel` only, so it missed 120 `Converse` and `ConverseStream` calls and paged on the data science
team's batch job instead.

## Step 3 · Old rules, new logs

```bash
make old-rules
```

Same as `python3 evaluate.py hardened --pack soc-v1`.

```output
Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 1
```

GuardDuty AI Protection raised four findings. Rule N3 forwards GuardDuty findings of severity 4 and above, like AWS's
own EventBridge example for "medium, high, and critical findings". All three AI Protection finding types default to
**Low** (1.0 to 3.9), so none got through. Read `detect.py`'s `n3_guardduty_medium_plus` and `d05_guardduty_ai`
side by side.

## Step 4 · New rules, old logs

```bash
make old-logs
```

Same as `python3 evaluate.py first-draft`.

```output
  S1  CAUGHT           Leaked Bedrock API key (LLMjacking)    D01 D02 D03 D04          named BedrockAPIKey-q4m8
  S2  MISSED           Jailbroken customer bot
  S3  SEEN, NOT NAMED  Hijacked agent                         D03                      named tsg-ci-deployer
  S4  MISSED           Denial of wallet through the app
  S5  MISSED           Poisoned knowledge base

Caught 1 of 5 | seen but not named 1 | missed 3 | false alarms 0
```

Good rules, no evidence. The gateway change is a management event, so D03 sees the policy engine leave `ENFORCE`,
but nothing shows what the agent did next: gateway tracing and AgentCore data events were off.

## Step 5 · Both: this module's rules on lesson 16.1's logs

```bash
make detect
```

Same as `python3 detect.py hardened`, then `python3 evaluate.py hardened`.

```output
[MEDIUM] 09:15 D13 Answer links to an unknown domain
         entity domain: vpn-helpdesk-support.example.net   (5 answers)
[HIGH  ] 10:40 D07 Repeated prompt attacks from one end user
         entity end-user: cust-8841   (6 guardrail interventions)
[HIGH  ] 10:48 D08 System prompt canary in an answer
         entity end-user: cust-8841   (the answer contains CANARY-M16-SYSPROMPT)
[MEDIUM] 10:55 D05 Impact:IAMUser/PromptInjection.Direct
         entity principal: HelpdeskAppRole   (severity 2.0 (Low), count 6; the IAM identity, not the end user)
[HIGH  ] 11:12 D03 Gateway policy engine not in ENFORCE
         entity principal: tsg-ci-deployer   (gateway tsg-helpdesk-gw-a1b2c3d4e5 mode=LOG_ONLY)
...
  S1  CAUGHT           Leaked Bedrock API key (LLMjacking)    D01 D02 D03 D04 D05 D06  named BedrockAPIKey-q4m8
  S2  CAUGHT           Jailbroken customer bot                D07 D08                  named HelpdeskAppRole, cust-8841
  S3  CAUGHT           Hijacked agent                         D09 D10                  named tsg-5120b0b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6, tsg-ci-deployer
  S4  SEEN, NOT NAMED  Denial of wallet through the app       D05 D06                  named HelpdeskAppRole
  S5  SEEN, NOT NAMED  Poisoned knowledge base                D13                      named vpn-helpdesk-support.example.net

Caught 3 of 5 | seen but not named 2 | missed 0 | false alarms 0
```

Three things to notice:

1. **GuardDuty names the role, not the person.** Its prompt injection finding says `HelpdeskAppRole`: every customer's
   prompt goes through that role. D07 names `cust-8841` because the app put the end user in `requestMetadata`, which
   the invocation log keeps.
2. **The benign one stays quiet.** Customer `cust-1034` wrote "Ignore my last message, I meant order 4471". The
   guardrail blocked it at MEDIUM confidence; GuardDuty raises `PromptInjection.Direct` only for HIGH confidence, and
   D07 needs three interventions in ten minutes. No alert.
3. **S4 and S5 are seen but not named.** D06 and GuardDuty's `CostHarvesting` say the app's role is burning tokens:
   true, and useless for containment, since blocking the role takes the bot down for everyone. D13 sees the phishing
   link in five answers but not who planted it. That's your challenge.

## Step 6 · The AI inventory (16.3)

```bash
make inventory
```

Same as `python3 inventory.py`.

```output
AI inventory: 16 AI assets (9 managed, 7 self-hosted)
...
  UNSANCTIONED AWS::BedrockAgentCore::Runtime     marketing_poc_agent-Zz98Yy76Xx  (owner: marketing)
...
  UNSANCTIONED SelfHosted::AI::InferenceEndpoint  inference-endpoint/ollama on i-0a1b2c3d4e5f60002  (owner: data-science)
  UNSANCTIONED SelfHosted::AI::Agent              agent/openclaw on i-0a1b2c3d4e5f60003  (owner: it)
  UNSANCTIONED SelfHosted::AI::ExternalEndpoint   api.openai.com on i-0a1b2c3d4e5f60001  (owner: finance)

Not attributed: 9 DNS queries to api.mistral.ai from 10.20.9.44, which is not an EC2 instance. ...
Your check: ollama on i-0a1b2c3d4e5f60002 listens on port 11434 and its security group allows 0.0.0.0/0. ...

9 of 16 AI assets are not on the approved register.
```

The three signals are the ones Security Hub's AI inventory uses: AWS Config items for managed services, Amazon
Inspector software inventories on EC2 and ECR, and GuardDuty DNS activity on EC2. The last two lines are its documented
blind spots: DNS from Lambda and other managed compute isn't attributed, and self-hosted resources have no findings,
so an internet-facing Ollama port is a check you write.

## Step 7 · Posture: what AWS Config can and can't tell you (16.4)

```bash
make posture
make posture-hardened
```

- `make posture`: same as `python3 posture.py first-draft`
- `make posture-hardened`: 0 NON_COMPLIANT of 14 evaluations

```output
  NON_COMPLIANT bedrockagentcore-runtime-private-network-required       [BedrockAgentCore.1]  tsg_helpdesk-AbCdEf1234  NetworkMode PUBLIC
  COMPLIANT     bedrockagentcore-gateway-authorizer-enabled             [BedrockAgentCore.2]  tsg-helpdesk-gw-a1b2c3d4e5
  NON_COMPLIANT bedrockagentcore-gateway-authorizer-enabled             [BedrockAgentCore.2]  marketing-poc-gw-Qq11Ww22Ee  AuthorizerType NONE
...
Custom rules (no AWS managed rule: you write these)
  NON_COMPLIANT C01 Bedrock model invocation logging on, text, with an S3 location for large data  model invocation logging is off (it is disabled by default)
  NON_COMPLIANT C02 GuardDuty AI Protection enabled  AI_PROTECTION DISABLED
  NON_COMPLIANT C03 An account-enforced guardrail with a prompt attack filter  no account-enforced guardrail: ...
  NON_COMPLIANT C04 Trail data events for bedrock-mantle and AgentCore Runtime and Gateway  no data event selector for ...
  NON_COMPLIANT C05 Every gateway with a policy engine runs it in ENFORCE  policy engine in LOG_ONLY on tsg-helpdesk-gw-a1b2c3d4e5

15 NON_COMPLIANT of 16 evaluations
```

The Helpdesk gateway passes the managed authorizer rule and still ran with its policy engine in `LOG_ONLY` (S3). The
things that decided today's five incidents (invocation logging, AI Protection, an enforced guardrail, data events,
`ENFORCE`) have no AWS managed rule: they're C01 to C05.

## Step 8 · From alert to report (16.5)

Pivot on the entity an alert named, and read the incident in order:

```bash
python3 report.py pivot BedrockAPIKey-q4m8
python3 report.py pivot BedrockAPIKey-q4m8 --setup first-draft
python3 report.py cost BedrockAPIKey-q4m8
python3 report.py pivot cust-8841
```

- `python3 report.py pivot BedrockAPIKey-q4m8`: make pivot ENTITY=BedrockAPIKey-q4m8

```output
2026-10-20T14:05:00Z  cloudtrail e8b7078f-0713-43a2-8132-dc7bcbd64dac  bedrock ListFoundationModels from 203.0.113.50
2026-10-20T14:05:20Z  cloudtrail 346ddb48-a9eb-4f5f-9ecf-c8c3bb9d22b6  bedrock GetFoundationModelAvailability from 203.0.113.50
2026-10-20T14:06:00Z  cloudtrail 91416ff2-1396-43d5-aab6-bbae57377fc9  bedrock InvokeModel ValidationException from 203.0.113.50
2026-10-20T14:07:00Z  cloudtrail 11e00817-0319-4a4b-b772-9c0fcadfcd4e  bedrock GetModelInvocationLoggingConfiguration from 203.0.113.50
2026-10-20T14:08:00Z  cloudtrail 84e57831-c80f-4dd3-929b-faccc0651302  bedrock DeleteModelInvocationLoggingConfiguration AccessDenied from 203.0.113.50
...
277 records mention BedrockAPIKey-q4m8 in the hardened telemetry
125 records mention BedrockAPIKey-q4m8 in the first-draft telemetry
```

`cost` adds up 120 calls from the invocation logs and reports **30 bedrock-mantle calls that aren't in them**:
invocation logging covers bedrock-runtime only, so those 30 exist only as CloudTrail data events. Its dollar figure
uses an illustrative price list in `anycompany.json`, not AWS's prices. Pivot on `cust-8841` and notice what's
missing: no CloudTrail record mentions the customer, only the app's role.

Then read `report/EXAMPLE-S3-hijacked-agent.md`, a complete report for S3, and check it:

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
ALL TESTS PASSED (18 run)
```

## Challenge (no solution included)

```bash
make challenge
```

You should see:

```text
6 of 24 TESTS FAILED until you finish
```

1. **D11, knowledge base poisoning** (16.4, 16.5). In `detect.py`, write `d11_kb_source_write`: an alert when anyone
   other than the KB pipeline role writes into the knowledge base source bucket (S3 `PutObject` data events) or starts
   an ingestion job. Name the principal. The nightly pipeline must stay quiet. `queries/d11-kb-source-writes.txt` is
   the Logs Insights version.
2. **D12, denial of wallet per end user** (16.1, 16.5). Write `d12_wallet_per_end_user`: one end user above
   `tokens_per_end_user_per_hour` in any hour. GuardDuty and D06 can only name the app's role; you can name the user.
3. **The S1 incident report** (16.5). `cp report/TEMPLATE.md report/INCIDENT-REPORT.md`, write it from the pivot and
   the playbook in lesson 16.5, then `make report-check`. The check wants every section, five UTC timestamps, three
   real record IDs and the facts a reviewer would ask for (both attacker addresses, the mantle calls, the containment
   command for a long-term key, the cost, how the key leaked).

When you're done: `Caught 5 of 5 | seen but not named 0 | missed 0 | false alarms 0`, and `ALL TESTS PASSED (24 run)`.

## Step 10 · Your own account (optional)

[`GUIDED-BUILD.md`](GUIDED-BUILD.md): GuardDuty AI Protection and its sample findings, an EventBridge alert for every AI
finding (and a test that shows a "Medium and above" pattern misses them), a guardrail with four requests and a real
`PromptInjection.Direct` finding, the Security Hub AI inventory, one AgentCore Config rule, hunting in CloudTrail
event history, and teardown. A few cents inside the free trials.

## Troubleshooting

- `no telemetry in out/hardened/`: run `make simulate` (or `python3 simulate.py`) first. `make test` doesn't need it.
- Numbers differ from this page after you changed `simulate.py` or `anycompany.json`: `git checkout` them; the tests
  pin the shipped day.
- Windows: `py simulate.py`, `py evaluate.py hardened`, `py run_tests.py`, and so on.
