# AI Security Engineer: free hands-on labs

Hands-on labs for **AI Security Engineer** by [The Sec Guy](https://thesecguy.com/course/): learn to attack and defend AI apps, RAG, agents and MCP servers. **Every lab runs free on your laptop first**, and then in your cloud of choice (AWS, Azure or Google Cloud) when you're ready.

> New here? It's OK not to know this yet. Run the Quick start below once, then do the labs in order, starting with `labs/m01`.

## Quick start: set up everything once

One script checks your computer, installs what is missing (it asks first, every time), starts Ollama safely on
`127.0.0.1`, downloads the two lab models, makes one shared Python environment and finishes with a health check.

**macOS, Linux (Ubuntu/Debian) and WSL**, in Terminal:

```bash
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git && cd ai-security-course-labs
./setup.sh
```

**Windows 10/11**, in PowerShell (no git yet? use **Code → Download ZIP**, unzip, and open PowerShell in that folder):

```powershell
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git; cd ai-security-course-labs
powershell -ExecutionPolicy Bypass -File setup.ps1
```

Then check your computer any time with `make doctor` (Windows: `py tools\doctor.py`). Want to look before anything
changes? Add `--check` (Windows: `-Check`). Details, options, uninstall and fixes for common errors:
[docs/SETUP.md](docs/SETUP.md).

**Why not a one-line `curl ... | bash` installer?** Because that runs code you have never seen, straight off the
internet. This is a security course, so we do it the way you'd want your developers to: get the file, read it (or
at least skim it), check its fingerprint, then run it. The script follows the same rule for the installers it
fetches: it downloads them to a file, shows their SHA-256 and offers to open them before they run.

**Check the file is the one we published** (optional, takes 10 seconds). Compare the output with `SHA256SUMS` in
this repo and with the hashes in the notes of the latest [GitHub release](https://github.com/thesecguyofficial/ai-security-course-labs/releases):

```bash
shasum -a 256 setup.sh setup.ps1 tools/doctor.py      # macOS (Linux: sha256sum ...)
```

```powershell
Get-FileHash setup.ps1, setup.sh, tools\doctor.py -Algorithm SHA256    # Windows
```

## What you need
- A laptop with 8 GB RAM or more and 15 GB free disk. The setup script installs the rest: git, Python 3.11+,
  Docker, [Ollama](https://ollama.com) and two small models.
- Optional, for cloud labs: your own AWS, Azure or Google Cloud account with a budget alert (see Module 0)

## Labs
| Module | Lab | Runs on | Status |
|---|---|---|---|
| M1 | Run a model locally, count tokens, fill the context window | Laptop ($0) | ✅ available |
| M2 | Threat-model the TSG Helpdesk AI app (template) | Pen & paper / Markdown | ✅ available |
| M3 | Prompt injection: hijack a local support bot via a planted email note, then add 4 layered defences (25 tests + promptfoo eval) | Laptop ($0) | ✅ available |
| M4 | PII detection and redaction in and out of a chat app (Presidio) | Laptop ($0) | ✅ available |
| M5 | Output handling: XSS, SQL and command injection via model output, then fix it | Laptop ($0) | ✅ available |
| M6 | RAG security: two-tenant Qdrant RAG app; poison it, leak across tenants, then add retrieval access control and grounding | Laptop ($0) | ✅ available |
| M7 | Agent security: contain an over-privileged helpdesk agent (tool allow-list, recipient allow-list, spotlighting, approval, budget, kill switch, audit log) | Laptop ($0) | ✅ available |
| M8 | MCP security: honest vs malicious MCP server; tool poisoning and rug pull, then pinning, allow-list, approval and a secure OAuth server | Laptop ($0) | ✅ available |
| M9 | AI supply chain: detonate a booby-trapped model safely, catch it with scanners, use safetensors, pin and verify hashes | Laptop ($0) | ✅ available |
| M10 (AWS) | AWS AI footprint: find over-broad IAM/SCP/Bedrock API key setups, allow-list models, hunt LLMjacking in CloudTrail samples | Laptop ($0) + optional AWS | ✅ available |
| M10 (Azure) | Azure AI footprint: find over-broad Foundry roles, key access and model policies, hunt stolen-key abuse in activity logs | Laptop ($0) + optional Azure | ✅ available |
| M10 (Google Cloud) | Google Cloud AI footprint: IAM, org policy model allow-list, API keys, hunt credential abuse in audit logs | Laptop ($0) + optional Google Cloud | ✅ available |
| M11 (AWS) | Securing Amazon Bedrock: review TSG Helpdesk's Terraform plan offline (least privilege, VPC endpoint policy, KMS, invocation logging, CloudTrail, cross-Region residency), then optionally deploy the hardened version | Laptop ($0) + optional AWS (~$0.02/h) | ✅ available |
| M11 (Azure) | Securing Foundry models: check a Terraform plan for network, DNS, identity, customer-managed key, logging and residency gaps, replay attacks, hunt prompts in AI gateway logs | Laptop ($0) + optional Azure | ✅ available |
| M11 (Google Cloud) | Securing Gemini on Agent Platform: check a Terraform twin of the Helpdesk for keys, broad roles, public paths, missing perimeter, CMEK, logs and residency; replay attacks and an audit; deploy the hardened setup with Terraform | Laptop ($0) + optional Google Cloud | ✅ available |
| M12 (AWS) | Bedrock Guardrails: attack TSG Helpdesk with and without a guardrail, measure catch rate and false positives, find who can skip it (IAM GuardrailIdentifier, org Bedrock policy, bedrock-mantle) | Laptop ($0) + optional AWS | ✅ available |
| M12 (Azure) | Foundry guardrails: review guardrail, agent and policy settings, measure attack success AND false positives with a 28-request suite across four setups, guard a self-hosted model with Content Safety, hunt a prober | Laptop ($0) + optional Azure | ✅ available |
| M12 (Google Cloud) | Model Armor and Gemini safety filters: attack the Helpdesk with and without Model Armor, check floor settings and templates, measure catch rate and false positives with an automated suite, fail closed | Laptop ($0) + optional Google Cloud | ✅ available |
| M13 (AWS) | Bedrock Knowledge Bases and agents: port the local RAG + agent without losing a control (ACL-aware managed knowledge base vs metadata filters, return of control and confirmation, Lambda resource policies, AgentCore harness allowedTools), parity check against M6/M7 | Laptop ($0) + optional AWS | ✅ available |
| M13 (Azure) | Azure AI Search, Foundry IQ and Foundry Agent Service: port the Helpdesk RAG + agent without losing a control; check search trimming, chunk labels, permission sync, knowledge-base tokens, MCP allow-lists, approval and connection identity; replay 9 attacks across three setups; hunt an audit log | Laptop ($0) + optional Azure (Search Free) | ✅ available |
| M13 (Google Cloud) | RAG Engine, Agent Search and ADK agents: find the controls lost in a cloud port (filters vs ACLs, agent vs user identity, approvals, tool-output screening), attack it, fix it, run the real ADK runtime offline, then build it with RAG Engine and Model Armor | Laptop ($0) + optional Google Cloud | ✅ available |
| M14 (AWS) | Amazon Bedrock AgentCore: hijack the Helpdesk on Runtime, Identity, Gateway, Policy and Memory (12 attacks: session replay, forged user ID, token from another app, gateway bypass, LOG_ONLY, injected tool calls, memory poisoning), harden it with Cedar policies and per-user namespaces, hunt the incident in CloudTrail and spans | Laptop ($0) + optional AWS | ✅ available |
| M14 (Azure) | Foundry hosted agents and Entra Agent ID: review a hosted-agent deployment (session identity, agent-scope access, agent identity RBAC, secrets, guardrail fail-open, egress, toolbox approval, memory scope, Code Interpreter isolation), try 11 hijacks across three setups, hunt the traces, then deploy it yourself with a toolbox and your own policy | Laptop ($0) + optional Azure (under $1) | ✅ available |
| M14 (Google Cloud) | Agent Runtime, Agent Identity and Agent Gateway: review a deployment like an auditor (17 rules: shared service agent, CAA opt-out, principalSet data grants, dry-run and catch-all access policies, allow-by-annotation, Model Armor fail-open, Memory Bank scope, TTL and topics), then ask every control who decides each of eight proposed tool calls across five setups, including a dry run, a rug pull and a Model Armor outage; optionally deploy it yourself behind a gateway with one deny rule | Laptop ($0) + optional Google Cloud (under $1) | ✅ available |
| M20 (advanced) | Agent identity and delegation: a 3-agent chain on a local OAuth server; 8 attacks (confused deputy, token passthrough, cross-audience replay, upscoping at exchange, late and repeated replay, a bystander agent), then RFC 8693 token exchange that shrinks audience, scope and lifetime at every hop, `act` chains and replay refusal; the same on Keycloak; AgentCore Identity attribution in CloudTrail | Laptop ($0) + optional Keycloak + optional AWS | ✅ available |
| M15 → M19 | One lab per section and cloud, released with the course | Laptop + AWS / Azure / Google Cloud | coming every two weeks |

Each lab folder has a `README.md` with step-by-step commands, what you should see, and troubleshooting.

## Safety rules (please read)
- **Only test what you own or are allowed to test.** These labs target apps running on *your* machine (`localhost`) or *your* own cloud account.
- Vulnerable practice apps bind to `127.0.0.1` only. Don't expose them to the internet.
- **Never commit or post keys or tokens.** If you pasted one somewhere, rotate it.
- Cloud labs print their cost before deploying and include `make down`. Always tear down.

## Get help
- Questions about a lab → [Discussions → Lab help](../../discussions)
- Found a bug in a lab → open an issue
- Found a real security issue in our site or labs → email hello@thesecguy.com (please don't post it publicly)

## Full course
Video walkthroughs, written lessons, solutions, downloadable PDF decks and a graded capstone: **[thesecguy.com/course](https://thesecguy.com/course/)**

## License
Lab code is released under the MIT License (see `LICENSE`). Course videos, lessons and PDFs are not part of this repo and are not open-licensed.
