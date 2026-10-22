# AI Security Engineer: free hands-on labs

Hands-on labs for **AI Security Engineer** by [The Sec Guy](https://thesecguy.com/course/): learn to attack and defend AI apps, RAG, agents and MCP servers. **Every lab runs free on your laptop first**, and then in your cloud of choice (AWS, Azure or Google Cloud) when you're ready.

> New here? It's OK not to know this yet. Start with `labs/m00` setup, then go in order.

## What you need
- A laptop (about 8 GB RAM), Docker, Python 3.10+, [Ollama](https://ollama.com)
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
| M11 → M19 | One lab per section and cloud, released with the course | Laptop + AWS / Azure / Google Cloud | coming every two weeks |

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
