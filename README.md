# AI Security for Cloud Folks: free hands-on labs

Hands-on labs for **AI Security for Cloud Folks** by [The Sec Guy](https://thesecguy.com/course/): learn to attack and defend AI apps, RAG, agents and MCP servers. **Every lab runs free on your laptop first**, and then on AWS (Bedrock, Guardrails, AgentCore, SageMaker AI) when you're ready.

> New here? It's OK not to know this yet. Start with `labs/m00` setup, then go in order.

## What you need
- A laptop (about 8 GB RAM), Docker, Python 3.10+, [Ollama](https://ollama.com)
- Optional, for AWS labs: your own AWS account with a budget alarm (see Module 0)

## Labs
| Module | Lab | Runs on | Status |
|---|---|---|---|
| M1 | Run a model locally, count tokens, fill the context window | Laptop ($0) | ✅ available |
| M2 | Threat-model the TSG Helpdesk AI app (template) | Pen & paper / Markdown | ✅ available |
| M3 → M19 | One lab per section, released with the course | Laptop + AWS | coming every two weeks |

Each lab folder has a `README.md` with step-by-step commands, what you should see, and troubleshooting.

## Safety rules (please read)
- **Only test what you own or are allowed to test.** These labs target apps running on *your* machine (`localhost`) or *your* AWS account.
- Vulnerable practice apps bind to `127.0.0.1` only. Don't expose them to the internet.
- **Never commit or post keys or tokens.** If you pasted one somewhere, rotate it.
- AWS labs print their cost before deploying and include `make down`. Always tear down.

## Get help
- Questions about a lab → [Discussions → Lab help](../../discussions)
- Found a bug in a lab → open an issue
- Found a real security issue in our site or labs → email hello@thesecguy.com (please don't post it publicly)

## Full course
Video walkthroughs, written lessons, solutions, downloadable PDF decks and a graded capstone: **[thesecguy.com/course](https://thesecguy.com/course/)**

## License
Lab code is released under the MIT License (see `LICENSE`). Course videos, lessons and PDFs are not part of this repo and are not open-licensed.
