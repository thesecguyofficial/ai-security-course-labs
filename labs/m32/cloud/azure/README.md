# Azure stream: cloud review (not available yet, use aws)

The Azure version of the M25 cloud review is not available yet. When it is, it will review the same Ops Crew on Azure AI
Foundry: one managed identity per agent, Foundry guardrails and content filters, an agent gateway with an
authorizer, hand-off and tool policy, model signing on the registry, diagnostic logging to Log Analytics, and a
budget. For now, run the cloud review on the AWS stream (`--stream aws`), which is graded with the same rubric
row. Set `"stream": "aws"` in `capstone.json`.
