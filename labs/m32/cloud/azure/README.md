# Azure stream: cloud review (coming with the Azure stream)

The Azure version of the M32 cloud review ships with the Azure stream. It reviews the same Ops Crew on Azure AI
Foundry: one managed identity per agent, Foundry guardrails and content filters, an agent gateway with an
authorizer, hand-off and tool policy, model signing on the registry, diagnostic logging to Log Analytics, and a
budget. Until then, run the cloud review on the AWS stream (`--stream aws`), which is graded with the same rubric
row. Set `"stream": "aws"` in `capstone.json`.
