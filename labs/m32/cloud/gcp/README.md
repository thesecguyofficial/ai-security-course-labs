# Google Cloud stream: cloud review (not available yet, use aws)

The Google Cloud version of the M32 cloud review is not available yet. When it is, it will review the same Ops Crew
on Vertex AI Agent Engine: one service account per agent, Model Armor, an agent gateway authorizer, hand-off and
tool policy, model signing, Cloud Audit Logs, and a budget. For now, run the cloud review on the AWS stream
(`--stream aws`), which is graded with the same rubric row. Set `"stream": "aws"` in `capstone.json`.
