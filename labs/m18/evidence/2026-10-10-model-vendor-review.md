# Evidence: model and vendor review, 10 Oct 2026 (sample for the M18 lab, fictional)

Template: `templates/MODEL-VENDOR-REVIEW.md`.

| Item | Licence checked | Data use terms | Security review | Decision |
|---|---|---|---|---|
| Gemma 3 1B (local) | Gemma Terms of Use, read; use allowed | runs locally, no data leaves | pinned digest, Ollama on 127.0.0.1 | approved |
| Managed model (cloud stream) | provider terms | provider says prompts are not used to train its models (Module 11) | private endpoint, least privilege, logging | approved |
| Ticketing MCP server 1.4.2 | MIT | n/a | tool descriptions reviewed, pinned | approved |
| Local embedding model | **not checked** | runs locally | hash-pinned, scanned | **open: licence unknown** |
