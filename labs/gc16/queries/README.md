# Saved hunting queries (Logs Explorer and BigQuery)

The cloud version of the lab's rules. `detect.py` runs the same logic offline on the simulated day; these run in your
own project. The `.txt` files are Logging query language: **Logging**, **Logs Explorer**, paste the query, set the time
range, **Run query**, then **Save** it so it's there on the bad day. The `.sql` files run in **BigQuery** on the
request-response logging table.

The service account names, project IDs and IP addresses are the lab's ExampleCo values: change them to yours.
Inference method names (`GenerateContent`, `StreamGenerateContent`, `RawPredict`) come from Google's API definitions;
Google's audit logging page for Agent Platform lists `endpoints.predict` and `endpoints.rawPredict`, not
`generateContent`, so open one real entry from your project and compare before you trust a query. These queries
haven't been run against a real project yet (see the module's fact-check); treat the first run as a test.

| File | Where | Lab rule | What it finds |
|---|---|---|---|
| `d01-key-unknown-ip.txt` | Logs Explorer (Admin Activity and Data Access) | D01 | Any call made with a downloaded service account key (`serviceAccountKeyName`) from an address that isn't yours |
| `d02-failed-ai-calls.txt` | Logs Explorer | D02 | Failed Agent Platform calls. Count them per principal per 10 minutes (a log-based metric with a label, or the D02 logic) |
| `d03-defence-tamper.txt` | Logs Explorer (Admin Activity: always on) | D03 | Audit config, request-response logging, Model Armor template or sink changes by anyone but the security admin, and an IAP authorization extension put in `DRY_RUN` |
| `d04-unapproved-inference.txt` | Logs Explorer (Data Access: off by default) | D04 | Model calls by a principal not on your approved list |
| `d06-tokens-by-model.sql` | BigQuery, request-response table | D06 | Tokens per model per hour. The table has no caller identity: it names the model |
| `d07-blocked-by-end-user.sql` | BigQuery, request-response table | D07 | Three or more Model Armor blocks for one end user in ten minutes. Needs `labels.end_user`, set by your backend |
| `d09-dry-run-denials.txt` | Logs Explorer (Data Access) | D09 | IAP decisions for Agent Gateway. In dry run, IAP logs the calls it would have denied; this is where they land |
| `d11-rag-source-writes.txt` | Logs Explorer (Data Access for Cloud Storage and Agent Platform) | D11 (challenge) | Writes into the RAG source bucket, or files imported into the corpus, by anyone who isn't the pipeline |

To turn a query into an alert: in Logs Explorer, **Actions**, **Create log alert** (one notification per matching
entry, rate-limited), or create a log-based metric from it and an alerting policy on the metric when you need a count
(D02, D06).
