# Saved hunting queries (Logs Explorer and BigQuery)

The cloud version of the lab's rules. `detect.py` runs the same logic offline on the simulated day; these run in your
own project. The `.txt` files are Logging query language: **Logging**, **Logs Explorer**, paste the query, set the time
range, **Run query**, then **Save** it so it's there on the bad day. The `.sql` files run in **BigQuery** on the
request-response logging table.

The service account names, project IDs and IP addresses are the lab's ExampleCo values: change them to yours.
Inference method names (`GenerateContent`, `StreamGenerateContent`, `RawPredict`) come from Google's API definitions;
Google's audit logging page for Agent Platform lists `endpoints.predict` and `endpoints.rawPredict`, not
`generateContent`, so open one real entry from your project and compare before you trust a query.

What has been run for real: on 12 November 2026 `d04-unapproved-inference.txt` ran in our project and returned our
own calls, and the Data Access entry for a Gemini call carried the method name
`google.cloud.aiplatform.v1.PredictionService.GenerateContent` (GUIDED-BUILD.md Parts A and D). The other seven
queries have not been run against a real project (as of 15 November 2026): treat your first run of each as a test.

| File | Where | Lab rule | What it finds |
|---|---|---|---|
| `d01-key-unknown-ip.txt` | Logs Explorer (Admin Activity and Data Access) | D01 | Any call made with a downloaded service account key (`serviceAccountKeyName`) from an address that isn't yours |
| `d02-failed-ai-calls.txt` | Logs Explorer | D02 | Failed Agent Platform calls. Count them per principal per 10 minutes (a log-based metric with a label, or the D02 logic) |
| `d03-defence-tamper.txt` | Logs Explorer (Admin Activity: always on) | D03 | Audit config, request-response logging, Model Armor template or sink changes by anyone but the security admin, and an IAP authorization extension put in `DRY_RUN` |
| `d04-unapproved-inference.txt` | Logs Explorer (Data Access: off by default) | D04 | Model calls by a principal not on your approved list |
| `d06-tokens-by-model.sql` | BigQuery, request-response table | D06 | Tokens per model per hour. The table has no caller identity: it names the model. Token counts are only in this table, so D06 can't be a log-based metric (see below) |
| `d07-blocked-by-end-user.sql` | BigQuery, request-response table | D07 | Three or more Model Armor blocks for one end user in ten minutes. Needs `labels.end_user`, set by your backend |
| `d09-dry-run-denials.txt` | Logs Explorer (Data Access) | D09 | IAP decisions for Agent Gateway. Google's page says that in dry run IAP logs the calls it would have denied, and this is the log they'd land in. In our GC14 runs (12 and 13 November 2026) every entry here said `granted: true`, in dry run and after enforcing: we found no would-be denial. Read the gateway's request log next to it (`labs/gc14/GUIDED-BUILD.md` Step 5) |
| `d11-rag-source-writes.txt` | Logs Explorer (Data Access for Cloud Storage and Agent Platform) | D11 (challenge) | Writes into the RAG source bucket, or files imported into the corpus, by anyone who isn't the pipeline |

To turn a query into an alert: in Logs Explorer, **Actions**, **Create log alert** (one notification per matching
entry, rate-limited). When you need a count, it depends on where the number lives:

- **D02** counts log entries, so create a log-based metric from the query and an alerting policy on the metric.
- **D06** can't be a log-based metric. It adds up tokens, and the token numbers are in the request-response table in
  BigQuery; the audit log entries a log-based metric could count carry no token counts. Keep D06 as a scheduled
  BigQuery query. The nearest log-based stand-in is a metric that counts model **calls** in the audit log, which is
  what the guided build's flood alert does (`cloud/ai-calls-metric-filter.txt`). That's a different rule: it sees a
  flood of calls, and misses a few calls with very large prompts.
