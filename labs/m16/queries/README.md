# Saved hunting queries (CloudWatch Logs Insights)

The cloud version of the lab's rules. `detect.py` runs the same logic offline on the simulated day; these run in
your account in **CloudWatch, Logs Insights**: pick the log group named below, paste the file's query, choose the time
range, **Run query**. Save the ones you use (**Save**), so they're there on the bad day.

Field names follow AWS's record formats. Logs Insights flattens nested JSON into dotted names (`userIdentity.arn`);
if a query returns nothing, open one record and compare its discovered fields with the query. The IP addresses and
role names are the lab's AnyCompany values: change them to yours. These queries haven't been run against a real log
group yet (see the module's fact-check); treat the first run as a test.

| File | Log group | Lab rule | What it finds |
|---|---|---|---|
| `d01-bearer-key-unknown-ip.txt` | CloudTrail (a trail that delivers to CloudWatch Logs) | D01 | Long-term Bedrock API keys (IAM users named `BedrockAPIKey...`) used from addresses you don't know. Short-term keys ride on a role session: to include them, also match `additionalEventData.callWithBearerToken` after checking how your log group shows that boolean |
| `d02-recon.txt` | CloudTrail | D02 | Model and logging reconnaissance, or a failed validation probe, by anyone but the security admins |
| `d03-defence-tamper.txt` | CloudTrail | D03 | Invocation logging, a guardrail or a trail switched off, or a gateway policy engine leaving `ENFORCE` |
| `d04-unapproved-inference.txt` | CloudTrail | D04 | Inference by a principal not on your approved list. Converse and InvokeModel are management events; bedrock-mantle `CreateInference` is a data event (only if your trail selects it) |
| `d06-tokens-by-principal.txt` | Bedrock model invocation logs | D06 | AWS's own "tokens by principal" query with one change, split by hour: compare each hour with the principal's normal hour. Covers bedrock-runtime only |
| `d07-guardrail-by-end-user.txt` | Bedrock model invocation logs | D07 | Three or more guardrail interventions for one end user in ten minutes. Needs the end user in Converse `requestMetadata`, set by your backend |
| `d09-deny-not-enforced.txt` | AgentCore spans (`aws/spans`; Transaction Search and gateway tracing on) | D09 | Tool calls the policy engine denied but the gateway ran, because it was in `LOG_ONLY` |
| `d11-kb-source-writes.txt` | CloudTrail, with S3 data events for the knowledge base source bucket only | D11 (challenge) | Writes to the knowledge base source, or a sync, by anyone who isn't the pipeline |
