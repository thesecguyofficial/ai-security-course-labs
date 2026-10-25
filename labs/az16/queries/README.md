# Saved hunting queries (KQL for Log Analytics and Microsoft Sentinel)

The cloud version of the lab's rules. `detect.py` runs the same logic offline on the simulated day; these run in
your own **Log Analytics workspace** (Azure portal, the workspace, **Logs**) or as the query of a Microsoft Sentinel
scheduled analytics rule. Paste a file, set the time range, **Run**. Save the ones you use, so they're there on the
bad day.

Table and column names follow Microsoft's table references (`AzureActivity`, `AzureDiagnostics`,
`ApiManagementGatewayLogs`, `ApiManagementGatewayLlmLog`, `SecurityAlert`). `HelpdeskApp_CL` is the lab's name for
your app's own log as a custom table. The addresses and identities are the lab's Contoso values: change them to
yours. These queries haven't been run against a real workspace yet (see the module's fact-check): treat the first
run as a test, and look at one real row of each table before you trust a filter.

| File | Table | Lab rule | What it finds |
|---|---|---|---|
| `d01-workload-identity-new-ip.kql` | AzureActivity | D01 | A service principal making control-plane calls (listKeys and friends) from an address outside your ranges |
| `d02-calls-skip-gateway.kql` | AzureDiagnostics (Foundry `RequestResponse`) | D02 | Model calls that didn't come from the API Management gateway: a key or a token in use somewhere else |
| `d03-defence-tamper.kql` | AzureActivity | D03 | A diagnostic setting or a Defender for Cloud plan changed by anyone but the security admins |
| `d04-defender-ai-all-severities.kql` | SecurityAlert | D04 | Every Defender for AI services alert, Low and Medium included |
| `d05-token-spike-per-subscription.kql` | ApiManagementGatewayLlmLog + ApiManagementGatewayLogs | D05 | Tokens per APIM subscription per hour above four times its baseline |
| `d06-content-filter-blocks-per-user.kql` | HelpdeskApp_CL | D06 | Three or more content-filter blocks for one end user in ten minutes |
| `d07-canary-in-answer.kql` | ApiManagementGatewayLlmLog + HelpdeskApp_CL | D07 | The system prompt's canary in an answer, and who got it |
| `d08-write-tool-without-approval.kql` | Application Insights (check your layout) | D08, D09 | Write tools the agent ran, and mail to outside addresses |
| `d10-unknown-link-in-answer.kql` | ApiManagementGatewayLlmLog | D10 | Answers that send users to a domain outside your allow-list |
| `inventory-resource-graph.kql` | Azure Resource Graph | 16.3 | Every Foundry, Azure OpenAI, AI Search, Azure Machine Learning and API Management resource you can read |

D11 and D12 are the lab's challenge, so there is no query for them here. When you've written them in `detect.py`,
writing their KQL twins (StorageBlobLogs and `HelpdeskApp_CL`) is good practice.
