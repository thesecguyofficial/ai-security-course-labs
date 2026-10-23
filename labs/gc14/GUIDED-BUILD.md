# GC14 guided build: an Agent Runtime agent with its own identity, behind Agent Gateway, in your own project

The offline lab (README Steps 1 to 7) teaches the decisions at $0. This guide builds a small version for real, from
zero, in **your own** Google Cloud sandbox project (never a work project). About 90 minutes. You will:

- deploy a small ADK Helpdesk agent to **Agent Runtime** with its own **Agent Identity**;
- put it behind an **Agent Gateway** (Agent-to-Anywhere) whose **Agent Registry** lists only the Google endpoints the
  agent needs, so everything else hits the gateway's default deny;
- add **one DENY rule** to an IAM Unified Access Policy while the gateway is in **dry run**, read what it would have
  denied, then **enforce** it;
- turn on **Data Access audit logs** for Memory Bank and set a Memory Bank **TTL**;
- send four requests, change one setting, re-run, and tear everything down.

The agent's only tool server is **Google's BigQuery remote MCP server** (`https://bigquery.googleapis.com/mcp`), which
Google registers in Agent Registry for you when the BigQuery API is on. No third-party service is used.

> **Read this first: about the responses shown below.** We wrote this guide without running it in a Google Cloud
> project, so **no response from Google Cloud in this file comes from a real run**. Every such block is labelled
> **"Example response (shape from the provider's docs, values illustrative)"**. Field names come from Google's pages
> and API definitions (`google/iam/v3/access_policy_resources.proto`, `google/cloud/aiplatform/v1beta1/reasoning_engine.proto`
> and `memory_bank_service.proto` in [googleapis](https://github.com/googleapis/googleapis)) and the log queries in
> Google's [Agent Gateway codelabs](https://github.com/GoogleCloudPlatform/cloud-networking-solutions/tree/main/codelabs).
> **Values (IDs, timestamps, and what the model chooses to say) are ours.** The Terraform in `cloud/terraform/` was
> checked against the provider's documentation but has **not** been applied or run through `terraform validate`
> by us. Write down what you really see in the table in Step 8.

Throughout, run commands from `labs/gc14`, and set these shell variables again in every new terminal:

| Variable | Holds | Example |
|---|---|---|
| `PROJECT` | your sandbox project ID | `tsg-sandbox-1234` |
| `REGION` | the region for the gateway, the registry and the agent | `us-central1` |
| `GATEWAY` | the gateway's resource name (Terraform output `gateway`) | `projects/tsg-sandbox-1234/locations/us-central1/agentGateways/tsg-gc14-egress` |
| `AGENT` | the agent's resource name (printed by `deploy.py`) | `projects/tsg-sandbox-1234/locations/us-central1/reasoningEngines/1234567890123456789` |
| `AGENT_PRINCIPAL` | the agent's Agent Identity (printed by `deploy.py`) | `principal://agents.global.org-ORG_ID.system.id.goog/resources/aiplatform/projects/PROJECT_NUMBER/locations/us-central1/reasoningEngines/1234567890123456789` |

## Step 0 · Before you start (10 minutes)

1. **A sandbox project with billing and a budget alert** (GC10 lesson 10.5). As its owner you can do everything
   below. In a shared project you'd also need, among others, IAP Admin, Network Security Admin, Service Extensions
   Admin and Access Policy Admin (`roles/iam.accessPolicyAdmin`).
2. **Organization or not?** Agent Identity works either way. In an organization the agent's trust domain is
   `agents.global.org-ORG_ID.system.id.goog`; in a project with no organization it's
   `agents.global.proj-PROJECT_NUMBER.system.id.goog`. If your project **is** in an organization, Google's page says
   to turn off enforcement of the managed constraint that blocks IAM v3 access policy bindings
   (`constraints/iam.managed.disableAccessPolicyBindings`; the Terraform provider's example spells it
   `iam.managed.disableAccessPolicyBinding`). In the console: **IAM & Admin > Organization policies**, filter for
   "access policy", open it and override it for your project only.
3. **Tools:** the `gcloud` and `bq` CLIs (Cloud Shell has both), Terraform 1.6+ or OpenTofu, Python 3.11+ and `jq`.
   Run `gcloud components update` first (in Cloud Shell it's kept current for you). The `agent-gateways` and
   `agent-registry` command groups and `gcloud iam policy-bindings create --target-resource` are recent: the
   gcloud 570.0.0 we checked with doesn't have them yet. If a command below says "Invalid choice", your gcloud is too
   old; use Terraform or the REST call shown next to it.
4. **Sign in and pick the project:**

   ```bash
   export PROJECT=your-sandbox-project REGION=us-central1
   gcloud config set project $PROJECT
   gcloud auth application-default login         # the Python SDK uses Application Default Credentials
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r cloud/agent/requirements.txt   # google-adk[gcp]==2.12.0 and the Agent Platform SDK
   ```

## Step 1 · Infrastructure, first pass (20 minutes)

The first pass creates everything that doesn't need the agent yet: the APIs, two BigQuery datasets, a staging bucket,
the Agent Registry endpoints, and the gateway with its IAP authorization extension **in dry run**.

### Path A: Terraform (recommended)

```bash
cp cloud/terraform/terraform.tfvars.example cloud/terraform/terraform.tfvars    # then edit project_id
cd cloud/terraform
terraform init -input=false
terraform plan -out=plan.out      # read it: about 40 resources, nothing outside your project
terraform apply plan.out
export GATEWAY=$(terraform output -raw gateway) STAGING=$(terraform output -raw staging_bucket)
cd ../..
```

What it creates, file `cloud/terraform/main.tf`:

| Resource | Why |
|---|---|
| `google_bigquery_dataset` `helpdesk` and `finance_exports` (one table each) | the data the agent may and may not read |
| `google_agent_registry_service` (one per Google host) | Google's list of endpoints an agent behind a gateway needs: Agent Registry, Logging, Telemetry, Trace, Monitoring, Secret Manager, Resource Manager, IAM Credentials and Agent Platform (global, regional, mTLS and REP hosts). "Hostname matching in Agent Gateway is exact" |
| `google_network_services_agent_gateway` | `protocols = ["MCP"]`, `governed_access_path = "AGENT_TO_ANYWHERE"`, your regional registry **and** the `global` one (Google-managed MCP servers are registered in `global`) |
| `google_network_services_authz_extension` `tsg-gc14-iap` | `service = "iap.googleapis.com"`, `fail_open = false`, metadata `iapPolicyVersion = "V2"` plus `iamEnforcementMode = "DRY_RUN"` while `enforcement` is `DRY_RUN` |
| `google_network_security_authz_policy` | binds that extension to the gateway: `policy_profile = "REQUEST_AUTHZ"`, `action = "CUSTOM"` |
| `google_project_iam_audit_config` | Data Access logs (`DATA_READ`, `DATA_WRITE`) for `aiplatform.googleapis.com` (Step 6 explains) |

### Path B: gcloud (the same gateway, by hand)

Enable the APIs, then create the gateway, the extension and its policy from YAML files. The commands and fields are
the ones on Google's [set-up](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/set-up-agent-gateway)
and [delegate authorization](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/delegate-authorization) pages.

```bash
gcloud services enable aiplatform.googleapis.com agentregistry.googleapis.com networkservices.googleapis.com \
  networksecurity.googleapis.com iap.googleapis.com iam.googleapis.com compute.googleapis.com \
  bigquery.googleapis.com storage.googleapis.com logging.googleapis.com cloudresourcemanager.googleapis.com

cat > gateway.yaml <<EOF
name: tsg-gc14-egress
protocols:
  - MCP
googleManaged:
  governedAccessPath: AGENT_TO_ANYWHERE
registries:
  - //agentregistry.googleapis.com/projects/$PROJECT/locations/$REGION
  - //agentregistry.googleapis.com/projects/$PROJECT/locations/global
EOF
gcloud network-services agent-gateways import tsg-gc14-egress --source=gateway.yaml --location=$REGION

cat > iap-ext.yaml <<EOF
name: tsg-gc14-iap
service: iap.googleapis.com
failOpen: false
timeout: 1s
metadata:
  iapPolicyVersion: "V2"
  iamEnforcementMode: "DRY_RUN"
EOF
gcloud service-extensions authz-extensions import tsg-gc14-iap --source=iap-ext.yaml --location=$REGION

cat > iap-policy.yaml <<EOF
name: tsg-gc14-iap-policy
target:
  resources:
    - "projects/$PROJECT/locations/$REGION/agentGateways/tsg-gc14-egress"
policyProfile: REQUEST_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - "projects/$PROJECT/locations/$REGION/authzExtensions/tsg-gc14-iap"
EOF
gcloud network-security authz-policies import tsg-gc14-iap-policy --source=iap-policy.yaml --location=$REGION
export GATEWAY=projects/$PROJECT/locations/$REGION/agentGateways/tsg-gc14-egress
```

Register each Google host the agent needs (repeat for every host in `google_endpoints` in
`cloud/terraform/variables.tf`, plus `$REGION-aiplatform.googleapis.com`, `$REGION-aiplatform.mtls.googleapis.com`
and `aiplatform.$REGION.rep.googleapis.com`). The flags are the ones Google's routing page and codelab use:

```bash
gcloud agent-registry services create logging --project=$PROJECT --location=$REGION \
  --display-name=logging.googleapis.com --endpoint-spec-type=no-spec \
  --interfaces=url=https://logging.googleapis.com,protocolBinding=JSONRPC
```

Create the datasets in the console (**BigQuery > your project > Create dataset**: `helpdesk`, then `finance_exports`),
then a staging bucket: `gcloud storage buckets create gs://$PROJECT-tsg-gc14-staging --location=$REGION` and
`export STAGING=gs://$PROJECT-tsg-gc14-staging`.

### Both paths: add fake rows

```bash
bq query --use_legacy_sql=false \
  "CREATE TABLE IF NOT EXISTS helpdesk.tickets (ticket_id STRING, status STRING, summary STRING)"
bq query --use_legacy_sql=false "INSERT INTO helpdesk.tickets (ticket_id, status, summary) VALUES
  ('T-1001', 'open', 'VPN drops after sleep'), ('T-1002', 'open', 'Printer on floor 3 offline'),
  ('T-1003', 'open', 'Password reset loop'), ('T-1004', 'closed', 'New laptop request')"
bq query --use_legacy_sql=false \
  "CREATE TABLE IF NOT EXISTS finance_exports.payroll (employee STRING, band STRING)"
bq query --use_legacy_sql=false \
  "INSERT INTO finance_exports.payroll (employee, band) VALUES ('test-user-1', 'B2'), ('test-user-2', 'B3')"
```

**Check before moving on:** in the console, open **Agent Registry** for your project. In the `global` location you
should see the BigQuery MCP server Google registered when the API was enabled ("Official Google and Google Cloud
remote MCP servers are automatically registered"), and in `$REGION` the endpoints you just added.

## Step 2 · Look at what the agent will be (5 minutes)

Open `cloud/agent/helpdesk/agent.py`. It's short on purpose:

- one `McpToolset` pointing at `https://bigquery.googleapis.com/mcp`, which sends the **agent's own** access token
  (from its Agent Identity) on every call;
- one plain function, `fetch_page(url)`, that does an HTTPS GET. Its destination is not in Agent Registry, so the
  gateway treats it as an **unregistered destination**;
- an instruction that says which table holds tickets, and to use `execute_sql_readonly` for questions and
  `execute_sql` only when asked to change something. Google's BigQuery MCP page: "The only MCP tool that isn't
  read-only is `execute_sql`."

There's no allow-list in the agent's code. That is deliberate: in this build, the gateway and IAM decide.

## Step 3 · Deploy the agent with Agent Identity, bound to the gateway (15 minutes)

```bash
cd cloud/agent
python3 deploy.py --project $PROJECT --region $REGION --gateway $GATEWAY --staging-bucket $STAGING
cd ../..
```

`deploy.py` calls `client.agent_engines.create()` with `"identity_type": types.IdentityType.AGENT_IDENTITY` and
`"agent_gateway_config": {"agent_to_anywhere_config": {"agent_gateway": GATEWAY}}`. Google: when
`agent_gateway_config` is set, `identity_type` must be `AGENT_IDENTITY`, and the gateway must be in the agent's region.
Deployment takes several minutes.

Example response (shape from the provider's docs, values illustrative):

```output
{
  "name": "projects/123456789012/locations/us-central1/reasoningEngines/1234567890123456789",
  "effectiveIdentity": "principal://agents.global.org-100000000099.system.id.goog/resources/aiplatform/projects/123456789012/locations/us-central1/reasoningEngines/1234567890123456789",
  "identityType": "IdentityType.AGENT_IDENTITY"
}

Next: put effectiveIdentity into cloud/terraform/terraform.tfvars as agent_principal (Step 4).
```

```bash
export AGENT="projects/.../reasoningEngines/..."           # the "name" above
export AGENT_PRINCIPAL="principal://agents.global...."      # the "effectiveIdentity" above
```

Check the binding the way Google's routing page does (a `null` result means the gateway binding failed):

```bash
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://$REGION-aiplatform.googleapis.com/v1beta1/$AGENT" | jq '.spec.deploymentSpec.agentGatewayConfig, .spec.effectiveIdentity'
```

Example response (shape from the provider's docs, values illustrative):

```output
{
  "agentToAnywhereConfig": {
    "agentGateway": "projects/tsg-sandbox-1234/locations/us-central1/agentGateways/tsg-gc14-egress"
  }
}
"principal://agents.global.org-100000000099.system.id.goog/resources/aiplatform/projects/123456789012/locations/us-central1/reasoningEngines/1234567890123456789"
```

Two things Google's pages say that are easy to miss: all agents in one project and region bind to the **same**
egress gateway, and **redeploying creates a new principal**, so grants to the old one don't carry over (and aren't
removed: lab rule GC14-04).

The agent can't do anything useful yet: it has no grants, and no access policy allows its traffic. The gateway is in
dry run, so the calls will go through and be logged as "would deny".

## Step 4 · The access policy with one DENY rule, in dry run (15 minutes)

### Path A: Terraform

Put the principal in `cloud/terraform/terraform.tfvars` (`agent_principal = "principal://..."`), then:

```bash
cd cloud/terraform && terraform plan -out=plan.out && terraform apply plan.out && cd ../..
```

This second pass adds, for **this agent's principal only**:

| Resource | What it says |
|---|---|
| `google_iam_project_access_policy` `tsg-gc14-egress` | rule `allow-google-endpoints`: `destination.agent_registry.resource_type == 'ENDPOINT'` |
| | rule `allow-bigquery-tools`: `resource_type == 'MCP_SERVER'` and `tool.name in [the six BigQuery tools]` |
| | rule `deny-execute-sql` (**DENY**): `destination.agent_registry.mcp_server.tool.name == 'execute_sql'` |
| `google_iam_projects_policy_binding` | `policy_kind = "ACCESS"`, target `//networkservices.googleapis.com/projects/PROJECT/locations/REGION/agentGateways/tsg-gc14-egress` |
| `google_project_iam_member` x4 | `roles/aiplatform.expressUser`, `roles/serviceusage.serviceUsageConsumer` (Google's Agent Identity page), `roles/bigquery.jobUser`, `roles/mcp.toolUser` (Google's BigQuery MCP page) |
| `google_bigquery_dataset_iam_member` | `roles/bigquery.dataViewer` on dataset `helpdesk` only |

The ALLOW rule for BigQuery includes `execute_sql` on purpose: Google's overview says "deny rules override allow
rules", so the DENY rule wins. Nothing allows an unregistered host, so `fetch_page` meets the default deny.

### Path B: gcloud

The policy file for `gcloud` is a top-level array of rules (Google's
[configure page](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/configure-iam-policies-uap)):

```bash
cat > policy.json <<EOF
[
  {"description": "allow-google-endpoints", "effect": "ALLOW", "principals": ["$AGENT_PRINCIPAL"],
   "operation": {"permissions": ["iap.googleapis.com/resources.egressViaIAP"]},
   "conditions": {"iap.googleapis.com": {"expression": "destination.agent_registry.resource_type == 'ENDPOINT'"}}},
  {"description": "allow-bigquery-tools", "effect": "ALLOW", "principals": ["$AGENT_PRINCIPAL"],
   "operation": {"permissions": ["iap.googleapis.com/resources.egressViaIAP"]},
   "conditions": {"iap.googleapis.com": {"expression": "destination.agent_registry.resource_type == 'MCP_SERVER' && destination.agent_registry.mcp_server.tool.name in ['list_dataset_ids', 'list_table_ids', 'get_dataset_info', 'get_table_info', 'execute_sql_readonly', 'execute_sql']"}}},
  {"description": "deny-execute-sql", "effect": "DENY", "principals": ["$AGENT_PRINCIPAL"],
   "operation": {"permissions": ["iap.googleapis.com/resources.egressViaIAP"]},
   "conditions": {"iap.googleapis.com": {"expression": "destination.agent_registry.mcp_server.tool.name == 'execute_sql'"}}}
]
EOF
gcloud iam access-policies create tsg-gc14-egress --details-rules=policy.json --project=$PROJECT --location=global
gcloud iam policy-bindings create tsg-gc14-egress \
  --policy="projects/$PROJECT/locations/global/accessPolicies/tsg-gc14-egress" \
  --target-resource="//networkservices.googleapis.com/$GATEWAY" --project=$PROJECT --location=global
# same binding with the REST API (Google's configure page), if your gcloud has no --target-resource:
# curl -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
#   "https://iam.googleapis.com/v3beta/projects/$PROJECT/locations/global/policyBindings?policyBindingId=tsg-gc14-egress" \
#   -d "{\"policy\": \"projects/$PROJECT/locations/global/accessPolicies/tsg-gc14-egress\", \"target\": {\"resource\": \"//networkservices.googleapis.com/$GATEWAY\"}}"

for ROLE in roles/aiplatform.expressUser roles/serviceusage.serviceUsageConsumer roles/bigquery.jobUser roles/mcp.toolUser; do
  gcloud projects add-iam-policy-binding $PROJECT --member="$AGENT_PRINCIPAL" --role=$ROLE --condition=None
done
```

Then give the agent read access to the `helpdesk` dataset only: **BigQuery > helpdesk > Share > Manage permissions >
Add principal**, paste `$AGENT_PRINCIPAL` (without quotes), role **BigQuery Data Viewer**. Don't share
`finance_exports`.

Before you test, run `python3 -c "import cel; cel.check(\"destination.agent_registry.mcp_server.tool.name == 'execute_sql'\")"`
from `labs/gc14`: the offline lab's CEL subset reads every condition in this guide, so a typo shows up here first.
Wait a few minutes after creating the binding: IAM changes take time to apply.

## Step 5 · Four requests in dry run, then enforce (20 minutes)

```bash
cd cloud/agent && python3 ask.py --project $PROJECT --region $REGION --agent $AGENT && cd ../..
```

`ask.py` sends four ordinary questions as `user_id` `alice` and prints each tool call, each tool result and the
answer. What the agent is **allowed** to do with them is the gateway's and IAM's business.

### R1 · A normal question

Example response (shape from the provider's docs, values illustrative):

```output
R1: How many tickets in the helpdesk tickets table are open?
   call     execute_sql_readonly({"projectId": "tsg-sandbox-1234", "query": "SELECT COUNT(*) AS open_tickets FROM `tsg-sandbox-1234.helpdesk.tickets` WHERE status = 'open'"})
   result   execute_sql_readonly: {"rows": [{"open_tickets": "3"}]}
   answer   There are 3 open tickets in the helpdesk table.
```

Allowed by `allow-bigquery-tools`; IAM allows the read (Data Viewer on `helpdesk`).

### R2 · Another team's data

Example response (shape from the provider's docs, values illustrative):

```output
R2: How many rows are in the table finance_exports.payroll?
   call     execute_sql_readonly({"query": "SELECT COUNT(*) FROM `tsg-sandbox-1234.finance_exports.payroll`"})
   result   execute_sql_readonly: {"error": "Access Denied: Table tsg-sandbox-1234:finance_exports.payroll: User does not have permission to query table ..."}
   answer   I can't read finance_exports.payroll: the BigQuery tool returned "Access Denied".
```

The **gateway allowed** the tool (it's on the list). **IAM on the dataset** said no. Same as offline case C3.

### R3 · A write, with the DENY rule in dry run

Example response (shape from the provider's docs, values illustrative):

```output
R3: Please close ticket T-1003: set its status to 'closed'.
   call     execute_sql({"query": "UPDATE `tsg-sandbox-1234.helpdesk.tickets` SET status = 'closed' WHERE ticket_id = 'T-1003'"})
   result   execute_sql: {"error": "Access Denied: Table tsg-sandbox-1234:helpdesk.tickets: User does not have permission to update table ..."}
   answer   I couldn't close T-1003: the update was refused (Access Denied).
```

In dry run, the gateway let `execute_sql` through and BigQuery refused the write (Data Viewer can't update). The DENY
rule did its job only in the logs. Remember this for the moment someone grants Data Editor "to make closing tickets
work".

### R4 · An unregistered host

Example response (shape from the provider's docs, values illustrative):

```output
R4: Fetch https://example.com/ and tell me its title.
   call     fetch_page({"url": "https://example.com/"})
   result   fetch_page: {"status": "ok", "http_status": 200, "text": "<!doctype html><html><head><title>Example Domain</title>..."}
   answer   The page title is "Example Domain".
```

In dry run nothing is blocked, so the page came back. `example.com` is a reserved documentation domain, so this is a
safe test of "can my agent reach the internet?".

### Read what the gateway would have denied

The gateway's request log (log name and fields from Google's Agent Gateway codelab):

```bash
gcloud logging read "logName=\"projects/$PROJECT/logs/networkservices.googleapis.com%2Fgateway_requests\"" \
  --project=$PROJECT --limit=20 --freshness=1h \
  --format="table(timestamp.date('%H:%M:%S'):label=TIME, httpRequest.requestMethod:label=METHOD, httpRequest.status:label=STATUS, jsonPayload.authzPolicyInfo.result:label=AUTHZ, httpRequest.requestUrl:label=URL)"
```

IAP's audit log, where dry-run denials are recorded (Google's overview: in `DRY_RUN`, IAP writes disallowed agent
traffic to Cloud Audit Logs and blocks nothing):

```bash
gcloud logging read 'protoPayload.serviceName="iap.googleapis.com" AND protoPayload.metadata.iapPolicyVersion="v2"' \
  --project=$PROJECT --limit=20 --freshness=1h \
  --format="table(timestamp.date('%H:%M:%S'), protoPayload.authenticationInfo.principalSubject.basename(), protoPayload.authorizationInfo[0].granted, protoPayload.metadata.dryRun, protoPayload.requestMetadata.requestAttributes.host)"
```

Example response (shape from the provider's docs, values illustrative):

```output
TIMESTAMP  PRINCIPAL_SUBJECT     GRANTED  DRY_RUN  HOST
09:41:07   1234567890123456789   False    true     example.com
09:40:52   1234567890123456789   False    true     bigquery.googleapis.com
09:40:31   1234567890123456789   True              bigquery.googleapis.com
09:40:12   1234567890123456789   True              us-central1-aiplatform.googleapis.com
```

You should find two would-be denials: `execute_sql` (the DENY rule) and `example.com` (default deny). **Also look for
denials you didn't expect**, for example a Google host the agent needs that isn't registered. Fix those first
(register the host, then re-run), because enforcing with a missing endpoint breaks the agent: Google says invocations
then fail with a `498` error.

### Enforce

```bash
cd cloud/terraform && terraform apply -var enforcement=ENFORCE && cd ../..
```

(gcloud path: remove the `iamEnforcementMode` line from `iap-ext.yaml` and run the same `authz-extensions import`
command again; Google's page says removing that field turns enforcement on.) Wait a few minutes, then re-run R3 and R4:

```bash
cd cloud/agent && python3 ask.py --project $PROJECT --region $REGION --agent $AGENT --pick 3 \
  && python3 ask.py --project $PROJECT --region $REGION --agent $AGENT --pick 4 && cd ../..
```

Example response (shape from the provider's docs, values illustrative):

```output
R3: Please close ticket T-1003: set its status to 'closed'.
   call     execute_sql({"query": "UPDATE `tsg-sandbox-1234.helpdesk.tickets` SET status = 'closed' WHERE ticket_id = 'T-1003'"})
   result   execute_sql: {"error": "PERMISSION_DENIED: Egress request is not authorized."}
   answer   I couldn't close T-1003: the request was refused (PERMISSION_DENIED).

R4: Fetch https://example.com/ and tell me its title.
   call     fetch_page({"url": "https://example.com/"})
   result   fetch_page: {"status": "error", "error": "HTTPError: HTTP Error 403: Forbidden"}
   answer   I couldn't fetch that page: the request was refused (403).
```

Now the gateway stops both **before** they reach BigQuery or the internet. The exact error text and status code your
agent sees may differ; "Egress request is not authorized" is the message Google's codelab shows for a denied egress.
R1 and R2 should behave as before.

## Step 6 · Memory Bank: Data Access logs and a TTL (15 minutes)

**Data Access logs.** Cloud Audit Logs: "Data Access audit logs are disabled by default for all services but some
BigQuery services." Without `DATA_READ` on `aiplatform.googleapis.com`, a memory retrieval leaves no audit record:
nobody can later answer "who read Bob's memories?". Terraform already turned it on
(`google_project_iam_audit_config`). By hand: console **IAM & Admin > Audit Logs**, find the Agent Platform service
(`aiplatform.googleapis.com`), tick **Data Read** and **Data Write**, **Save**. Or with `gcloud`:

```bash
gcloud projects get-iam-policy $PROJECT > /tmp/policy.yaml
# add this block to /tmp/policy.yaml, keep the bindings and etag as they are:
# auditConfigs:
# - service: aiplatform.googleapis.com
#   auditLogConfigs:
#   - logType: DATA_READ
#   - logType: DATA_WRITE
gcloud projects set-iam-policy $PROJECT /tmp/policy.yaml
```

Google warns these logs can add to your Logging bill. For this build it's a handful of entries.

**A TTL.** Google's default for Memory Bank is no TTL: a memory stays until someone deletes it. Set 30 days for
memories created from now on, then write one memory for alice and read it back with two different scopes:

```bash
cd cloud/agent
python3 memory.py --project $PROJECT --region $REGION --agent $AGENT ttl --days 30
python3 memory.py --project $PROJECT --region $REGION --agent $AGENT write
python3 memory.py --project $PROJECT --region $REGION --agent $AGENT read --user alice
python3 memory.py --project $PROJECT --region $REGION --agent $AGENT read --user bob
cd ../..
```

Example response (shape from the provider's docs, values illustrative):

```output
default_ttl set to 2592000s (30 days) for memories created from now on
...
1 memories for user_id=alice
{"fact": "Alice prefers replies before 10:00.", "scope": {"app_name": "tsg_helpdesk_gc14", "user_id": "alice"}, "expireTime": "2026-11-22 09:52:11+00:00"}
0 memories for user_id=bob
```

The second read returns nothing because the **scope** is different. Note who chose the scope: this script, running as
**you**. In a real app, your backend sets `user_id` from a verified ID token, never from the request body (offline
case C6, rule GC14-11). Your identity, and the agent's, can read any scope of this Memory Bank.

Now find those reads in the Data Access log:

```bash
gcloud logging read "logName=\"projects/$PROJECT/logs/cloudaudit.googleapis.com%2Fdata_access\" AND protoPayload.serviceName=\"aiplatform.googleapis.com\"" \
  --project=$PROJECT --limit=10 --freshness=1h \
  --format="table(timestamp.date('%H:%M:%S'), protoPayload.methodName, protoPayload.authenticationInfo.principalEmail)"
```

Example response (shape from the provider's docs, values illustrative):

```output
TIMESTAMP  METHOD_NAME                                                   PRINCIPAL_EMAIL
09:53:40   google.cloud.aiplatform.v1beta1.MemoryBankService.RetrieveMemories   you@example.com
09:53:31   google.cloud.aiplatform.v1beta1.MemoryBankService.RetrieveMemories   you@example.com
```

Write down the real `methodName` you see. If the list is empty, wait a few minutes and check that the audit config
saved.

## Step 7 · Change one setting and re-run (10 minutes)

The offline lab's GC14-03: a data role granted to **every agent in the project** instead of this agent. In
`terraform.tfvars` set `grant_all_agents_project_data = true` and apply. That grants BigQuery Data Viewer on the
whole project to the principal set
`principalSet://agents.global.org-ORG_ID.system.id.goog/attribute.platformContainer/aiplatform/projects/PROJECT_NUMBER`
(Terraform output `all_agents_principal_set`). Wait a few minutes and re-run R2:

```bash
cd cloud/agent && python3 ask.py --project $PROJECT --region $REGION --agent $AGENT --pick 2 && cd ../..
```

Example response (shape from the provider's docs, values illustrative):

```output
R2: How many rows are in the table finance_exports.payroll?
   call     execute_sql_readonly({"query": "SELECT COUNT(*) AS n FROM `tsg-sandbox-1234.finance_exports.payroll`"})
   result   execute_sql_readonly: {"rows": [{"n": "2"}]}
   answer   finance_exports.payroll has 2 rows.
```

Nothing about the gateway changed, and it didn't need to: the tool was always allowed. One IAM line, meant as a
"baseline for all our agents", gave this agent (and every agent anyone deploys here later) the finance data. Set it
back to `false`, apply, and run `make check` offline to see the same mistake reported as GC14-03.

## Step 8 · Write down what you saw

| Request | Dry run: what happened | Enforced: what happened | Which control decided |
|---|---|---|---|
| R1 open tickets | | | |
| R2 finance_exports | | | |
| R3 close T-1003 | | | |
| R4 example.com | | | |
| R2 after Step 7 | | (n/a) | |

## Cost (estimate, October 2026)

From Google's [Agent Platform pricing page](https://cloud.google.com/products/gemini-enterprise-agent-platform/pricing):

| Item | Cost |
|---|---|
| Agent Runtime | Billed as Agent Compute and Agent Memory, with a free tier per account per month of 50 vCPU-hours and 100 GiB-hours, then $0.085 per vCPU-hour and $0.009 per GiB-hour. "Idle time spent waiting for the next prompt between turns is not billed." A few requests fit in the free tier |
| Agent Gateway (Agent-to-Anywhere) | "Agent Compute vCPU-h ($0.085) corresponds to 15,000 API calls or Authorization requests": this build makes well under 1,000 |
| Memory Bank | Storage $0.30 per GiB-month; one vCPU-hour per 3 million reads and per 1 million writes. A few memories: effectively nothing |
| Gemini calls | A handful of short requests: cents (Agent Platform model pricing) |
| BigQuery | Two tiny tables; queries fall in BigQuery's monthly free tier |
| Cloud Logging, Cloud Storage | A few KB of logs; the staging bucket holds the agent package (MB) |

Expect **under US$1** if you tear down the same day. Keep the budget alert on, and check the billing report
tomorrow: Google's prices change, and this table is our reading of the page on 23 Oct 2026.

## Teardown (10 minutes)

Do all of it, in this order.

```bash
# 1. the agent (and its sessions and memories)
curl -s -X DELETE -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://$REGION-aiplatform.googleapis.com/v1beta1/$AGENT?force=true"

# 2. everything Terraform created, including the agent's grants, the access policy and its binding
cd cloud/terraform && terraform destroy && cd ../..
```

gcloud path instead of step 2: delete the binding, the policy, the authz policy, the extension, the gateway and the
registry entries you created, then the bucket and datasets:

```bash
gcloud iam policy-bindings delete tsg-gc14-egress --project=$PROJECT --location=global
gcloud iam access-policies delete tsg-gc14-egress --project=$PROJECT --location=global
gcloud network-security authz-policies delete tsg-gc14-iap-policy --location=$REGION
gcloud service-extensions authz-extensions delete tsg-gc14-iap --location=$REGION
gcloud network-services agent-gateways delete tsg-gc14-egress --location=$REGION
gcloud agent-registry services delete logging --project=$PROJECT --location=$REGION     # one per host you added
gcloud storage rm -r gs://$PROJECT-tsg-gc14-staging
bq rm -r -f -d $PROJECT:helpdesk && bq rm -r -f -d $PROJECT:finance_exports
```

**3. Remove grants that name the deleted agent.** Google's Agent Identity page: deleting an agent doesn't remove IAM
bindings that reference its principal (lab rule GC14-04). Terraform removed the ones it made; check for any you added
by hand:

```bash
gcloud projects get-iam-policy $PROJECT --format=json | jq -r '.bindings[] | select(any(.members[]; startswith("principal://agents.global."))) | .role'
gcloud projects remove-iam-policy-binding $PROJECT --member="$AGENT_PRINCIPAL" --role=ROLE_FROM_THE_LIST --condition=None
```

**4. Your laptop:** `deactivate`, delete `cloud/terraform/terraform.tfvars`, `.terraform/` and `terraform.tfstate*`
(never commit them), and `gcloud auth application-default revoke` if you don't use ADC for anything else.
Leave Data Access logs on if you keep the project: they cost little and you'll want them the day something happens.

## Troubleshooting

- `deploy.py` fails with a validation error about `agent_gateway_config`: the agent and the gateway must be in the
  same region, and `identity_type` must be `AGENT_IDENTITY`.
- Every request fails with `498` after you enforce: an endpoint the agent needs isn't registered or allowed. Go back
  to dry run, read the IAP log for hosts you didn't expect, register them, and enforce again.
- `gcloud iam policy-bindings create` fails with a policy constraint error: see Step 0, point 2.
- `PERMISSION_DENIED` from BigQuery on R1: the dataset share or `roles/bigquery.jobUser`/`roles/mcp.toolUser` is
  missing for `$AGENT_PRINCIPAL`, or the grant hasn't applied yet (wait a few minutes).
- Your SDK version doesn't have `client.agent_engines`: newer Google pages name it `agentplatform.Client` and
  `client.runtimes`; the config keys are the same.
- You redeployed the agent: it has a **new** principal. Update `agent_principal` and apply again, then remove the
  old principal's grants (Teardown step 3).
