# GC14 console rehearsal notes (13 Nov 2026)

Working notes for the recording script. Console in the owner's account; Cloud Shell only where the console can't.
Region `us-central1`, BigQuery datasets in `US`. In progress: sections are added as each step is rehearsed.

## Before you start
- APIs (one gcloud line, the guide's Step 1 Path B list): enabled from Cloud Shell; the console's "Enable APIs"
  banner on every Agent Platform page lists ~20 APIs: don't click it.
- Cloud Shell has gcloud 592.0.0: `agent-gateways`, `agent-registry`, `authz-extensions` and `access-policies` all exist.

## Step 1 · The gateway (console) and two fixes the console can't make
- Agent Platform > **Gateways** > **Add gateway** (side panel): **Name** `tsg-gc14-egress`; **Region** `us-central1
  (Iowa)`; Deployment mode Google-managed (fixed); **Agent registry** auto-fills
  `//agentregistry.googleapis.com/projects/PROJECT_ID/locations/us-central1` (read-only); Governed access path
  **Agent-to-anywhere (egress)**; Access authorisation (IAP): **Audit only** ("Permit all traffic through the gateway <!-- style-ok: quotes the UK console -->
  and generate audit logs. Google Cloud IAM policies are not enforced.") = dry run, or **Enforce policies**; Policy
  model **Unified Access Policy**; AI Security **Enable Model Armor** (off); Connectivity template toggles (off).
  **Add gateway**. The list shows the row at once; creation takes about 2 minutes.
- That one panel makes three resources: the gateway, an authz extension `tsg-gc14-egress-iap-authzextension`
  (`iap.googleapis.com`, metadata `iamEnforcementMode: DRY_RUN`, `iapPolicyVersion: V2`, `timeout: 10s`) and an authz
  policy `tsg-gc14-egress-iap-authzpolicy`.
- **Finding 1: the console's extension is `failOpen: true`.** If IAP can't answer, the gateway lets traffic through.
  The guide (and Terraform) set `failOpen: false`. The console has no field for it. Fix in Cloud Shell:
  `gcloud service-extensions authz-extensions describe ... --format=yaml` > edit `failOpen: false` > `... import`.
  Right after creation the import fails with "The resource is being created and therefore can not be updated yet":
  wait a few minutes. Teach this on camera: the console default fails open.
- **Finding 2: the console registers only the regional registry.** Google's own MCP servers (BigQuery's included)
  are registered in `global`. Fix: `gcloud network-services agent-gateways import` with both registries (the guide's
  `gateway.yaml`). The gateway details page has no edit for registries.

## Step 1 · Agent Registry (console)
- Agent Platform > **Agent Registry**: tabs Agents (46, Google's system agents), **MCP Servers (21)** (Google's,
  in `global`; **BigQuery MCP server** lists **9 tools**, the guide's rule names 6), **Endpoints (0)**, Skills.
- Endpoints > **Add endpoint** > **GCP service endpoint** (choices: only *Vertex AI Platform (aiplatform)* and *Gemini
  Enterprise (discoveryengine)*) or **Custom endpoint**. Vertex AI Platform + Region `us-central1` shows
  "Automatically generated endpoint URL variants": Base, Base mTLS, Locational, Locational mTLS, Regional REP, and
  says "System APIs (Cloud Resource Manager) and platform APIs (logging, monitoring, trace, OAuth2) are
  automatically permitted." **Save** > "Created Vertex AI Platform (aiplatform)". One endpoint, five URLs.
- So the guide's ~21-host list may be unnecessary now; this rehearsal tests the agent with only this endpoint.

## Step 1 · Datasets, rows, staging bucket
- Same forms as GC11 (dataset) and GC13 (bucket); done in Cloud Shell here: `bq --location=US mk -d helpdesk`,
  `finance_exports`, the guide's INSERTs, `gcloud storage buckets create gs://PROJECT_ID-tsg-gc14-staging`.

## Step 4 · Policies (console) - form seen, rules below once the agent exists
- Agent Platform > **Policies** > **Access policies** > **Create** ("Create rules"): Policy name (ID `default-policy`,
  **Edit**), **New rule**: Rule description, **Rule effect** Allow / Deny, **Select principal(s)**: All agents in this
  project / All agents in the scoped project / **Individual agents** / Specific agents in the scoped project / Custom
  principal set; **Select resource(s)**: Standard / Custom, then Registry / Agent / **MCP server** / **Endpoint** /
  **Unregistered endpoint**. "For this policy to have an effect, it will separately need to be enforced by an Agent
  Gateway."
