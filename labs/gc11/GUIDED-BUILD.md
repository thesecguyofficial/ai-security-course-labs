# GC11 guided build: the hardened Helpdesk model access in your own project (least privilege, private path, CMEK, logs, region)

The offline lab (README Steps 1 to 7) checks a twin at $0, and README Step 8 deploys the Terraform in two commands.
This guide builds the same foundation **piece by piece**, so you see every control go in and then prove it works:
a predict-only identity with no keys, a VM with no internet route that reaches Gemini through a Private Service
Connect endpoint, a customer-managed key on the data, Data Access and request-response logging, and a pinned
regional endpoint. About 90 minutes in **your own** sandbox project (the GC10 project is fine). Cost: cents, plus a
small VM while it runs (table at the end). Teardown is the last section: do it the same day.

> **Read this first: about the responses shown below.** We wrote this guide without access to a Google Cloud
> project, so **no response in this file comes from a real run**. Every response block is labelled
> **"Example response (shape from Google docs, values illustrative)"**. Field names come from Google's API
> definitions and reference pages: Gemini
> ([`prediction_service.proto`](https://github.com/googleapis/googleapis/blob/master/google/cloud/aiplatform/v1/prediction_service.proto)),
> errors ([`error_reason.proto`](https://github.com/googleapis/googleapis/blob/master/google/api/error_reason.proto)),
> audit logs ([`AuditLog`](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)),
> request-response logging ([Google's page](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/multimodal/request-response-logging)).
> **The values are our guesses.** The serial-port lines come from the lab's own `smoke_call.sh.tftpl`, so their
> format is real; the values aren't. Paste your real results into the table in Step 4.

Throughout: `PROJECT_ID`, `PROJECT_NUMBER` (`gcloud projects describe PROJECT_ID --format="value(projectNumber)"`),
`REGION` = `europe-west4` (zone `europe-west4-a`), model `gemini-3.1-flash-lite`, and you run commands from
`labs/gc11`. The names (`chatbot-runtime`, `helpdesk-vpc`, `tsgapis`, `10.100.0.2`, `helpdesk-eu`, `ai_logs`) match
the Terraform, so you can switch paths at any point. Check the model is offered in your region on Google's model page
before you start: we couldn't read the location table for it.

## Step 0 · Before you start (10 minutes)

1. **Your own sandbox project**, never a work project. GC10's **budget alert and spend cap** in place first
   (GC10 guided build Step 0 and 2f).
2. **Pick one build path and stay on it:** console (Path A), gcloud (Path B) or Terraform (Path C, README Step 8:
   `make cost`, `make plan`, `make up` with `create_test_vm = true`). Path C users skip to Step 2.
3. **APIs** (the same list as `terraform/identity.tf`):

   ```bash
   gcloud config set project PROJECT_ID
   gcloud services enable aiplatform.googleapis.com bigquery.googleapis.com cloudkms.googleapis.com \
     compute.googleapis.com dns.googleapis.com iam.googleapis.com servicedirectory.googleapis.com
   ```

4. **Permissions.** As project owner you can build everything except the organization pieces. The model allow-list
   needs Organization Policy Administrator on an organization (lesson 10.3), and the VPC Service Controls perimeter
   needs an organization and an access policy (lesson 11.2). Without one, skip 1f; the offline `make dryrun-report`
   and `make challenge` cover it.

## Step 1 · Build it from zero (45 minutes)

Each part shows the console path, then the gcloud commands. Labels come from the Google page linked in each part;
where we couldn't check a label we say "(label may differ slightly)".

### 1a. Identity: two service accounts, no keys, a predict-only role (lesson 11.1)

**Console.** **IAM & Admin** > **Service Accounts** > **Create service account**: `chatbot-runtime`, then
`ticket-summariser`, no roles yet, **Done** (label may differ slightly). Then the custom role, from Google's
[custom roles](https://docs.cloud.google.com/iam/docs/creating-custom-roles) page: **Roles** page, pick your project,
**Create custom role**, **Title** `Helpdesk model caller`, **ID** `helpdeskModelCaller`, **Role launch stage**
General Availability, **Add Permissions**, find `aiplatform.endpoints.predict`, **Add Permissions**, **Create**. Then
**IAM** > **Grant access**: both service accounts, role **Helpdesk model caller** (label may differ slightly).

**gcloud.**

```bash
gcloud iam service-accounts create chatbot-runtime --display-name="TSG Helpdesk runtime"
gcloud iam service-accounts create ticket-summariser --display-name="Ticket summariser"
gcloud iam roles create helpdeskModelCaller --project=PROJECT_ID --title="Helpdesk model caller" \
  --description="Call Agent Platform models. Nothing else." --permissions=aiplatform.endpoints.predict --stage=GA
for SA in chatbot-runtime ticket-summariser; do
  gcloud projects add-iam-policy-binding PROJECT_ID --role="projects/PROJECT_ID/roles/helpdeskModelCaller" \
    --member="serviceAccount:$SA@PROJECT_ID.iam.gserviceaccount.com"
done
```

No `keys create` anywhere: the VM gets credentials from its attached account (lesson 11.1, "the preferred method for
finding credentials in a production environment on Google Cloud").

### 1b. Network: no internet route, Google APIs through Private Service Connect (lesson 11.2)

**Console.** **VPC network** > **Create VPC network**: name `helpdesk-vpc`, subnet creation mode **Custom**, one
subnet `helpdesk-eu` in your region, range `10.10.0.0/24`, **Private Google Access** On, **Create** (label may
differ slightly). The endpoint, from Google's
[configure PSC for Google APIs](https://docs.cloud.google.com/vpc/docs/configure-private-service-connect-apis) page:
**Private Service Connect** > **Connected endpoints** tab > **Connect endpoint**, **Target** **VPC-SC**, **Endpoint
name** `tsgapis` (1 to 20 lowercase letters and numbers, starting with a letter), **Network** `helpdesk-vpc`, **IP
Address** > **Create IP address** `10.100.0.2`, **Save**, **Add endpoint**. Then **Cloud DNS** > **Create zone**:
**Private**, DNS name `googleapis.com.`, network `helpdesk-vpc`; add an **A** record for `googleapis.com.` to
`10.100.0.2` and a **CNAME** `*.googleapis.com.` to `googleapis.com.`. Last, two firewall rules under **VPC network**
> **Firewall** (labels may differ slightly): egress deny all to `0.0.0.0/0` at priority 65000, and egress allow
TCP 443 to `10.100.0.2/32` at priority 1000.

**gcloud.**

```bash
gcloud compute networks create helpdesk-vpc --subnet-mode=custom
gcloud compute networks subnets create helpdesk-eu --network=helpdesk-vpc --region=europe-west4 \
  --range=10.10.0.0/24 --enable-private-ip-google-access
gcloud compute addresses create psc-google-apis --global --purpose=PRIVATE_SERVICE_CONNECT \
  --addresses=10.100.0.2 --network=helpdesk-vpc
gcloud compute forwarding-rules create tsgapis --global --network=helpdesk-vpc \
  --address=psc-google-apis --target-google-apis-bundle=vpc-sc
gcloud dns managed-zones create googleapis-private --dns-name=googleapis.com. --visibility=private \
  --networks=helpdesk-vpc --description="Google APIs through the PSC endpoint"
gcloud dns record-sets create googleapis.com. --zone=googleapis-private --type=A --ttl=300 --rrdatas=10.100.0.2
gcloud dns record-sets create "*.googleapis.com." --zone=googleapis-private --type=CNAME --ttl=300 \
  --rrdatas=googleapis.com.
gcloud compute firewall-rules create deny-all-egress --network=helpdesk-vpc --direction=EGRESS \
  --action=DENY --rules=all --destination-ranges=0.0.0.0/0 --priority=65000
gcloud compute firewall-rules create allow-google-apis-egress --network=helpdesk-vpc --direction=EGRESS \
  --action=ALLOW --rules=tcp:443 --destination-ranges=10.100.0.2/32 --priority=1000
gcloud compute forwarding-rules describe tsgapis --global      # Google's own check
```

Why `vpc-sc` and not `all-apis`: it only reaches APIs that support VPC Service Controls, which is what you'd put in a
perimeter. One open question from lesson 11.2: no Google page we found says the `vpc-sc` bundle serves the regional
host `europe-west4-aiplatform.googleapis.com`. Test 1 in Step 2 answers it for your project.

### 1c. Encryption: your own key on the data, and the cache (lesson 11.3)

**Console.** **Security** > **Key Management** > **Create key ring** `helpdesk-eu`, location type **Region**, your
region; then **Create key** `helpdesk-data`, purpose symmetric encrypt/decrypt, rotation period 90 days (labels may
differ slightly). For the BigQuery datasets: **BigQuery** > your project > **Create dataset** `helpdesk_tickets`,
same region, and under the advanced options choose a customer-managed key and select `helpdesk-data`; repeat for
`ai_logs` (labels may differ slightly: Google's CMEK page documents bq, SQL and the API for this, not the console).

**gcloud and bq**, from Google's
[BigQuery CMEK](https://docs.cloud.google.com/bigquery/docs/customer-managed-encryption) page:

```bash
gcloud kms keyrings create helpdesk-eu --location=europe-west4      # key rings can't be deleted: lesson 11.3
gcloud kms keys create helpdesk-data --keyring=helpdesk-eu --location=europe-west4 --purpose=encryption \
  --rotation-period=90d --next-rotation-time=2027-01-20T00:00:00Z
bq show --encryption_service_account --project_id=PROJECT_ID          # creates and prints BigQuery's service account
gcloud kms keys add-iam-policy-binding helpdesk-data --keyring=helpdesk-eu --location=europe-west4 \
  --member="serviceAccount:bq-PROJECT_NUMBER@bigquery-encryption.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
KEY=projects/PROJECT_ID/locations/europe-west4/keyRings/helpdesk-eu/cryptoKeys/helpdesk-data
bq mk --dataset --location=europe-west4 --default_kms_key="$KEY" PROJECT_ID:helpdesk_tickets
bq mk --dataset --location=europe-west4 --default_kms_key="$KEY" PROJECT_ID:ai_logs
```

Dataset access, as in `terraform/identity.tf`, with BigQuery's `GRANT` statement (the `bq add-iam-policy-binding`
command only covers tables and views):

```bash
bq query --use_legacy_sql=false \
 'GRANT `roles/bigquery.dataViewer` ON SCHEMA `PROJECT_ID.helpdesk_tickets` TO "serviceAccount:chatbot-runtime@PROJECT_ID.iam.gserviceaccount.com"'
bq query --use_legacy_sql=false \
 'GRANT `roles/bigquery.dataEditor` ON SCHEMA `PROJECT_ID.helpdesk_tickets` TO "serviceAccount:ticket-summariser@PROJECT_ID.iam.gserviceaccount.com"'
```

Nobody gets `ai_logs` except your incident readers (lesson 11.4). The cache: in-memory only, the challenge's answer
(GC11-11). No console page in the sources we read, so it's the REST call from lesson 11.3:

```bash
curl -s -X PATCH -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
  "https://europe-west4-aiplatform.googleapis.com/v1/projects/PROJECT_ID/cacheConfig" \
  -d '{"name": "projects/PROJECT_ID/cacheConfig", "disableCache": false, "retentionConfig": {"retentionType": "EPHEMERAL"}}'
```

### 1d. Logging: who called, and what was said (lesson 11.4)

**Data Access logs.** Console, from Google's
[configure Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) page:
**IAM & Admin** > **Audit Logs**, select the Agent Platform API row (it may still say Vertex AI API), **Permission
types**, tick **Data Read** and **Data Write**, **Save**. gcloud: as in GC10 Step 2b, add to the policy file

```json
"auditConfigs": [{"service": "aiplatform.googleapis.com",
                  "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]
```

**Request-response logging.** Google's page marks it **Preview** and documents only the SDK and REST, no console.
Our script sends `setPublisherModelConfig` (v1beta1) with `samplingRate` 1 into
`bq://PROJECT_ID.ai_logs.request_response_logging`; "the Dataset must exist and table must not exist" (lesson 11.4):

```bash
terraform/scripts/request_response_logging.sh on PROJECT_ID europe-west4
terraform/scripts/request_response_logging.sh show PROJECT_ID europe-west4
```

Example response (shape from Google docs, values illustrative), from `on`:

```json
{
  "name": "projects/PROJECT_ID/locations/europe-west4/operations/1234567890123456789",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.aiplatform.v1beta1.SetPublisherModelConfigOperationMetadata",
    "genericMetadata": {"createTime": "2026-10-22T09:00:00.000000Z", "updateTime": "2026-10-22T09:00:00.000000Z"}
  }
}
```

It's an operation, not the final state, and Google says "Logging configurations can take a few minutes to take
effect". Run `show` a few minutes later: you want `loggingConfig` with `"enabled": true`.

### 1e. Region pinning (lesson 11.5)

The pin is the **host and location your code calls**: `europe-west4-aiplatform.googleapis.com` and
`locations/europe-west4`, never `aiplatform.googleapis.com` with `locations/global`. In this build it lives in the
VM's startup script (1g); in a real app it's one reviewed setting, like the twin's `app.json`. The KMS key ring and
datasets in 1c are in the same region, so data at rest stays there too. With an organization, the allow-list
(`publishers/google/models/gemini-3.1-flash-lite:predict`) is `terraform/orgpolicy.tf`, or the GC10 guided build 2g
steps on your folder.

### 1f. Only with an organization: the perimeter, in dry run (lesson 11.2)

```bash
gcloud access-context-manager perimeters dry-run create helpdesk --policy=ACCESS_POLICY_ID \
  --perimeter-title=helpdesk --perimeter-resources=projects/PROJECT_NUMBER \
  --perimeter-restricted-services=aiplatform.googleapis.com,bigquery.googleapis.com,storage.googleapis.com
```

Dry run logs violations and blocks nothing. Read a week of them before you enforce (`make dryrun-report` is the
offline rehearsal). Terraform: set `access_policy_id` in `terraform.tfvars`.

### 1g. The test VM: the Helpdesk's stand-in

One small VM with **no external IP**, running as `chatbot-runtime`. At boot it calls Gemini once through the private
path and writes the result to its serial port. Render the lab's startup script, then create the VM:

```bash
sed -e 's/${project}/PROJECT_ID/g' -e 's/${region}/europe-west4/g' \
    -e 's#${model}#publishers/google/models/gemini-3.1-flash-lite#g' -e 's/%%/%/g' \
    terraform/scripts/smoke_call.sh.tftpl > smoke.sh
gcloud compute instances create helpdesk-vm --zone=europe-west4-a --machine-type=e2-small \
  --subnet=helpdesk-eu --no-address --shielded-secure-boot \
  --service-account=chatbot-runtime@PROJECT_ID.iam.gserviceaccount.com --scopes=cloud-platform \
  --image-family=debian-12 --image-project=debian-cloud --metadata-from-file=startup-script=smoke.sh
```

Console: **Compute Engine** > **VM instances** > **Create instance**, `e2-small`, Debian 12, under networking set
**External IPv4 address** to **None** on the `helpdesk-eu` subnet, under security pick `chatbot-runtime` as the service
account, paste `smoke.sh` into the startup script box (labels may differ slightly).

`--scopes=cloud-platform` looks broad, and it's what `terraform/vm.tf` uses too: the scope lets the VM ask for a token
for Google APIs, and IAM (the predict-only role) decides what that token can do.

## Step 2 · Prove it: five tests (20 minutes)

### Test 1 · The private path works, the internet doesn't

Wait two minutes after the VM starts, then:

```bash
gcloud compute instances get-serial-port-output helpdesk-vm --zone=europe-west4-a | grep TSG-SMOKE
```

Example response (shape from the lab's startup script, values illustrative):

```text
TSG-SMOKE resolve: 10.100.0.2      googleapis.com europe-west4-aiplatform.googleapis.com
TSG-SMOKE generateContent HTTP 200
{"candidates": [{"content": {"role": "model", "parts": [{"text": "private"}]}, "finishReason": "STOP"}], ...
TSG-SMOKE internet test: 000blocked
```

Read it, line by line: the Agent Platform hostname resolves to **your** endpoint, `10.100.0.2` (the private zone did
that); the call came back `200` as `chatbot-runtime`; `https://example.com` got no answer at all (`000`, then the
script's `blocked`), because the only egress rule that allows anything points at the endpoint. If you see `HTTP 403`,
check the custom role binding (1a); if the resolve line is empty or the call hangs, check the DNS records and the
allow rule (1b). If DNS and firewall are right and it still fails, that's the `vpc-sc` bundle question from 1b:
write it down and try `--target-google-apis-bundle=all-apis` on a new endpoint.

### Test 2 · The workload identity can't do more than predict

Lesson 11.1's A2: a stolen `chatbot-runtime` credential shouldn't be able to deploy anything. Give **yourself** Token
Creator on that one account (never on the project), try to create an endpoint as it, then take the grant away. Use
your own Google account email for `YOUR_EMAIL`:

```bash
SA=chatbot-runtime@PROJECT_ID.iam.gserviceaccount.com
gcloud iam service-accounts add-iam-policy-binding "$SA" --member="user:YOUR_EMAIL" \
  --role="roles/iam.serviceAccountTokenCreator"
gcloud ai endpoints create --region=europe-west4 --display-name=should-fail --impersonate-service-account="$SA"
```

Example response (shape from Google docs, values illustrative):

```text
ERROR: (gcloud.ai.endpoints.create) PERMISSION_DENIED: Permission 'aiplatform.endpoints.create' denied on resource '//aiplatform.googleapis.com/projects/PROJECT_ID/locations/europe-west4' (or it may not exist).
```

Read it: the permission named is `aiplatform.endpoints.create`, which Agent Platform User would have granted
(lesson 10.3) and your custom role doesn't. Keep the Token Creator grant for Test 3, then remove it.

### Test 3 · The same identity, over the public path

Now call the model as `chatbot-runtime` from Cloud Shell or your laptop, outside the VPC:

```bash
TOKEN=$(gcloud auth print-access-token --impersonate-service-account="$SA")
curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://europe-west4-aiplatform.googleapis.com/v1/projects/PROJECT_ID/locations/europe-west4/publishers/google/models/gemini-3.1-flash-lite:generateContent" \
  -d '{"contents": [{"role": "user", "parts": [{"text": "Reply with one word: public"}]}], "generationConfig": {"maxOutputTokens": 10}}'
gcloud iam service-accounts remove-iam-policy-binding "$SA" --member="user:YOUR_EMAIL" \
  --role="roles/iam.serviceAccountTokenCreator"
```

Without a perimeter, expect `200`. That's the honest result, and the point of lesson 11.2: the private path keeps the
**VM** off the internet, but a stolen token still works from anywhere until VPC Service Controls checks where the call
comes from. With an **enforced** perimeter (1f, after the dry run), the same call is refused, and the record lands in
the Policy Denied log:

```bash
gcloud logging read 'log_id("cloudaudit.googleapis.com/policy")' --project=PROJECT_ID --freshness=1h --format=json
```

Example response (shape from Google docs, values illustrative), trimmed to the VPC-SC fields:

```json
{
  "protoPayload": {
    "methodName": "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
    "metadata": {
      "@type": "type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata",
      "violationReason": "NO_MATCHING_ACCESS_LEVEL",
      "securityPolicyInfo": {"servicePerimeterName": "accessPolicies/ACCESS_POLICY_ID/servicePerimeters/helpdesk"},
      "ingressViolations": [{"targetResource": "projects/PROJECT_NUMBER"}],
      "vpcServiceControlsUniqueId": "EXAMPLE_UNIQUE_ID",
      "dryRun": false
    }
  }
}
```

In dry run you'd see the same entry with `"dryRun": true` and a `200` for the caller. Without an organization, record
"200, no perimeter" and run `make challenge` for the perimeter half.

### Test 4 · The trail: who called, from where, and what was said

**Who and where** (Data Access log, a few minutes after Test 1):

```bash
gcloud logging read 'log_id("cloudaudit.googleapis.com/data_access") AND protoPayload.serviceName="aiplatform.googleapis.com"' \
  --project=PROJECT_ID --freshness=2h --format=json > my-audit.json
```

Example response (shape from Google docs, values illustrative), the VM's call, trimmed:

```json
{
  "protoPayload": {
    "serviceName": "aiplatform.googleapis.com",
    "methodName": "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
    "resourceName": "projects/PROJECT_ID/locations/europe-west4/publishers/google/models/gemini-3.1-flash-lite",
    "authenticationInfo": {"principalEmail": "chatbot-runtime@PROJECT_ID.iam.gserviceaccount.com"},
    "requestMetadata": {"callerIp": "10.10.0.2"},
    "authorizationInfo": [{"permission": "aiplatform.endpoints.predict", "granted": true}]
  }
}
```

Read it: `callerIp` is the VM's **internal** address. Google's AuditLog reference says that for a VM without an
external IP in the same project, `callerIp` "will be the VM's internal IPv4 address". Test 3's entry shows your
public address and a `serviceAccountDelegationInfo` naming you: that's what a stolen token used from outside looks
like (lesson 11.1, "the workload's account calling from an address that isn't the workload's"). `resourceName` names
`locations/europe-west4`: your residency evidence (lesson 11.5). Check the real `methodName` against the lab's
assumption, as in GC10.

**What was said** (request-response log, a few minutes after Test 1; Google says logging config "can take a few
minutes to take effect", so if the table is empty, reset the VM with `gcloud compute instances reset helpdesk-vm
--zone=europe-west4-a` and look again):

```bash
bq query --use_legacy_sql=false \
 'SELECT logging_time, model, api_method, LEFT(TO_JSON_STRING(full_request), 200) AS req,
         LEFT(TO_JSON_STRING(full_response), 200) AS resp
  FROM `PROJECT_ID.ai_logs.request_response_logging` ORDER BY logging_time DESC LIMIT 5'
```

The column names are from Google's request-response logging page (`endpoint`, `deployed_model_id`, `logging_time`,
`request_id`, `request_payload`, `response_payload`, `model`, `model_version`, `api_method`, `full_request`,
`full_response`, `metadata`, `otel_log`); we didn't see their types, which is why the query wraps them in
`TO_JSON_STRING`. You should find the VM's "Reply with the single word: private" and the answer. That row is customer
data in your own dataset, under your key: lesson 11.4's trade-off.

### Test 5 · Your key, switched off

Lesson 11.3: "if you disable or destroy the CMEK, that data can't be accessed". Disable the key version and query
`ai_logs` again:

```bash
gcloud kms keys versions disable 1 --key=helpdesk-data --keyring=helpdesk-eu --location=europe-west4
```

(Console, from Google's [enable and disable key versions](https://docs.cloud.google.com/kms/docs/enable-disable)
page: **Key Management**, the key ring, the key, tick version 1, **Disable**, confirm **Disable**.) Cloud KMS says
disabling is "consistent within one minute", but BigQuery's CMEK page says the effect on BigQuery "doesn't take place
instantly, but happens within an hour". Re-run the `bq query` from Test 4 every ten minutes until it fails.

Example response (shape from Google docs, values illustrative):

```text
BigQuery error in query operation: Error processing job 'PROJECT_ID:bqjob_r1a2b3c4d5_0000019a2b3c4d5e_1': The Cloud KMS key projects/PROJECT_ID/locations/europe-west4/keyRings/helpdesk-eu/cryptoKeys/helpdesk-data is disabled.
```

Read it: one command made a whole dataset unreadable, for you and for anyone who copied your credentials. That's the
auditor's question from the lab ("can we make it unreadable in one step?") answered yes. Now turn it back on:

```bash
gcloud kms keys versions enable 1 --key=helpdesk-data --keyring=helpdesk-eu --location=europe-west4
```

Google's BigQuery page warns that performance can stay degraded for a while after access is restored. And while the
key was off, Agent Platform had nowhere to write request-response rows. We haven't tested what it does with them;
expect a gap and check the table.

## Step 3 · Change one setting and re-run: the residency trap

Lesson 11.5's trap, for real. A developer moves the Helpdesk from the regional endpoint to the `eu` multi-region one
"for availability". Change only the host and location in the VM's script and restart it:

```bash
sed -e 's#https://europe-west4-aiplatform.googleapis.com#https://aiplatform.eu.rep.googleapis.com#' \
    -e 's#locations/europe-west4#locations/eu#' \
    -e 's#getent hosts europe-west4-aiplatform.googleapis.com#getent hosts aiplatform.eu.rep.googleapis.com#' \
    smoke.sh > smoke-eu.sh
gcloud compute instances add-metadata helpdesk-vm --zone=europe-west4-a --metadata-from-file=startup-script=smoke-eu.sh
gcloud compute instances reset helpdesk-vm --zone=europe-west4-a
# two minutes later
gcloud compute instances get-serial-port-output helpdesk-vm --zone=europe-west4-a | grep TSG-SMOKE | tail -4
```

(Path C users: render `smoke.sh` with the `sed` line from 1g first.)

Example response (shape from the lab's startup script, values illustrative):

```text
TSG-SMOKE resolve: 10.100.0.2      googleapis.com aiplatform.eu.rep.googleapis.com
TSG-SMOKE generateContent HTTP 000
TSG-SMOKE internet test: 000blocked
```

Read it: the wildcard record in your private zone sends the `rep` hostname to the same endpoint, but that endpoint
is for global Google APIs (lesson 11.2: `all-apis` "Excludes `*.rep.googleapis.com`", and nothing says `vpc-sc`
covers them), and Private Google Access "doesn't support regional and multi-regional endpoints". Any code other than
`200` is the trap working: the private path breaks. Whatever code you get, write it down. The tempting fix under
pressure is the global endpoint, and residency is gone. The right fix is a PSC endpoint for regional Google APIs
(lesson 11.5), which this guide doesn't build. Put the regional script back:

```bash
gcloud compute instances add-metadata helpdesk-vm --zone=europe-west4-a --metadata-from-file=startup-script=smoke.sh
gcloud compute instances reset helpdesk-vm --zone=europe-west4-a
```

## Step 4 · Write down what you saw

| Test | What you expected | What you got | Same as the twin? |
|---|---|---|---|
| 1 Private path (resolve / HTTP / internet) | `10.100.0.2` / 200 / blocked | | L1 |
| 2 Deploy as `chatbot-runtime` | `PERMISSION_DENIED` on `aiplatform.endpoints.create` | | A2 |
| 3 Public path as `chatbot-runtime` | 200 without perimeter | | A1, A5 |
| 4 Data Access `callerIp` and `methodName` / request-response row | internal IP / a row | | Q1, Q2 |
| 5 Query with key disabled (minutes until it failed) | error | | Q4 |
| Step 3 `eu` endpoint from the VM | not 200 | | residency trap |

Then run the live check and feed your real plan to the checker if you used Terraform:

```bash
terraform/scripts/check_live.sh PROJECT_ID europe-west4
```

## Cost (estimate, October 2026; prices change, so check the pages)

| Item | Price | This guide (about 3 hours) |
|---|---|---|
| PSC endpoint for Google APIs | $0.01 per hour, "No data charge" ([VPC pricing](https://cloud.google.com/vpc/pricing)) | $0.03 |
| Cloud DNS private zone | $0.000273973 per zone per hour, billed by the hour (about $0.20 a month); queries $0.40 per million ([Cloud DNS pricing](https://cloud.google.com/dns/pricing)) | under $0.01 |
| Cloud KMS key version | $0.000082192 per hour; versions scheduled for destruction count as active for the default 30 days ([KMS pricing](https://cloud.google.com/kms/pricing)) | about $0.06 including the 30 days |
| KMS operations | $0.03 per 10,000 | well under $0.01 |
| BigQuery | first 10 GiB storage and first 1 TiB of queries per month free ([pricing](https://cloud.google.com/bigquery/pricing)) | $0 |
| Cloud Logging | first 50 GiB per project per month free (GC10) | $0 |
| Gemini calls | a handful of very short calls | fractions of a cent |
| `e2-small` VM and its boot disk | billed per second at your region's rate | **not estimated here**: we couldn't open Compute Engine's price page; check it, and delete the VM after Step 3 |

Free Trial: "You will not be billed for any Google Cloud usage during your Free Trial"
([Free Trial](https://docs.cloud.google.com/free/docs/free-cloud-features)).

## Teardown (15 minutes)

**Path C (Terraform):**

```bash
terraform/scripts/request_response_logging.sh off PROJECT_ID europe-west4
make down
```

**Paths A and B**, in this order:

```bash
terraform/scripts/request_response_logging.sh off PROJECT_ID europe-west4
gcloud compute instances delete helpdesk-vm --zone=europe-west4-a --quiet
gcloud compute firewall-rules delete deny-all-egress allow-google-apis-egress --quiet
gcloud dns record-sets delete "*.googleapis.com." --zone=googleapis-private --type=CNAME
gcloud dns record-sets delete googleapis.com. --zone=googleapis-private --type=A
gcloud dns managed-zones delete googleapis-private
gcloud compute forwarding-rules delete tsgapis --global --quiet
gcloud compute addresses delete psc-google-apis --global --quiet
gcloud compute networks subnets delete helpdesk-eu --region=europe-west4 --quiet
gcloud compute networks delete helpdesk-vpc --quiet
bq rm -r -f -d PROJECT_ID:ai_logs
bq rm -r -f -d PROJECT_ID:helpdesk_tickets
gcloud kms keys versions destroy 1 --key=helpdesk-data --keyring=helpdesk-eu --location=europe-west4
for SA in chatbot-runtime ticket-summariser; do
  gcloud projects remove-iam-policy-binding PROJECT_ID --role="projects/PROJECT_ID/roles/helpdeskModelCaller" \
    --member="serviceAccount:$SA@PROJECT_ID.iam.gserviceaccount.com"
  gcloud iam service-accounts delete "$SA@PROJECT_ID.iam.gserviceaccount.com" --quiet
done
gcloud iam roles delete helpdeskModelCaller --project=PROJECT_ID
gcloud access-context-manager perimeters delete helpdesk --policy=ACCESS_POLICY_ID   # only if you did 1f
```

If the key rotated while you worked, destroy every enabled version (`gcloud kms keys versions list --key=helpdesk-data
--keyring=helpdesk-eu --location=europe-west4`). The key ring and key stay forever ("Key rings can't be deleted",
lesson 11.3); a destroyed key costs nothing once the 30 days pass. Leave Data Access logs on if you'll do GC12 here.
Delete `smoke.sh`, `smoke-eu.sh` and `my-audit.json`. If the project was only for this course, `gcloud projects delete
PROJECT_ID` is the cleanest end.
