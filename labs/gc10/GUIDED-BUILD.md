# GC10 guided build: inventory your Google Cloud AI footprint and lock it down, in your own project

The offline lab (README Steps 1 to 7) teaches the mechanics at $0 on a fictional company. This guide does the same
job on a real project, **your own** sandbox: find which AI services are on, who can call the models, which keys and
identities exist, which guardrails and logs are in place, then close the gaps and prove each fix with a request.
About 60 minutes. Cost: cents at most (table at the end). Teardown is the last section: do it.

README Step 8 is the short version of this guide. If you already did it, reuse that project and skip what you've done.

> **Read this first: about the responses shown below.** We wrote this guide without access to a Google Cloud
> project, so **no response in this file comes from a real run**. Every response block is labelled
> **"Example response (shape from Google docs, values illustrative)"**. Field names come from Google's API
> definitions in their JSON (camelCase) form: Gemini
> ([`prediction_service.proto`](https://github.com/googleapis/googleapis/blob/master/google/cloud/aiplatform/v1/prediction_service.proto)),
> error details ([`error_reason.proto`](https://github.com/googleapis/googleapis/blob/master/google/api/error_reason.proto))
> and audit logs ([`AuditLog`](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)).
> **The values are our guesses.** Your real responses will differ: that's the point of running them. Paste your real
> results into the table in Step 5.

Throughout: `PROJECT_ID` = your project, `PROJECT_NUMBER` = its number (`gcloud projects describe PROJECT_ID
--format="value(projectNumber)"`), `BILLING_ACCOUNT_ID` = your billing account, and the model is
`gemini-3.1-flash-lite` on the **global** endpoint, as in README Step 8. Region pinning is Module 11's job (lesson 11.5).
Run everything from `labs/gc10` in Cloud Shell or on a laptop with the `gcloud` CLI.

## Step 0 · Before you start (10 minutes)

1. **A sandbox project you own**, ideally on the Free Trial (lesson 10.5: "You will not be billed for any Google Cloud
   usage during your Free Trial"). Not a work project, and never a work organization without written permission
   (lesson 0.8).
2. **A budget alert first.** Console: **Billing** > **Budgets & alerts** > **Create budget**, scope it to this project,
   an amount of $5, keep the default thresholds, **Finish** (label may differ slightly). Or:

   ```bash
   gcloud billing budgets create --billing-account=BILLING_ACCOUNT_ID --display-name="gc10-build alerts" \
     --budget-amount=5USD --filter-projects=projects/PROJECT_ID \
     --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0
   ```

   Remember lesson 10.5: this only emails you, hours late. Step 2f adds a spend cap.
3. **APIs.** Agent Platform, API Keys and Cloud Asset (for Policy Analyzer in Step 1b):

   ```bash
   gcloud config set project PROJECT_ID
   gcloud services enable aiplatform.googleapis.com apikeys.googleapis.com cloudasset.googleapis.com
   ```

   Console: **APIs & Services** > **Library**, search each one, **Enable** (label may differ slightly; the Agent
   Platform API may still be listed under its old name, Vertex AI API, lesson 10.1).
4. **Permissions.** As the project owner you can do Steps 1 to 4. In a shared project you'd need: Cloud Asset Viewer
   (`roles/cloudasset.viewer`) and Role Viewer for Policy Analyzer
   ([analyze IAM policies](https://docs.cloud.google.com/policy-intelligence/docs/analyze-iam-policies)), Agent
   Platform Admin to change the cache setting (lesson 10.2), and permission to create API keys and service accounts.
   **Organization Policy Administrator on an organization** is only needed for the optional Step 2g.

## Step 1 · Inventory: what AI do you have, and who can use it? (15 minutes)

Write each answer in the table in Step 5 as you go. This is the "before" picture.

### 1a. Which AI APIs are switched on?

```bash
gcloud services list --enabled --project=PROJECT_ID \
  --filter="config.name=(aiplatform.googleapis.com generativelanguage.googleapis.com)"
```

Console: **APIs & Services** > **Enabled APIs & services** (label may differ slightly). Two doors, two sets of
controls (lesson 10.1): `aiplatform.googleapis.com` is Agent Platform; `generativelanguage.googleapis.com` is the
Gemini API you reach with an AI Studio key. If the second one is on and nobody can say why, that's finding number one.

### 1b. Who can call a model?

Calling a model needs `aiplatform.endpoints.predict` (lesson 10.3). Ask Policy Analyzer who holds it, directly or
through a role, group or inherited grant:

```bash
gcloud asset analyze-iam-policy --project=PROJECT_ID --permissions=aiplatform.endpoints.predict
```

Console, from Google's page: open **Policy analyzer**, in **Analyze policies** click **Create custom query**, under
**Select query scope** choose your project, set **Parameter 1** to **Permission**, pick `aiplatform.endpoints.predict`,
then **Analyze** > **Run query**.

Read the result: each match shows the policy it came from (`attachedResourceFullName`, the `iamBinding` with its
`role` and `members`) and the identities it reaches (`identityList`). In a fresh personal project you should see your
own user through `roles/owner`. Anything you don't recognise is a finding. Google lists a limit of 20 policy
analysis queries per organization per day unless Security Command Center Premium or Enterprise is active, so run it
a handful of times, not in a loop. If the command errors in your project, fall back to the plain IAM policy:

```bash
gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members)" \
  --filter="bindings.role:(aiplatform editor owner)"
```

### 1c. Which identities and keys exist?

```bash
gcloud iam service-accounts list --project=PROJECT_ID
for SA in $(gcloud iam service-accounts list --project=PROJECT_ID --format="value(email)"); do
  echo "== $SA"; gcloud iam service-accounts keys list --iam-account="$SA" --managed-by=user
done
gcloud services api-keys list --project=PROJECT_ID --format=json > my-keys.json
python3 policy_checker.py --keys my-keys.json
```

What to look for: any user-managed service account key (lesson 10.0: a downloadable credential), any API key with no
`restrictions`, and any key with a `serviceAccountEmail` (an authorization key, lesson 10.4). The checker prints
`GC10-05` to `GC10-09` for the key mistakes it knows. Console: **IAM & Admin** > **Service Accounts** (open each, tab
**Keys**) and the **Credentials** page for API keys (label may differ slightly).

### 1d. Is anyone writing down model calls? Is Google caching prompts?

```bash
gcloud projects get-iam-policy PROJECT_ID --format=json > policy.json
python3 policy_checker.py --iam policy.json          # GC10-15 = no Data Access logs for aiplatform.googleapis.com
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://us-central1-aiplatform.googleapis.com/v1/projects/PROJECT_ID/cacheConfig"
```

Example response (shape from Google docs, values illustrative), the cache check:

```json
{"name": "projects/123456789012/cacheConfig"}
```

Read it (lesson 10.2): only `name` means caching is on, the default. `"disableCache": true` means it's off.

### 1e. Which guardrails apply?

```bash
gcloud org-policies describe vertexai.allowedModels --effective --project=PROJECT_ID
gcloud org-policies describe iam.managed.disableServiceAccountApiKeyCreation --effective --project=PROJECT_ID
```

With no policy on `vertexai.allowedModels`, "all models and actions are allowed" (lesson 10.3). A personal project
with no organization can't set either policy (lesson 10.3); write "no organization" and move on.

## Step 2 · Lock it down (20 minutes)

Each part has the console path and the command. Do one or the other, not both.

### 2a. Two test identities: one that may call models, one that may not

Lesson 10.3's fix: the workload gets its own service account with `roles/aiplatform.user` **on the project**, nothing
on the organization, no basic roles. The second account has no AI role at all: it's your "should be denied" caller.

```bash
gcloud iam service-accounts create gc10-caller --display-name="GC10 model caller"
gcloud iam service-accounts create gc10-nobody --display-name="GC10 no AI role"
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:gc10-caller@PROJECT_ID.iam.gserviceaccount.com" --role="roles/aiplatform.user"
```

To act as these accounts from your terminal, you need Service Account Token Creator **on each account**, not on the
project (lesson 11.1: "Don't grant access to service accounts at the Google Cloud project or folder level"). Use your
own Google account email for `YOUR_EMAIL`:

```bash
for SA in gc10-caller gc10-nobody; do
  gcloud iam service-accounts add-iam-policy-binding "$SA@PROJECT_ID.iam.gserviceaccount.com" \
    --member="user:YOUR_EMAIL" --role="roles/iam.serviceAccountTokenCreator"
done
```

Console: **IAM & Admin** > **Service Accounts** > **Create service account**, name it, grant **Agent Platform User**
(may still show as Vertex AI User) to `gc10-caller` only, **Done**. Then open each account, tab **Principals with
access** > **Grant access**, add yourself with **Service Account Token Creator** (labels may differ slightly).

Production note: a workload never needs Token Creator for itself. It gets the attached service account through
Application Default Credentials (lesson 10.4). The binding here is only so *you* can test as the account.

### 2b. Data Access audit logs on for Agent Platform

They're off by default, and without them Step 3's R4 has nothing to find. Console, from Google's
[configure Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) page:
**IAM & Admin** > **Audit Logs**, in the **Data Access audit logs configuration** table select the Agent Platform API
row (search "Agent Platform" or "Vertex AI"), in the panel open **Permission types**, tick **Data Read**, **Save**.

Or edit the policy file from 1d: keep `bindings` and `etag` exactly as they are and add

```json
"auditConfigs": [{"service": "aiplatform.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}]
```

then `gcloud projects set-iam-policy PROJECT_ID policy.json`. If it reports a conflict, someone changed the policy:
fetch it again and redo the edit. Run `python3 policy_checker.py --iam policy.json`: GC10-15 should be gone.

### 2c. One restricted API key (and delete the rest)

Lesson 10.4: prefer no key at all. You'll make one anyway, to see what restrictions do. It only works for Agent
Platform and only from `192.0.2.10`, a documentation address, so it will refuse your machine:

```bash
gcloud services api-keys create --project=PROJECT_ID --display-name=gc10-build \
  --api-target=service=aiplatform.googleapis.com --allowed-ips=192.0.2.10
gcloud services api-keys list --project=PROJECT_ID --format="value(name,displayName)"
gcloud services api-keys get-key-string KEY_ID --project=PROJECT_ID   # KEY_ID: last part of "name"
```

Console (Google's API keys page): **Credentials** > **Create credentials** > **API key**. Click the key's name; under
**API restrictions** choose **Restrict key** and select the Agent Platform API; under **Application restrictions**
choose **IP addresses**, **Add** `192.0.2.10`, **Done**, then **Save**.

Delete any key from 1c you can't justify: `gcloud services api-keys delete KEY_ID --project=PROJECT_ID` (it can be
restored for 30 days, lesson 10.4). Keep the key string out of files and screenshots.

### 2d. Switch off prompt caching (zero-retention projects)

Lesson 10.2: caching is on by default, and turning it off needs Agent Platform Admin. There's no console page in the
sources we read, so this is REST only:

```bash
curl -s -X PATCH -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
  "https://us-central1-aiplatform.googleapis.com/v1/projects/PROJECT_ID/cacheConfig" \
  -d '{"name": "projects/PROJECT_ID/cacheConfig", "disableCache": true}'
```

Run the GET from 1d again. You want `"disableCache": true`. (Lesson 11.3 shows the middle setting, in-memory only.)

### 2e. The second Gemini door

If 1a showed `generativelanguage.googleapis.com` and nothing in this project uses AI Studio keys, switch it off:
`gcloud services disable generativelanguage.googleapis.com --project=PROJECT_ID`. Don't do this on a project where
someone's app depends on it; ask first.

### 2f. A spend cap on Agent Platform

From lesson 10.5 and README Step 8b: **Billing** > **Budgets & alerts** > **Create new budget**, choose **Spend cap
enforcement** instead of *Alerts only*, a *single* project, the service *Gemini Enterprise Agent Platform (formerly
Vertex AI)*, an amount, **Finish** ([spend caps](https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps)).
The Budget API version is `gcp-twin/budget-spend-cap.json` (replace `PROJECT_NUMBER`). Spend caps are "limited to
first-party Google Cloud customers", so you may not see the option. Write that down if so.

### 2g. Only with an Organization: the model allow-list and the key constraint

Skip this if 1e said "no organization"; README Step 5 (`make twin-preview`) is the offline version.

```bash
# edit gcp-twin/allowed-models-dryrun.json: replace ORGANIZATION_ID, list only the models you use
python3 policy_checker.py --orgpolicy gcp-twin/allowed-models-dryrun.json
gcloud org-policies set-policy gcp-twin/allowed-models-dryrun.json --update-mask=policy.dry_run_spec
gcloud org-policies describe vertexai.allowedModels --effective --project=PROJECT_ID
```

In dry run, "violations of the policy are audit-logged, but the violating actions aren't denied", and changes "can
take up to 15 minutes to be fully enforced" (lesson 10.3). The key constraint: if 1e showed
`iam.managed.disableServiceAccountApiKeyCreation` not enforced, `fixes/orgpolicy-org-block-sa-api-keys.json` puts it
back (replace the organization number first).

Console, from Google's
[create organization policies](https://docs.cloud.google.com/organization-policy/create-organization-policies) page:
**Organization policies**, pick the organization in the project picker, select the constraint, **Manage policy**,
**Override parent's policy**, **Add a rule**, enter the values, then **Test changes** and **Set dry run policy**. Google
describes these steps for managed constraints; `vertexai.allowedModels` is a list constraint, so its value fields may
look different (labels may differ slightly).

## Step 3 · Prove it: five requests (15 minutes)

Save the request body once:

```bash
cat > hello.json <<'EOF'
{"contents": [{"role": "user", "parts": [{"text": "Say hello in five words."}]}],
 "generationConfig": {"maxOutputTokens": 50}}
EOF
URL="https://aiplatform.googleapis.com/v1/projects/PROJECT_ID/locations/global/publishers/google/models/gemini-3.1-flash-lite:generateContent"
```

### R1 · An identity that should be denied

```bash
TOKEN=$(gcloud auth print-access-token --impersonate-service-account=gc10-nobody@PROJECT_ID.iam.gserviceaccount.com)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$URL" -d @hello.json
```

Example response (shape from Google docs, values illustrative):

```json
{
  "error": {
    "code": 403,
    "message": "Permission 'aiplatform.endpoints.predict' denied on resource '//aiplatform.googleapis.com/projects/PROJECT_ID/locations/global/publishers/google/models/gemini-3.1-flash-lite' (or it may not exist).",
    "status": "PERMISSION_DENIED",
    "details": [{
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      "reason": "IAM_PERMISSION_DENIED",
      "domain": "googleapis.com",
      "metadata": {"permission": "aiplatform.endpoints.predict",
                   "resource": "projects/PROJECT_ID/locations/global/publishers/google/models/gemini-3.1-flash-lite"}
    }]
  }
}
```

Read it: `403` with `PERMISSION_DENIED`, and the `ErrorInfo` names the missing permission. That's IAM working. If you
get `200` instead, 1b missed a grant that reaches this account: run Policy Analyzer with
`--identity=serviceAccount:gc10-nobody@PROJECT_ID.iam.gserviceaccount.com` to find it.

### R2 · The identity that should work

```bash
TOKEN=$(gcloud auth print-access-token --impersonate-service-account=gc10-caller@PROJECT_ID.iam.gserviceaccount.com)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$URL" -d @hello.json
```

Example response (shape from Google docs, values illustrative):

```json
{
  "candidates": [{
    "content": {"role": "model", "parts": [{"text": "Hello there, nice to meet you."}]},
    "finishReason": "STOP"
  }],
  "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 7, "totalTokenCount": 14},
  "modelVersion": "gemini-3.1-flash-lite"
}
```

Read it: `usageMetadata` is what you pay for. If R2 fails with `403` right after Step 2a, wait a few minutes: IAM
changes take time to reach every service.

### R3 · A copied API key, used from the wrong place

The key string from 2c, sent in the header Google recommends (lesson 10.4):

```bash
curl -s -X POST -H "x-goog-api-key: KEY_STRING" -H "Content-Type: application/json" "$URL" -d @hello.json
```

Example response (shape from Google docs, values illustrative):

```json
{
  "error": {
    "code": 403,
    "message": "The provided API key has an IP address restriction. The originating IP address of the call (203.0.113.25) violates this restriction.",
    "status": "PERMISSION_DENIED",
    "details": [{
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      "reason": "API_KEY_IP_ADDRESS_BLOCKED",
      "domain": "googleapis.com",
      "metadata": {"consumer": "projects/123456789012", "service": "aiplatform.googleapis.com"}
    }]
  }
}
```

Read it: the reason `API_KEY_IP_ADDRESS_BLOCKED` is Google's documented code for "the caller IP of the request
violates API key IP address restrictions". No model ran, so this cost nothing. A stolen copy of this key is useless
anywhere but `192.0.2.10`.

### R4 · The trail: R1 and R2 in your audit logs

Give the logs a few minutes, then:

```bash
gcloud logging read 'log_id("cloudaudit.googleapis.com/data_access") AND protoPayload.serviceName="aiplatform.googleapis.com"' \
  --project=PROJECT_ID --freshness=1h --format=json > my-audit.json
python3 hunt.py --summary --file my-audit.json
```

Example response (shape from Google docs, values illustrative), one entry, trimmed:

```json
{
  "logName": "projects/PROJECT_ID/logs/cloudaudit.googleapis.com%2Fdata_access",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "aiplatform.googleapis.com",
    "methodName": "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
    "resourceName": "projects/PROJECT_ID/locations/global/publishers/google/models/gemini-3.1-flash-lite",
    "authenticationInfo": {
      "principalEmail": "gc10-caller@PROJECT_ID.iam.gserviceaccount.com",
      "serviceAccountDelegationInfo": [{"firstPartyPrincipal": {"principalEmail": "you@example.com"}}]
    },
    "requestMetadata": {"callerIp": "203.0.113.25", "callerSuppliedUserAgent": "curl/8.5.0"},
    "authorizationInfo": [{"resource": "projects/PROJECT_ID/locations/global/publishers/google/models/gemini-3.1-flash-lite",
                           "permission": "aiplatform.endpoints.predict", "granted": true}]
  }
}
```

Read it, field by field:

- `principalEmail`: the identity that called. `serviceAccountDelegationInfo`: **who acted as it** (you, through
  impersonation). That's the field that tells a human borrowing a robot apart from the robot itself.
- `callerIp`: where the call came from. Write yours down; you need it in Step 4.
- `authorizationInfo[].granted`: `true` for R2. If R1's denial is logged too, it shows `false` and a `status` with
  code `7` (`PERMISSION_DENIED`).
- `methodName`: **check this one against your real entry.** Google's audit-logging page doesn't name Gemini's
  method; the value above is the lab's assumption from the API definition (README, "Three assumptions"). If your
  real name differs, the lab's hunt rules need it: that's a real finding for your detections.
- R3 left no entry here, as far as we know: what a refused API-key call looks like in audit logs isn't documented.

### R5 · Re-run the inventory

Run 1b (Policy Analyzer), 1c (`policy_checker.py --keys`), 1d (cache GET) again. Example response (shape from Google
docs, values illustrative), the cache check:

```json
{"name": "projects/123456789012/cacheConfig", "disableCache": true}
```

What should have changed: `gc10-caller` now appears with `roles/aiplatform.user` on the project (and `gc10-nobody`
doesn't), the key checker reports no GC10-05 or GC10-07 for `gc10-build`, GC10-15 is gone, and caching is off. If you
did 2g, `describe --effective` shows your allow-list in `dryRunSpec`.

## Step 4 · Change one setting and re-run

Lesson 10.4's trade-off: an application restriction only helps if it names the right place. Add your own address
(the `callerIp` from R4) to the key, keeping the API restriction:

```bash
gcloud services api-keys update KEY_ID --project=PROJECT_ID \
  --api-target=service=aiplatform.googleapis.com --allowed-ips=192.0.2.10,YOUR_CALLER_IP
```

(`update` replaces the lists, so pass both flags every time. Console: open the key, edit **IP addresses**, **Save**.)
Wait a minute, run R3 again, and you get an R2-shaped answer. Now run R4 again and look for that call. Then ask the
question lesson 10.4 asks: if your laptop's address changes, or the key is copied to a machine behind the same
office NAT, what does this restriction still protect? Put the key back to `192.0.2.10` only when you're done:

```bash
gcloud services api-keys update KEY_ID --project=PROJECT_ID \
  --api-target=service=aiplatform.googleapis.com --allowed-ips=192.0.2.10
```

## Step 5 · Write down what you saw

| Check | Before (Step 1) | After (Steps 2 to 4) | Same as the offline lab? |
|---|---|---|---|
| AI APIs enabled | | | |
| Who has `aiplatform.endpoints.predict` | | | |
| User-managed SA keys / API keys / bound keys | | | |
| Data Access logs for `aiplatform.googleapis.com` | | | |
| `cacheConfig` | | | |
| `vertexai.allowedModels` effective policy | | | |
| R1 status and `reason` | | | |
| R3 status and `reason` (before / after Step 4) | | | |
| R4 real `methodName` | | | |

## Cost (estimate, October 2026)

| Item | Cost |
|---|---|
| Free Trial | "You will not be billed for any Google Cloud usage during your Free Trial" ([Free Trial](https://docs.cloud.google.com/free/docs/free-cloud-features)) |
| Service accounts, IAM, API keys, budgets, cache setting, org policies | Configuration only: no compute, storage or tokens |
| Policy Analyzer | No price on Google's page; 20 queries per organization per day without SCC Premium or Enterprise |
| R1, R3 | Refused before a model runs: $0 |
| R2 and Step 4 (two or three calls) | Gemini 3.1 Flash-Lite, $0.25 per 1M input and $1.50 per 1M output tokens ([pricing](https://cloud.google.com/gemini-enterprise-agent-platform/generative-ai/pricing)): with `maxOutputTokens` 50, under $0.001 in total |
| Data Access logs | A few KB; Cloud Logging's first 50 GiB per project per month are free ([pricing](https://cloud.google.com/stackdriver/pricing)) |

## Teardown (10 minutes)

Do it today. Keep the Data Access logs and the cache setting if you plan to do GC11 in the same project.

```bash
gcloud services api-keys delete KEY_ID --project=PROJECT_ID
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:gc10-caller@PROJECT_ID.iam.gserviceaccount.com" --role="roles/aiplatform.user"
for SA in gc10-caller gc10-nobody; do
  gcloud iam service-accounts delete "$SA@PROJECT_ID.iam.gserviceaccount.com" --quiet
done
gcloud billing budgets list --billing-account=BILLING_ACCOUNT_ID       # note the budget IDs you created
gcloud billing budgets delete BUDGET_ID --billing-account=BILLING_ACCOUNT_ID
gcloud org-policies delete vertexai.allowedModels --organization=ORGANIZATION_ID   # only if you did 2g
```

Remove `my-keys.json`, `policy.json` and `my-audit.json` from the lab folder: they describe your real project. If the
project was only for this guide, `gcloud projects delete PROJECT_ID` is the cleanest end (a deleted project is "fully
deleted after 30 days", README Step 8). Budgets live on the billing account, so delete them yourself either way.
