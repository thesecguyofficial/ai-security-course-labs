# GC15 guided build: a private endpoint for an open model, in your own Google Cloud project

The offline lab (README Steps 1 to 8) teaches the mechanics at $0. This guide builds the real thing from zero in
**your own** Google Cloud sandbox project (GC10, never a work project), in **us-central1**. About 2 hours. Nothing
here uses a third-party service except the model download itself, which comes from the model publisher's page on the
Hugging Face Hub to your laptop.

> **This one costs money every hour.** A deployed model bills for its node hours while it is deployed, whether anyone
> calls it or not (Google's pricing page counts the time "waiting in an active state"). So the guide creates an
> **auto-undeploy job first**: a Cloud Scheduler job that calls `undeployModel` 60 minutes after you deploy, created
> **before** the deployment. Run `make cost`, set a budget alert, and run `make cloud-down` the same day.

| Part | What you build | Lesson |
|---|---|---|
| A | APIs, three service accounts, a Cloud KMS key, a model bucket, an Artifact Registry repository | 15.2 |
| B | The serving image (built by Cloud Build, scanned by Artifact Analysis, deployed by digest) | 15.1, 15.4 |
| C | The model: download, scan, record licence and hashes, upload, register | 15.3 |
| D | A Private Service Connect endpoint with CMEK, the auto-undeploy job, then the deployment | 15.2, 15.3 |
| E | Five requests and what each one leaves in the logs | 15.4 |
| F | One setting changed: request-response logging on | 15.4 |
| G | Teardown | 15.5 |

> **Read this first: about the responses shown below.** We wrote this guide without running it in a Google Cloud
> project, so **no response from Google Cloud in this file comes from a real run**. Every such block is labelled
> **"Example response (shape from the provider's docs, values illustrative)"**. Field names come from Google's REST
> and audit log references; values (IDs, timings, error wording, what the model writes) are ours. Commands were
> checked against the gcloud reference pages for `ai endpoints deploy-model`, `ai models upload` and the Private
> Service Connect page, not run. Write down what you really see.

**What this build does NOT include:** a VPC Service Controls perimeter. A perimeter needs an organization (an access
policy lives at the organization or is scoped to its folders and projects), and most sandbox projects have none. If
yours is in an organization you own, add the project to a perimeter that restricts `aiplatform.googleapis.com` and
`storage.googleapis.com` **before Part D**: Google says endpoints "must be created after the project is added to the
service perimeter".

Shell variables used throughout (set them again in a new terminal):

| Variable | Holds | Example |
|---|---|---|
| `PROJECT` | your sandbox project ID | `tsg-sandbox-1234` |
| `PROJECT_NUMBER` | its number | `123456789012` |
| `REGION` | the region | `us-central1` |
| `MODEL_DIR` | the model folder on your laptop | `~/models/qwen3-0.6b` |
| `ENDPOINT_ID` | the endpoint's numeric ID (Part D) | `1234567890123456789` |

## Step 0 · Before you start (15 minutes)

1. **Your own sandbox project with billing and a budget alert** (GC10 lesson 10.5). As its owner you can do
   everything below. This build uses CPU only, so it doesn't need a GPU quota (Google's Free Trial page lists "Add
   GPUs to your VM instances" among the things a Free Trial account can't do).
2. **Cost.** Run `make cost`:

   ```output
   item                                          per hour
   inference node, e2-standard-4 (1 replica)       0.1541
   Private Service Connect endpoint                0.0100
   Cloud KMS key version ($0.06 a month)           0.0001
   total while the model is deployed               0.1642

   The auto-undeploy job runs 60 minutes after you deploy: about $0.16 if you forget everything else.
   Not included: Artifact Registry storage for the image, Cloud Build minutes, Cloud Storage for the model, BigQuery, logs.
   ```

   These are the us-central1 list prices we read on 25 Oct 2026 on the
   [pricing page](https://cloud.google.com/vertex-ai/pricing) (e2-standard-4 node hour $0.1541128),
   [VPC pricing](https://cloud.google.com/vpc/pricing) (a Private Service Connect endpoint "$0.01 / 1 hour", plus
   $0.01 per GiB processed) and [Cloud KMS pricing](https://cloud.google.com/kms/pricing) ($0.06 per key version per
   month). Cloud Scheduler gives each billing account "3 jobs per month free"
   ([pricing](https://cloud.google.com/scheduler/pricing)). Check the pages again before you start. The small test
   VM in Part E is extra (an e2-micro: look up its price on the Compute Engine pricing page).
3. **Tools:** `gcloud` (Cloud Shell has it), Python 3.11+, `jq`, and on your laptop the `hf` command from the
   `huggingface_hub` package for the download (`pip install huggingface_hub` in a fresh `.venv`).
4. **Sign in and set the variables:**

   ```bash
   export PROJECT=your-sandbox-project REGION=us-central1
   gcloud config set project $PROJECT
   export PROJECT_NUMBER=$(gcloud projects describe $PROJECT --format='value(projectNumber)')
   mkdir -p cloud/out
   ```

## Part A · The plumbing (20 minutes)

1. **Turn on the APIs.**

   ```bash
   gcloud services enable aiplatform.googleapis.com compute.googleapis.com artifactregistry.googleapis.com \
     cloudbuild.googleapis.com cloudkms.googleapis.com cloudscheduler.googleapis.com storage.googleapis.com \
     containerscanning.googleapis.com
   ```

2. **Three service accounts, each with one job.** The runtime account is what the serving container runs as
   (`deployedModel.serviceAccount`). It gets **no project roles**: Agent Platform grants it read access to the model
   copy by itself (Google: it "automatically grants your specified service account the Storage Object Viewer" role
   on that bucket). The app account plays the Helpdesk. The teardown account is what the auto-undeploy job uses.

   ```bash
   for sa in tsg-gc15-runtime tsg-gc15-app tsg-gc15-teardown; do
     gcloud iam service-accounts create $sa --display-name="GC15 lab $sa"; done
   gcloud iam roles create tsgGc15Undeploy --project=$PROJECT --title="GC15 undeploy only" \
     --permissions=aiplatform.endpoints.undeploy,aiplatform.endpoints.get
   gcloud projects add-iam-policy-binding $PROJECT \
     --member="serviceAccount:tsg-gc15-teardown@$PROJECT.iam.gserviceaccount.com" \
     --role="projects/$PROJECT/roles/tsgGc15Undeploy"
   ```

   Console: **IAM & Admin > Service Accounts > Create service account**, once per name. Skip "Grant this service
   account access to project" for the runtime and app accounts.

3. **A Cloud KMS key, and access for Agent Platform's service agent.** The endpoint's `encryptionSpec` covers "All
   model files used for the model deployment under the endpoint"
   ([CMEK](https://docs.cloud.google.com/vertex-ai/docs/general/cmek)).

   ```bash
   gcloud kms keyrings create tsg-gc15 --location=$REGION
   gcloud kms keys create tsg-gc15-ai --keyring=tsg-gc15 --location=$REGION --purpose=encryption
   gcloud beta services identity create --service=aiplatform.googleapis.com     # makes sure the service agent exists
   gcloud kms keys add-iam-policy-binding tsg-gc15-ai --keyring=tsg-gc15 --location=$REGION \
     --member="serviceAccount:service-$PROJECT_NUMBER@gcp-sa-aiplatform.iam.gserviceaccount.com" \
     --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
   ```

4. **A model bucket and an image repository.** Keep the bucket private, with uniform access.

   ```bash
   gcloud storage buckets create gs://$PROJECT-tsg-gc15-models --location=$REGION --uniform-bucket-level-access \
     --public-access-prevention
   gcloud artifacts repositories create tsg-gc15 --repository-format=docker --location=$REGION
   ```

## Part B · The serving image (15 minutes)

1. **Read `cloud/serve/server.py` first.** It's about 120 lines. It loads weights with `use_safetensors=True` and
   `trust_remote_code=False`, reads the model only from `AIP_STORAGE_URI` (Agent Platform's copy), listens on
   `0.0.0.0` as Google's [custom container contract](https://docs.cloud.google.com/vertex-ai/docs/predictions/custom-container-requirements)
   requires, and logs request counts and timings, never prompts.
2. **Build and push it with Cloud Build:**

   ```bash
   gcloud builds submit cloud/serve --region=$REGION \
     --tag=$REGION-docker.pkg.dev/$PROJECT/tsg-gc15/summariser:lab-1
   ```

3. **Pin it by digest and read the scan.** Artifact Analysis "scans new images when they're uploaded to Artifact
   Registry" ([overview](https://docs.cloud.google.com/artifact-analysis/docs/container-scanning-overview)).

   ```bash
   export IMAGE=$(gcloud artifacts docker images describe $REGION-docker.pkg.dev/$PROJECT/tsg-gc15/summariser:lab-1 \
     --format='value(image_summary.fully_qualified_digest)')
   gcloud artifacts docker images describe $IMAGE --show-package-vulnerability
   echo $IMAGE > cloud/out/image
   ```

   Console: **Artifact Registry > Repositories > tsg-gc15 > summariser**, then the digest's **Vulnerabilities** tab.
   Decide now what you'd do with a CRITICAL finding in the base image: rebuild on a newer base, or accept it in
   writing. That's GC15-02.

## Part C · The model: download, scan, record, upload (20 minutes)

This guide uses `Qwen/Qwen3-0.6B`, the same small model family as the course's local labs. Any small text model in
safetensors format works.

1. **Read the licence on the model card yourself** and write it down. Google's Hugging Face page says it scans
   listed repositories but "we don't guarantee the absence of vulnerabilities or malicious code"
   ([Google](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/open-models/use-hugging-face-models)), and it
   says nothing about licences: that check is yours.
2. **Download to your laptop, then scan before anything else touches it:**

   ```bash
   export MODEL_DIR=~/models/qwen3-0.6b
   hf download Qwen/Qwen3-0.6B --local-dir "$MODEL_DIR"
   python3 model_files.py scan "$MODEL_DIR"
   ```

   You want `SAFE FORMATS ONLY`. A `.bin` or `.pt` file, or `.py` files, mean stop and find out why.
3. **Record the hashes and the licence as labels** (Model Registry labels allow lowercase letters, digits, `_` and
   `-`, up to 64 characters, so `licence=apache-2.0` and a hex sha256 both fit):

   ```bash
   python3 model_files.py manifest "$MODEL_DIR" | jq -r 'to_entries | map("\(.key)=\(.value)") | join(",")' > cloud/out/labels
   export LICENCE=<what you read in step 1, for example apache-2.0>
   ```

4. **Upload the folder, then register a version from it:**

   ```bash
   gcloud storage cp --recursive "$MODEL_DIR"/* gs://$PROJECT-tsg-gc15-models/qwen3-0.6b/v1/
   gcloud ai models upload --region=$REGION --display-name=tsg-gc15-summariser \
     --container-image-uri=$(cat cloud/out/image) --artifact-uri=gs://$PROJECT-tsg-gc15-models/qwen3-0.6b/v1/ \
     --container-ports=8080 --container-predict-route=/predict --container-health-route=/health \
     --labels="licence=$LICENCE,$(cat cloud/out/labels)"
   export MODEL_ID=$(gcloud ai models list --region=$REGION --filter='displayName=tsg-gc15-summariser' --format='value(name)' | head -1 | xargs basename)
   ```

   No `--container-env-vars` with a token: the model is public, and a secret there would be readable by anyone with
   `aiplatform.models.get` (Agent Platform Viewer has it). Agent Platform copies the folder into its own bucket now;
   changing `gs://...v1/` later doesn't change what you registered.

## Part D · Endpoint, auto-undeploy, deploy (40 minutes, mostly waiting)

1. **Create the endpoint as a Private Service Connect endpoint with your key.** gcloud has no flag for this, so use
   REST. Fill in `cloud/requests/create-endpoint.json` first (replace `PROJECT_ID`):

   ```bash
   sed "s/PROJECT_ID/$PROJECT/g" cloud/requests/create-endpoint.json > cloud/out/create-endpoint.json
   curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
     -d @cloud/out/create-endpoint.json \
     "https://$REGION-aiplatform.googleapis.com/v1/projects/$PROJECT/locations/$REGION/endpoints"
   ```

   Console: **Agent Platform (Vertex AI) > Online prediction > Create**, name it, choose **Private**, then **Private
   Service Connect**, **Select project IDs** (your project only), **Continue**. The console doesn't set CMEK the same
   way, so use REST if you want the key.

   Example response (shape from the provider's docs, values illustrative):

   ```output
   {
     "name": "projects/123456789012/locations/us-central1/endpoints/1234567890123456789/operations/987654321",
     "metadata": {"@type": "type.googleapis.com/google.cloud.aiplatform.v1.CreateEndpointOperationMetadata", ...}
   }
   ```

   ```bash
   export ENDPOINT_ID=1234567890123456789      # the number after endpoints/ in your response
   echo $ENDPOINT_ID > cloud/out/endpoint-id
   ```

   Two facts from Google's [PSC page](https://docs.cloud.google.com/vertex-ai/docs/predictions/private-service-connect)
   to know before you go on: "An endpoint's `projectAllowlist` value can't be changed", and "If all models are
   undeployed for more than 10 minutes, the service attachment might be deleted."

2. **Create the auto-undeploy job before you deploy anything.** You choose the deployed model's ID yourself in step
   3, so the job can name it now. Cloud Scheduler uses cron, so this fires once a year at the time you set; teardown
   deletes it. Calls to Google APIs need an OAuth token (Google: OIDC "is generally used except for Google APIs hosted
   on `*.googleapis.com` as these APIs expect an OAuth token",
   [Scheduler auth](https://docs.cloud.google.com/scheduler/docs/http-target-auth)).

   ```bash
   export DEPLOYED_ID=150101
   WHEN=$(date -u -d '+60 min' '+%M %H %d %m' 2>/dev/null || date -u -v+60M '+%M %H %d %m')
   sed "s/DEPLOYED_MODEL_ID/$DEPLOYED_ID/" cloud/requests/undeploy-schedule-body.json > cloud/out/undeploy-body.json
   gcloud scheduler jobs create http tsg-gc15-undeploy --location=$REGION --schedule="$WHEN *" --time-zone=Etc/UTC \
     --uri="https://$REGION-aiplatform.googleapis.com/v1/projects/$PROJECT/locations/$REGION/endpoints/$ENDPOINT_ID:undeployModel" \
     --http-method=POST --headers=Content-Type=application/json --message-body-from-file=cloud/out/undeploy-body.json \
     --oauth-service-account-email=tsg-gc15-teardown@$PROJECT.iam.gserviceaccount.com
   ```

   Creating a job that uses the teardown account needs `iam.serviceAccounts.actAs` on it; as project owner you have
   it. If deploying takes longer than 60 minutes, update the job's schedule before it fires.

3. **Deploy, as the runtime account, with access logging on:**

   ```bash
   gcloud ai endpoints deploy-model $ENDPOINT_ID --region=$REGION --model=$MODEL_ID --display-name=tsg-gc15-summariser \
     --deployed-model-id=$DEPLOYED_ID --machine-type=e2-standard-4 --min-replica-count=1 --max-replica-count=1 \
     --service-account=tsg-gc15-runtime@$PROJECT.iam.gserviceaccount.com --enable-access-logging
   ```

   The gcloud reference says that without `--service-account` the container has no access to the project's
   resources. With it, the container runs as that account, so keep it role-free. Deploying takes a while (the image
   is large: PyTorch alone is a big download). If `--deployed-model-id` is refused, deploy without it, read the ID with
   `gcloud ai endpoints describe $ENDPOINT_ID --region=$REGION --format='value(deployedModels[0].id)'` and update the
   job's body (`gcloud scheduler jobs update http tsg-gc15-undeploy --location=$REGION --message-body=...`) at once.

4. **Let the app account call this endpoint only.** A role on the endpoint, not the project. gcloud has no IAM
   command for endpoints, so use the REST `setIamPolicy` method Google documents (it's on `v1beta1`, and it replaces
   the endpoint's whole policy, which is empty on a new endpoint:
   [endpoint access control](https://docs.cloud.google.com/vertex-ai/docs/general/endpoint-access-control)):

   ```bash
   gcloud iam roles create tsgGc15PredictOnly --project=$PROJECT --title="GC15 predict only" --permissions=aiplatform.endpoints.predict
   curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
     -d "{\"policy\": {\"bindings\": [{\"role\": \"projects/$PROJECT/roles/tsgGc15PredictOnly\", \"members\": [\"serviceAccount:tsg-gc15-app@$PROJECT.iam.gserviceaccount.com\"]}]}}" \
     "https://$REGION-aiplatform.googleapis.com/v1beta1/projects/$PROJECT/locations/$REGION/endpoints/$ENDPOINT_ID:setIamPolicy"
   ```

5. **Connect your VPC to it.** Read the service attachment, reserve an internal address, create the forwarding rule:

   ```bash
   SA_URI=$(gcloud ai endpoints describe $ENDPOINT_ID --region=$REGION --format='value(privateServiceConnectConfig.serviceAttachment)')
   gcloud compute addresses create tsg-gc15-psc-ip --region=$REGION --subnet=default
   gcloud compute forwarding-rules create tsg-gc15-psc --region=$REGION --network=default \
     --address=tsg-gc15-psc-ip --target-service-attachment=$SA_URI
   gcloud compute forwarding-rules describe tsg-gc15-psc --region=$REGION --format='value(IPAddress,pscConnectionStatus)'
   ```

   You want `ACCEPTED`. If you were refused, check the project is on the endpoint's `projectAllowlist`.

6. **Turn on Data Access audit logs for Agent Platform.** Console: **IAM & Admin > Audit Logs**, find
   `aiplatform.googleapis.com` in the list, tick **Data Read**, **Save**. Google: "Data Access audit logs are disabled
   by default and aren't written unless explicitly enabled"
   ([audit logging](https://docs.cloud.google.com/gemini-enterprise-agent-platform/machine-learning/general/audit-logging)).

## Part E · Five requests (20 minutes)

The PSC address is reachable only from inside your VPC, so make a tiny test VM with **no external IP** that runs as
the app account, and reach it over IAP:

```bash
gcloud compute firewall-rules create tsg-gc15-iap-ssh --network=default --allow=tcp:22 --source-ranges=35.235.240.0/20
gcloud compute instances create tsg-gc15-client --zone=$REGION-a --machine-type=e2-micro --no-address \
  --service-account=tsg-gc15-app@$PROJECT.iam.gserviceaccount.com --scopes=cloud-platform
gcloud compute scp cloud/requests/predict-*.json tsg-gc15-client:~ --zone=$REGION-a --tunnel-through-iap
gcloud compute ssh tsg-gc15-client --zone=$REGION-a --tunnel-through-iap
```

On the VM, set `IP` to the forwarding rule's address and `URL` to
`http://$IP/v1/projects/$PROJECT/locations/$REGION/endpoints/$ENDPOINT_ID:predict` (Google documents port 80 without
TLS and 443 with a self-signed certificate on this address).

1. **A normal summary, through the private path, as the app:**

   ```bash
   TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
   curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @predict-normal.json "$URL"
   ```

   Example response (shape from the provider's docs, values illustrative):

   ```output
   {"predictions": [{"summary": "After a firmware update, the floor 3 printer shows error 49 and two teams can't print."}], "deployedModelId": "150101", "model": "projects/123456789012/locations/us-central1/models/987654321", "modelVersionId": "1"}
   ```

2. **The same call from your laptop, through the public API host.** On your laptop:

   ```bash
   curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
     -d @cloud/requests/predict-normal.json \
     "https://$REGION-aiplatform.googleapis.com/v1/projects/$PROJECT/locations/$REGION/endpoints/$ENDPOINT_ID:predict"
   ```

   A PSC endpoint is meant to be called through your forwarding rule, so expect an error here. Write down the exact
   code and message you get: it is the evidence that the public path is closed. Example response (shape from the
   provider's docs, values illustrative):

   ```output
   {"error": {"code": 400, "message": "...", "status": "FAILED_PRECONDITION"}}
   ```

3. **A ticket with personal data** (`predict-personal-data.json`, fictional values). Then ask: where does that text
   live now? Not in access logs (Google: they hold "information like timestamp and latency for each request"), not in
   the container logs (the server doesn't print prompts), and not in request-response logs (off). In Part F you'll
   change the last one.
4. **An instruction hidden in a ticket** (`predict-injection.json`, a labelled lab placeholder). A self-hosted model
   has no safety layer of its own: whatever the model does, nothing screened it. Model Armor (GC12) can screen any
   model's prompts and answers.
5. **The evidence.** Wait a few minutes, then in **Logging > Logs Explorer**:

   ```text
   protoPayload.serviceName="aiplatform.googleapis.com"
   protoPayload.methodName:"Predict"
   ```

   Example entry (shape from Google's AuditLog reference, values illustrative):

   ```output
   protoPayload.authenticationInfo.principalEmail: tsg-gc15-app@tsg-sandbox-1234.iam.gserviceaccount.com
   protoPayload.requestMetadata.callerIp: 10.128.0.5
   protoPayload.requestMetadata.callerNetwork: //compute.googleapis.com/projects/tsg-sandbox-1234/global/networks/default
   protoPayload.methodName: google.cloud.aiplatform.v1.PredictionService.Predict
   ```

   Then look for the access log entries: search Logs Explorer for your endpoint ID and the deployed model ID 150101.
   Compare with the lab's hunt: which fields would catch the 203.0.113.50 calls?

## Part F · Change one setting: request-response logging (15 minutes)

Turn on request-response logging for a 100 percent sample into a BigQuery dataset only you can read:

```bash
bq --location=$REGION mk --dataset $PROJECT:tsg_gc15_audit
curl -s -X PATCH -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
  -d "{\"predictRequestResponseLoggingConfig\": {\"enabled\": true, \"samplingRate\": 1.0, \"bigqueryDestination\": {\"outputUri\": \"bq://$PROJECT.tsg_gc15_audit.requests\"}}}" \
  "https://$REGION-aiplatform.googleapis.com/v1/projects/$PROJECT/locations/$REGION/endpoints/$ENDPOINT_ID?updateMask=predictRequestResponseLoggingConfig"
```

Send request 3 again from the VM, wait a few minutes, then query the table in **BigQuery > tsg_gc15_audit**. The
trade-off: you now have evidence of what the model saw and said, and you also have a second copy of personal data
that needs its own access rules, key and retention. In the lab's first draft that table was readable by all staff
(attack A8). Turn it back off (`"enabled": false`) or keep a small sample and lock the dataset down.

## Part G · Teardown (10 minutes, today)

```bash
make cloud-down PROJECT=$PROJECT
gcloud compute instances delete tsg-gc15-client --zone=$REGION-a --quiet
gcloud compute firewall-rules delete tsg-gc15-iap-ssh --quiet
bq rm -r -f -d $PROJECT:tsg_gc15_audit
gcloud kms keys versions destroy 1 --key=tsg-gc15-ai --keyring=tsg-gc15 --location=$REGION
for sa in tsg-gc15-runtime tsg-gc15-app tsg-gc15-teardown; do gcloud iam service-accounts delete $sa@$PROJECT.iam.gserviceaccount.com --quiet; done
make cloud-check PROJECT=$PROJECT
```

The `cloud-down` target undeploys the model first (an endpoint must be undeployed before it can be deleted), then
deletes the forwarding rule, the address, the endpoint, the model, the scheduler job, the bucket contents and the
image repository. Cloud KMS bills a version until it is actually destroyed (a version scheduled for destruction still
counts as active), then it's free; the key ring itself stays, empty. Simplest of all, if the project was only for this: delete the project.

Write down what you saw in each step, especially the real responses for Part E 1, 2 and 5. That's what a reviewer
asks for.
