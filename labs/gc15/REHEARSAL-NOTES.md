# GC15 console rehearsal notes (13 Nov 2026)

Working notes for the recording script. Console in the owner's account (project `tsg-course-lab`, region
`us-central1`); Cloud Shell only where the console can't. In progress: sections are added as each step is rehearsed.

## Part A · Plumbing
- Two custom roles from an earlier run were in **Deleted** state (`tsgGc15Undeploy`, `tsgGc15PredictOnly`): their IDs
  stay blocked for 37 days, so `gcloud iam roles undelete` (or the Roles page > **Undelete**) instead of create.
- KMS key `tsg-gc15-ai` (key ring `tsg-gc15`) existed with destroyed versions: console **Rotate key** gave version 3
  "Enabled and primary". The Agent Platform service agent got Encrypter/Decrypter on the key (Cloud Shell, as the guide).

## Part B · Image
- Image `us-central1-docker.pkg.dev/PROJECT_ID/tsg-gc15/summariser:lab-1` (345.6 MB). Artifact Registry's console scan:
  101 findings, 0 Critical, 4 High (perl, zlib), 1 Medium, 51 Low, 14 with fixes, no malicious packages.

## Part C · Model files, upload, register
- Download + `model_files.py` scan: "SAFE FORMATS ONLY"; hashes written to `cloud/out/labels`.
- **Upload is slow from Cloud Shell:** `gcloud storage cp` of the 1.5 GB `model.safetensors` took about **13 minutes**
  (10:32 to 10:45 IST); gcloud splits it into ~31 parallel composite parts under `gs://BUCKET/gcloud/tmp/...` while it
  runs. Speed it up on camera, or upload before the take.
- **Register in the console:** Agent Platform > **Model registry** > **Import** ("Import model", 3 steps).
  1. Name and region: **Import as new model**, Name `tsg-gc15-summariser`, Region `us-central1`; Advanced options
     has **Encryption** (Google-managed / Cloud KMS key) and **Model ID**: leave default. **Continue**.
  2. Model settings: **Import an existing custom container**. **Container image** (type the digest form:
     `us-central1-docker.pkg.dev/PROJECT_ID/tsg-gc15/summariser@sha256:...`), **Model artifact location**
     `BUCKET/qwen3-0.6b/v1/`, **Inference route** `/predict`, **Health route** `/health`, **Port** `8080` (the
     default). Environment variables empty (no token). Advanced options: shared memory, start-up probe, health probe:
     leave. **Continue**.
  3. Explainability: **No explainability**. **Import**.
  - The panel closes at once; the notification bell shows "Uploading model tsg-gc15-summariser". The model appeared
    after about **2.5 minutes** (imported 10:47:57, listed 10:50 IST).
- **The console has no labels field.** The guide's hash labels: Cloud Shell `PATCH .../models/MODEL_ID?updateMask=labels`
  with the `cloud/out/labels` pairs plus `licence=apache-2_0` (11 labels). The model details page then shows them.
  Or keep the guide's `gcloud ai models upload --labels=...` for this one step.

## Part D · Endpoint (console)
- Agent Platform > **Endpoints** > **Create** is greyed out until a model exists in the region.
- "New endpoint", step 1 **Define your endpoint**: Endpoint name `tsg-gc15-summariser`; Access **Private** > Endpoint
  type **Private Service Connect** (the other choice is Private services access); **Project IDs \*** > **Select project
  IDs** > tick the project (the picker also lists the owner's other projects: blur) > **Select**; Enable dedicated DNS
  off; **Advanced options > Encryption > Cloud KMS key** > Key management type Cloud KMS > key `tsg-gc15-ai` > **OK**.
  So the console **can** set CMEK on a PSC endpoint (the guide said use REST). **Continue**.
- Step 2 **Model settings**: the console won't create an endpoint without a model ("Please select at least one model
  for deployment"; **Create** stays disabled). So console = endpoint + deployment in one go: Model name
  `tsg-gc15-summariser`, Version 1, Traffic 100; Minimum replicas 1, Maximum empty (= no scaling); **Machine type**
  filter `e2-standard-4`; VM provisioning Standard; **Service account** `tsg-gc15-runtime` (the list shows the Compute
  Engine default account with the project number: blur); Logging has only **Disable container logging** (no access
  logging or request-response logging switch here); Explainability none. **Done** > **Create** (10:56 IST).
- Result (Cloud Shell describe): `encryptionSpec.kmsKeyName` = our key, `privateServiceConnectConfig`
  `enablePrivateServiceConnect: true`, `projectAllowlist: [PROJECT_ID]`, `predictRequestResponseLoggingConfig: None`.
- **Deployed model ID:** the console picks it (ours `515207509275836416`); the endpoint details page shows it in the
  Deployed models row while the status is still **Deploying**. The API's `deployedModels` stays empty until the
  deployment finishes, and the deploy operation doesn't name it either.

## Part D · Auto-undeploy job (console)
- Because the console deploys at create time, the job can't exist before the deployment. Order for the take: Create
  the endpoint, open its details page, copy the deployed model ID, then create the job at once.
- Cloud Scheduler > **Create job**: Name `tsg-gc15-undeploy`; Region `us-central1`; Description; **Frequency**
  `5 12 13 11 *` (the page explains it: "At 12:05, day 13, November"); **Time zone** search country `India` > **India
  Standard Time (IST)** (a note warns about daylight saving zones). **Continue**. Target type **HTTP**; URL
  `https://us-central1-aiplatform.googleapis.com/v1/projects/PROJECT_ID/locations/us-central1/endpoints/ENDPOINT_ID:undeployModel`;
  method POST; **Add a header** `Content-Type` = `application/json`; Body `{"deployedModelId": "DEPLOYED_ID"}`;
  **Auth header** > **Add OAuth token** ("generally used for Google APIs hosted on *.googleapis.com") > Service account
  `tsg-gc15-teardown`; Scope empty (default cloud-platform). **Create** > "Job 'tsg-gc15-undeploy' created", Enabled,
  next run 13 Nov 2026 12:05 (shown as Asia/Calcutta).

## Part D · Predict-only grant (console)
- IAM > **Grant access**: New principals `tsg-gc15-app@...` (pick the suggestion), role search
  `tsgGc15PredictOnly` > "GC15 tsgGc15PredictOnly" > **Save**. Check: the binding exists.
  - Typing before the role search box has focus sends the text nowhere, then later appends it ("...PredictOnlyGC15"),
    and a stray click picked **AutoML Predictor**. Click the box, wait, type once, pick by name, read it back.
