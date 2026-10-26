# M25 guided build: sign in CI, verify at deploy, register on SageMaker AI only when it passes

The offline lab (README Steps 1 to 8) teaches the mechanics at $0. This guide runs the same gate against **your own**
AWS sandbox account (the one from lesson 0.7, never a work account), in **us-east-1**. About 45 minutes.

It creates **no instances, endpoints, jobs or notebooks**: a private S3 bucket with a few kilobytes in it, and a
model package group in the SageMaker AI Model Registry. Registering a package doesn't start a container. Check your
Billing console the next day; we expect this guide to cost cents at most, but we haven't measured it.

- **Part A** creates the bucket (private, versioned) and the model package group, by CLI or in the console.
- **Part B** signs a release. Offline with the lab key (the default), or keyless in GitHub Actions with Sigstore.
- **Part C** uploads it and runs the gate on a fresh download. Only a release that passes every check is registered.
- **Part D** sends five requests: a clean release, its evidence, a tampered release, the audit trail, and a check
  that the tampered bytes never reached the registry.
- **Part E** changes one setting (fail open) and shows what that costs. **Part F** tears everything down.

> **Read this first: about the responses shown below.** We wrote this guide without access to an AWS account, so
> **no response in this file comes from a real run**. Every response block is labelled **"Example response (shape
> from AWS docs, values illustrative)"**. The request fields match the botocore 1.43.118 service model for SageMaker
> AI. Values (ARNs, version IDs, times) are our guesses. The gate's own lines (`GATE`, `REFUSED`) come from the same
> code you ran offline. Write your real results down as you go.

> **This guide registers the lab's toy model, not a real one.** The package points at the same inference image as
> the M15 guided build so the request is complete, but **don't deploy it**: the toy model is not something that image
> can serve. To gate a real model, sign the model folder you downloaded in M15 (Part B, option 1, with that folder in
> place of `release/1.1.0-hardened/model`) and deploy the approved version with M15's guided build, Part D.

## Step 0 · Before you start (5 minutes)

1. **Sandbox account with a budget alarm** (lesson 0.7).
2. **Tools:** the AWS CLI v2, and this lab set up (`make setup` in `labs/m25`).
3. **Terminal in `labs/m25`:**

   ```bash
   cd labs/m25
   export AWS_REGION=us-east-1
   aws sts get-caller-identity --query Account --output text
   export BUCKET=tsg-m25-lab-$(aws sts get-caller-identity --query Account --output text)-$RANDOM
   echo $BUCKET
   ```

   - `aws sts get-caller-identity --query Account --output text`: check it IS the sandbox

   Bucket names are global, so the account ID and a random number keep yours unique.

## Part A · The bucket and the model package group

### Path A: the CLI

```bash
make cloud-bucket BUCKET=$BUCKET
```

It runs four calls: `s3api create-bucket`, `put-public-access-block` (all four settings on), `put-bucket-versioning`
(`Status=Enabled`) and `sagemaker create-model-package-group --model-package-group-name tsg-guard-lab`.

Example response (shape from the CreateModelPackageGroup API reference, values illustrative)

```output
{
    "ModelPackageGroupArn": "arn:aws:sagemaker:us-east-1:111122223333:model-package-group/tsg-guard-lab"
}
```

### Path B: the console

1. Open the **Amazon S3** console, choose **Create bucket**, Region **US East (N. Virginia) us-east-1**, the name in
   `$BUCKET`. Leave **Block all public access** on. Under **Bucket Versioning** choose **Enable**. Choose **Create bucket**.
2. The model package group: there's no harm in creating it with the CLI line above even if you use the console for
   the rest. You'll see it in SageMaker Studio under **Models**, the **Registered models** tab, **Model Groups**
   (the labels AWS documents for the registry
   ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html))). The same page documents a
   newer layout in us-east-1 and a few other Regions, where the group sits under **Models**, **Registered Models**.
   Follow whichever one your console shows.

**Why versioning:** every overwrite becomes a new object version with its own ID. In Part D the gate records the
version ID of the weights it checked, so "which bytes did we approve?" has an answer.

## Part B · Sign a release

**Option 1 (default): the lab key, offline.**

```bash
make release
```

That is the hardened CI job from the offline lab: our own int8 quantization, the eval gate on both files, the ML-BOM,
then `model_signing` with `keys/ci.priv`. The deploy gate trusts only `setups/hardened/trusted-keys/ci.pub`.

**Option 2: keyless, in GitHub Actions.** `cloud/sign-in-ci.example.yml` signs the same folder with Sigstore using
the workflow's own identity (`permissions: id-token: write`, then
`model_signing sign sigstore ... --use_ambient_credentials`). The verifier then pins an **identity**, the workflow
file path and branch, with `--identity_provider https://token.actions.githubusercontent.com`, instead of a key file.
Two things to know first: the signing event goes into Sigstore's public transparency log, so the workflow identity
and the file digests become public; and `cloud/gate.py` verifies with the lab key, so with Option 2 you'd swap
`verify_signature()` in `deploy.py` for `use_sigstore_verifier(identity=..., oidc_issuer=...)`. We haven't run
Option 2; treat it as a sketch.

## Part C · Upload, then gate a fresh download

```bash
make cloud-upload BUCKET=$BUCKET
make cloud-gate BUCKET=$BUCKET
```

`cloud/gate.py` lists the object versions, downloads the release into a fresh `cloud/out/1.1.0-hardened/`, runs
`deploy.gate("hardened", ...)` on that copy, and only then calls `create-model-package` (status
`PendingManualApproval`, evidence in `CustomerMetadataProperties`) and `update-model-package` (`Approved`, the reason
in `ApprovalDescription`).

Example response (gate lines from this lab's code; ARN illustrative)

```output
GATE [hardened] on the copy downloaded from S3:
  $ aws --region us-east-1 --output json sagemaker create-model-package --cli-input-json file://.../cloud/out/create-model-package.json
  $ aws --region us-east-1 --output json sagemaker update-model-package --model-package-arn arn:aws:sagemaker:us-east-1:111122223333:model-package/tsg-guard-lab/1 --model-approval-status Approved --approval-description M25 gate (hardened): signature verified, 0 warning(s)
  REGISTERED and approved: arn:aws:sagemaker:us-east-1:111122223333:model-package/tsg-guard-lab/1
```

**Approval is a signal, not a lock.** AWS's own wording: "Setting the status to `Approved` can initiate CI/CD
deployment for the model" ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html)). Your
deploy pipeline acts on it, so who may set it matters. Give `sagemaker:UpdateModelPackage` on this group to the gate's
role only, not to data scientists (M15's checker flags self-approval as M15-18).

## Part D · Five requests

1. **The clean release** (Part C): registered as version 1.

2. **Read the evidence back:**

   ```bash
   ARN=$(aws sagemaker list-model-packages --model-package-group-name tsg-guard-lab \
     --query 'ModelPackageSummaryList[0].ModelPackageArn' --output text)
   aws sagemaker describe-model-package --model-package-name $ARN \
     --query '{status: ModelApprovalStatus, why: ApprovalDescription, evidence: CustomerMetadataProperties}'
   ```

   Example response (shape from the DescribeModelPackage API reference, values illustrative)

   ```output
   {
       "status": "Approved",
       "why": "M25 gate (hardened): signature verified, 0 warning(s)",
       "evidence": {
           "signature-verify": "verified",
           "weights-sha256": "2803b6512ddd936231eec1c5bed5b90f949abbc132d7d02e9a5674f960f6ceb6",
           "signer-key-sha256": "f0dc874e...",
           "signature-sha256": "2b4807d3...",
           "s3-version-weights": "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY",
           "gate-setup": "hardened"
       }
   }
   ```

   Your `weights-sha256` should match `sha256sum release/1.1.0-hardened/model/model.safetensors` on your laptop.

3. **Tamper with the weights in S3, then gate again:**

   ```bash
   make cloud-tamper BUCKET=$BUCKET
   make cloud-gate BUCKET=$BUCKET
   ```

   Example response (gate lines from this lab's code)

   ```output
   GATE [hardened] on the copy downloaded from S3:
     REFUSED: signature check failed: Signature mismatch: Hash mismatch for 'model.safetensors'
     nothing was registered in SageMaker AI
   ```

4. **The audit trail.** SageMaker AI API calls are CloudTrail management events, so they're in Event history
   (90 days) without a trail:

   ```bash
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateModelPackage \
     --max-results 5 --query 'Events[].{time: EventTime, who: Username, event: EventName}'
   ```

   You should see one `UpdateModelPackage`, from the identity that ran the gate. In production that identity is the
   gate's role, and an `UpdateModelPackage` to `Approved` from anyone else is an alert (lesson 25.5, "Spot it").

5. **Did the tampered bytes reach the registry?**

   ```bash
   aws s3api list-object-versions --bucket $BUCKET --prefix tsg-guard/1.1.0-hardened/model/model.safetensors \
     --query 'Versions[].{id: VersionId, latest: IsLatest, size: Size}'
   aws sagemaker list-model-packages --model-package-group-name tsg-guard-lab --query 'ModelPackageSummaryList[].ModelPackageArn'
   ```

   Two object versions of the weights; one model package. Its `s3-version-weights` is the older version ID.

   **One gap to see clearly:** the package points at the S3 **prefix**, and the prefix now holds the tampered file.
   A deploy that reads "latest" from that prefix would load the bytes the gate refused. The fixes, best first: copy
   approved files into a separate, write-protected "released" prefix or bucket that only the gate's role can write
   (M15's hardened bucket policy does this), or have the serving side re-verify the signature before loading.

## Part E · Change one setting: fail open

```bash
make cloud-warn BUCKET=$BUCKET
```

The same gate with the first draft's `deploy.json`: warn and carry on.

Example response (gate lines from this lab's code; ARN illustrative)

```output
GATE [first-draft] on the copy downloaded from S3:
  WARNING: trusted key cloud/out/1.1.0-hardened/keys/ci.pub not found (continuing)
  ...
  REGISTERED and approved: arn:aws:sagemaker:us-east-1:111122223333:model-package/tsg-guard-lab/2
  ...with warnings. This is what fail-open looks like in a real account. Delete it: make cloud-down
```

The tampered weights are now an **Approved** model package version, and the only trace is a warning in a log nobody
reads. That one setting is the difference between the two pipelines in `make hunt`.

## Part F · Teardown (do it today)

```bash
make cloud-down BUCKET=$BUCKET
```

It deletes every model package in `tsg-guard-lab`, the group, every object version and delete marker in the bucket,
then the bucket. Check nothing is left:

```bash
aws sagemaker list-model-package-groups --name-contains tsg-guard
aws s3api head-bucket --bucket $BUCKET
```

You should see:

- `aws s3api head-bucket --bucket $BUCKET`: should fail: Not Found

Then delete `cloud/out/` on your laptop (`make clean`).
