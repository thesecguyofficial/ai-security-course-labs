# M15 guided build: a private endpoint for an open model, in your own AWS account

The offline lab (README Steps 1 to 8) teaches the mechanics at $0. This guide builds the real thing from zero in
**your own** AWS sandbox account (the one from lesson 0.7, never a work account), in **us-east-1**. About 2 hours.
Nothing here uses a third-party service except the model download itself, which comes from the model publisher's page
on the Hugging Face Hub to your laptop.

> **This one costs money every hour.** A real-time endpoint runs on a GPU instance that bills while it exists, whether
> anyone calls it or not. So the guide creates an **auto-teardown** first: an EventBridge Scheduler one-time schedule
> that deletes the endpoint two hours later, created **before** the endpoint. Read the cost table in Step 0, set a
> budget alarm, and run `make cloud-down` the same day.

- **Part A** builds the private plumbing with one CloudFormation stack: a VPC with no route to the internet, an S3
  gateway endpoint and a `sagemaker.runtime` interface endpoint (both with policies), a KMS key, a model bucket and a
  data capture bucket, the endpoint's execution role, a Lambda function that plays the Helpdesk app, and a trail that
  records `InvokeEndpoint` data events for this one endpoint.
- **Part B** downloads an open model to your laptop, scans it, records its licence and file hashes, and uploads it.
- **Part C** registers it in the Model Registry and approves it.
- **Part D** creates the auto-teardown schedule, then the model (network isolation, VPC), the endpoint configuration
  (encrypted data capture) and the endpoint.
- **Part E** sends five requests: a normal summary, stolen keys from your laptop, a prompt with personal data, a burst
  of calls, and the evidence in CloudTrail.
- **Part F** changes one setting (the VPC endpoint policy) and shows what breaks. **Part G** tears everything down.

> **Read this first: about the responses shown below.** We wrote this guide without access to an AWS account, so **no
> response in this file comes from a real run**. Every response block is labelled **"Example response (shape from AWS
> docs, values illustrative)"** and names the page its shape comes from. Request bodies match the botocore 1.43.118
> service models, and `cloud/base.yaml` passes `cfn-lint`. **Values (IDs, timings, error wording, and what the model
> writes back) are our guesses.** Write your real results down as you go.

Shell variables used throughout (set them again in a new terminal):

| Variable | Holds | Example |
|---|---|---|
| `AWS_REGION` | the Region | `us-east-1` |
| `MODEL_DIR` | the model folder on your laptop | `~/models/qwen3-0.6b` |
| `PACKAGE_ARN` | the approved registry version | `arn:aws:sagemaker:us-east-1:111122223333:model-package/tsg-summariser-lab/1` |
| `APP` | the app Lambda's name | `tsg-m15-lab-AppFunction-AbCdEf123456` |

## Step 0 · Before you start (15 minutes)

1. **Sandbox account with a budget alarm** (lesson 0.7). An alarm tells you; it doesn't stop anything.
2. **GPU quota.** Open **Service Quotas**, choose **Amazon SageMaker**, and search for `ml.g5.xlarge for endpoint usage`.
   If the applied value is 0, request 1 and wait for it before you go on: the endpoint can't start without it.
3. **Tools.** AWS CLI v2, Python 3.11+, and the Hugging Face command line for the download
   (`pip install -U huggingface_hub`, which installs the `hf` command). About 2 GB free disk.
4. **Terminal in `labs/m15`:**

   ```bash
   cd labs/m15
   export AWS_REGION=us-east-1
   aws sts get-caller-identity --query Account --output text    # check it IS the sandbox
   ```

5. **Cost.** Look up the GPU price before you start: on the
   [SageMaker AI pricing page](https://aws.amazon.com/sagemaker/ai/pricing/), On-Demand, Real-Time Inference,
   US East (N. Virginia), find **ml.g5.xlarge** and write the hourly price down (a third-party price tracker showed
   about $1.41 an hour on 24 Oct 2026; AWS's page is the one that counts). For scale, AWS's own examples on that
   page price an ml.c5.xlarge (a CPU instance) at $0.204 an hour for inference and an ml.g4dn.xlarge (a GPU) at $0.7364
   an hour for a notebook.

   | Item | Price (read 24 Oct 2026) | For a 2-hour run |
   |---|---|---|
   | ml.g5.xlarge endpoint | the hourly price you wrote down | 2 × that price, then the schedule deletes it |
   | `sagemaker.runtime` interface endpoint | "$0.01 per hour for each endpoint ENI" ([PrivateLink](https://aws.amazon.com/privatelink/pricing/)), two subnets = two ENIs, plus $0.01 per GB processed | about $0.04 |
   | S3 gateway endpoint | "There is no additional charge for using gateway endpoints" ([AWS](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)) | $0 |
   | KMS key | "$1/month (prorated hourly)"; no charge while scheduled for deletion ([KMS](https://aws.amazon.com/kms/pricing/)) | cents |
   | CloudTrail data events | "$0.10 per 100,000 data events delivered" ([CloudTrail](https://aws.amazon.com/cloudtrail/pricing/)) | cents |
   | S3, Lambda, EventBridge Scheduler, data processing | per use | cents |

   The interface endpoint and the key keep billing until **Part G** deletes the stack, endpoint or no endpoint.

# Part A · The private plumbing

## A1 · Create it from zero

### Path A: CloudFormation from the command line (recommended)

```bash
make cloud-base      # aws cloudformation deploy ... --template-file cloud/base.yaml, then saves the outputs
```

It takes a few minutes. `cloud/out/stack.json` now holds the stack outputs (bucket names, role ARNs, subnet IDs).
Read `cloud/base.yaml` while you wait: every resource has a comment saying which lesson it comes from. Three things to
find in it:

- `PrivateRoutes` has no route at all: no internet gateway, no NAT gateway. The only ways out are the two VPC endpoints.
- `RuntimeEndpoint` carries a policy: `sagemaker:InvokeEndpoint`, on this one endpoint ARN, for principals in your
  account (`aws:PrincipalAccount`). Without it, the default policy "allows full access" (lesson 15.3).
- `AppFunctionRole` may invoke the endpoint only when `aws:SourceVpce` is your runtime endpoint. AWS's own example
  for this uses the same key: "To restrict access to the API to only calls made using the interface endpoint, use the
  `aws:SourceVpce` condition key" ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_id-based-policy-examples.html)).

### Path B: the console

1. Open the **CloudFormation** console in us-east-1 and create a stack from a template file: upload `cloud/base.yaml`,
   name the stack `tsg-m15-lab`, keep the parameter `EndpointName` = `tsg-summariser-lab`, acknowledge that the
   template creates IAM resources, and create it.
2. When it shows `CREATE_COMPLETE`, save the outputs where `render.py` expects them:

   ```bash
   mkdir -p cloud/out && aws cloudformation describe-stacks --stack-name tsg-m15-lab --output json > cloud/out/stack.json
   ```

3. In the **VPC** console, open **Endpoints**, select the endpoint whose service name ends in `sagemaker.runtime`, and
   read its **Policy** tab. You'll change it in Part F.

## A2 · Check the plumbing

```bash
aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=$(aws ec2 describe-vpcs --filters Name=tag:Name,Values=tsg-m15-lab --query 'Vpcs[0].VpcId' --output text) \
  --query 'VpcEndpoints[].[ServiceName,VpcEndpointType,PrivateDnsEnabled]' --output table
```

```output
Example response (shape from the EC2 DescribeVpcEndpoints API reference, values illustrative)
-------------------------------------------------------------------------
|                         DescribeVpcEndpoints                          |
+---------------------------------------------+------------+------------+
|  com.amazonaws.us-east-1.s3                 |  Gateway   |  False     |
|  com.amazonaws.us-east-1.sagemaker.runtime  |  Interface |  True      |
+---------------------------------------------+------------+------------+
```

Private DNS on the runtime endpoint means the normal hostname resolves to it from inside the VPC. AWS: "the default
SageMaker AI Runtime DNS hostname (https://runtime.sagemaker.Region.amazonaws.com) also resolves to your VPC endpoint"
([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/interface-vpc-endpoint.html)).

# Part B · The model files

## B1 · Download, then read the licence

This guide uses `Qwen/Qwen3-0.6B`, the same small model family as the course's local labs. Any small model in Hugging
Face format with safetensors weights works, if the container supports its architecture.

1. **Read the licence before you download.** Open the model's page on the Hub and read its licence field and its
   `LICENSE` file. Write down what it says and whether your organisation allows it for your use (on 24 Oct 2026 the
   card for `Qwen/Qwen3-0.6B` said `apache-2.0`; check it again, licences change). AWS says the same about
   models it offers: "You are responsible for reviewing and complying with any applicable license terms and making sure
   they are acceptable for your use case before downloading or using the content"
   ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/jumpstart-foundation-models-choose.html)).
2. Download it:

   ```bash
   export MODEL_DIR=~/models/qwen3-0.6b
   hf download Qwen/Qwen3-0.6B --local-dir "$MODEL_DIR"
   ```

## B2 · Scan it, the same scanner as the offline lab

```bash
python3 model_files.py scan "$MODEL_DIR"
python3 model_files.py manifest "$MODEL_DIR"
```

```output
Example response (shape from this lab's scanner; the file list depends on the model)
[OK  ] .gitattributes               data
[OK  ] LICENSE                      data
[OK  ] README.md                    data
[OK  ] config.json                  data
[OK  ] generation_config.json       data
[OK  ] merges.txt                   data
[OK  ] model.safetensors            safetensors
[OK  ] tokenizer.json               data
[OK  ] tokenizer_config.json        data
[OK  ] vocab.json                   data

verdict: SAFE FORMATS ONLY
```

If anything says `STOP` (a `.bin`, `.pt`, `.pkl`, `.npy` or `.py` file), don't ship it: delete the file if the model
also has safetensors weights, or pick another model.

## B3 · Upload it, encrypted, to the released-models path

```bash
MODELS=$(python3 -c "import json;o=json.load(open('cloud/out/stack.json'))['Stacks'][0]['Outputs'];print([x['OutputValue'] for x in o if x['OutputKey']=='ModelsBucket'][0])")
KEY=$(python3 -c "import json;o=json.load(open('cloud/out/stack.json'))['Stacks'][0]['Outputs'];print([x['OutputValue'] for x in o if x['OutputKey']=='KeyArn'][0])")
aws s3 cp "$MODEL_DIR" "s3://$MODELS/tsg-summariser/v1/" --recursive --exclude ".cache/*" --sse aws:kms --sse-kms-key-id "$KEY"
```

The folder is uploaded uncompressed. SageMaker AI downloads it to `/opt/ml/model` in the container: "SageMaker AI will
automatically download the uncompressed model artifacts to `/opt/ml/model` for inference"
([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/large-model-inference-uncompressed.html)). The container never
needs the internet, which is what network isolation requires.

# Part C · Register and approve

1. Fill in the request bodies with your outputs, the licence you read and the hashes from B2:

   ```bash
   export LICENCE=<what you read in B1, e.g. apache-2.0>  MODEL_SOURCE=huggingface.co/Qwen/Qwen3-0.6B
   python3 cloud/render.py                 # writes cloud/out/*.json; read create-model-package.json
   ```

2. Register the version:

   ```bash
   aws sagemaker create-model-package-group --cli-input-json file://cloud/out/create-model-package-group.json
   aws sagemaker create-model-package --cli-input-json file://cloud/out/create-model-package.json
   ```

   ```output
   Example response (shape from the CreateModelPackage API reference, values illustrative)
   {
       "ModelPackageArn": "arn:aws:sagemaker:us-east-1:111122223333:model-package/tsg-summariser-lab/1"
   }
   ```

3. **Approve it, the way a gate would.** Before you approve, re-run the scan, and compare the recorded hashes with what
   is in S3 now (the guide's version of challenge 2). Then:

   ```bash
   export PACKAGE_ARN=<the ModelPackageArn above>
   aws sagemaker update-model-package --model-package-arn "$PACKAGE_ARN" \
     --model-approval-status Approved --approval-description "Scanned, licence checked, hashes recorded"
   aws sagemaker describe-model-package --model-package-name "$PACKAGE_ARN" \
     --query '[ModelApprovalStatus,CustomerMetadataProperties.licence]'
   ```

   In your sandbox you are registrant and approver at once. In a team, that is the self-approval the offline lab's
   A4 shows: give `UpdateModelPackage` to an approver role only.

# Part D · Auto-teardown first, then the endpoint

## D1 · The schedule that deletes the endpoint (create it now)

```bash
export PACKAGE_ARN                        # from Part C
python3 cloud/render.py                   # again, so create-model.json has the package ARN and the schedule has a fresh time
cat cloud/out/create-schedule.json        # at(...) = 2 hours from now, UTC; TEARDOWN_HOURS=1 python3 cloud/render.py for 1 hour
aws scheduler create-schedule --cli-input-json file://cloud/out/create-schedule.json
```

The schedule's target is a **universal target**: any API action, called with the role you name. AWS documents the ARN
form `arn:aws:scheduler:::aws-sdk:service:apiAction`
([AWS](https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-universal.html)); here it is
`arn:aws:scheduler:::aws-sdk:sagemaker:deleteEndpoint`, with `{"EndpointName": "tsg-summariser-lab"}` as input and a
role that may delete only that endpoint. `ActionAfterCompletion: DELETE` removes the schedule after it fires. It deletes
the **endpoint** (the part that bills by the hour); `make cloud-down` removes the rest.

The console path works too (EventBridge, **Scheduler**, create a one-time schedule whose target is the SageMaker
`DeleteEndpoint` API), but the command line makes sure the schedule exists before the endpoint does.

## D2 · Create the model, the configuration and the endpoint

### Path A: AWS CLI

```bash
aws sagemaker create-model --cli-input-json file://cloud/out/create-model.json
aws sagemaker create-endpoint-config --cli-input-json file://cloud/out/create-endpoint-config.json
aws sagemaker create-endpoint --cli-input-json file://cloud/out/create-endpoint.json
aws sagemaker wait endpoint-in-service --endpoint-name tsg-summariser-lab     # often 10 minutes or more
```

Read `cloud/out/create-model.json` and `create-endpoint-config.json` while it starts:

- **`ModelPackageName`**: the endpoint runs the approved registry version, not an S3 path (lesson 15.3).
- **`EnableNetworkIsolation: true`** and **`VpcConfig`**: no outbound calls from the container; the model download goes
  through your subnets and the S3 gateway endpoint (lesson 15.2).
- **No `KmsKeyId` on the endpoint configuration.** ml.g5.xlarge has NVMe instance storage, and AWS: "You can't use a KMS
  key on an instance type with local storage" ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest-nbi.html)).
  Your key protects the S3 copies instead: the model files and the data capture (its own `KmsKeyId`).
- **No `EnableSSMAccess`**: no shell into the production container.

### Path B: SageMaker Studio (only if you already have a Studio domain in this VPC)

AWS documents these labels for Studio ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/realtime-endpoints-deploy-models.html)):

1. In Studio, choose **Models**, the **Deployable models** tab, then **Create**. Name it `tsg-summariser-lab`.
   Under **Container definition** and **Artifacts**, use the image and the S3 location from
   `cloud/out/create-model-package.json`. Under **Security**, choose the execution role from the stack outputs and turn
   on **Network isolation**. Choose **Create deployable model**.
2. Select the model and choose **Deploy**. Create a new endpoint named `tsg-summariser-lab`, instance type
   `ml.g5.xlarge`, initial instance count 1. Under **Advanced options**, set **Virtual Private Cloud (VPC)** to the
   lab VPC's two subnets and the model security group, and **Enable network isolation**. Leave **Encryption KMS key**
   empty for this instance type (see Path A). Choose **Deploy**.

Studio deploys from the S3 location, not from your approved registry version, and doesn't set data capture: the CLI
path is the one that matches the hardened setup.

## D3 · Check what you built

```bash
aws sagemaker describe-model --model-name tsg-summariser-lab --query '[EnableNetworkIsolation,VpcConfig.Subnets,PrimaryContainer.ModelPackageName]'
aws sagemaker describe-endpoint --endpoint-name tsg-summariser-lab --query '[EndpointStatus,DataCaptureConfig.EnableCapture]'
```

```output
Example response (shape from the DescribeModel and DescribeEndpoint API references, values illustrative)
[
    true,
    ["subnet-0a1b2c3d4e5f60011", "subnet-0a1b2c3d4e5f60012"],
    "arn:aws:sagemaker:us-east-1:111122223333:model-package/tsg-summariser-lab/1"
]
[
    "InService",
    true
]
```

If the endpoint fails, `describe-endpoint` has a `FailureReason`, and the container's own log is in CloudWatch Logs
under `/aws/sagemaker/Endpoints/tsg-summariser-lab`. The usual causes: the GPU quota (Step 0), a model architecture the
image doesn't support, or a missing S3 path.

# Part E · Five requests

```bash
export APP=$(python3 -c "import json;o=json.load(open('cloud/out/stack.json'))['Stacks'][0]['Outputs'];print([x['OutputValue'] for x in o if x['OutputKey']=='AppFunctionName'][0])")
```

## E1 · A normal summary, through the private path

```bash
aws lambda invoke --function-name "$APP" --cli-binary-format raw-in-base64-out \
  --payload '{"prompt": "Summarise in one sentence: VPN drops every time my laptop wakes from sleep. Restarting the client fixes it."}' \
  cloud/out/e1.json && cat cloud/out/e1.json
```

```output
Example response (shape from the LMI input/output schema, values illustrative)
{"endpoint": "tsg-summariser-lab", "answer": {"generated_text": " The VPN connection drops after the laptop wakes from sleep and comes back after a client restart."}}
```

The Lambda runs in the private subnets. Its call resolves `runtime.sagemaker.us-east-1.amazonaws.com` to the interface
endpoint, the endpoint policy allows it (your account, this endpoint), and the role's `aws:SourceVpce` condition holds.
The request body is the LMI schema: `inputs` plus `parameters.max_new_tokens`; the answer is `generated_text`
([LMI schema](https://docs.djl.ai/master/docs/serving/serving/docs/lmi/user_guides/lmi_input_output_schema.html)).

## E2 · Stolen keys, used from your laptop

`LeakedKeysTestRole` has exactly the app's permission. Use it from your laptop, outside the VPC:

```bash
ROLE=$(python3 -c "import json;o=json.load(open('cloud/out/stack.json'))['Stacks'][0]['Outputs'];print([x['OutputValue'] for x in o if x['OutputKey']=='LeakedKeysTestRoleArn'][0])")
eval $(aws sts assume-role --role-arn "$ROLE" --role-session-name stolen-keys-test \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text \
  | awk '{print "export AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" AWS_SESSION_TOKEN="$3}')
echo '{"inputs": "hello", "parameters": {"max_new_tokens": 20}}' > cloud/out/e2-body.json
aws sagemaker-runtime invoke-endpoint --endpoint-name tsg-summariser-lab --content-type application/json \
  --body fileb://cloud/out/e2-body.json cloud/out/e2.json
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN      # back to your own identity
```

```output
Example response (shape from the AWS CLI error format, wording illustrative)
An error occurred (AccessDeniedException) when calling the InvokeEndpoint operation: User: arn:aws:sts::111122223333:assumed-role/tsg-m15-lab-LeakedKeysTestRole-AbC/stolen-keys-test is not authorized to perform: sagemaker:InvokeEndpoint on resource: arn:aws:sagemaker:us-east-1:111122223333:endpoint/tsg-summariser-lab
```

The same credentials work from the Lambda and fail from your laptop. That is attack A7 in the offline lab, blocked. The
endpoint itself has no public address to firewall: "Endpoints are scoped to an individual account, and are not public"
(InvokeEndpoint API reference). What decides is IAM, and the condition on where the call came from.

## E3 · A prompt with personal data, and where it ends up

```bash
aws lambda invoke --function-name "$APP" --cli-binary-format raw-in-base64-out \
  --payload '{"prompt": "Summarise: Employee LAB-0042, date of birth 01/01/1990, cannot log in to payroll."}' cloud/out/e3.json
CAPTURE=$(python3 -c "import json;o=json.load(open('cloud/out/stack.json'))['Stacks'][0]['Outputs'];print([x['OutputValue'] for x in o if x['OutputKey']=='CaptureBucket'][0])")
aws s3 ls "s3://$CAPTURE/tsg-summariser/" --recursive | tail -3        # files can take a few minutes to appear
```

Download the newest `.jsonl` file and look at one line, then check how S3 stored it:

```bash
aws s3 cp "s3://$CAPTURE/<key from the listing>" cloud/out/capture.jsonl
python3 -c "import json,base64;r=json.loads(open('cloud/out/capture.jsonl').readline());print(r['captureData']['endpointInput']['encoding']);print(base64.b64decode(r['captureData']['endpointInput']['data']).decode()[:200])"
aws s3api head-object --bucket "$CAPTURE" --key "<key from the listing>" --query '[ServerSideEncryption,SSEKMSKeyId]'
```

```output
Example response (shape from the data capture record format and HeadObject, values illustrative)
BASE64
{"inputs": "Summarise: Employee LAB-0042, date of birth 01/01/1990, cannot log in to payroll.", "parameters": {"max_new_tokens": 200}}
[
    "aws:kms",
    "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
]
```

Data capture keeps the whole prompt. Base64 is an encoding, not protection: the KMS key and the bucket policy are. The
path follows AWS's layout, `{endpoint-name}/{variant-name}/yyyy/mm/dd/hh/filename.jsonl`
([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-capture-endpoint.html)), and the bucket
expires captured files after 30 days. (AWS's data capture pages carry the note that Model Monitor is no longer open to
new customers; if `DataCaptureConfig` is refused in a new account, remove it from the endpoint configuration and
record prompts in the app instead. Lesson 15.4.)

## E4 · A burst of calls, and the metrics

```bash
for i in $(seq 1 20); do aws lambda invoke --function-name "$APP" --cli-binary-format raw-in-base64-out \
  --payload '{"prompt": "Summarise: printer offline", "max_new_tokens": 20}' /dev/null >/dev/null; done
aws cloudwatch get-metric-statistics --namespace AWS/SageMaker --metric-name Invocations \
  --dimensions Name=EndpointName,Value=tsg-summariser-lab Name=VariantName,Value=AllTraffic \
  --start-time $(date -u -d '-30 min' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) --period 300 --statistics Sum --query 'Datapoints[].Sum'
```

`Invocations` is "The number of InvokeEndpoint requests sent to a model endpoint"; `Invocation4XXErrors` counts 4xx
answers ([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/monitoring-cloudwatch.html)). A sudden jump in either is
the first sign of abuse or probing, and costs nothing to alarm on (lesson 15.4).

## E5 · The evidence in CloudTrail

Data events for this endpoint go to the lab's trail bucket. Delivery can take several minutes.

```bash
TRAIL=$(python3 -c "import json;o=json.load(open('cloud/out/stack.json'))['Stacks'][0]['Outputs'];print([x['OutputValue'] for x in o if x['OutputKey']=='TrailBucket'][0])")
aws s3 ls "s3://$TRAIL/AWSLogs/" --recursive | tail -3
```

Download a file (CloudTrail writes gzipped JSON) and look for `"eventName": "InvokeEndpoint"`. Compare two records:

```output
Example response (shape from the CloudTrail record contents and the SageMaker AI CloudTrail examples, values illustrative)
{"eventName": "InvokeEndpoint", "eventCategory": "Data", "sourceIPAddress": "10.42.1.87",
 "userIdentity": {"arn": "arn:aws:sts::111122223333:assumed-role/tsg-m15-lab-AppFunctionRole-AbC/tsg-m15-lab-AppFunction-AbC"},
 "vpcEndpointId": "vpce-0a1b2c3d4e5f60001", "requestParameters": null}
{"eventName": "InvokeEndpoint", "eventCategory": "Data", "sourceIPAddress": "198.51.100.23",
 "userIdentity": {"arn": "arn:aws:sts::111122223333:assumed-role/tsg-m15-lab-LeakedKeysTestRole-AbC/stolen-keys-test"},
 "errorCode": "AccessDenied"}
```

The Lambda's call carries the VPC endpoint ID; your laptop's attempt carries a public IP and an error. Neither carries
the prompt: AWS says `InvokeEndpoint` calls "don't log the request parameters"
([AWS](https://docs.aws.amazon.com/sagemaker/latest/dg/logging-using-cloudtrail.html)). That is the offline lab's
challenge 3, on real records.

# Part F · Change one setting: the VPC endpoint policy

1. Save the current policy, then replace it with one that allows a different endpoint name:

   ```bash
   VPCE=$(python3 -c "import json;o=json.load(open('cloud/out/stack.json'))['Stacks'][0]['Outputs'];print([x['OutputValue'] for x in o if x['OutputKey']=='RuntimeEndpointId'][0])")
   ACCT=$(aws sts get-caller-identity --query Account --output text)
   aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$VPCE" --query 'VpcEndpoints[0].PolicyDocument' --output text > cloud/out/original-policy.json
   cat > cloud/out/other-policy.json <<EOF
   {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sagemaker:InvokeEndpoint",
     "Resource": "arn:aws:sagemaker:us-east-1:${ACCT}:endpoint/some-other-endpoint"}]}
   EOF
   aws ec2 modify-vpc-endpoint --vpc-endpoint-id "$VPCE" --policy-document file://cloud/out/other-policy.json
   ```

2. Wait a minute, then repeat E1. It fails, with the role still allowing the call: a request through the VPC endpoint
   must be allowed by the endpoint policy **and** by IAM.

   ```output
   Example response (shape from the Lambda Invoke error format, wording illustrative)
   {"errorMessage": "An error occurred (AccessDeniedException) when calling the InvokeEndpoint operation: ... because no VPC endpoint policy allows the sagemaker:InvokeEndpoint action", "errorType": "ClientError"}
   ```

3. Put the saved policy back, and check E1 works again:

   ```bash
   aws ec2 modify-vpc-endpoint --vpc-endpoint-id "$VPCE" --policy-document file://cloud/out/original-policy.json
   ```

   One more thing to try on paper, not in your account: `aws ec2 modify-vpc-endpoint --reset-policy` puts back the
   default policy, which "allows full access". Nothing would visibly break. That's why the offline lab's checker
   looks for it (M15-15) and attack A8 needs nothing else.

# Part G · Teardown (today)

```bash
make cloud-down      # endpoint, endpoint config, model, registry versions and group, schedule, bucket contents, stack
make cloud-check     # nothing with the lab's names should be left
```

- If the schedule already deleted the endpoint, the first commands print an error and carry on.
- Deleting the stack removes the Lambda function's network interfaces, which can take a while.
- The KMS key enters a 7-day waiting period, the minimum, and costs nothing while it waits.
- Delete `~/models/qwen3-0.6b` on your laptop if you no longer need it, and `cloud/out/` (`make clean`).

Write down what was different from the example responses. That's your evidence that you ran it.
