# M11 guided build: the hardened TSG Helpdesk on Bedrock, by hand, in your own account

The offline lab (README Steps 1 to 6) reviews the Terraform plan at $0, and README Step 7 deploys it with one
`make up`. This guide builds the **same hardened design piece by piece**, so you see every setting the module
teaches: a least-privilege role (11.1), a private VPC endpoint with its own policy and no internet path (11.2), a
customer managed KMS key for the prompt logs (11.3), invocation logging and a CloudTrail trail for what it misses
(11.4), and a US-only inference profile (11.5). Then you prove each control with a request, change one setting and
watch the difference.

**Your own sandbox account only** (lesson 0.7), in **us-east-1**. About 90 minutes. Cost: roughly **US$0.02 to $0.03
an hour** while it exists, mostly the endpoint and the two keys (cost table at the end). Teardown is the last section:
do it the same day.

> **Read this first: about the responses shown below.** We wrote this guide without access to an AWS account, so **no
> response in this file comes from a real run**. Every response block is labelled **"Example response (shape from AWS
> docs, values illustrative)"** and links the page its shape comes from. Field names are copied from the AWS API and
> CLI references and checked against the botocore service models (botocore 1.43.117) for `bedrock`,
> `bedrock-runtime`, `lambda`, `logs`, `cloudtrail`, `iam` and `ec2`. **The values (IDs, IPs, token counts, error
> wording) are our guesses.** Write down what you really get: where it differs, the real service wins. The policies
> are the ones in `terraform/hardened/`, which pass `terraform validate` and the offline checker but were not applied
> in a live account for this guide either (README Step 7 says the same).

Throughout: Region `us-east-1`, one Availability Zone (it halves the endpoint cost; README Step 7 uses two), and these
shell variables. Set them as you go; if you open a new terminal, set them again (the `describe` commands in the
teardown find them for you).

| Variable | What it holds | Example (AWS documentation values) |
|---|---|---|
| `ACCOUNT` | your 12-digit account ID | `111122223333` |
| `PROFILE_ID` | the approved US inference profile | `us.anthropic.claude-haiku-4-5-20251001-v1:0` |
| `VPC`, `SUBNET`, `APP_SG`, `EP_SG` | the network you create in Step 1a | `vpc-0example1`, `subnet-0example1`, `sg-0exampleapp`, `sg-0exampleendpoint` |
| `VPCE` | the bedrock-runtime interface endpoint (Step 1b) | `vpce-0example1` |
| `PROMPTS_KEY`, `AUDIT_KEY` | the two KMS key ARNs (Step 1d) | `arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab` |

**Shortcut, Path C (Terraform).** `make up` (README Step 7) creates all of Step 1 except the probe function, with two
Availability Zones. If you use it, read Step 1 anyway (every setting maps to a file in `terraform/hardened/`), set the
variables from `terraform output` and the console, then start at Step 1i. Tear down with `make down`.

## Step 0 · Before you start (10 minutes)

1. **The budget from M10** (M10 README Step 8b or guided build Step 0). Don't start without it.
2. **AWS CLI v2, recent** (`aws --version`): older versions don't know `bedrock get-account-data-retention`. Python
   3.11+ (you have it for the offline lab).
3. **Enable the model once, as yourself.** The Helpdesk role has no AWS Marketplace permissions, on purpose: "someone
   with AWS Marketplace permissions must enable the model for the account as a one-time step"
   ([model access](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html)). Run README Step 7a's
   `converse` call from your admin session (and fill in the Anthropic use-case form if it asks).
4. **No other invocation logging you care about.** There's one logging configuration per account and Region; Step 1e
   **replaces** any existing one (M10's guided build, for example), and the teardown deletes it.
5. **Permissions.** An administrator in your sandbox covers everything. Otherwise you need create and delete rights for
   EC2 VPC resources (VPC, subnet, security groups, VPC endpoints), IAM roles and inline policies (plus
   `iam:PassRole` for the Lambda and logging roles), KMS keys and aliases, CloudWatch Logs, S3 buckets and bucket
   policies, CloudTrail trails, Lambda functions, and `bedrock:PutModelInvocationLoggingConfiguration`,
   `bedrock:GetInferenceProfile`, `bedrock:GetAccountDataRetention`.
6. **Open a terminal in `labs/m11`**:

   ```bash
   cd labs/m11
   make package
   export AWS_REGION=us-east-1
   export ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
   export PROFILE_ID=us.anthropic.claude-haiku-4-5-20251001-v1:0
   export PROFILE_ARN=arn:aws:bedrock:us-east-1:$ACCOUNT:inference-profile/$PROFILE_ID
   echo "$ACCOUNT"
   ```

   - `make package`: zips lambda/handler.py into terraform/hardened/build/helpdesk.zip
   - `echo "$ACCOUNT"`: is this really the sandbox?

## Step 1 · Build it from zero (45 minutes)

Do the parts in order. For each one you get console clicks (Path A) and CLI commands (Path B). Pick one path per part;
mixing is fine as long as the names match, because later parts refer to them.

### 1a · A VPC with no way out (lesson 11.2)

No internet gateway, no NAT gateway. A new VPC's main route table only has the `local` route, so nothing in it can
reach the internet: the endpoint in 1b will be the only door. Security groups: the function may send HTTPS only to the
endpoint, and the endpoint accepts HTTPS only from the function.

**Path A, console:** **VPC** console, **Your VPCs**, **Create VPC**, **VPC only**, name `tsg-helpdesk-vpc`, IPv4 CIDR
`10.20.0.0/16`, **Create VPC**; then **Actions**, **Edit VPC settings**, tick **Enable DNS hostnames** (DNS resolution
is on by default). **Subnets**, **Create subnet**: that VPC, name `tsg-helpdesk-private-1`, Availability Zone
`us-east-1a`, CIDR `10.20.1.0/24`. **Security groups**, **Create security group** twice: `tsg-helpdesk-app` and
`tsg-helpdesk-bedrock-endpoint`, both in that VPC. On `tsg-helpdesk-app`, delete the default outbound rule and add an
outbound rule HTTPS (443) to `tsg-helpdesk-bedrock-endpoint`; on `tsg-helpdesk-bedrock-endpoint`, add an inbound rule
HTTPS (443) from `tsg-helpdesk-app` (labels may differ slightly).

**Path B, CLI:**

```bash
export VPC=$(aws ec2 create-vpc --cidr-block 10.20.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=tsg-helpdesk-vpc}]' --query Vpc.VpcId --output text)
aws ec2 modify-vpc-attribute --vpc-id $VPC --enable-dns-support '{"Value":true}'
aws ec2 modify-vpc-attribute --vpc-id $VPC --enable-dns-hostnames '{"Value":true}'
export SUBNET=$(aws ec2 create-subnet --vpc-id $VPC --cidr-block 10.20.1.0/24 --availability-zone us-east-1a \
  --query Subnet.SubnetId --output text)

export APP_SG=$(aws ec2 create-security-group --vpc-id $VPC --group-name tsg-helpdesk-app \
  --description "Helpdesk function: HTTPS to the Bedrock endpoint only" --query GroupId --output text)
export EP_SG=$(aws ec2 create-security-group --vpc-id $VPC --group-name tsg-helpdesk-bedrock-endpoint \
  --description "bedrock-runtime endpoint: HTTPS from the Helpdesk function only" --query GroupId --output text)
aws ec2 revoke-security-group-egress --group-id $APP_SG \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
aws ec2 authorize-security-group-egress --group-id $APP_SG \
  --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":443,\"ToPort\":443,\"UserIdGroupPairs\":[{\"GroupId\":\"$EP_SG\"}]}]"
aws ec2 authorize-security-group-ingress --group-id $EP_SG --protocol tcp --port 443 --source-group $APP_SG
```

- `aws ec2 modify-vpc-attribute`: both needed for private DNS

If `us-east-1a` doesn't offer the Bedrock endpoint in your account (zone names map to different physical zones per
account), list the zones that do and use one of them:
`aws ec2 describe-vpc-endpoint-services --service-names com.amazonaws.us-east-1.bedrock-runtime --query 'ServiceDetails[0].AvailabilityZones'`.

### 1b · The bedrock-runtime endpoint, with a policy (lesson 11.2)

The default endpoint policy "grants full access to the endpoint", for any principal, including credentials from
someone else's account ([PrivateLink](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)).
Yours lets only the Helpdesk role run models (`terraform/hardened/network.tf`):

```bash
cat > endpoint-policy.json <<EOF
{"Version": "2012-10-17", "Statement": [{
  "Sid": "OnlyTheHelpdeskRoleMayInvokeModels", "Effect": "Allow", "Principal": "*",
  "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], "Resource": "*",
  "Condition": {"StringEquals": {"aws:PrincipalAccount": "$ACCOUNT"},
                "ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::$ACCOUNT:role/tsg-helpdesk-app"}}}]}
EOF
```

**Path A, console** (steps quoted from [create an interface endpoint](https://docs.aws.amazon.com/vpc/latest/privatelink/create-interface-endpoint.html)):
**VPC** console, "In the navigation pane, choose **Endpoints**", **Create endpoint**. "For **Type**, choose **AWS
services**." **Service name**: `com.amazonaws.us-east-1.bedrock-runtime`. **VPC**: `tsg-helpdesk-vpc`. **Additional
settings**, **Enable DNS name**: "already selected. We recommend that you keep the default." **Subnets**: your one
subnet. **Security groups**: `tsg-helpdesk-bedrock-endpoint` only (untick `default`). **Policy**: **Custom**, paste
`endpoint-policy.json` (the role it names doesn't exist yet; that's fine for an endpoint policy). **Add new tag**:
key `Name`, value `tsg-helpdesk-bedrock-runtime` (the teardown finds it by this tag). **Create endpoint**.

**Path B, CLI:**

```bash
export VPCE=$(aws ec2 create-vpc-endpoint --vpc-id $VPC --vpc-endpoint-type Interface \
  --service-name com.amazonaws.us-east-1.bedrock-runtime --subnet-ids $SUBNET --security-group-ids $EP_SG \
  --private-dns-enabled --policy-document file://endpoint-policy.json \
  --tag-specifications 'ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=tsg-helpdesk-bedrock-runtime}]' \
  --query VpcEndpoint.VpcEndpointId --output text)
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids $VPCE --query 'VpcEndpoints[0].[State,PrivateDnsEnabled]' --output text
```

Wait until the state is `available` (a few minutes). Lesson 11.2's audit command now shows **your** policy, not
`"Principal":"*","Action":"*"` with no condition.

### 1c · Three IAM roles (lessons 11.1, 11.3, 11.4)

| Role | Trusted by | May do |
|---|---|---|
| `tsg-helpdesk-app` | `lambda.amazonaws.com` | invoke one model through one US profile (`app.tf`), plus `AWSLambdaVPCAccessExecutionRole` for its network interface and its own logs |
| `tsg-helpdesk-bedrock-logging` | `bedrock.amazonaws.com`, only for **your** account (`aws:SourceAccount`, `aws:SourceArn`) | write to one log stream (`logging.tf`) |
| `tsg-helpdesk-log-investigator` | people in your account, **with MFA** | decrypt prompt logs, through the key policy in 1d (`kms.tf`) |

**Path B, CLI** (the policy JSON is the Terraform's, with your account ID):

```bash
cat > app-trust.json <<'EOF'
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
EOF
cat > app-invoke.json <<EOF
{"Version": "2012-10-17", "Statement": [
  {"Sid": "TheApprovedGeographicProfile", "Effect": "Allow",
   "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], "Resource": "$PROFILE_ARN"},
  {"Sid": "TheModelOnlyThroughThatProfile", "Effect": "Allow",
   "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
   "Resource": ["arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
                "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
                "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"],
   "Condition": {"StringEquals": {"bedrock:InferenceProfileArn": "$PROFILE_ARN"}}}]}
EOF
aws iam create-role --role-name tsg-helpdesk-app --assume-role-policy-document file://app-trust.json
aws iam put-role-policy --role-name tsg-helpdesk-app --policy-name invoke-approved-model-only --policy-document file://app-invoke.json
aws iam attach-role-policy --role-name tsg-helpdesk-app \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole

cat > logging-trust.json <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
  "Action": "sts:AssumeRole",
  "Condition": {"StringEquals": {"aws:SourceAccount": "$ACCOUNT"},
                "ArnLike": {"aws:SourceArn": "arn:aws:bedrock:us-east-1:$ACCOUNT:*"}}}]}
EOF
cat > logging-perms.json <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
  "Resource": "arn:aws:logs:us-east-1:$ACCOUNT:log-group:/tsg-helpdesk/bedrock/model-invocations:log-stream:aws/bedrock/modelinvocations"}]}
EOF
aws iam create-role --role-name tsg-helpdesk-bedrock-logging --assume-role-policy-document file://logging-trust.json
aws iam put-role-policy --role-name tsg-helpdesk-bedrock-logging --policy-name write-invocation-logs \
  --policy-document file://logging-perms.json

cat > investigator-trust.json <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::$ACCOUNT:root"},
  "Action": "sts:AssumeRole", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}
EOF
aws iam create-role --role-name tsg-helpdesk-log-investigator --assume-role-policy-document file://investigator-trust.json
```

**Path A, console:** **IAM**, **Roles**, **Create role**. For the app role: **AWS service**, **Lambda**, attach
`AWSLambdaVPCAccessExecutionRole`, name `tsg-helpdesk-app`, then **Add permissions**, **Create inline policy**,
**JSON**, paste `app-invoke.json`. For the logging role: **Custom trust policy**, paste `logging-trust.json`, then an
inline policy from `logging-perms.json`. For the investigator: **AWS account**, **This account**, tick **Require MFA**
(labels may differ slightly). Generate the JSON files with the CLI block above even if you click: they carry your
account ID.

Why the trust conditions on the logging role: without `aws:SourceAccount` and `aws:SourceArn`, Bedrock acting for
**another** account could be steered into using your role, the confused deputy (lesson 11.4). They're copied from
AWS's own invocation-logging example.

### 1d · Two customer managed keys (lesson 11.3)

The **prompts** key protects the invocation logs; the **audit** key protects the CloudTrail files. Two keys, because
two different groups should read two different things. The key policies are `terraform/hardened/kms.tf`, turned into
JSON by this script (create the roles in 1c first: KMS refuses a key policy whose principals don't exist yet, with
`MalformedPolicyDocumentException`):

```bash
python3 - <<'EOF'
import json, os
A, R = os.environ["ACCOUNT"], "us-east-1"
root, inv = f"arn:aws:iam::{A}:root", f"arn:aws:iam::{A}:role/tsg-helpdesk-log-investigator"
lg = f"arn:aws:logs:{R}:{A}:log-group:/tsg-helpdesk/bedrock/model-invocations"
trail = f"arn:aws:cloudtrail:{R}:{A}:trail/tsg-helpdesk-ai-data-events"
admin = {"Sid": "KeyAdministrationByTheAccount", "Effect": "Allow", "Principal": {"AWS": root}, "Action": "kms:*", "Resource": "*"}
prompts = {"Version": "2012-10-17", "Statement": [admin,
  {"Sid": "CloudWatchLogsForThePromptLogGroupOnly", "Effect": "Allow", "Principal": {"Service": f"logs.{R}.amazonaws.com"},
   "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"], "Resource": "*",
   "Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": lg}}},
  {"Sid": "BedrockLogDeliveryFromThisAccountOnly", "Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
   "Action": "kms:GenerateDataKey", "Resource": "*",
   "Condition": {"StringEquals": {"aws:SourceAccount": A}, "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{R}:{A}:*"}}},
  {"Sid": "BedrockLoggingRoleWritesThroughCloudWatchLogsOnly", "Effect": "Allow",
   "Principal": {"AWS": f"arn:aws:iam::{A}:role/tsg-helpdesk-bedrock-logging"},
   "Action": ["kms:Encrypt", "kms:ReEncrypt*", "kms:Decrypt", "kms:GenerateDataKey*", "kms:Describe*"], "Resource": "*",
   "Condition": {"StringEquals": {"kms:ViaService": f"logs.{R}.amazonaws.com"}}},
  {"Sid": "InvestigatorsMayDecryptPromptLogs", "Effect": "Allow", "Principal": {"AWS": inv}, "Action": "kms:Decrypt", "Resource": "*"}]}
audit = {"Version": "2012-10-17", "Statement": [admin,
  {"Sid": "AllowCloudTrailEncryptLogs", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
   "Action": "kms:GenerateDataKey*", "Resource": "*",
   "Condition": {"StringEquals": {"aws:SourceArn": trail},
                 "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{A}:trail/*"}}},
  {"Sid": "AllowCloudTrailAccess", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
   "Action": "kms:DescribeKey", "Resource": "*", "Condition": {"StringEquals": {"aws:SourceArn": trail}}},
  {"Sid": "EnableCloudTrailLogDecryptPermissions", "Effect": "Allow", "Principal": {"AWS": inv}, "Action": "kms:Decrypt",
   "Resource": "*", "Condition": {"Null": {"kms:EncryptionContext:aws:cloudtrail:arn": "false"}}}]}
json.dump(prompts, open("key-prompts.json", "w"), indent=2); json.dump(audit, open("key-audit.json", "w"), indent=2)
print("wrote key-prompts.json and key-audit.json")
EOF
```

**Path B, CLI:**

```bash
export PROMPTS_KEY=$(aws kms create-key --description "tsg-helpdesk: Bedrock model invocation logs (prompts and answers)" \
  --policy file://key-prompts.json --query KeyMetadata.Arn --output text)
export AUDIT_KEY=$(aws kms create-key --description "tsg-helpdesk: CloudTrail log files" \
  --policy file://key-audit.json --query KeyMetadata.Arn --output text)
aws kms enable-key-rotation --key-id $PROMPTS_KEY
aws kms enable-key-rotation --key-id $AUDIT_KEY
aws kms create-alias --alias-name alias/tsg-helpdesk-prompt-logs --target-key-id $PROMPTS_KEY
aws kms create-alias --alias-name alias/tsg-helpdesk-trail --target-key-id $AUDIT_KEY
```

**Path A, console:** **KMS**, **Customer managed keys**, **Create key**: **Symmetric**, **Encrypt and decrypt**,
alias `tsg-helpdesk-prompt-logs`, skip the administrator and user pages, then on the review page edit the key policy
and paste `key-prompts.json`; **Finish**. Open the key, **Key rotation** tab, tick automatic rotation. Repeat with
alias `tsg-helpdesk-trail` and `key-audit.json` (labels may differ slightly).

Read `key-prompts.json` before you go on. Who can decrypt prompt logs? The investigator role; CloudWatch Logs, but only
for that one log group (encryption context); the logging role, but only through CloudWatch Logs (`kms:ViaService`).
And, through the first statement, any IAM identity in your account whose own policy allows `kms:Decrypt` on this key.
That's AWS's default first statement, and it's why lesson 11.3 says to search IAM for `kms:Decrypt` on `"*"`.

### 1e · Prompt logging, encrypted and time-limited (lessons 11.3, 11.4)

A log group with the prompts key and 30-day retention, an S3 bucket for bodies over 100 KB, and the logging
configuration: text only.

**Path B, CLI:**

```bash
aws logs create-log-group --log-group-name /tsg-helpdesk/bedrock/model-invocations --kms-key-id $PROMPTS_KEY
aws logs put-retention-policy --log-group-name /tsg-helpdesk/bedrock/model-invocations --retention-in-days 30

export PROMPT_BUCKET=tsg-helpdesk-prompt-logs-$ACCOUNT-us-east-1
aws s3api create-bucket --bucket $PROMPT_BUCKET
aws s3api put-public-access-block --bucket $PROMPT_BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-ownership-controls --bucket $PROMPT_BUCKET \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
aws s3api put-bucket-encryption --bucket $PROMPT_BUCKET --server-side-encryption-configuration \
  "{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$PROMPTS_KEY\"},\"BucketKeyEnabled\":true}]}"
aws s3api put-bucket-lifecycle-configuration --bucket $PROMPT_BUCKET --lifecycle-configuration \
  '{"Rules":[{"ID":"expire-prompt-logs","Status":"Enabled","Filter":{},"Expiration":{"Days":30}}]}'
cat > prompt-bucket-policy.json <<EOF
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AmazonBedrockLogsWrite", "Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
   "Action": "s3:PutObject", "Resource": "arn:aws:s3:::$PROMPT_BUCKET/*",
   "Condition": {"StringEquals": {"aws:SourceAccount": "$ACCOUNT"}, "ArnLike": {"aws:SourceArn": "arn:aws:bedrock:us-east-1:$ACCOUNT:*"}}},
  {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::$PROMPT_BUCKET", "arn:aws:s3:::$PROMPT_BUCKET/*"],
   "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
EOF
aws s3api put-bucket-policy --bucket $PROMPT_BUCKET --policy file://prompt-bucket-policy.json

cat > logging-config.json <<EOF
{"cloudWatchConfig": {"logGroupName": "/tsg-helpdesk/bedrock/model-invocations",
                      "roleArn": "arn:aws:iam::$ACCOUNT:role/tsg-helpdesk-bedrock-logging",
                      "largeDataDeliveryS3Config": {"bucketName": "$PROMPT_BUCKET", "keyPrefix": "large-data"}},
 "textDataDeliveryEnabled": true, "imageDataDeliveryEnabled": false,
 "embeddingDataDeliveryEnabled": false, "videoDataDeliveryEnabled": false}
EOF
aws bedrock put-model-invocation-logging-configuration --logging-config file://logging-config.json
aws bedrock get-model-invocation-logging-configuration
```

Field names are from [PutModelInvocationLoggingConfiguration](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_PutModelInvocationLoggingConfiguration.html)
(`cloudWatchConfig.largeDataDeliveryS3Config.bucketName`, `keyPrefix`). Bodies up to 100 KB go into the log record;
larger ones go to S3 "If an Amazon S3 location for large data delivery is provided" (lesson 11.4).

**Path A, console:** **CloudWatch**, **Log groups**, **Create log group**: name `/tsg-helpdesk/bedrock/model-invocations`,
retention **1 month**, **KMS key ARN** = the prompts key ARN. **S3**, **Create bucket**: the name above, **ACLs
disabled**, **Block all public access** on, **Default encryption** SSE-KMS with the prompts key and **Bucket Key**
enabled; then **Management**, a lifecycle rule expiring objects after 30 days, and **Permissions**, **Bucket policy**
with `prompt-bucket-policy.json`. Bedrock console, **Settings**, **Model invocation logging**: **Text** only,
**CloudWatch Logs only**, the log group, the existing role `tsg-helpdesk-bedrock-logging`, and the bucket for large
data (the console steps are quoted from
[invocation logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html); the role and
large-data labels may differ slightly).

If `put-model-invocation-logging-configuration` fails with a validation error about the role or the log group, IAM
hadn't finished creating the role: wait 30 seconds and retry.

### 1f · A trail for what invocation logging misses (lesson 11.4)

Runtime calls are already management events in the free 90-day event history. This trail records only what isn't:
**bedrock-mantle** inference (a data event, and not in invocation logs), **network activity** through your Bedrock
endpoint (including calls the endpoint policy refused), and guardrail evaluations. It's `terraform/hardened/trail.tf`.

**Path B, CLI:**

```bash
export TRAIL_BUCKET=tsg-helpdesk-trail-$ACCOUNT-us-east-1
export TRAIL_ARN=arn:aws:cloudtrail:us-east-1:$ACCOUNT:trail/tsg-helpdesk-ai-data-events
aws s3api create-bucket --bucket $TRAIL_BUCKET
aws s3api put-public-access-block --bucket $TRAIL_BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-ownership-controls --bucket $TRAIL_BUCKET \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
cat > trail-bucket-policy.json <<EOF
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AWSCloudTrailAclCheck20150319", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
   "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::$TRAIL_BUCKET",
   "Condition": {"StringEquals": {"aws:SourceArn": "$TRAIL_ARN"}}},
  {"Sid": "AWSCloudTrailWrite20150319", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
   "Action": "s3:PutObject", "Resource": "arn:aws:s3:::$TRAIL_BUCKET/AWSLogs/$ACCOUNT/*",
   "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": "$TRAIL_ARN"}}},
  {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::$TRAIL_BUCKET", "arn:aws:s3:::$TRAIL_BUCKET/*"],
   "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
EOF
aws s3api put-bucket-policy --bucket $TRAIL_BUCKET --policy file://trail-bucket-policy.json

aws cloudtrail create-trail --name tsg-helpdesk-ai-data-events --s3-bucket-name $TRAIL_BUCKET \
  --is-multi-region-trail --enable-log-file-validation --kms-key-id $AUDIT_KEY
cat > selectors.json <<'EOF'
[
  {"Name": "Bedrock mantle: CreateInference and other inference/file calls",
   "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
                      {"Field": "resources.type", "Equals": ["AWS::BedrockMantle::Project"]}]},
  {"Name": "Network activity through our VPC endpoints for Amazon Bedrock, including VpceAccessDenied",
   "FieldSelectors": [{"Field": "eventCategory", "Equals": ["NetworkActivity"]},
                      {"Field": "eventSource", "Equals": ["bedrock.amazonaws.com"]}]},
  {"Name": "Bedrock guardrails: ApplyGuardrail, including evaluations during model calls",
   "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
                      {"Field": "resources.type", "Equals": ["AWS::Bedrock::Guardrail"]}]}
]
EOF
aws cloudtrail put-event-selectors --trail-name tsg-helpdesk-ai-data-events --advanced-event-selectors file://selectors.json
aws cloudtrail start-logging --name tsg-helpdesk-ai-data-events
```

No management-event selector, on purpose: a trail with only advanced selectors records only what they select, and
management events are free in event history (in a real organization your org trail delivers them; a second copy costs
$2.00 per 100,000). The network-activity selector fields (`eventCategory` = `NetworkActivity`, `eventSource`) are from
the [network activity events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-network-events-with-cloudtrail.html)
page.

**Path A, console:** **CloudTrail**, **Trails**, **Create trail**: name `tsg-helpdesk-ai-data-events`, the existing
bucket above, **Log file SSE-KMS encryption** with the audit key, **Log file validation** enabled. Next page: untick
**Management events**; tick **Data events** and add the Bedrock mantle project and Bedrock guardrail resource types;
tick **Network activity events**, **Network activity event source** `bedrock.amazonaws.com`, the log-all template
(labels may differ slightly). The trail's **JSON view** should match `selectors.json`.

### 1g · The Helpdesk function (lesson 11.6)

The same Lambda function as the Terraform: `lambda/handler.py`, `MODEL_ID` = the US profile, `MAX_TOKENS` = 300 (lesson
10.5's cost cap), in your private subnet with the app security group.

**Path B, CLI:**

```bash
aws logs create-log-group --log-group-name /aws/lambda/tsg-helpdesk
aws logs put-retention-policy --log-group-name /aws/lambda/tsg-helpdesk --retention-in-days 14
aws lambda create-function --function-name tsg-helpdesk --runtime python3.13 --handler handler.handler \
  --role arn:aws:iam::$ACCOUNT:role/tsg-helpdesk-app --zip-file fileb://terraform/hardened/build/helpdesk.zip \
  --timeout 30 --memory-size 256 \
  --vpc-config SubnetIds=$SUBNET,SecurityGroupIds=$APP_SG \
  --environment "Variables={MODEL_ID=$PROFILE_ID,MAX_TOKENS=300}"
aws lambda wait function-active-v2 --function-name tsg-helpdesk
```

`--vpc-config` uses the syntax from the [Lambda VPC guide](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html).
If `create-function` says the role can't be assumed, IAM is still catching up: wait 10 seconds and retry.

**Path A, console** (procedure from the same guide): **Lambda** console, **Create Event Function** (older consoles say
**Create function**), **Author from scratch**, name `tsg-helpdesk`, runtime **Python 3.13**, execution role **Use an
existing role** `tsg-helpdesk-app`; **Advanced settings**, **Enable VPC**, `tsg-helpdesk-vpc`, your subnet, security
group `tsg-helpdesk-app` only. Create it, upload `terraform/hardened/build/helpdesk.zip` (**Code**, **Upload from**,
**.zip file**), set the handler to `handler.handler`, and under **Configuration** set the timeout to 30 seconds and the
environment variables `MODEL_ID` and `MAX_TOKENS` (labels may differ slightly).

### 1h · Residency: check where the profile can run, and the retention mode (lessons 11.3, 11.5)

```bash
aws bedrock get-inference-profile --inference-profile-identifier $PROFILE_ID \
  --query '[inferenceProfileId, type, models[].modelArn]' --output json
aws bedrock get-account-data-retention
```

Example response (shape from AWS docs, values illustrative;
[GetInferenceProfile](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GetInferenceProfile.html)):

```json
[
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "SYSTEM_DEFINED",
    [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
        "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
        "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"
    ]
]
```

How to read it: `models[].modelArn` lists where this profile may send a request from us-east-1. Every Region is a US
one, which is AnyCompany's residency rule, and they are exactly the three model ARNs in `app-invoke.json`. If AWS ever
adds a Region to the profile, the role refuses calls routed there until you add it on purpose. Compare with the
`global.` profile: `aws bedrock get-inference-profile --inference-profile-identifier global.anthropic.claude-haiku-4-5-20251001-v1:0`.

The retention answer is a `mode` (`default`, `none`, `aws_review`, `provider_data_share` or `inherit`, per the
botocore `bedrock` model) and `updatedAt`. Lesson 11.3: choose it on purpose, per Region. If you set `none`
(`aws bedrock put-account-data-retention --mode none`), remember the trade-off: models that require retention become
unavailable in this Region. It doesn't affect Claude Haiku 4.5 as of October 2026 (check its model card).

### 1i · A probe function, for the tests (5 minutes)

To test the endpoint policy and the network you need a **second** caller inside the VPC that isn't the Helpdesk role.
The probe has its own role with **the same IAM permissions** as the Helpdesk (so IAM would allow its model call) and
the same security group. It does two things: `runtime` resolves the Bedrock hostname and calls the model; `internet`
tries to reach bedrock-mantle's public endpoint.

```bash
cat > probe.py <<'EOF'
import os, socket, urllib.request
import boto3

def handler(event, context):
    test = (event or {}).get("test", "runtime")
    region = os.environ["AWS_REGION"]
    out = {"test": test}
    if test == "runtime":
        host = f"bedrock-runtime.{region}.amazonaws.com"
        out["resolves_to"] = sorted({a[4][0] for a in socket.getaddrinfo(host, 443)})
        try:
            r = boto3.client("bedrock-runtime").converse(
                modelId=os.environ["MODEL_ID"], inferenceConfig={"maxTokens": 10},
                messages=[{"role": "user", "content": [{"text": "Say OK."}]}])
            out["result"] = "ALLOWED"
            out["stopReason"] = r["stopReason"]
        except Exception as e:
            out["result"] = "REFUSED"
            out["error"] = f"{type(e).__name__}: {e}"
    else:
        try:
            urllib.request.urlopen(f"https://bedrock-mantle.{region}.api.aws/", timeout=5)
            out["result"] = "REACHED THE INTERNET"
        except Exception as e:
            out["result"] = "NO PATH"
            out["error"] = f"{type(e).__name__}: {e}"
    return out
EOF
python3 -c "import zipfile; zipfile.ZipFile('probe.zip', 'w').write('probe.py')"

aws iam create-role --role-name tsg-m11-probe --assume-role-policy-document file://app-trust.json
aws iam put-role-policy --role-name tsg-m11-probe --policy-name invoke-approved-model-only --policy-document file://app-invoke.json
aws iam attach-role-policy --role-name tsg-m11-probe \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole
sleep 10
aws lambda create-function --function-name tsg-m11-probe --runtime python3.13 --handler probe.handler \
  --role arn:aws:iam::$ACCOUNT:role/tsg-m11-probe --zip-file fileb://probe.zip --timeout 30 \
  --vpc-config SubnetIds=$SUBNET,SecurityGroupIds=$APP_SG --environment "Variables={MODEL_ID=$PROFILE_ID}"
aws lambda wait function-active-v2 --function-name tsg-m11-probe
```

## Step 2 · Prove it: five requests (15 minutes)

Each `aws lambda invoke` prints a small status object; the function's answer goes into `out.json`.

### R1 · The Helpdesk answers, through the endpoint (allowed)

```bash
aws lambda invoke --function-name tsg-helpdesk --cli-binary-format raw-in-base64-out \
  --payload '{"question":"How do I reset my VPN token?"}' out.json && cat out.json; echo
```

Example response (shape from AWS docs, values illustrative;
[Invoke](https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html) for the status,
[Converse](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html) `usage` inside the
answer, which `lambda/handler.py` passes through):

```json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
{"answer": "Open the self-service portal, choose Reset VPN token and follow the prompts on your registered phone. If you're locked out, raise a ticket.", "usage": {"inputTokens": 61, "outputTokens": 31, "totalTokens": 92}}
```

How to read it: `StatusCode` 200 with no `FunctionError` field means the function ran without crashing. The answer
came back although the function's subnet has **no route to the internet**: the call went through your endpoint. If
the invoke hangs for 30 seconds and returns a timeout, private DNS or the security groups are wrong (README
troubleshooting). If the answer is an `AccessDeniedException`, do Step 0.3.

### R2 · Another identity, inside the VPC, through the same endpoint (refused by the endpoint policy)

```bash
aws lambda invoke --function-name tsg-m11-probe --cli-binary-format raw-in-base64-out \
  --payload '{"test":"runtime"}' out.json && cat out.json; echo
```

Example response (shape from the IAM docs' access-denied message format, values illustrative;
[IAM access denied messages](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)):

```json
{"test": "runtime", "resolves_to": ["10.20.1.57"], "result": "REFUSED", "error": "ClientError: An error occurred (AccessDeniedException) when calling the Converse operation: User: arn:aws:sts::111122223333:assumed-role/tsg-m11-probe/tsg-m11-probe is not authorized to perform: bedrock:InvokeModel on resource: arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0 because no VPC endpoint policy allows the bedrock:InvokeModel action"}
```

How to read it, field by field:

- `resolves_to` is a **private** address in your subnet: private DNS sent the normal hostname to the endpoint. That's
  lesson 11.2's "No code changes needed".
- "**because no VPC endpoint policy allows**" is the IAM docs' wording for an endpoint-policy refusal. The probe's own
  IAM policy allows this exact call (it's a copy of the Helpdesk's). Only the endpoint said no.
- This is attack X1 in miniature. In X1 the outsider uses keys from **their** account; here it's another role in
  yours. Same policy line stops both: `aws:PrincipalArn` names one role.

### R3 · The public path (no route)

```bash
aws lambda invoke --function-name tsg-m11-probe --cli-binary-format raw-in-base64-out \
  --payload '{"test":"internet"}' out.json && cat out.json; echo
```

Example response (shape from the Python standard library's `urllib` errors, values illustrative):

```json
{"test": "internet", "result": "NO PATH", "error": "URLError: <urlopen error timed out>"}
```

How to read it: the function asked for `bedrock-mantle.us-east-1.api.aws`, the endpoint lesson 11.2 calls the side
door. With no NAT or internet gateway, and egress allowed only to the endpoint's security group, the connection can't
leave the VPC. In the first draft (NAT gateway), this same code would reach mantle, where your bedrock-runtime endpoint
policy never sees it and invocation logging doesn't record it (attack X7). Any error here is a pass; `REACHED THE
INTERNET` is a finding.

### R4 · What the Helpdesk role itself can't do (least privilege and residency, simulated)

The Helpdesk role is trusted by Lambda only, so you can't become it from your terminal. The IAM policy simulator
answers the question without making any call. Three requests: the approved route, the same model called directly in
us-west-2 (attack X3), and the global profile (attack X4):

```bash
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::$ACCOUNT:role/tsg-helpdesk-app \
  --action-names bedrock:InvokeModel \
  --resource-arns $PROFILE_ARN \
    arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0 \
    arn:aws:bedrock:us-east-1:$ACCOUNT:inference-profile/global.anthropic.claude-haiku-4-5-20251001-v1:0 \
  --query 'EvaluationResults[].[EvalResourceName,EvalDecision]' --output text
```

Example response (shape from AWS docs, values illustrative;
[SimulatePrincipalPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html):
`EvalDecision` is `allowed`, `explicitDeny` or `implicitDeny`):

```text
arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0	allowed
arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0	implicitDeny
arn:aws:bedrock:us-east-1:111122223333:inference-profile/global.anthropic.claude-haiku-4-5-20251001-v1:0	implicitDeny
```

How to read it: the profile is allowed. The model ARN in us-west-2 is allowed **only** with `bedrock:InferenceProfileArn`
set to your profile, and a direct call doesn't carry that key, so it's `implicitDeny` (the simulator may also list
`bedrock:InferenceProfileArn` under `MissingContextValues`). The global profile isn't named anywhere: `implicitDeny`.
That's lesson 11.1's "one model, one route", and lesson 11.5's residency rule enforced by the role.

### R5 · Find the evidence: prompt log, CloudTrail, network activity

Wait about 5 minutes after R1 and R2, then:

1. The log group really uses your key, and R1 is in it:

```bash
aws logs describe-log-groups --log-group-name-prefix /tsg-helpdesk/bedrock --query 'logGroups[].[logGroupName,kmsKeyId,retentionInDays]' --output text
aws logs filter-log-events --log-group-name /tsg-helpdesk/bedrock/model-invocations \
  --start-time $(( ($(date +%s) - 3600) * 1000 )) --max-items 1 --query 'events[0].message' --output text
```

2. CloudTrail event history: R1's Converse, and which endpoint it used.

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=Converse --max-items 5 \
  --query 'Events[].CloudTrailEvent' --output json \
  | python3 -c "import sys,json; [print(json.dumps({k: e.get(k) for k in ('eventTime','errorCode','vpcEndpointId')} | {'who': e['userIdentity'].get('arn')})) for e in map(json.loads, json.load(sys.stdin))]"
```

3. Network activity events in the trail bucket (R2's refusal), 5 to 15 minutes after R2:

```bash
aws s3 ls s3://$TRAIL_BUCKET/AWSLogs/$ACCOUNT/ --recursive | tail -5
```

Copy one key from the list, then:

```bash
aws s3 cp s3://$TRAIL_BUCKET/<key from the list> - | gunzip | python3 -m json.tool | grep -n -E 'VpceAccessDenied|eventCategory|vpcEndpointId'
```

Example response for the prompt log (shape from AWS docs, values illustrative;
[invocation log record](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)), trimmed:

```json
{
    "schemaType": "ModelInvocationLog",
    "schemaVersion": "1.0",
    "timestamp": "2026-10-22T10:05:41Z",
    "accountId": "111122223333",
    "region": "us-east-1",
    "requestId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE44444",
    "operation": "Converse",
    "modelId": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "identity": {"arn": "arn:aws:sts::111122223333:assumed-role/tsg-helpdesk-app/tsg-helpdesk"},
    "requestMetadata": {"app": "tsg-helpdesk", "env": "m11-lab"},
    "input": {"inputContentType": "application/json", "inputBodyJson": {"messages": [{"role": "user", "content": [{"text": "How do I reset my VPN token?"}]}]}, "inputTokenCount": 61},
    "output": {"outputContentType": "application/json", "outputBodyJson": {"stopReason": "end_turn"}, "outputTokenCount": 31}
}
```

How to read it: `describe-log-groups` shows a `kmsKeyId` (your prompts key) and `30`: lesson 11.3's evidence. The
record holds the question in plain text, so who can read this log group is who can read your users' questions.
`identity.arn` is the Helpdesk role (Bedrock fills it); `requestMetadata` came from the handler code, and "is the only
field supplied by the caller", so never use it to attribute a call. R2's refused call is **not** here: it never reached
a model. As an admin you could read this record because your IAM policy allows `kms:Decrypt` on `*` and the key's first
statement delegates to IAM. In a real account, that's the line to tighten.

Example response for CloudTrail (shape from AWS docs, values illustrative;
[CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html):
`vpcEndpointId` "Identifies the VPC endpoint in which requests were made"):

```text
{"eventTime": "2026-10-22T10:05:40Z", "errorCode": null, "vpcEndpointId": "vpce-0example1", "who": "arn:aws:sts::111122223333:assumed-role/tsg-helpdesk-app/tsg-helpdesk"}
```

How to read it: R1 is a management event with your endpoint's ID: the call took the private path. A Helpdesk call
**without** `vpcEndpointId` would mean it took another path (lesson 11.2's spot-it rule). R2 may also appear here with
an access-denied `errorCode`; whether an endpoint-policy refusal reaches event history isn't something AWS spells out,
so note what you see.

For the trail files: look for a record with `"eventCategory": "NetworkActivity"`, your `vpcEndpointId` and
`"errorCode": "VpceAccessDenied"` ("when there is a VPC endpoint policy violation, the error code is
`VpceAccessDenied`", lesson 11.2). **This is the open question from the fact-check:** AWS lists Amazon Bedrock
(`bedrock.amazonaws.com`) for network activity events but doesn't say which Bedrock endpoint services that covers. If
R2's refusal shows up, you've confirmed it for bedrock-runtime; if after 15 minutes it doesn't, that's a real finding
too. Either way, write it down before you build an alert on it.

## Step 3 · Change one setting, re-run, compare (5 minutes)

The claim in R2 was "only the endpoint said no". Test it: add the probe role to the endpoint policy's
`aws:PrincipalArn`, re-run R2, then put it back.

```bash
python3 - <<'EOF'
import json, os
p = json.load(open("endpoint-policy.json"))
a = os.environ["ACCOUNT"]
p["Statement"][0]["Condition"]["ArnEquals"]["aws:PrincipalArn"] = [
    f"arn:aws:iam::{a}:role/tsg-helpdesk-app", f"arn:aws:iam::{a}:role/tsg-m11-probe"]
json.dump(p, open("endpoint-policy-wider.json", "w"), indent=2)
EOF
aws ec2 modify-vpc-endpoint --vpc-endpoint-id $VPCE --policy-document file://endpoint-policy-wider.json
sleep 30
aws lambda invoke --function-name tsg-m11-probe --cli-binary-format raw-in-base64-out \
  --payload '{"test":"runtime"}' out.json && cat out.json; echo
```

- `sleep 30`: endpoint policy changes can take a moment to apply

Console: **VPC**, **Endpoints**, your endpoint, **Policy** tab, **Edit policy**, change the `aws:PrincipalArn` value to
a list with both role ARNs, **Save** (labels may differ slightly).

Example response (shape from AWS docs, values illustrative;
[Converse](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html) `stopReason`):

```json
{"test": "runtime", "resolves_to": ["10.20.1.57"], "result": "ALLOWED", "stopReason": "end_turn"}
```

| | R2 before (Helpdesk role only) | R2 after (both roles listed) |
|---|---|---|
| Probe's IAM policy | allows the call | allows the call (unchanged) |
| Endpoint policy | refuses: "no VPC endpoint policy allows" | allows |
| Result | `REFUSED` | `ALLOWED`, a model ran and billed a few tokens |
| Prompt log | nothing | a record with `identity.arn` = `tsg-m11-probe` |
| Trail | `VpceAccessDenied` (if Bedrock runtime is covered) | no network-activity refusal |

One policy line was the whole difference. That's why lesson 11.2 calls the endpoint policy the **identity perimeter**:
it's the only control here that says "not you, whatever IAM thinks". Now put it back and confirm R2 is refused again:

```bash
aws ec2 modify-vpc-endpoint --vpc-endpoint-id $VPCE --policy-document file://endpoint-policy.json
sleep 30
aws lambda invoke --function-name tsg-m11-probe --cli-binary-format raw-in-base64-out \
  --payload '{"test":"runtime"}' out.json && cat out.json; echo
```

Optional, the same idea one layer down: set the Helpdesk's `MODEL_ID` to the global profile
(`aws lambda update-function-configuration --function-name tsg-helpdesk --environment
"Variables={MODEL_ID=global.anthropic.claude-haiku-4-5-20251001-v1:0,MAX_TOKENS=300}"`), run R1, read the
`AccessDeniedException` ("because no identity-based policy allows"), and set it back to `$PROFILE_ID`. The role
refused it, so nothing ran outside the US: R4's simulation, for real.

## Cost (list prices, October 2026)

| Item | Price | Source |
|---|---|---|
| bedrock-runtime interface endpoint, **1** network interface | $0.01 per hour, "Each partial VPC endpoint-hour consumed is billed as a full hour"; data $0.01 per GB | [PrivateLink pricing](https://aws.amazon.com/privatelink/pricing/) |
| 2 KMS keys | "$1/month (prorated hourly)" each; "no charge" while scheduled for deletion | [KMS pricing](https://aws.amazon.com/kms/pricing/) |
| Trail: data and network activity events | $0.10 per 100,000 events delivered | [CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/) |
| Lambda, CloudWatch Logs, S3 | per request and per GB; this guide makes about 10 invocations and writes a few KB | AWS pricing pages |
| Claude Haiku 4.5 tokens | per token, "billed through AWS Marketplace", shown under the model provider in Cost Explorer; 3 to 5 short calls, at most 300 output tokens each | [model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-haiku-4-5.html), [Bedrock pricing](https://aws.amazon.com/bedrock/pricing/) |

So about **$0.01 an hour** for the endpoint plus about **$0.003 an hour** for the two keys' prorated share, and cents
for the rest. An afternoon of this guide stays well under **US$0.20**. The thing that costs money is forgetting the
teardown.

## Teardown (10 minutes; do it today)

In your own admin credentials, in this order. If you used Terraform (Path C), delete the probe (step 1 below) and then
run `make down` instead of the rest.

1. The two functions and their roles:

```bash
aws lambda delete-function --function-name tsg-m11-probe
aws lambda delete-function --function-name tsg-helpdesk
for R in tsg-m11-probe tsg-helpdesk-app; do
  aws iam delete-role-policy --role-name $R --policy-name invoke-approved-model-only
  aws iam detach-role-policy --role-name $R --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole
  aws iam delete-role --role-name $R
done
aws logs delete-log-group --log-group-name /aws/lambda/tsg-helpdesk
aws logs delete-log-group --log-group-name /aws/lambda/tsg-m11-probe 2>/dev/null
```

2. Logging: configuration, role, log group, bucket.

```bash
aws bedrock delete-model-invocation-logging-configuration
aws iam delete-role-policy --role-name tsg-helpdesk-bedrock-logging --policy-name write-invocation-logs
aws iam delete-role --role-name tsg-helpdesk-bedrock-logging
aws logs delete-log-group --log-group-name /tsg-helpdesk/bedrock/model-invocations
aws s3 rb s3://tsg-helpdesk-prompt-logs-$ACCOUNT-us-east-1 --force
```

3. The trail and its bucket:

```bash
aws cloudtrail delete-trail --name tsg-helpdesk-ai-data-events
aws s3 rb s3://tsg-helpdesk-trail-$ACCOUNT-us-east-1 --force
```

4. The endpoint (wait until it's gone: Lambda's network interfaces can take several minutes to release)

```bash
VPCE=$(aws ec2 describe-vpc-endpoints --filters Name=tag:Name,Values=tsg-helpdesk-bedrock-runtime \
  Name=service-name,Values=com.amazonaws.us-east-1.bedrock-runtime --query 'VpcEndpoints[0].VpcEndpointId' --output text)
echo "$VPCE"
aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $VPCE
```

- `echo "$VPCE"`: None? then set VPCE to the ID from Step 1b by hand

5. The network (if a delete fails with DependencyViolation, Lambda's interfaces haven't been released yet: wait and retry)

```bash
VPC=$(aws ec2 describe-vpcs --filters Name=tag:Name,Values=tsg-helpdesk-vpc --query 'Vpcs[0].VpcId' --output text)
for SG in $(aws ec2 describe-security-groups --filters Name=vpc-id,Values=$VPC \
            --query "SecurityGroups[?GroupName!='default'].GroupId" --output text); do
  aws ec2 revoke-security-group-ingress --group-id $SG \
    --ip-permissions "$(aws ec2 describe-security-groups --group-ids $SG --query 'SecurityGroups[0].IpPermissions' --output json)" 2>/dev/null
  aws ec2 revoke-security-group-egress --group-id $SG \
    --ip-permissions "$(aws ec2 describe-security-groups --group-ids $SG --query 'SecurityGroups[0].IpPermissionsEgress' --output json)" 2>/dev/null
done
for SG in $(aws ec2 describe-security-groups --filters Name=vpc-id,Values=$VPC \
            --query "SecurityGroups[?GroupName!='default'].GroupId" --output text); do aws ec2 delete-security-group --group-id $SG; done
for S in $(aws ec2 describe-subnets --filters Name=vpc-id,Values=$VPC --query 'Subnets[].SubnetId' --output text); do
  aws ec2 delete-subnet --subnet-id $S; done
aws ec2 delete-vpc --vpc-id $VPC
```

6. The keys: 7 days' wait, the minimum AWS allows; no charge while pending.

```bash
for A in alias/tsg-helpdesk-prompt-logs alias/tsg-helpdesk-trail; do
  K=$(aws kms describe-key --key-id $A --query KeyMetadata.KeyId --output text)
  aws kms delete-alias --alias-name $A
  aws kms schedule-key-deletion --key-id $K --pending-window-in-days 7
done
aws iam delete-role --role-name tsg-helpdesk-log-investigator
```

7. Local files:

```bash
rm -f endpoint-policy.json endpoint-policy-wider.json app-trust.json app-invoke.json logging-trust.json \
  logging-perms.json investigator-trust.json key-prompts.json key-audit.json prompt-bucket-policy.json \
  trail-bucket-policy.json selectors.json logging-config.json probe.py probe.zip out.json
```

If you created the endpoint in the console without the `Name` tag `tsg-helpdesk-bedrock-runtime`, step 4's lookup
prints `None`: set `VPCE` to the endpoint ID from Step 1b and run the delete line again. The security-group loop removes the two groups' rules first, because each references the
other and AWS won't delete a group another group's rule still points at. Then check nothing is left:
`aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=$VPC` should be empty (or fail because the VPC is gone),
and `aws kms list-aliases --query "Aliases[?starts_with(AliasName, 'alias/tsg-helpdesk')]"` should print `[]`.

"After a KMS key is deleted, you can no longer decrypt the data that was encrypted under that KMS key" (lesson 11.3).
Here that's on purpose: the prompt logs are gone with it. Tomorrow, glance at **Billing**, **Bills**: this guide should
show a few cents of VPC endpoint, KMS and Claude Haiku 4.5 under its provider.

## What to write in your findings notebook (lesson 0.5)

Your results table from Step 3, plus three lines: what you proved (the endpoint refuses an identity IAM allows; no
public path; the role can't reach the model directly or globally; prompt logs are KMS-encrypted and kept 30 days),
what you could not confirm (whether R2's refusal appears as a `VpceAccessDenied` network activity event), and what
you'd alert on (`vpcEndpointId` missing from a Helpdesk call, `VpceAccessDenied`, `Decrypt` on the prompts key,
`PutModelInvocationLoggingConfiguration` by anyone but the security admin).
