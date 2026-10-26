# M10 guided build: map your AWS AI footprint, then lock it down, in your own account

The offline lab (README Steps 1 to 7) teaches the mechanics at $0 with AnyCompany's fake account. This guide does the
same job for real, step by step, in **your own** AWS sandbox account, in **us-east-1**. About 60 to 75 minutes.
Cost: a few US cents if you follow it as written (cost table at the end). Teardown is the last section: do it today.

You'll do what lesson 10.1 calls "build the inventory before you build the controls": find which AI services run in
the account, who can call the models, which Bedrock API keys exist and which logs are on. Then you'll lock it down:
invocation logging on, a usage alarm, a least-privilege app role, a guardrail policy against long-term keys, logging
tampering and unapproved models, and a test key you'll watch being refused.

> **Read this first: about the responses shown below.** We wrote this guide without access to an AWS account, so **no
> response in this file comes from a real run**. Every response block is labelled **"Example response (shape from AWS
> docs, values illustrative)"** and links the page its shape comes from. Field names are copied from the AWS API and
> CLI references and checked against the botocore service models (botocore 1.43.117) for `iam`, `bedrock`,
> `bedrock-runtime`, `cloudtrail` and `guardduty`. **The values (IDs, dates, token counts, error wording) are our
> guesses.** Write down what you really get: where it differs, the real service wins.

Throughout: Region `us-east-1`, and these shell variables (set them in Step 0, and again if you open a new terminal):

| Variable | What it holds | Example (AWS documentation values) |
|---|---|---|
| `ACCOUNT` | your 12-digit account ID | `111122223333` |
| `MODEL` | the approved model, through the US inference profile (as in M11 and M12) | `us.anthropic.claude-haiku-4-5-20251001-v1:0` |
| `ROLE_ARN` | the least-privilege demo role you create in Step 2d | `arn:aws:iam::111122223333:role/tsg-m10-app-demo` |
| `KEY_ID` | the `ServiceSpecificCredentialId` of the test API key (Step 2e) | `ACCAEXAMPLEKEYID1234` |
| `AWS_BEARER_TOKEN_BEDROCK` | the test API key itself, **only in your shell, never in a file** | (secret) |

## Step 0 · Before you start (10 minutes)

1. **A sandbox account with a budget alarm** (lesson 0.7). Not a work account, and never one you aren't allowed to
   test (lesson 0.8). If you don't have a budget yet, the lab ships one: put your email in
   `aws-twin/notifications-with-subscribers.json` (replace `you@example.com`), then run the `create-budget` command
   in Step 0.5.
2. **The AWS CLI v2, recent.** `aws --version` should show `aws-cli/2.x`. Update it if it's older than a few months:
   older CLIs don't know `bedrock get-account-data-retention` and fail with `Invalid choice`. You also need `curl`
   (Mac and Linux have it).
3. **Use the model once, as yourself.** Most serverless models are "enabled on first use", and Anthropic models ask
   first-time customers for use-case details
   ([model access](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html)). Do that first call from
   your admin session, so the test identities below never need Marketplace permissions (lesson 11.1):

   ```bash
   aws bedrock-runtime converse --region us-east-1 --model-id us.anthropic.claude-haiku-4-5-20251001-v1:0 \
     --messages '[{"role":"user","content":[{"text":"hello"}]}]' --inference-config maxTokens=20
   ```

   If it returns an `AccessDeniedException` about the use case, open the Bedrock console, find Claude Haiku 4.5 in the
   **Model catalog** (label may differ slightly), submit the form, wait a few minutes and retry.
4. **Permissions.** In a sandbox you'll normally be an administrator (lesson 0.7), which covers everything here. If
   you're not, your identity needs read access to IAM, CloudTrail, Bedrock, SageMaker AI and GuardDuty for Step 1
   (`iam:List*`, `iam:Get*`, `iam:SimulatePrincipalPolicy`, `cloudtrail:LookupEvents`, `cloudtrail:DescribeTrails`,
   `cloudtrail:GetEventSelectors`, `bedrock:List*`, `bedrock:Get*`, `sagemaker:List*`, `guardduty:ListDetectors`,
   `guardduty:GetDetector`), and for Step 2: `logs:CreateLogGroup`, `logs:PutRetentionPolicy`, `iam:CreateRole`,
   `iam:PutRolePolicy`, `iam:CreatePolicy`, `iam:AttachRolePolicy`, `iam:CreateUser`, `iam:AttachUserPolicy`,
   `iam:CreateServiceSpecificCredential`, `iam:PassRole` (for the logging role),
   `bedrock:PutModelInvocationLoggingConfiguration`, `sns:CreateTopic`, `sns:Subscribe`, `cloudwatch:PutMetricAlarm`,
   `budgets:ModifyBudget`, `sts:AssumeRole`; plus the matching delete actions for the teardown.
5. **Open a terminal in `labs/m10`** and set the basics:

   ```bash
   cd labs/m10
   export AWS_REGION=us-east-1
   export ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
   export MODEL=us.anthropic.claude-haiku-4-5-20251001-v1:0
   echo "$ACCOUNT"
   ```

   What to look for: `echo "$ACCOUNT"` prints 12 digits. Is this really the sandbox?

   Only if you have no budget yet (free: "You can monitor and receive notifications on your budgets free of charge")

   ```bash
   aws budgets create-budget --account-id $ACCOUNT --budget file://aws-twin/budget.json \
     --notifications-with-subscribers file://aws-twin/notifications-with-subscribers.json
   ```

## Step 1 · Inventory: what's there, who can call it, what's logged (15 minutes, read-only, $0)

Nothing in this step changes your account. Fill in the one-page map at the end of the step as you go (lesson 10.1).

### 1a · Which AI services have been used?

CloudTrail event history keeps "the past 90 days of management events" for free (lesson 10.0). Bedrock records
`InvokeModel`, `InvokeModelWithResponseStream`, `Converse` and `ConverseStream` there as management events, with event
source `bedrock.amazonaws.com` ([CloudTrail for Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)).

**Console:** open **CloudTrail**, choose **Event history**, set the lookup attribute to **Event source** and type
`bedrock.amazonaws.com` (labels may differ slightly). Repeat with `sagemaker.amazonaws.com` and
`bedrock-agentcore.amazonaws.com`.

**CLI** (lookup attributes from the [LookupEvents API](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html):
`EventId`, `EventName`, `ReadOnly`, `Username`, `ResourceType`, `ResourceName`, `EventSource`, `AccessKeyId`):

```bash
for SRC in bedrock.amazonaws.com sagemaker.amazonaws.com bedrock-agentcore.amazonaws.com; do
  echo "== $SRC"
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventSource,AttributeValue=$SRC \
    --max-items 50 --query 'Events[].[EventTime,EventName,Username]' --output text
done
```

Example response (shape from AWS docs, values illustrative;
[LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)):

```text
== bedrock.amazonaws.com
2026-10-22T08:41:10+00:00   Converse                 your-admin-user
2026-10-22T08:40:55+00:00   ListFoundationModels     your-admin-user
== sagemaker.amazonaws.com
== bedrock-agentcore.amazonaws.com
```

How to read it: your own Step 0.3 call shows up as `Converse`. Any principal you **don't** recognise, or a service
nobody told you about, is finding number one. Two blind spots, both from lesson 10.1:

- **bedrock-mantle** (the OpenAI-compatible and Anthropic Messages endpoint) logs inference as CloudTrail **data
  events**, which never appear in event history and are recorded only if a trail selects them
  ([mantle CloudTrail](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-cloudtrail-mantle.html)). Step 1e
  checks for such a trail.
- Event history is per Region. If your account could have used other Regions, repeat the loop with `--region`.

### 1b · Which AI resources exist?

```bash
aws bedrock list-guardrails --query 'guardrails[].[name,id,status]' --output text
aws bedrock list-inference-profiles --type-equals APPLICATION --query 'inferenceProfileSummaries[].inferenceProfileId' --output text
aws bedrock list-provisioned-model-throughputs --query 'provisionedModelSummaries[].[provisionedModelName,status]' --output text
aws bedrock-agent list-knowledge-bases --query 'knowledgeBaseSummaries[].[name,status]' --output text
aws bedrock-agent list-agents --query 'agentSummaries[].[agentName,agentStatus]' --output text
aws bedrock-agentcore-control list-agent-runtimes --query 'agentRuntimes[].[agentRuntimeName,status]' --output text
aws sagemaker list-endpoints --query 'Endpoints[].[EndpointName,EndpointStatus]' --output text
aws sagemaker list-notebook-instances --query 'NotebookInstances[].[NotebookInstanceName,NotebookInstanceStatus]' --output text
```

In a fresh sandbox every line prints nothing. That's the answer you want. A **provisioned throughput** you didn't
buy is urgent: it's billed hourly and some terms can't be cancelled (lesson 10.4). If a command fails with
`Invalid choice`, your CLI is older than that service: update it (Step 0.2) or skip the line.

### 1c · Who can call the models?

Two questions: who carries AWS's broad Bedrock policies, and which roles and users would be **allowed** to run a
model or switch off prompt logging.

```bash
for P in AmazonBedrockLimitedAccess AmazonBedrockFullAccess; do
  echo "== $P"
  aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/$P \
    --query '[PolicyUsers[].UserName, PolicyRoles[].RoleName, PolicyGroups[].GroupName]' --output text
done
```

Then ask the IAM policy simulator about every role and user (it evaluates the identity's policies and, in an
organization, the SCPs above it; it doesn't make the calls):

```bash
for ARN in $(aws iam list-roles --query "Roles[?!starts_with(Path, '/aws-service-role/')].Arn" --output text) \
           $(aws iam list-users --query 'Users[].Arn' --output text); do
  ALLOWED=$(aws iam simulate-principal-policy --policy-source-arn "$ARN" \
    --action-names bedrock:InvokeModel bedrock-mantle:CreateInference \
                   bedrock:DeleteModelInvocationLoggingConfiguration bedrock:CreateProvisionedModelThroughput \
    --query "EvaluationResults[?EvalDecision=='allowed'].EvalActionName" --output text)
  [ -n "$ALLOWED" ] && echo "$ARN -> $ALLOWED"
done
```

Example response (shape from AWS docs, values illustrative;
[SimulatePrincipalPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html):
`EvaluationResults[].EvalActionName` and `EvalDecision`, which is `allowed`, `explicitDeny` or `implicitDeny`):

```text
arn:aws:iam::111122223333:role/OrganizationAccountAccessRole -> bedrock:InvokeModel bedrock-mantle:CreateInference bedrock:DeleteModelInvocationLoggingConfiguration bedrock:CreateProvisionedModelThroughput
arn:aws:iam::111122223333:user/your-admin-user -> bedrock:InvokeModel bedrock-mantle:CreateInference bedrock:DeleteModelInvocationLoggingConfiguration bedrock:CreateProvisionedModelThroughput
```

How to read it: every line is an identity that can run **any** model (the simulator used `*` as the resource) on
both endpoints, delete invocation logging and buy capacity. Admins will show up: that's expected in a sandbox, and
it's exactly what the M10 checker's `M10-01` and `M10-02` mean in a real account. A workload role on this list is
the finding. The loop skips service-linked roles (path `/aws-service-role/`), which you can't change.

### 1d · Which Bedrock API keys exist?

```bash
aws iam list-service-specific-credentials --all-users --service-name bedrock.amazonaws.com
aws iam list-users --query "Users[?starts_with(UserName, 'BedrockAPIKey')].[UserName,CreateDate]" --output text
```

`--all-users` lists every user's credentials ("This parameter cannot be specified together with UserName":
[CLI reference](https://docs.aws.amazon.com/cli/latest/reference/iam/list-service-specific-credentials.html)). The
second line finds the IAM users the console creates for long-term keys (lesson 10.4).

Example response (shape from AWS docs, values illustrative;
[list-service-specific-credentials](https://docs.aws.amazon.com/cli/latest/reference/iam/list-service-specific-credentials.html)):

```json
{
    "ServiceSpecificCredentials": [
        {
            "UserName": "BedrockAPIKey-a1b2",
            "Status": "Active",
            "ServiceCredentialAlias": "BedrockAPIKey-a1b2-at-111122223333",
            "CreateDate": "2026-09-30T10:12:44+00:00",
            "ServiceSpecificCredentialId": "ACCAEXAMPLEKEYID0001",
            "ServiceName": "bedrock.amazonaws.com"
        }
    ]
}
```

How to read it: **no `ExpirationDate`** on a Bedrock key means it never expires: the IAM reference says the field is present only
for Bedrock and CloudWatch Logs API keys created with an expiration period. For every key: who owns it, does anything still use
it, and what policy does its user carry (1c)? Short-term keys never appear here: they're made client-side from a
session and "you can't prevent generation of a short-term key" (lesson 10.4).

### 1e · Which logs and detectors are on?

```bash
aws bedrock get-model-invocation-logging-configuration
aws cloudtrail describe-trails --query 'trailList[].[Name,HomeRegion,IsMultiRegionTrail]' --output text
for T in $(aws cloudtrail describe-trails --query 'trailList[].TrailARN' --output text); do
  echo "== $T"; aws cloudtrail get-event-selectors --trail-name "$T" --query 'AdvancedEventSelectors[].FieldSelectors' --output json
done
aws guardduty list-detectors
aws bedrock get-account-data-retention
```

- `aws bedrock get-model-invocation-logging-configuration`: {} = invocation logging is OFF
- `aws guardduty list-detectors`: empty = GuardDuty is off in this Region
- `aws bedrock get-account-data-retention`: lesson 11.3: inherit, none, default...

How to read them, one by one:

- **Invocation logging**: an empty answer means "disabled by default" is still true
  ([AWS](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)). Step 2a turns it on.
- **Trails**: no trail means you only have the 90-day event history. Look in the selectors for `resources.type`
  `AWS::BedrockMantle::Project`: if no trail selects it, nobody records bedrock-mantle inference (M11 builds that trail).
- **GuardDuty**: if a detector exists, `aws guardduty get-detector --detector-id <id> --query
  "Features[?Name=='AI_PROTECTION'].Status"` tells you whether AI Protection is on (Step 2f).
- **Data retention**: the `mode` field is one of `default`, `none`, `aws_review`, `provider_data_share` or `inherit`
  (botocore `bedrock` model). New accounts are at `inherit` (lesson 11.3). Write it down; M11 decides it.

### 1f · Your one-page map

Copy this into your findings notebook and fill it in (lesson 10.1's five questions):

| Service | In use? (1a, 1b) | Endpoint (runtime / mantle) | Identities that can call it (1c, 1d) | Logs on? (1e) | Owner |
|---|---|---|---|---|---|
| Bedrock models | | | | | |
| Guardrails / Knowledge Bases / Agents | | | | | |
| AgentCore | | | | | |
| SageMaker AI | | | | | |

## Step 2 · Lock it down, from zero (25 minutes)

Six pieces, each with console clicks **and** CLI. Do them in order: later steps use names from earlier ones.

### 2a · Turn on model invocation logging (CloudWatch Logs, text only, kept 7 days)

Invocation logging is what stores the prompt and the answer; CloudTrail only says who called what (lesson 10.2). You
need a log group and a role Bedrock can assume to write to it. M11 hardens this further with your own KMS key.

**Console** (steps quoted from [invocation logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)):

1. **CloudWatch** console, **Log groups**, **Create log group**: name `/tsg-m10/bedrock/model-invocations`,
   retention **1 week** (labels may differ slightly).
2. Bedrock console (Region **US East (N. Virginia)**): "From the left navigation pane, select **Settings**", then
   select **Model invocation logging**.
3. Data types: tick **Text** only (the demo doesn't send images, embeddings or video).
4. Destination: **CloudWatch Logs only**. Log group name: `/tsg-m10/bedrock/model-invocations`. For the service role,
   choose the option that creates a new role (label may differ slightly), then **Save settings**.

**CLI** (the role's trust and permission policies are AWS's own, from the same page):

```bash
aws logs create-log-group --log-group-name /tsg-m10/bedrock/model-invocations
aws logs put-retention-policy --log-group-name /tsg-m10/bedrock/model-invocations --retention-in-days 7

cat > logging-trust.json <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
  "Action": "sts:AssumeRole",
  "Condition": {"StringEquals": {"aws:SourceAccount": "$ACCOUNT"},
                "ArnLike": {"aws:SourceArn": "arn:aws:bedrock:us-east-1:$ACCOUNT:*"}}}]}
EOF
cat > logging-perms.json <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
  "Resource": "arn:aws:logs:us-east-1:$ACCOUNT:log-group:/tsg-m10/bedrock/model-invocations:log-stream:aws/bedrock/modelinvocations"}]}
EOF
aws iam create-role --role-name tsg-m10-bedrock-logging --assume-role-policy-document file://logging-trust.json
aws iam put-role-policy --role-name tsg-m10-bedrock-logging --policy-name write-invocation-logs \
  --policy-document file://logging-perms.json

cat > logging-config.json <<EOF
{"cloudWatchConfig": {"logGroupName": "/tsg-m10/bedrock/model-invocations",
                      "roleArn": "arn:aws:iam::$ACCOUNT:role/tsg-m10-bedrock-logging"},
 "textDataDeliveryEnabled": true, "imageDataDeliveryEnabled": false,
 "embeddingDataDeliveryEnabled": false, "videoDataDeliveryEnabled": false}
EOF
sleep 10
aws bedrock put-model-invocation-logging-configuration --logging-config file://logging-config.json
aws bedrock get-model-invocation-logging-configuration
```

- `sleep 10`: IAM needs a moment before Bedrock can assume the new role

Field names are from the [PutModelInvocationLoggingConfiguration](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_PutModelInvocationLoggingConfiguration.html)
API (`loggingConfig.cloudWatchConfig.logGroupName`, `roleArn`, and the `...DataDeliveryEnabled` switches).
**Careful:** there is one configuration per account and Region, so if 1e showed an existing one, this replaces it.

Example response (shape from AWS docs, values illustrative;
[GetModelInvocationLoggingConfiguration](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GetModelInvocationLoggingConfiguration.html)):

```json
{
    "loggingConfig": {
        "cloudWatchConfig": {
            "logGroupName": "/tsg-m10/bedrock/model-invocations",
            "roleArn": "arn:aws:iam::111122223333:role/tsg-m10-bedrock-logging"
        },
        "textDataDeliveryEnabled": true,
        "imageDataDeliveryEnabled": false,
        "embeddingDataDeliveryEnabled": false,
        "videoDataDeliveryEnabled": false
    }
}
```

That's lesson 10.2's evidence column: "`GetModelInvocationLoggingConfiguration` returns a destination".

### 2b · A usage alarm that fires in minutes, not hours

Budgets update "up to three times a day" (lesson 10.5). A CloudWatch alarm on `AWS/Bedrock` `Invocations` fires
within minutes. Bedrock publishes its metrics "both with and without the `ModelId` dimension", and "To account for all
requests, query these metrics without specifying a dimension"
([runtime metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html)). So this
alarm has no dimension: it counts every model.

**Console:** **SNS**, **Topics**, **Create topic**, type **Standard**, name `tsg-m10-ai-alerts`; then **Create
subscription**, protocol **Email**, your address, and confirm the email AWS sends you. Then **CloudWatch**,
**Alarms**, **Create alarm**, **Select metric**, **Bedrock**, the metric `Invocations` across all model IDs, statistic
**Sum**, period **5 minutes**, threshold **Greater than 20**, notification to `tsg-m10-ai-alerts`, name
`tsg-m10-bedrock-invocations` (labels may differ slightly).

**CLI:**

```bash
TOPIC=$(aws sns create-topic --name tsg-m10-ai-alerts --query TopicArn --output text)
aws sns subscribe --topic-arn $TOPIC --protocol email --notification-endpoint you@example.com
aws cloudwatch put-metric-alarm --alarm-name tsg-m10-bedrock-invocations \
  --namespace AWS/Bedrock --metric-name Invocations --statistic Sum --period 300 \
  --evaluation-periods 1 --threshold 20 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching --alarm-actions $TOPIC
```

- `aws sns subscribe`: your address; confirm the email

Twenty calls in five minutes is far above anything this guide does, and far below what an LLMjacking proxy does
(lesson 10.5's hunt sees 61 in one hour from one key). In production, set it from your own baseline. Mantle traffic
lives in `AWS/BedrockMantle` and this alarm won't see it (lesson 10.5).

### 2c · The guardrail policy: no long-term keys, no logging changes, no capacity, approved models only

With an AWS Organization, these rules belong in SCPs: the three files in `fixes/` (README Step 8c shows how to attach
one to a sandbox member account). Most personal sandboxes are a single account with no Organization, so here you'll
write the same rules as a **customer managed IAM policy** and attach it to every non-admin identity. Be clear about
the difference: an SCP caps every identity in the account; this policy only caps the identities you attach it to.

**CLI** (console: **IAM**, **Policies**, **Create policy**, **JSON** tab, paste the same JSON, name
`tsg-m10-ai-guardrails`):

```bash
cat > guardrails.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "NoLongTermBedrockKeyUse", "Effect": "Deny",
      "Action": "bedrock:CallWithBearerToken", "Resource": "*",
      "Condition": { "StringEquals": { "bedrock:BearerTokenType": "LONG_TERM" } } },
    { "Sid": "NoLongTermBedrockKeyUseMantle", "Effect": "Deny",
      "Action": "bedrock-mantle:CallWithBearerToken", "Resource": "*",
      "Condition": { "StringEquals": { "bedrock-mantle:BearerTokenType": "LONG_TERM" } } },
    { "Sid": "NoAiAuditTrailChanges", "Effect": "Deny",
      "Action": [ "bedrock:DeleteModelInvocationLoggingConfiguration", "bedrock:PutModelInvocationLoggingConfiguration",
                  "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors" ],
      "Resource": "*" },
    { "Sid": "NoCapacityPurchases", "Effect": "Deny",
      "Action": "bedrock:CreateProvisionedModelThroughput", "Resource": "*" },
    { "Sid": "OnlyApprovedModelsOnBedrockRuntime", "Effect": "Deny",
      "Action": "bedrock:InvokeModel*",
      "NotResource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
        "arn:aws:bedrock:*:*:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0" ] },
    { "Sid": "TheseIdentitiesNeverUseMantle", "Effect": "Deny",
      "Action": "bedrock-mantle:CreateInference", "Resource": "*" }
  ]
}
EOF
aws iam create-policy --policy-name tsg-m10-ai-guardrails --policy-document file://guardrails.json
export GUARD_ARN=arn:aws:iam::$ACCOUNT:policy/tsg-m10-ai-guardrails
```

Where each statement comes from:

- `NoLongTermBedrockKeyUse` and the mantle twin: `bedrock:CallWithBearerToken` and `bedrock-mantle:CallWithBearerToken`
  with `BearerTokenType` = `LONG_TERM` (lesson 10.4, [API key permissions](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-permissions.html)).
  The lab's SCP adds "outside the sandbox"; here the whole account is the sandbox and you want to see the deny.
- `NoAiAuditTrailChanges` and `NoCapacityPurchases`: `fixes/scp-protect-ai-logging-and-spend.json`, without the
  admin-role exception, because you'll only attach this policy to identities that should never do either.
- `OnlyApprovedModelsOnBedrockRuntime`: lesson 10.3's allow-list, scoped to `bedrock:InvokeModel*` so Guardrails and
  Knowledge Bases keep working, with **both** the model and the profile ARN.
- `TheseIdentitiesNeverUseMantle`: the M10 challenge closes the mantle gap with a model allow-list on
  `bedrock-mantle:Model`. These two demo identities never use mantle at all, so the simplest correct rule is a plain
  Deny.

Validate it for free (lesson 10.3; `IDENTITY_POLICY` because this is not an SCP here):

```bash
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://guardrails.json \
  --query 'findings[].[findingType,issueCode]' --output text
```

An empty answer means no grammar or best-practice findings. You may see a `SUGGESTION` or `WARNING` about the Deny
statements: read it, it doesn't stop the policy working.

### 2d · A least-privilege app role (the Helpdesk's)

This is `fixes/helpdesk-app-role.least-privilege.json` with your account ID, minus its guardrail and knowledge-base
statement (those resources don't exist in your sandbox). It can call one model, only through one US profile
(`bedrock:InferenceProfileArn`, lessons 10.3 and 11.1). The trust policy lets identities in **your** account assume
it, so you can test it from your terminal; a real app role would trust `lambda.amazonaws.com` or similar.

**CLI** (console: **IAM**, **Roles**, **Create role**, **AWS account**, **This account**; skip the permissions page;
name `tsg-m10-app-demo`; then **Add permissions**, **Create inline policy**, **JSON** with the policy below, and
**Attach policies** `tsg-m10-ai-guardrails`):

```bash
python3 - <<'EOF'
import json, os
d = json.load(open("fixes/helpdesk-app-role.least-privilege.json"))
d["Statement"] = [s for s in d["Statement"] if s["Sid"] != "ItsOwnGuardrailAndKnowledgeBase"]
open("app-role.json", "w").write(json.dumps(d, indent=2).replace("111122223333", os.environ["ACCOUNT"]))
EOF
cat > app-trust.json <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::$ACCOUNT:root"}, "Action": "sts:AssumeRole"}]}
EOF
aws iam create-role --role-name tsg-m10-app-demo --assume-role-policy-document file://app-trust.json
aws iam put-role-policy --role-name tsg-m10-app-demo --policy-name invoke-approved-model-only \
  --policy-document file://app-role.json
aws iam attach-role-policy --role-name tsg-m10-app-demo --policy-arn $GUARD_ARN
export ROLE_ARN=arn:aws:iam::$ACCOUNT:role/tsg-m10-app-demo
```

Belt and braces on purpose: the role's own policy already refuses everything except the approved model, and the
guardrail policy refuses it again. Each layer should hold on its own (M11 test 06 makes the same point).

### 2e · A long-term API key to test with (1 day, guardrail attached)

You'll create the kind of key lesson 10.4 warns about, the way the console does it (an IAM user carrying
`AmazonBedrockLimitedAccess`), but with a **1-day** expiry and the guardrail policy attached. Step 3 shows it being
refused; Step 4 shows what it could do without the guardrail.

**Console** (steps quoted from [generate API keys](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-generate.html)):

1. Bedrock console, "In the left navigation pane, select **API keys**", the **Long-term API keys** tab, **Generate
   long-term API keys**.
2. In **API key expiration**, choose **1 day**. Leave **Advanced permissions** as it is ("By default,
   **AmazonBedrockLimitedAccess** is attached to the IAM user associated with the key"). Choose **Generate**.
3. Copy the key **now** (you won't see it again) and keep it only in your terminal:
   `export AWS_BEARER_TOKEN_BEDROCK='<the key>'`. Never paste it into a file, a chat or a ticket.
4. **IAM**, **Users**: the console created a user whose name starts `BedrockAPIKey-`. Open it, **Add permissions**,
   **Attach policies directly**, tick `tsg-m10-ai-guardrails`, **Add permissions**. Set `KEY_USER` to that user's
   name and `KEY_ID` to the credential ID shown under its API keys or by Step 1d's command.

**CLI** (commands from the same page):

```bash
export KEY_USER=tsg-m10-key-demo
aws iam create-user --user-name $KEY_USER
aws iam attach-user-policy --user-name $KEY_USER --policy-arn arn:aws:iam::aws:policy/AmazonBedrockLimitedAccess
aws iam attach-user-policy --user-name $KEY_USER --policy-arn $GUARD_ARN
aws iam create-service-specific-credential --user-name $KEY_USER \
  --service-name bedrock.amazonaws.com --credential-age-days 1
```

Example response (shape from AWS docs, values illustrative;
[CreateServiceSpecificCredential](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateServiceSpecificCredential.html),
[ServiceSpecificCredential](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ServiceSpecificCredential.html)):

```json
{
    "ServiceSpecificCredential": {
        "CreateDate": "2026-10-22T09:30:12+00:00",
        "ExpirationDate": "2026-10-23T09:30:12+00:00",
        "ServiceName": "bedrock.amazonaws.com",
        "ServiceCredentialAlias": "tsg-m10-key-demo-at-111122223333",
        "ServiceCredentialSecret": "ABSK...(the key: shown once)",
        "ServiceSpecificCredentialId": "ACCAEXAMPLEKEYID1234",
        "UserName": "tsg-m10-key-demo",
        "Status": "Active"
    }
}
```

The key is the secret field, and IAM returns it only when the credential is created. The IAM API reference and the botocore
model call it `ServiceCredentialSecret`; the Bedrock guide calls it `ServiceApiKeyValue`. Use whichever your output
has:

```bash
export KEY_ID=<ServiceSpecificCredentialId from the response>
export AWS_BEARER_TOKEN_BEDROCK='<the secret value>'
```

Bedrock "recognizes the environment variable `AWS_BEARER_TOKEN_BEDROCK`"
([use API keys](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-use.html)). Note `ExpirationDate`: Step
1d's check would now show this key expiring tomorrow, not never.

### 2f (optional) · GuardDuty AI Protection

AI Protection reads CloudTrail data events from Bedrock (and AgentCore and SageMaker AI) through a service-linked
channel: "You don't need to create a trail, enable data event logging, or make any changes to your AI applications"
([AI Protection](https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html)). It's charged by the GB of data
events analysed, with a 30-day trial for accounts that haven't used it
([pricing](https://aws.amazon.com/guardduty/pricing/)). GuardDuty itself also starts charging after its own trial, so
only turn this on if you'll remember to turn it off.

**Console** (quoted from [enable in a standalone account](https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection-enable-standalone-account.html)):
GuardDuty console, Region **US East (N. Virginia)**, "In the navigation pane, choose **Protection Plans**", **Configure
all enablements**, under **AI Protection** choose **Enable**, then **Save all**, **Confirm and save**. If GuardDuty
isn't on yet, the console first offers to enable it (label may differ slightly).

**CLI** (the `update-detector` line is AWS's; `create-detector` only if 1e found no detector):

```bash
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
[ "$DETECTOR" = "None" ] && DETECTOR=$(aws guardduty create-detector --enable --query DetectorId --output text)
aws guardduty update-detector --detector-id $DETECTOR --features '[{"Name": "AI_PROTECTION", "Status": "ENABLED"}]'
aws guardduty get-detector --detector-id $DETECTOR --query "Features[?Name=='AI_PROTECTION'].Status" --output text
```

Don't expect a finding from this guide: a handful of calls is not "anomalous token volumes" (lesson 10.5).

## Step 3 · Prove it: five requests (10 minutes)

Open a **second terminal tab** and become the demo role there, so your admin credentials stay untouched in the first:

```bash
cd labs/m10; export AWS_REGION=us-east-1 MODEL=us.anthropic.claude-haiku-4-5-20251001-v1:0
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
eval $(aws sts assume-role --role-arn arn:aws:iam::$ACCOUNT:role/tsg-m10-app-demo --role-session-name m10-test \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text \
  | awk '{print "export AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" AWS_SESSION_TOKEN="$3}')
aws sts get-caller-identity --query Arn --output text
```

What to look for: the ARN from `aws sts get-caller-identity` should end in `assumed-role/tsg-m10-app-demo/m10-test`.

### R1 · The approved model, through the approved profile (allowed)

```bash
aws bedrock-runtime converse --model-id $MODEL --inference-config maxTokens=100 \
  --messages '[{"role":"user","content":[{"text":"In one sentence: how do I reset my VPN token?"}]}]'
```

Example response (shape from AWS docs, values illustrative;
[Converse](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html)):

```json
{
    "output": {
        "message": {
            "role": "assistant",
            "content": [
                {"text": "Open the self-service portal, choose Reset VPN token, and follow the prompts on your registered phone."}
            ]
        }
    },
    "stopReason": "end_turn",
    "usage": {"inputTokens": 19, "outputTokens": 24, "totalTokens": 43},
    "metrics": {"latencyMs": 812}
}
```

How to read it: `stopReason` `end_turn` means the model finished normally, and `usage` is what you pay for. IAM
checked four things to allow this: the profile, and the model in each of its three US destination Regions (lesson
10.3). The role allowed all four, and the guardrail policy's allow-list matched both ARN shapes.

### R2 · A model nobody approved (denied)

The same model through the **global** profile, which can run outside the US (lesson 11.5):

```bash
aws bedrock-runtime converse --model-id global.anthropic.claude-haiku-4-5-20251001-v1:0 \
  --inference-config maxTokens=20 --messages '[{"role":"user","content":[{"text":"hello"}]}]'
```

Example response (shape from the IAM docs' access-denied message format, values illustrative;
[IAM access denied messages](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)):

```text
An error occurred (AccessDeniedException) when calling the Converse operation: User: arn:aws:sts::111122223333:assumed-role/tsg-m10-app-demo/m10-test is not authorized to perform: bedrock:InvokeModel on resource: arn:aws:bedrock:us-east-1:111122223333:inference-profile/global.anthropic.claude-haiku-4-5-20251001-v1:0 with an explicit deny in an identity-based policy
```

How to read it: the action is `bedrock:InvokeModel` although you called Converse (Converse is authorized as
InvokeModel). "**with an explicit deny**" points at `OnlyApprovedModelsOnBedrockRuntime`: a `Deny` statement fired.
If you see "**because no identity-based policy allows**" instead, the role's own policy refused it first: also a
pass. No model ran, so there's no charge.

### R3 · Switch off prompt logging (denied)

What attackers do after recon (lesson 10.5, Sysdig's step 5):

```bash
aws bedrock delete-model-invocation-logging-configuration
```

Example response (shape from the IAM docs' access-denied message format, values illustrative;
[IAM access denied messages](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)):

```text
An error occurred (AccessDeniedException) when calling the DeleteModelInvocationLoggingConfiguration operation: User: arn:aws:sts::111122223333:assumed-role/tsg-m10-app-demo/m10-test is not authorized to perform: bedrock:DeleteModelInvocationLoggingConfiguration with an explicit deny in an identity-based policy
```

If this ever **succeeds**, stop: your logging is off. Go back to your admin tab, re-run Step 2a's
`put-model-invocation-logging-configuration`, and find which policy allowed it.

Now go back to your **first** tab (or `unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN`) for R4 and R5.

### R4 · The long-term API key (denied by the guardrail policy)

A plain HTTPS call with the key as a bearer token, exactly as a leaked key would be used (AWS's curl example,
[use API keys](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-use.html)). The `:` in the profile ID
is URL-encoded as `%3A`:

```bash
curl -sS -X POST "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-haiku-4-5-20251001-v1%3A0/converse" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AWS_BEARER_TOKEN_BEDROCK" \
  -d '{"messages":[{"role":"user","content":[{"text":"hello"}]}],"inferenceConfig":{"maxTokens":20}}' \
  -w '\nHTTP %{http_code}\n'
```

Example response (shape from the IAM docs' access-denied message format, values illustrative;
[IAM access denied messages](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)):

```text
{"message":"User: arn:aws:iam::111122223333:user/tsg-m10-key-demo is not authorized to perform: bedrock:CallWithBearerToken on resource: * with an explicit deny in an identity-based policy"}
HTTP 403
```

How to read it: the key itself is valid, but every call made with a long-term key is also authorized as
`bedrock:CallWithBearerToken` with `BearerTokenType` = `LONG_TERM` (lesson 10.4), and `NoLongTermBedrockKeyUse`
denied that. The principal is an IAM **user**: Wiz's tip for telling a long-term key from a short-term one (a role).
Your real error text may differ; the 403 is the part that matters.

### R5 · Find the evidence: the prompt log and CloudTrail

Wait 2 to 5 minutes, then:

The prompt log for R1:

```bash
aws logs filter-log-events --log-group-name /tsg-m10/bedrock/model-invocations \
  --start-time $(( ($(date +%s) - 3600) * 1000 )) --max-items 5 --query 'events[].message' --output text
```

CloudTrail: the refused and the allowed model calls of the last hour. First set `START` to one hour ago.

**Linux:**

```bash
START=$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ)
```

**Mac:**

```bash
START=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)
```

Then:

```bash
aws cloudtrail lookup-events --start-time $START \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=bedrock.amazonaws.com \
  --query 'Events[].CloudTrailEvent' --output json \
  | python3 -c "import sys,json; [print(json.dumps({k: e.get(k) for k in ('eventName','errorCode','additionalEventData')} | {'who': e['userIdentity'].get('arn')})) for e in map(json.loads, json.load(sys.stdin))]"
```

Example response for the prompt log (shape from AWS docs, values illustrative;
[invocation log record](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)), trimmed:

```json
{
    "schemaType": "ModelInvocationLog",
    "schemaVersion": "1.0",
    "timestamp": "2026-10-22T09:41:03Z",
    "accountId": "111122223333",
    "region": "us-east-1",
    "requestId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE33333",
    "operation": "Converse",
    "modelId": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "identity": {"arn": "arn:aws:sts::111122223333:assumed-role/tsg-m10-app-demo/m10-test"},
    "input": {"inputContentType": "application/json", "inputBodyJson": {"messages": [{"role": "user", "content": [{"text": "In one sentence: how do I reset my VPN token?"}]}]}, "inputTokenCount": 19},
    "output": {"outputContentType": "application/json", "outputBodyJson": {"stopReason": "end_turn"}, "outputTokenCount": 24}
}
```

How to read it: `identity.arn` says **who** (Bedrock fills it; "`requestMetadata` is the only field supplied by the
caller"), `operation` and `modelId` say **what**, and `inputBodyJson` holds the **prompt**, in plain text. Only R1
is there: R2 to R4 never reached a model. That's also why this log group is sensitive data (M11 encrypts it).

Example response for CloudTrail (shape from AWS docs, values illustrative;
[CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html),
`callWithBearerToken` from the [AWS Security Blog](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management)):

```text
{"eventName": "Converse", "errorCode": "AccessDenied", "additionalEventData": {"callWithBearerToken": true}, "who": "arn:aws:iam::111122223333:user/tsg-m10-key-demo"}
{"eventName": "DeleteModelInvocationLoggingConfiguration", "errorCode": "AccessDenied", "additionalEventData": null, "who": "arn:aws:sts::111122223333:assumed-role/tsg-m10-app-demo/m10-test"}
{"eventName": "Converse", "errorCode": "AccessDenied", "additionalEventData": null, "who": "arn:aws:sts::111122223333:assumed-role/tsg-m10-app-demo/m10-test"}
{"eventName": "Converse", "errorCode": null, "additionalEventData": null, "who": "arn:aws:sts::111122223333:assumed-role/tsg-m10-app-demo/m10-test"}
{"eventName": "PutModelInvocationLoggingConfiguration", "errorCode": null, "additionalEventData": null, "who": "arn:aws:iam::111122223333:user/your-admin-user"}
```

How to read it: refused calls are recorded with an `errorCode` (lesson 10.3: "model calls that fail with an
access-denied `errorCode` in CloudTrail tell you the SCP is working and who tried"). We guessed the exact code and
the fields on the refused key call: services write `AccessDenied` or `AccessDeniedException`, and AWS doesn't document
whether a call refused on `CallWithBearerToken` still carries `callWithBearerToken`. Note what yours says, then
compare with the lab's hunt rules H04 (logging change) and H07 (key use from a new source). Your Step 2a `Put...`
shows up too: that's the change rule H04 should **not** page you for, because the security admin made it.

## Step 4 · Change one setting, re-run, compare (5 minutes)

What does that key do **without** the guardrail policy, as most keys out there have it? Detach it from the key's user
only (console: **IAM**, **Users**, the key user, **Permissions**, `tsg-m10-ai-guardrails`, **Remove**):

```bash
aws iam detach-user-policy --user-name $KEY_USER --policy-arn $GUARD_ARN
sleep 15
```

- `sleep 15`: IAM changes take a few seconds to apply

Re-run **R4** exactly as before.

Example response (shape from AWS docs, values illustrative;
[Converse](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html)):

```text
{"metrics":{"latencyMs":640},"output":{"message":{"content":[{"text":"Hello! How can I help you today?"}],"role":"assistant"}},"stopReason":"end_turn","usage":{"inputTokens":8,"outputTokens":11,"totalTokens":19}}
HTTP 200
```

How to read it: same key, same request, one policy detached, and the call now **runs and bills**. That's the leaked
key from the offline lab's Attacker 1: `AmazonBedrockLimitedAccess` allows `bedrock:InvokeModel` on `"Resource": "*"`,
so swap the profile ID in the URL for any other model and it would run too (don't: that's someone else's bill in the
real world, and yours here). Run R5's CloudTrail command again: the new `Converse` has no `errorCode`, the
`additionalEventData` should show `callWithBearerToken` `true`, and the principal is the key's IAM user. And the prompt
log now has a second entry, this time with `identity.arn` = the key's user.

| | R4 with the guardrail policy | R4 without it |
|---|---|---|
| HTTP status | 403 | 200 |
| Model ran, tokens billed | no | yes |
| CloudTrail | `Converse` with an access-denied `errorCode` | `Converse`, no `errorCode` |
| Prompt log entry | none | yes, `identity.arn` = the key's user |

Fill in your real results. Then decide: in your real accounts, where would this rule live? (Lesson 10.4's answer: an
SCP on `CallWithBearerToken` for both endpoints, so no single forgotten user escapes it.)

## Cost (list prices, October 2026)

| Item | Price | This guide |
|---|---|---|
| Model calls (Claude Haiku 4.5, Step 0.3, R1, Step 4) | per token, "billed through AWS Marketplace" (model card); see the [Bedrock pricing page](https://aws.amazon.com/bedrock/pricing/) | 3 short calls, at most 100 output tokens each: a fraction of a US cent |
| Refused calls (R2 to R4) | no model runs | $0 |
| CloudWatch Logs | free tier "5 GB Data (ingestion, archive storage, and data scanned by Logs Insights queries)" ([pricing](https://aws.amazon.com/cloudwatch/pricing/)) | a few KB: $0 |
| CloudWatch alarm | $0.10 per alarm metric per month; free tier "10 Alarm metrics" (same page) | $0 in the free tier, otherwise under one cent for a day |
| SNS email, IAM, Budgets, Access Analyzer validation, policy simulator, CloudTrail event history | free | $0 |
| GuardDuty (optional 2f) | 30-day trial, then charged ([pricing](https://aws.amazon.com/guardduty/pricing/)) | $0 if you disable it in the teardown |
| **Total** | | **a few US cents at most** |

## Teardown (5 minutes; do it today)

In your **own** credentials (first terminal tab), in this order.

**1. Revoke the key, and watch it stop working.** Deactivate first, so you can see the effect (lesson 10.4: "Revoke
fast"), then delete it:

```bash
aws iam update-service-specific-credential --user-name $KEY_USER --service-specific-credential-id $KEY_ID --status Inactive
sleep 15
```

Re-run R4: you should now get HTTP 403 again, this time because the key is no longer valid (the exact message isn't documented; write down what you see)

```bash
aws iam delete-service-specific-credential --user-name $KEY_USER --service-specific-credential-id $KEY_ID
unset AWS_BEARER_TOKEN_BEDROCK
```

`Status` `Inactive` means the key is no longer valid for API calls
([ServiceSpecificCredential](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ServiceSpecificCredential.html)).
That one command is your incident response for a leaked long-term key.

**2. The key's user, the demo role and the guardrail policy:**

```bash
aws iam detach-user-policy --user-name $KEY_USER --policy-arn arn:aws:iam::aws:policy/AmazonBedrockLimitedAccess
aws iam detach-user-policy --user-name $KEY_USER --policy-arn $GUARD_ARN 2>/dev/null
aws iam delete-user --user-name $KEY_USER
aws iam detach-role-policy --role-name tsg-m10-app-demo --policy-arn $GUARD_ARN
aws iam delete-role-policy --role-name tsg-m10-app-demo --policy-name invoke-approved-model-only
aws iam delete-role --role-name tsg-m10-app-demo
aws iam delete-policy --policy-arn $GUARD_ARN
```

- `aws iam detach-user-policy --user-name $KEY_USER --policy-arn $GUARD_ARN 2>/dev/null`: already detached in Step 4

**3. Logging, alarm, topic** (keep invocation logging on if this sandbox will run M11 or M12; M11 replaces it with
its own encrypted configuration anyway):

```bash
aws bedrock delete-model-invocation-logging-configuration
aws iam delete-role-policy --role-name tsg-m10-bedrock-logging --policy-name write-invocation-logs
aws iam delete-role --role-name tsg-m10-bedrock-logging
aws logs delete-log-group --log-group-name /tsg-m10/bedrock/model-invocations
aws cloudwatch delete-alarms --alarm-names tsg-m10-bedrock-invocations
aws sns delete-topic --topic-arn arn:aws:sns:us-east-1:$ACCOUNT:tsg-m10-ai-alerts
```

**4. GuardDuty** (only if you did 2f): `aws guardduty update-detector --detector-id $DETECTOR --features
'[{"Name": "AI_PROTECTION", "Status": "DISABLED"}]'`, and if you created the detector in 2f,
`aws guardduty delete-detector --detector-id $DETECTOR`.

**5. Check, then remove the local files:**

```bash
aws iam list-service-specific-credentials --all-users --service-name bedrock.amazonaws.com
aws bedrock get-model-invocation-logging-configuration
rm -f logging-trust.json logging-perms.json logging-config.json guardrails.json app-role.json app-trust.json
```

What each command does, and what to look for:

- `aws iam list-service-specific-credentials`: your test key is gone
- `aws bedrock get-model-invocation-logging-configuration`: {} if you deleted it

Keep the budget from Step 0: it costs nothing and you'll want it for M11. Tomorrow, glance at **Billing**, **Bills**:
this guide should show cents at most.

## What to write in your findings notebook (lesson 0.5)

Your one-page map from Step 1f, plus three lines: what you found (which identities can run any model, which keys exist
and whether they expire, which logs were off), how you locked it down (invocation logging, a usage alarm, a
least-privilege role, a guardrail policy or SCPs), and how you'd spot abuse (the R5 evidence: `identity.arn` in the
prompt log, access-denied `errorCode` and `callWithBearerToken` in CloudTrail).
