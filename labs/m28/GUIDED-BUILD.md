# M28 guided build: invocation logs, a redaction Lambda, Amazon Macie, two KMS keys, retention

The offline lab (README, Steps 1 to 7) teaches the mechanics at $0 with local stand-ins. This guide builds the real
thing in **your own** AWS sandbox account (lesson 0.7, never a work account), in **us-east-1**. About 60 to 90 minutes,
plus a wait for the Macie job. Nothing here uses a third-party service, and every request uses fake data.

What you build:

| Piece | Name | Why |
|---|---|---|
| KMS key for raw logs | `alias/tsg-m28-raw` | Only Bedrock (write), the redactor and Macie (read) may use it. Your own admin user may **administer** it but not decrypt with it |
| KMS key for the redacted copy | `alias/tsg-m28-redacted` | The redactor writes; you (the "analyst" here) and Macie read |
| Raw bucket | `tsg-m28-raw-<account>` | Versioned, SSE-KMS with the raw key, expire after 30 days **and** remove old versions a day later |
| Redacted bucket | `tsg-m28-redacted-<account>` | SSE-KMS with the redacted key, expire after 365 days |
| Lambda | `tsg-log-redactor` | Runs on every new raw object and writes the redacted copy |
| Bedrock invocation logging | one per account and Region | Text only, to the raw bucket |
| Macie | custom data identifiers + a one-time job | The independent check: findings in raw, none in redacted |

> **Read this first: about the responses shown below.** This guide was written without access to an AWS account, so
> **no response in this file comes from a real run**. Every response block is labelled **"Example response (shape from
> the provider's docs, values illustrative)"** and names the page its shape comes from. Request shapes were checked
> against the botocore 1.43.118 service models (`macie2`, `bedrock`, `bedrock-runtime`, `kms`, `s3`, `lambda`, `iam`).
> Where AWS doesn't document what you'll see, the guide says "write down what you get".

## Step 0 · Before you start (10 minutes)

1. **Sandbox account with a budget alarm** (lesson 0.7).
2. **Tools:** AWS CLI v2, Python 3.11+, `zip`.
3. **Terminal in `labs/m28`**, then set the names once (set them again in a new terminal):

   ```bash
   cd labs/m28
   export AWS_REGION=us-east-1
   export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
   export RAW_BUCKET=tsg-m28-raw-$ACCOUNT_ID REDACTED_BUCKET=tsg-m28-redacted-$ACCOUNT_ID
   aws sts get-caller-identity --query Arn --output text
   ```

   - `aws sts get-caller-identity --query Arn --output text`: check it IS the sandbox

4. **Who reads the redacted copy.** Here it's you. Set `READER_ARN` to your principal: an IAM user's ARN as printed,
   or for an assumed role the **role** ARN (`arn:aws:iam::<account>:role/<role name>`, not the `assumed-role/...`
   session ARN):

   ```bash
   export READER_ARN=arn:aws:iam::$ACCOUNT_ID:role/YOUR-ROLE-NAME
   ```

   - `READER_ARN`: or arn:aws:iam::$ACCOUNT_ID:user/YOUR-USER

5. **Fill in the policy templates** in `cloud/` (they carry placeholders):

   ```bash
   mkdir -p cloud/out
   for f in cloud/*.json; do
     sed -e "s/ACCOUNT_ID/$ACCOUNT_ID/g" -e "s/RAW_BUCKET/$RAW_BUCKET/g" \
         -e "s/REDACTED_BUCKET/$REDACTED_BUCKET/g" -e "s#READER_ARN#$READER_ARN#g" "$f" > "cloud/out/$(basename "$f")"
   done
   ```

## Step 1 · Macie on, and the redactor's role (the key policies name both)

A key policy can only name principals that exist, so these come first.

1. **Enable Macie.** Console: open Amazon Macie, pick **US East (N. Virginia)** in the Region selector, choose **Get
   started**, then **Enable Macie**. Macie creates its service-linked role, `AWSServiceRoleForAmazonMacie`. CLI:

   ```bash
   aws macie2 enable-macie
   ```

   AWS: "Depending on your account settings, Macie also begins performing automated sensitive data discovery for your
   S3 buckets" ([Getting started](https://docs.aws.amazon.com/macie/latest/user/getting-started.html)). New accounts
   get a 30-day free trial of that; jobs you create are not part of the trial
   ([Macie pricing](https://aws.amazon.com/macie/pricing/)).

2. **The redactor's role**, with an inline policy that reads raw and writes redacted (the KMS permissions come from
   the key policies in Step 2):

   ```bash
   aws iam create-role --role-name tsg-log-redactor --assume-role-policy-document file://cloud/out/redactor-trust.json
   aws iam put-role-policy --role-name tsg-log-redactor --policy-name m28-redactor \
     --policy-document file://cloud/out/redactor-policy.json
   ```

## Step 2 · Two KMS keys

Read `cloud/out/raw-key-policy.json` first. The account statement lists **administration actions only**; there's no
`kms:Decrypt` in it. So an IAM policy anywhere in the account that says `kms:Decrypt` on `*` opens nothing here,
because a key policy "does not automatically give permission to the account or any of its identities"
([KMS, default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html)). The only
readers are the redactor role and Macie's service-linked role. Macie needs that statement: without it, "Macie can only
store and report metadata for the object"
([Macie, encrypted objects](https://docs.aws.amazon.com/macie/latest/user/discovery-supported-encryption-types.html)).

1. **Console** (either key): **Key Management Service** → **Customer managed keys** → **Create key**, keep
   **Symmetric** and **Encrypt and decrypt**, give the alias, and before you finish replace the proposed key policy with
   the file's contents.
2. **CLI:**

   ```bash
   export RAW_KEY=$(aws kms create-key --description "M28 raw invocation logs" \
     --policy file://cloud/out/raw-key-policy.json --query KeyMetadata.Arn --output text)
   aws kms create-alias --alias-name alias/tsg-m28-raw --target-key-id $RAW_KEY
   export REDACTED_KEY=$(aws kms create-key --description "M28 redacted invocation logs" \
     --policy file://cloud/out/redacted-key-policy.json --query KeyMetadata.Arn --output text)
   aws kms create-alias --alias-name alias/tsg-m28-redacted --target-key-id $REDACTED_KEY
   ```

   If `create-key` refuses the policy with a message about not being able to update it later, your principal can't
   pass the lockout check: run the command as a principal with IAM permission for `kms:PutKeyPolicy` (the account
   statement delegates it to IAM).

## Step 3 · Two buckets with encryption, a policy and retention

```bash
for B in $RAW_BUCKET $REDACTED_BUCKET; do
  aws s3api create-bucket --bucket $B
  aws s3api put-bucket-ownership-controls --bucket $B --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
done
aws s3api put-bucket-versioning --bucket $RAW_BUCKET --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket $RAW_BUCKET --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"'$RAW_KEY'"},"BucketKeyEnabled":false}]}'
aws s3api put-bucket-encryption --bucket $REDACTED_BUCKET --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"'$REDACTED_KEY'"},"BucketKeyEnabled":false}]}'
aws s3api put-bucket-policy --bucket $RAW_BUCKET --policy file://cloud/out/raw-bucket-policy.json
aws s3api put-bucket-lifecycle-configuration --bucket $RAW_BUCKET --lifecycle-configuration file://cloud/out/raw-lifecycle.json
aws s3api put-bucket-lifecycle-configuration --bucket $REDACTED_BUCKET --lifecycle-configuration file://cloud/out/redacted-lifecycle.json
```

Why each line:

- **Ownership controls:** Bedrock's bucket policy only works with ACLs off ("The bucket ACL must be disabled in order
  for the bucket policy to take effect", [invocation logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)).
- **Bucket Keys off:** each object then gets its own encryption context (`aws:s3:arn` = the object ARN), so every
  `Decrypt` in CloudTrail names the exact log object. With a Bucket Key the context is the bucket ARN, and KMS
  requests drop "by up to 99 percent" ([S3, SSE-KMS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)).
  For a high-volume production bucket you may decide the cost saving wins. Write the decision down.
- **The raw bucket policy** is AWS's documented statement for Bedrock, with `aws:SourceAccount` and `aws:SourceArn`.
- **Lifecycle:** in a versioned bucket "Object expiration applies only to an object's current version", so
  `NoncurrentVersionExpiration` is what actually removes the data
  ([S3 lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html)).
  S3 removes expired objects asynchronously: "There may be a delay".

## Step 4 · The redaction Lambda

```bash
(cd cloud/lambda && zip -q ../out/redactor.zip redactor.py)
aws lambda create-function --function-name tsg-log-redactor --runtime python3.13 --handler redactor.handler \
  --role arn:aws:iam::$ACCOUNT_ID:role/tsg-log-redactor --zip-file fileb://cloud/out/redactor.zip \
  --environment "Variables={REDACTED_BUCKET=$REDACTED_BUCKET}" --timeout 30
aws lambda add-permission --function-name tsg-log-redactor --statement-id s3-raw --action lambda:InvokeFunction \
  --principal s3.amazonaws.com --source-arn arn:aws:s3:::$RAW_BUCKET --source-account $ACCOUNT_ID
aws s3api put-bucket-notification-configuration --bucket $RAW_BUCKET --notification-configuration \
  '{"LambdaFunctionConfigurations":[{"LambdaFunctionArn":"arn:aws:lambda:us-east-1:'$ACCOUNT_ID':function:tsg-log-redactor","Events":["s3:ObjectCreated:*"]}]}'
```

If `create-function` says the role can't be assumed yet, wait ten seconds and run it again (a new role takes a moment
to appear everywhere). Read `cloud/lambda/redactor.py`: the same simple detectors as the offline lab, minus names.
It has no name detector, on purpose, so you can watch Macie catch what the redactor missed in Step 7.

## Step 5 · Turn on invocation logging, text only

Console: **Amazon Bedrock** → left navigation **Settings** → select **Model invocation logging**. Tick **Text** only
(leave **Image**, **Embedding** and **Video** clear), choose **Amazon S3 only**, and enter the raw bucket name. CLI:

```bash
aws bedrock put-model-invocation-logging-configuration --logging-config \
  '{"s3Config":{"bucketName":"'$RAW_BUCKET'","keyPrefix":""},"textDataDeliveryEnabled":true,"imageDataDeliveryEnabled":false,"embeddingDataDeliveryEnabled":false,"videoDataDeliveryEnabled":false}'
aws bedrock get-model-invocation-logging-configuration
```

The S3 bucket "must be in the same AWS account and AWS Region" as the logging configuration.

## Step 6 · See it work: five requests

1. **A normal question:**

   ```bash
   aws bedrock-runtime converse --model-id amazon.nova-micro-v1:0 \
     --messages '[{"role":"user","content":[{"text":"What are your opening hours on public holidays?"}]}]' \
     --query 'output.message.content[0].text' --output text
   ```

2. **Fake personal data** (all invented; the card is the Visa test number):

   ```bash
   aws bedrock-runtime converse --model-id amazon.nova-micro-v1:0 \
     --messages '[{"role":"user","content":[{"text":"Hi, I am Dana Reyes (dana.reyes@customer.example), account TSG-CUST-104233. My card 4111 1111 1111 1111 was charged twice."}]}]' \
     --query 'output.message.content[0].text' --output text
   ```

3. **An embedding call** (with the Embedding modality off, the vector shouldn't be logged):

   ```bash
   aws bedrock-runtime invoke-model --model-id amazon.titan-embed-text-v2:0 --cli-binary-format raw-in-base64-out \
     --body '{"inputText":"Ticket from Sam Okafor (TSG-CUST-104871): refund order 7781","dimensions":256}' /tmp/m28-embed.json
   ```

4. **Read the redacted copy** (wait a few minutes for delivery, then list both buckets):

   ```bash
   aws s3 ls s3://$RAW_BUCKET --recursive
   aws s3 ls s3://$REDACTED_BUCKET --recursive
   aws s3 cp s3://$REDACTED_BUCKET/<a key from the listing> - | gunzip | python3 -m json.tool
   ```

   Example response (shape from the provider's docs, values illustrative: record fields from the
   [invocation-logging page](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html),
   labels from `cloud/lambda/redactor.py`):

   ```output
   {
       "schemaType": "ModelInvocationLog",
       "schemaVersion": "1.0",
       "timestamp": "...",
       "operation": "Converse",
       "modelId": "amazon.nova-micro-v1:0",
       "identity": {"arn": "arn:aws:sts::111122223333:assumed-role/..."},
       "input": {"inputBodyJson": {"messages": [{"role": "user", "content": [{"text":
           "Hi, I am Dana Reyes ([EMAIL_ADDRESS]), account [TSG_CUSTOMER_ID]. My card [CREDIT_CARD_NUMBER] was charged twice."}]}]}, ...}
   }
   ```

   If the object isn't gzipped, drop `| gunzip`. Write down the real file layout you see (one record or several per
   object, the key pattern): the offline lab's layout is a stand-in.

5. **Try to read a RAW record as yourself:**

   ```bash
   aws s3 cp s3://$RAW_BUCKET/<a raw key from the listing> /tmp/m28-raw.gz
   ```

   You're an admin, and it should still fail: your identity can manage `alias/tsg-m28-raw` but has no `kms:Decrypt`
   on it. Write down the exact error you get. Then find the refusal in CloudTrail (management events, so they're in
   the free event history):

   ```bash
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt --max-results 5 \
     --query 'Events[].CloudTrailEvent' --output text | tr '\t' '\n' | python3 -m json.tool --json-lines
   ```

   Look for an event with an `errorCode` and the raw key's ARN. Write down which identity it names. The fields are
   the documented ones: `eventSource` `kms.amazonaws.com`, `eventName` `Decrypt`,
   `userIdentity.arn`, `requestParameters.keyId` and `encryptionContext`
   ([KMS, CloudTrail Decrypt](https://docs.aws.amazon.com/kms/latest/developerguide/ct-decrypt.html)).

## Step 7 · Macie checks both buckets

1. **Test a custom identifier before you trust it** (no job, no data scanned):

   ```bash
   aws macie2 test-custom-data-identifier --regex 'TSG-CUST-[0-9]{6}' --sample-text 'account TSG-CUST-104233 and TSG-CUST-104871'
   ```

   Example response (shape from the provider's docs, values illustrative: `TestCustomDataIdentifier` returns
   `matchCount`):

   ```output
   {
       "matchCount": 2
   }
   ```

2. **Create the two custom identifiers.** Macie's managed list has no e-mail address identifier
   ([managed data identifiers](https://docs.aws.amazon.com/macie/latest/user/mdis-reference-quick.html)), so you add
   one:

   ```bash
   export CDI_EMAIL=$(aws macie2 create-custom-data-identifier --name EMAIL_ADDRESS \
     --regex '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' --query customDataIdentifierId --output text)
   export CDI_CUST=$(aws macie2 create-custom-data-identifier --name TSG_CUSTOMER_ID \
     --regex 'TSG-CUST-[0-9]{6}' --query customDataIdentifierId --output text)
   ```

3. **A one-time job over both buckets**, every managed identifier plus yours:

   ```bash
   export JOB=$(aws macie2 create-classification-job --job-type ONE_TIME --name m28-check \
     --managed-data-identifier-selector ALL --custom-data-identifier-ids $CDI_EMAIL $CDI_CUST \
     --s3-job-definition '{"bucketDefinitions":[{"accountId":"'$ACCOUNT_ID'","buckets":["'$RAW_BUCKET'","'$REDACTED_BUCKET'"]}]}' \
     --query jobId --output text)
   aws macie2 describe-classification-job --job-id $JOB --query jobStatus
   aws macie2 get-findings --finding-ids $(aws macie2 list-findings --query 'findingIds' --output text) \
     --query 'findings[].{type: type, bucket: resourcesAffected.s3Bucket.name, key: resourcesAffected.s3Object.key}'
   ```

   - `aws macie2 describe-classification-job --job-id $JOB --query jobStatus`: repeat until COMPLETE

   What to expect: findings on the **raw** bucket (`SensitiveData:S3Object/Multiple` or `/CustomIdentifier` for the
   e-mail and customer ID, `/Financial` for the card). On the **redacted** bucket: none for e-mail, card or customer
   ID. If Macie's `NAME` identifier flags "Dana Reyes" in a redacted object, that's the check working: the Lambda has
   no name detector. Write down what you get. A job costs $1 per GB scanned in the pricing page's US East examples;
   this one scans a few kilobytes.

## Step 8 · Change one setting and run again

Turn the **Embedding** modality on, repeat request 3, wait for delivery, and open the new redacted object:

```bash
aws bedrock put-model-invocation-logging-configuration --logging-config \
  '{"s3Config":{"bucketName":"'$RAW_BUCKET'","keyPrefix":""},"textDataDeliveryEnabled":true,"imageDataDeliveryEnabled":false,"embeddingDataDeliveryEnabled":true,"videoDataDeliveryEnabled":false}'
```

If the raw record now carried the vector, the redacted copy shows the Lambda's marker in its place:
`{"removed": "embedding vector", "length": 256}`. That's the trade-off from lesson 28.1: the raw bucket now holds the
input text **and** its vector, and only your key policy keeps that pair from becoming a second copy of the text.
Turn the modality back off. (A second variation, if you have time: remove the Macie statement from the raw key's
policy, run a new job, and compare the job's statistics with the first run.)

## Step 9 · Cost and teardown (do it today)

Costs while it exists: 2 KMS keys at "$1/month (prorated hourly)" each, with no charge once "scheduled for deletion"
([KMS pricing](https://aws.amazon.com/kms/pricing/)); Macie $0.10 per bucket per month and $1 per GB for the job
(pricing page examples, trial excluded for jobs); a handful of Bedrock, Lambda and S3 requests. Check Billing the next
day.

```bash
aws bedrock delete-model-invocation-logging-configuration
aws macie2 disable-macie
aws s3api put-bucket-notification-configuration --bucket $RAW_BUCKET --notification-configuration '{}'
aws lambda delete-function --function-name tsg-log-redactor
aws iam delete-role-policy --role-name tsg-log-redactor --policy-name m28-redactor
aws iam delete-role --role-name tsg-log-redactor
```

- `aws macie2 disable-macie`: permanently deletes this Region's findings, jobs and custom identifiers

Empty the raw bucket, EVERY version and delete marker, then delete both buckets:

```bash
python3 - <<'EOF'
import json, os, subprocess
b = os.environ["RAW_BUCKET"]
out = json.loads(subprocess.check_output(["aws", "s3api", "list-object-versions", "--bucket", b, "--output", "json"]) or b"{}")
for v in out.get("Versions", []) + out.get("DeleteMarkers", []):
    subprocess.run(["aws", "s3api", "delete-object", "--bucket", b, "--key", v["Key"], "--version-id", v["VersionId"]], check=True)
EOF
aws s3 rm s3://$REDACTED_BUCKET --recursive
aws s3api delete-bucket --bucket $RAW_BUCKET
aws s3api delete-bucket --bucket $REDACTED_BUCKET
aws kms schedule-key-deletion --key-id $RAW_KEY --pending-window-in-days 7
aws kms schedule-key-deletion --key-id $REDACTED_KEY --pending-window-in-days 7
```

Disabling Macie "permanently delete[s] all of your existing findings, sensitive data discovery jobs, custom data
identifiers" in the Region ([Disabling Macie](https://docs.aws.amazon.com/macie/latest/user/disable-macie.html)). KMS
waits "7 – 30 days" before it deletes a key; after that, data under it "becomes unrecoverable"
([Deleting KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html)). That's the point of
crypto-shredding, and also why you schedule it only after the buckets are empty.
