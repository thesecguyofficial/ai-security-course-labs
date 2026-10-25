# M29 guided build (optional, your own AWS sandbox account): alert on a Bedrock call from an unexpected network

About 30 minutes. You test the lab's EventBridge patterns against AWS's own matcher, then deploy one rule that emails
you when **your** IAM user calls Bedrock without going through a VPC endpoint, and measure how long the alert takes.

> **Course rule for this module: no decoy keys in the cloud.** The honeytoken in this lab stays a local mock. This
> build creates no access key, no API key and no IAM user. You only test the honeytoken *pattern* (Part A).
> Use a sandbox account you own (lesson 0.8). Every response below is labelled **Example response (shape from the
> provider's docs, values illustrative)** until you run it yourself.

**You need:** the AWS CLI v2 signed in to your sandbox account as an IAM user you control (or an Identity Center
user: then change `userName` to an `arn` prefix match in Part B), a CloudTrail trail that logs management events in
`us-east-1` (EventBridge only receives CloudTrail events when "you must enable a CloudTrail trail with logging"), and
an email address for the alert.

## Part A · Test the patterns against AWS's matcher ($0, nothing created)

`aws events test-event-pattern` "Tests whether the specified event pattern matches the provided event." The files
come from this lab (`cloud/`), so this checks that the local matcher and AWS agree.

```bash
cd labs/m29
aws events test-event-pattern --region us-east-1 \
  --event-pattern file://cloud/pattern-unexpected-network-lab.json --event file://cloud/event-from-elsewhere.json
aws events test-event-pattern --region us-east-1 \
  --event-pattern file://cloud/pattern-unexpected-network-lab.json --event file://cloud/event-via-endpoint.json
aws events test-event-pattern --region us-east-1 \
  --event-pattern file://cloud/pattern-honeytoken.json --event file://cloud/event-honeytoken-read-only.json
```

Example response (shape from the provider's docs, values illustrative), one per command:

```output
{ "Result": true }
{ "Result": false }
{ "Result": true }
```

The third one matters: the pattern matches the decoy's read-only `GetCallerIdentity` call, but a deployed rule in
state `ENABLED` would never be handed that event. `test-event-pattern` checks the pattern only, not the rule state.

**Console instead:** EventBridge console → **Developer resources** → **Sandbox** → **Event pattern** tab → **Event
source**: **AWS events or EventBridge partner events** → paste the event file as your sample event → **Creation
method**: **Custom pattern (JSON editor)** → paste the pattern → **Test pattern**.

## Part B · Deploy one rule and an email target

1. Put your IAM user name into `cloud/pattern-unexpected-network.json` (replace `REPLACE-WITH-YOUR-IAM-USER-NAME`).
   Find it with:

   ```bash
   aws sts get-caller-identity --query Arn --output text
   ```

2. Create the topic, allow EventBridge to publish to it, and subscribe your email (confirm the email AWS sends):

   ```bash
   ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
   TOPIC=$(aws sns create-topic --region us-east-1 --name tsg-m29-alerts --query TopicArn --output text)
   sed "s/REPLACE-WITH-ACCOUNT-ID/$ACCOUNT/" cloud/sns-policy.json > /tmp/tsg-m29-sns-policy.json
   aws sns set-topic-attributes --region us-east-1 --topic-arn "$TOPIC" \
     --attribute-name Policy --attribute-value file:///tmp/tsg-m29-sns-policy.json
   aws sns subscribe --region us-east-1 --topic-arn "$TOPIC" --protocol email --notification-endpoint you@example.com
   ```

3. Create the rule. The state matters: `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` also passes read-only calls.

   ```bash
   aws events put-rule --region us-east-1 --name tsg-m29-unexpected-network \
     --event-pattern file://cloud/pattern-unexpected-network.json \
     --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS
   aws events put-targets --region us-east-1 --rule tsg-m29-unexpected-network \
     --targets "Id"="email","Arn"="$TOPIC"
   ```

   **Console instead:** EventBridge → **Rules** → **Create rule** → name `tsg-m29-unexpected-network`, event bus
   `default` → **Custom pattern (JSON editor)** → paste the pattern → target **SNS topic** `tsg-m29-alerts`. Then
   check the rule's state is the "all CloudTrail management events" option, not plain Enabled.

## Part C · See it work (from your laptop, which has no VPC endpoint)

Note the time before each command. Your laptop is "an unexpected network" for this rule on purpose.

| # | Request | Expect |
|---|---|---|
| 1 | `aws bedrock list-foundation-models --region us-east-1 --query 'modelSummaries[0].modelId'` | an email: a read-only Bedrock call by your user, no `vpcEndpointId` |
| 2 | `aws sts get-caller-identity` | no email: not a Bedrock call (`eventSource` prefix `bedrock`) |
| 3 | `aws bedrock list-foundation-models --region eu-west-1 --query 'modelSummaries[0].modelId'` | no email: the rule lives in `us-east-1` only. A real deployment needs a rule in every Region you use |
| 4 | `aws bedrock get-model-invocation-logging-configuration --region us-east-1` | an email: the call LLMjacking actors made to see whether anyone was logging |

Example alert body (shape from the provider's docs, values illustrative): the SNS email carries the EventBridge event
as JSON, with `"detail-type": "AWS API Call via CloudTrail"` and the CloudTrail record under `detail`
(`eventSource`, `eventName`, `sourceIPAddress`, `userIdentity`, no `vpcEndpointId`).

## Part D · Change one setting and re-run

```bash
aws events put-rule --region us-east-1 --name tsg-m29-unexpected-network \
  --event-pattern file://cloud/pattern-unexpected-network.json --state ENABLED
```

Run request 1 again. No email this time: a rule in state `ENABLED` does not receive read-only management events.
That is lab case H1: the first thing someone does with a found key is a read-only check. Set the state back with the
Part B command.

## Part E · Measure your delay

For requests 1 and 4, write down the command time and the email's arrival time. CloudTrail documents an average of
about 5 minutes for delivery to S3 and no figure for EventBridge, so the lab uses an assumption
(`eventbridge_delivery_s` in `data/org.json`). Put your own median there and re-run `make respond`: does the
hardened responder still act inside 10 minutes?

## Part F · Cost and teardown (do it today)

Cost: EventBridge pricing says "AWS management events are ingested by the event bus for free"; a few SNS emails and
read-only Bedrock calls should round to US$0. Check the EventBridge and SNS pricing pages for your Region. If you
created a trail only for this build, delete it too.

```bash
aws events remove-targets --region us-east-1 --rule tsg-m29-unexpected-network --ids email
aws events delete-rule --region us-east-1 --name tsg-m29-unexpected-network
aws sns delete-topic --region us-east-1 --topic-arn "$TOPIC"
rm -f /tmp/tsg-m29-sns-policy.json
```
