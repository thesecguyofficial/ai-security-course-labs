# M20 guided build (lesson 20.5): one identity per agent, tagged with the human it acts for, proven in CloudTrail

The offline part (`make aws-check`, `make aws-hunt`) teaches the rules at $0. This guide builds the same thing from
zero in **your own** AWS sandbox account (lesson 0.7, never a work account), in **us-east-1**, with the AWS CLI only.
About 60 to 90 minutes. Nothing here uses a third-party service.

What you build:

- **A Cognito user pool** with Alice and Bob: the identity provider that proves which human is signed in.
- **Three AgentCore workload identities** (`tsg-orchestrator`, `tsg-tickets`, `tsg-mail`), each tagged with an
  owner, a purpose and an environment.
- **Three IAM roles**, one per agent. Each trust policy only lets your launcher assume it when the launcher sets a
  **SourceIdentity** (`user-<the Cognito sub>`), and each permissions policy reaches only that agent's own workload
  identity, with an explicit deny on the unverified user-ID path.
- **A CloudTrail trail** that records management events plus AgentCore Identity **data events**
  (`AWS::BedrockAgentCore::WorkloadIdentity`, `AWS::BedrockAgentCore::TokenVault`).

Then you run agents for Alice and Bob, try three things that must fail, and read the proof in CloudTrail with the
same `attribution.py` you used offline.

> **Read this first: about the responses shown below.** We wrote this guide without running it in an AWS account, so
> **no response in this file comes from a real run**. Every response block is labelled **"Example response (shape
> from AWS docs, values illustrative)"**. Field names follow the AWS documentation; values are our guesses. Two
> things in particular are unconfirmed until you run it: the exact `requestParameters` AgentCore writes into its
> CloudTrail data events, and whether a manually created workload identity accepts a Cognito **access** token as
> `userToken` (the API asks for "The OAuth 2.0 token issued by the user's identity provider"). If it refuses the
> access token, use the `IdToken` from the same sign-in and note it in your findings notebook.

## Step 0 · Before you start (10 minutes)

1. A sandbox account with a budget alarm (lesson 0.7), the AWS CLI v2 (recent: AgentCore commands are new; an old
   CLI fails with `Invalid choice`) and Python 3.11+.
2. Set the variables used throughout:

   ```bash
   export AWS_REGION=us-east-1
   export ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
   export LAUNCHER=$(aws sts get-caller-identity --query Arn --output text)
   export BUCKET=tsg-m20-trail-$ACCOUNT
   ```

   `LAUNCHER` is you. In production it would be the backend's own role; here your CLI identity plays the backend
   that starts agent runs. If it prints an `assumed-role/...` ARN (SSO), use the role ARN instead:
   `arn:aws:iam::$ACCOUNT:role/<the role name in that ARN>`.

3. From the lab folder (`labs/m20`), write your policy files:

   ```bash
   python3 aws/render.py --account "$ACCOUNT" --region "$AWS_REGION" --launcher-arn "$LAUNCHER" --bucket "$BUCKET"
   ```

## Part A · Build it (30 minutes)

### A1 · The identity provider: Cognito with two users

1. Create the pool and an app client that allows the CLI sign-in used in this lab:

   ```bash
   export POOL=$(aws cognito-idp create-user-pool --pool-name tsg-m20 --query UserPool.Id --output text)
   export POOL_CLIENT=$(aws cognito-idp create-user-pool-client --user-pool-id "$POOL" --client-name tsg-m20-web \
     --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH --no-generate-secret \
     --query UserPoolClient.ClientId --output text)
   ```

   `USER_PASSWORD_AUTH` sends the password to Cognito from your terminal. It's a lab shortcut so you don't need a web
   page; a real app uses the hosted sign-in with authorization code and PKCE (lesson 20.0).

2. Create Alice and Bob. Choose one lab password of at least 12 characters that you use nowhere else:

   ```bash
   read -s PW_LAB; export PW_LAB
   for u in alice bob; do
     aws cognito-idp admin-create-user --user-pool-id "$POOL" --username "$u" --message-action SUPPRESS >/dev/null
     aws cognito-idp admin-set-user-password --user-pool-id "$POOL" --username "$u" --password "$PW_LAB" --permanent
   done
   ```

### A2 · One workload identity per agent, with an accountable owner

```bash
for a in orchestrator tickets mail; do
  aws bedrock-agentcore-control create-workload-identity --name "tsg-$a" \
    --tags "{\"owner\": \"$(whoami)\", \"purpose\": \"m20 lab $a agent\", \"environment\": \"lab\"}"
done
aws bedrock-agentcore-control list-workload-identities
```

```output
Example response (shape from AWS docs, values illustrative)
{
  "workloadIdentities": [
    {"name": "tsg-mail", "workloadIdentityArn": "arn:aws:bedrock-agentcore:us-east-1:111122223333:workload-identity-directory/default/workload-identity/tsg-mail"},
    ...
  ]
}
```

`CreateWorkloadIdentity` takes `name`, `allowedResourceOauth2ReturnUrls` and `tags`. The owner tag answers the first
question of lesson 20.1: who do we call when this agent misbehaves?

### A3 · One IAM role per agent that needs a human on every session

```bash
for a in orchestrator tickets mail; do
  aws iam create-role --role-name "tsg-agent-$a" --max-session-duration 3600 \
    --assume-role-policy-document "file://aws/out/trust-tsg-agent-$a.json" >/dev/null
  aws iam put-role-policy --role-name "tsg-agent-$a" --policy-name agentcore-identity \
    --policy-document "file://aws/out/policy-tsg-agent-$a.json"
done
cat aws/out/trust-tsg-agent-tickets.json
```

Read the trust policy before you move on. `sts:SetSourceIdentity` lets the launcher stamp a source identity on the
session; the `StringLike` condition on `sts:SourceIdentity` (`user-*`) makes it mandatory, because a request
without the key doesn't match and so isn't allowed. AWS: once set, "the value cannot be changed", and it "persists
into subsequent role sessions" when the role is used to assume another role
([IAM condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html)).

Then read `aws/out/policy-tsg-agent-tickets.json`: `GetWorkloadAccessTokenForJWT` on the directory and on
`tsg-tickets` only, `GetResourceOauth2Token` scoped to named providers, and a `Deny` on
`GetWorkloadAccessTokenForUserId` and `InvokeAgentRuntimeForUser`.

IAM changes can take a few seconds to apply. If the next step says `AccessDenied` straight away, wait 30 seconds.

### A4 · A trail that records Identity data events

```bash
aws s3api create-bucket --bucket "$BUCKET" >/dev/null
aws s3api put-bucket-policy --bucket "$BUCKET" --policy file://aws/out/bucket-policy.json
aws cloudtrail create-trail --name tsg-m20-trail --s3-bucket-name "$BUCKET" >/dev/null
aws cloudtrail put-event-selectors --trail-name tsg-m20-trail --advanced-event-selectors file://aws/out/selectors.json
aws cloudtrail start-logging --name tsg-m20-trail
```

Data events are off unless you ask for them: "By default, trails and event data stores do not log data events"
([CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)).

## Part B · Run it and prove it (30 minutes plus waiting for CloudTrail)

### B1 · Normal runs

```bash
bash aws/run_as_agent.sh orchestrator alice
bash aws/run_as_agent.sh tickets alice
bash aws/run_as_agent.sh mail alice
bash aws/run_as_agent.sh tickets bob
```

```output
Example response (shape from AWS docs, values illustrative)
workload access token received, length 1024
run tickets-run-101512: agent tickets acted for alice (sub 3f1c...e9)
```

Each run signs the user in, assumes **that agent's** role with `SourceIdentity user-<sub>` for 15 minutes, and asks
AgentCore Identity for a workload access token for **that agent's** identity with the user's JWT. AgentCore uses the
JWT's `iss` and `sub` to tie the token to the user
([get-workload-access-token](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.md)).
The script also writes what the launcher believed to `aws/out/app-log.jsonl`.

### B2 · Three things that must fail

1. **No human on the session.** Assume the role without a source identity:

   ```bash
   aws sts assume-role --role-arn "arn:aws:iam::$ACCOUNT:role/tsg-agent-tickets" --role-session-name no-human
   ```

   Expected: `AccessDenied` (the trust condition doesn't match).

2. **The unverified user-ID path.** Inside a tickets session, try to name a user without a token:

   ```bash
   creds=$(aws sts assume-role --role-arn "arn:aws:iam::$ACCOUNT:role/tsg-agent-tickets" --role-session-name probe \
     --source-identity user-probe --duration-seconds 900 \
     --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
   read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<<"$creds"
   export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
   aws bedrock-agentcore get-workload-access-token-for-user-id --workload-name tsg-tickets --user-id alice
   ```

   Expected: `AccessDeniedException` (explicit deny).

3. **Another agent's identity.** In the same session:

   ```bash
   aws bedrock-agentcore get-workload-access-token-for-jwt --workload-name tsg-mail --user-token "<any user token>"
   unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
   ```

   Expected: `AccessDeniedException` (the tickets role reaches only `tsg-tickets`). Don't forget the `unset`, or
   every later command runs as the probe session.

### B3 · Change one setting and watch the proof break

Let the tickets role be assumed without a source identity, run once, then put the condition back:

```bash
python3 -c 'import json; d=json.load(open("aws/out/trust-tsg-agent-tickets.json")); [s.pop("Condition") for s in d["Statement"]]; json.dump(d, open("aws/out/trust-open.json","w"))'
aws iam update-assume-role-policy --role-name tsg-agent-tickets --policy-document file://aws/out/trust-open.json
creds=$(aws sts assume-role --role-arn "arn:aws:iam::$ACCOUNT:role/tsg-agent-tickets" --role-session-name tickets-anon \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text); read -r AK SK ST <<<"$creds"
jwt=$(aws cognito-idp initiate-auth --client-id "$POOL_CLIENT" --auth-flow USER_PASSWORD_AUTH \
      --auth-parameters USERNAME=bob,PASSWORD="$PW_LAB" --query AuthenticationResult.AccessToken --output text)
AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_SESSION_TOKEN=$ST \
  aws bedrock-agentcore get-workload-access-token-for-jwt --workload-name tsg-tickets --user-token "$jwt" >/dev/null
aws iam update-assume-role-policy --role-name tsg-agent-tickets --policy-document file://aws/out/trust-tsg-agent-tickets.json
```

The call still works: AgentCore knows the user from the JWT. What you lose is the human in **CloudTrail's view of
the AWS session**, which is what Q2 below catches.

### B4 · Read the proof

CloudTrail delivers log files to S3 within minutes (often about 5, sometimes 15). Then:

```bash
aws s3 cp "s3://$BUCKET/AWSLogs/" aws/out/trail --recursive
python3 aws/attribution.py --cloudtrail-dir aws/out/trail --app-log aws/out/app-log.jsonl
```

```output
Example response (shape from AWS docs, values illustrative)
Q1 who acted for whom (SourceIdentity on the agent's role session):
   user-3f1c...e9
      2027-01-21T10:15:14Z  tsg-agent-orchestrator   identity tsg-orchestrator  GetWorkloadAccessTokenForJWT
      2027-01-21T10:15:31Z  tsg-agent-tickets        identity tsg-tickets       GetWorkloadAccessTokenForJWT
      ...
Q2 agent calls with no human on the session:
   2027-01-21T10:31:02Z  tsg-agent-tickets        tickets-anon     GetWorkloadAccessTokenForJWT
```

Then open one `GetWorkloadAccessTokenForJWT` record yourself (`zcat` one file and search for the event name) and
write down, in your notebook, the real field names AgentCore used: `userIdentity.sessionContext.sourceIdentity` (the
IAM documentation shows this field), `requestParameters`, and `resources`. If `workloadName` is missing from
`requestParameters`, `attribution.py` falls back to the `resources` ARN; if neither is there, tell us.

The refused calls from B2 show up as management or data events with an `errorCode`; find them too.

**Optional: the human in AgentCore's own spans.** AgentCore Identity can also emit spans, and its documented span
attributes for `GetWorkloadAccessTokenForJWT` include `issuer` and `user_sub`
([identity observability](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-identity-metrics.md)).
They need observability enabled on the workload identity, which you can do from the AgentCore console. That gives a
second, independent record of who each token was for.

## Cost and teardown (do it the same day)

Cost at the list prices on 25 Oct 2026: CloudTrail data events US$0.10 per 100,000 delivered (you'll make a few
dozen), the first copy of management events free, S3 storage for a few kilobytes, Cognito for two users. AgentCore
Identity charges US$0.010 per 1,000 OAuth token or API key requests for non-AWS resources; this build makes none
([AgentCore pricing](https://aws.amazon.com/bedrock/agentcore/pricing/),
[CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/)). Expect well under one US dollar.

```bash
aws cloudtrail stop-logging --name tsg-m20-trail
aws cloudtrail delete-trail --name tsg-m20-trail
aws s3 rm "s3://$BUCKET" --recursive && aws s3api delete-bucket --bucket "$BUCKET"
for a in orchestrator tickets mail; do
  aws iam delete-role-policy --role-name "tsg-agent-$a" --policy-name agentcore-identity
  aws iam delete-role --role-name "tsg-agent-$a"
  aws bedrock-agentcore-control delete-workload-identity --name "tsg-$a"
done
aws cognito-idp delete-user-pool --user-pool-id "$POOL"
rm -rf aws/out
```

Check `aws bedrock-agentcore-control list-workload-identities` and the IAM console show nothing named `tsg-` left.
