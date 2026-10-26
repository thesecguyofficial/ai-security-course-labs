# M21 guided build: the refund rules on a real AgentCore Gateway

The offline lab (README, Steps 1 to 8) teaches the mechanics at $0. This guide puts the two rules from lesson 21.5 on
a real Amazon Bedrock AgentCore Gateway in **your own** AWS sandbox account (lesson 0.7, never a work account), in
**us-east-1**. About 60 to 90 minutes. Nothing here uses a third-party service.

- **Part A** builds a gateway with three refund tools and a policy engine with four Cedar policies in `ENFORCE`:
  refunds up to $100 for the signed-in user, never more through the agent, and an approval request tool for the rest.
- **Part B** adds a Dogwood temporal policy, "at most 3 refunds an hour", and shows what the policy session ID does
  to it (and who should choose it).
- **Part C** changes one setting: the temporal policy in `LOG_ONLY`, then the effect of editing a temporal policy
  on open sessions.
- **Part D** turns on the evidence you'd want, then tears everything down.

> **Read this first: about the responses shown below.** We wrote this guide without access to an AWS account, so **no
> response in this file comes from a real run**. Every response block is labelled **"Example response (shape from AWS
> docs, values illustrative)"** and names the page its shape comes from. Request bodies were checked against the
> botocore 1.43.118 service model for `bedrock-agentcore-control` (required members, union members, string limits).
> Where AWS doesn't document what happens, the guide says "write down what you get". Write your real results down.

**Why the approval isn't on the gateway.** "Refund over $100 unless approved" has two honest designs. Here the
gateway refuses any refund over $100 from the agent, whoever is signed in, and the agent can only *ask* for one
(`request_refund_approval`); a supervisor pays approved refunds through the back office, outside the agent's path.
That is human deferral (lesson 21.4). A Dogwood policy *can* require an earlier approval in the same session, but a
policy session is bound to one signed-in principal, and AWS's own example notes that `count` "cannot express
'approved by two different people'". So the approval would come from the same person whose agent is being steered.
The offline lab shows the other design (a signed approval bound to the exact arguments, checked by the PEP).

Shell variables used throughout (set them again in a new terminal):

| Variable | Holds |
|---|---|
| `AWS_REGION` | `us-east-1` |
| `POOL`, `WEB` | the user pool ID and the web app client ID |
| `GATEWAY_URL`, `GATEWAY_ID`, `GW_ARN` | the gateway's MCP URL, ID and ARN |
| `PE_ID` | the policy engine ID |
| `BOB`, `ALICE` | access tokens (never paste them anywhere public) |

## Step 0 · Before you start (10 minutes)

1. **Sandbox account with a budget alarm** (lesson 0.7).
2. **Tools.** AWS CLI v2 (recent: AgentCore commands are new; an old CLI fails with `Invalid choice`), Terraform 1.6+
   or OpenTofu, Python 3.11+.
3. **Region.** AWS lists temporal policies as available in US East (N. Virginia)
   ([Temporal policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.md)).
4. **Terminal in `labs/m21`:**

   ```bash
   cd labs/m21
   export AWS_REGION=us-east-1
   aws sts get-caller-identity --query Account --output text
   ```

   - `aws sts get-caller-identity --query Account --output text`: check it IS the sandbox

# Part A · The gateway and four Cedar policies

## A1 · Create it from zero

1. Read `cloud/terraform/main.tf` first. It was adapted from the M14 build and not applied by the authors, so run a
   check before anything is created:

   ```bash
   make cloud-zip
   cd cloud/terraform && terraform init -input=false && terraform validate && cd ../..
   ```

2. Create everything except the users and the temporal policy:

   ```bash
   make cloud-up
   ```

   - `make cloud-up`: type yes: Cognito pool + web client, tools Lambda + role, gateway role, policy engine,
     gateway (CUSTOM_JWT, allowedClients = web app, ENFORCE), target, 4 Cedar policies

3. Read the outputs into variables:

   ```bash
   cd cloud/terraform
   export POOL=$(terraform output -raw user_pool_id) WEB=$(terraform output -raw web_client_id)
   export GATEWAY_URL=$(terraform output -raw gateway_url) GATEWAY_ID=$(terraform output -raw gateway_id)
   export GW_ARN=$(terraform output -raw gateway_arn) PE_ID=$(terraform output -raw policy_engine_id)
   cd ../..
   ```

   If `gateway_url` doesn't end in `/mcp`, add it: AWS's examples post to `.../mcp`
   ([policy sessions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-session-based-temporal.md)).

**What the Terraform gives the gateway role, and why.** Invoke the one Lambda function; `GetPolicyEngine`,
`AuthorizeAction` and `PartiallyAuthorizeActions`, without which "all tool invocations will be denied by default even
if you have permit policies configured"; and `GetWorkloadAccessToken` on the default workload-identity directory,
which temporal policies need
([Policy IAM permissions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-permissions.md)).

**Why `amount_cents` is an integer.** AWS maps a JSON Schema `integer` to a Cedar `Long` and a `number` to a
`decimal`, and inside a temporal block "ordering requires an `integer`"
([Resource configuration for examples](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/example-policies-reference.md)).
Money as integer minor units is what lets Part B count and compare it.

## A2 · Users and tokens

1. Create two users (choose a password of at least 12 characters, not reused anywhere):

   ```bash
   read -s PW_LAB; export PW_LAB
   for u in alice bob; do
     aws cognito-idp admin-create-user --user-pool-id "$POOL" --username "$u" --message-action SUPPRESS >/dev/null
     aws cognito-idp admin-set-user-password --user-pool-id "$POOL" --username "$u" --password "$PW_LAB" --permanent
   done
   ```

2. Get access tokens (they last 60 minutes by default; run `tok` again when they expire):

   ```bash
   tok() { aws cognito-idp initiate-auth --client-id "$WEB" --auth-flow USER_PASSWORD_AUTH \
           --auth-parameters USERNAME="$1",PASSWORD="$PW_LAB" --query AuthenticationResult.AccessToken --output text; }
   export BOB=$(tok bob) ALICE=$(tok alice)
   ```

## A3 · Six requests, and how to read them

`cloud/mcp_call.py` posts MCP JSON-RPC to the gateway with a bearer token (standard library only).

1. **A normal refund.** Bob refunds $45, as himself:

   ```bash
   TOKEN=$BOB python3 cloud/mcp_call.py call issue_refund \
     '{"order_id": "O-1001", "amount_cents": 4500, "currency": "USD", "caller_username": "bob"}'
   ```

   Example response (shape from AWS docs, values illustrative; [use-gateway-with-policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/use-gateway-with-policy.html)):

   ```example
   {"status": 200, "body": {"jsonrpc": "2.0", "id": "call-1", "result": {"isError": false,
     "content": [{"type": "text", "text": "{\"result\": \"LAB: refund of 4500 cents on O-1001 recorded for bob. No money moved.\"}"}]}}}
   ```

2. **Over the limit.** The same call for $950 (95000 cents):

   ```bash
   TOKEN=$BOB python3 cloud/mcp_call.py call issue_refund \
     '{"order_id": "O-3001", "amount_cents": 95000, "currency": "USD", "caller_username": "bob"}'
   ```

   Example response (shape and text from AWS docs, values illustrative; use-gateway-with-policy):

   ```example
   {"status": 200, "body": {"jsonrpc": "2.0", "id": "call-1", "result": {"content": [{"type": "text",
     "text": "AuthorizeActionException - Tool Execution Denied: Tool call not allowed due to policy enforcement [...]"}],
     "isError": true}}}
   ```

   HTTP 200 with `isError: true` is a refused tool call, not a transport error. Check the Lambda's CloudWatch log
   group: no log line for this call. The function never ran.

3. **The deferral path.** The agent asks for an approval instead:

   ```bash
   TOKEN=$BOB python3 cloud/mcp_call.py call request_refund_approval \
     '{"order_id": "O-3001", "amount_cents": 95000, "caller_username": "bob"}'
   ```

   Expect `isError: false` and the Lambda's "approval request filed" message. Asking moves no money.

4. **A forged caller.** Bob's token, Alice's name:

   ```bash
   TOKEN=$BOB python3 cloud/mcp_call.py call issue_refund \
     '{"order_id": "O-1001", "amount_cents": 4500, "currency": "USD", "caller_username": "alice"}'
   ```

   Expect `isError: true`: no permit matches, so default deny.

5. **The amount as a string.** `"amount_cents": "4500"`. AWS doesn't document whether the gateway rejects a value that
   doesn't match the tool's input schema before Policy runs. Write down what you get, and compare it with lab A7.

6. **A smuggled field.** Add `"amount": "950.00"` to request 1. The inline tool schema in the API model has `type`,
   `properties`, `required`, `items` and `description`, and no `additionalProperties` (botocore 1.43.118,
   `SchemaDefinition`). Write down whether the call is refused, and if it runs, look at the Lambda's log line: does
   the extra field reach the function? That answer tells you whether your Lambda must refuse unknown fields itself.

## A4 · Change one setting

Flip the gateway to `LOG_ONLY` and repeat request 2:

```bash
cd cloud/terraform && terraform apply -var policy_mode=LOG_ONLY && cd ../..
TOKEN=$BOB python3 cloud/mcp_call.py call issue_refund \
  '{"order_id": "O-3001", "amount_cents": 95000, "currency": "USD", "caller_username": "bob"}'
```

Expect `isError: false` and a Lambda log line: in `LOG_ONLY` "every tool call succeeds regardless of forbid policies"
([policy-enforcement-modes](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-enforcement-modes.md)).
In CloudWatch, **Metrics**, namespace `AWS/Bedrock-AgentCore`, look at `DenyDecisions` with the dimension
`Mode` = `LOG_ONLY`: the engine still said no, and the gateway didn't act on it. (`LogOnlyDecisionFlips` is a
different signal: it counts matches of single policies whose own `enforcementMode` is `LOG_ONLY`, which Part C uses.)
([metrics](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-policy-metrics.md);
[Test a policy in LOG_ONLY mode](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-test-a-policy.md)).
Flip it back before Part B:

```bash
cd cloud/terraform && terraform apply -var policy_mode=ENFORCE && cd ../..
```

# Part B · "At most 3 refunds an hour" with Dogwood

## B1 · Create the temporal policy

A temporal policy's statement goes under `policy` in the definition, not under `cedar`
([Authoring temporal policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal-authoring.md)).
The statement in `cloud/temporal/max_3_refunds_per_hour.dw` follows AWS's "Cap how many times an action runs"
example, with a one-hour window
([Temporal policy examples](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/example-policies-temporal.md)).
It counts `request` events, which include the request being authorized, so the fourth call in an hour is the first
one denied.

```bash
stmt=$(sed "s#GATEWAY_ARN#$GW_ARN#" cloud/temporal/max_3_refunds_per_hour.dw)
aws bedrock-agentcore-control create-policy --policy-engine-id "$PE_ID" --name max_3_refunds_per_hour \
  --validation-mode FAIL_ON_ANY_FINDINGS \
  --definition "$(python3 -c 'import json,sys; print(json.dumps({"policy": {"statement": sys.argv[1]}}))' "$stmt")"
aws bedrock-agentcore-control list-policies --policy-engine-id "$PE_ID"
```

`CreatePolicy` returns 202 and the policy then goes `ACTIVE` or `CREATE_FAILED`; check the status before you test.

## B2 · Four refunds in one session

From now on every request needs a policy session ID: "If the associated policy engine contains a temporal policy,
requests without a session ID fail with a validation error." Allowed characters are letters, digits and hyphens, 1 to
128 of them
([policy sessions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-session-based-temporal.md)).

```bash
for i in 1 2 3 4; do
  TOKEN=$BOB python3 cloud/mcp_call.py call issue_refund \
    '{"order_id": "O-1001", "amount_cents": 1000, "currency": "USD", "caller_username": "bob"}' --session tsg-bob-try1
done
```

If every call fails with `AccessDenied` on a `GetWorkloadAccessToken...` action, read the action name in the error.
AWS documents `GetWorkloadAccessToken` for the token the gateway mints on the AWS IAM inbound flow; this gateway uses
`CUSTOM_JWT`, and the page doesn't say which action the mint calls there. Write down what you get, and add that one
action to the gateway role with the same two resources.

Expect three `isError: false` and one `isError: true`. AWS's sample flow for a three-transfer limit shows the same
pattern ("3 of 3 ... DENIED by temporal policy").

## B3 · Break it: pick a new session

```bash
TOKEN=$BOB python3 cloud/mcp_call.py call issue_refund \
  '{"order_id": "O-1001", "amount_cents": 1000, "currency": "USD", "caller_username": "bob"}' --session tsg-bob-try2
```

Expect `isError: false`. AWS says it directly: "Starting a new session begins a new count", and on the rate-limit
example, "This is not a security control. The caller supplies the session ID". Whoever chooses the session ID can
reset the limit.

## B4 · Fix it: the backend chooses the session

The session ID must come from code the model and the browser can't influence. For a limit that has to hold across
conversations, AWS lists a per-user strategy ("Stable ID per user ... useful for daily budget enforcement"). A sketch
for the Helpdesk backend, one session per user per UTC day:

```python
import datetime, hashlib
def policy_session_id(username: str) -> str:
    day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    return f"tsg-{hashlib.sha256(username.encode()).hexdigest()[:16]}-{day}"
```

The one-hour window is relative, so it still slides inside that day's session; sessions expire after 24 hours of
inactivity. Two limits to plan for: sessions are bound to the caller's identity on authenticated gateways ("Two
different callers supplying the same session ID get isolated sessions"), and the maximum window is 24 hours.

# Part C · LOG_ONLY for one policy, and what an edit does

1. **One policy in LOG_ONLY.** `UpdatePolicy` takes an `enforcementMode` (`ACTIVE` or `LOG_ONLY`):

   ```bash
   POLICY_ID=<the policyId of max_3_refunds_per_hour from list-policies>
   aws bedrock-agentcore-control update-policy --policy-engine-id "$PE_ID" --policy-id "$POLICY_ID" \
     --enforcement-mode LOG_ONLY
   ```

   Repeat B2 with a new session ID. All four calls should run, and the fourth should show up in
   `LogOnlyDecisionFlips` ("would have changed the decision if promoted"). Then set it back to `ACTIVE`. Both
   `update-policy` calls change a temporal policy, so expect them to end open sessions too (step 2).

2. **What an edit does to open sessions.** "Adding or updating a temporal policy on the engine invalidates the
   engine's active temporal policy sessions", and the next request in such a session fails with HTTP 409
   `ConflictException`. Send one more call with `--session tsg-bob-try1` and write down the status. Your backend must
   treat a 409 as "start a new session", and that resets the count: plan policy changes for quiet hours.

# Part D · Evidence, then tear down

1. **Traces.** Turn on tracing for the gateway (lesson 14.7). Each `AuthorizeAction` span carries
   `aws.agentcore.policy.authorization_decision` and `aws.agentcore.policy.determining_policies`, and temporal
   evaluation adds `aws.agentcore.policy.temporal.evaluation_invoked` and `aws.agentcore.policy.temporal.latency_ms`
   ([Temporal policies, Observability](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.md)).
2. **Alarms worth keeping.** `DenyDecisions` rising for one gateway; any `LogOnlyDecisionFlips` in production; any
   `UpdateGateway` or `UpdatePolicy` call in CloudTrail.
3. **Tear down.** Delete the temporal policy (Terraform didn't create it, so it doesn't know about it), then
   everything else:

   ```bash
   aws bedrock-agentcore-control delete-policy --policy-engine-id "$PE_ID" --policy-id "$POLICY_ID"
   make cloud-down
   for u in alice bob; do aws cognito-idp admin-delete-user --user-pool-id "$POOL" --username "$u" 2>/dev/null; done
   ```

   - `make cloud-down`: type yes

   If `cloud-down` stops because the policy is still `DELETING`, wait a minute and run it again.

## Cost

A few US cents at the list prices on the AgentCore pricing page (gateway calls US$0.005 per 1,000, policy decisions
US$0.000025 each), plus Lambda and CloudWatch free-tier usage
([pricing](https://aws.amazon.com/bedrock/agentcore/pricing/)). No model is called in this guide. Tear down the same day.
