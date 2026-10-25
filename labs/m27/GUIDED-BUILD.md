# M27 guided build (optional): a Code Interpreter with no way out but the ones you named

Your own **sandbox** AWS account, `us-east-1`, about 45 minutes, then teardown the same day. You build what
`configs/hardened.json` describes, in a smaller form: an AgentCore Code Interpreter in **VPC mode**, private subnets
with no internet or NAT gateway, an **S3 gateway endpoint** whose policy names one bucket, and a **Route 53 Resolver
DNS Firewall walled garden** with query logging. Then you send four example requests, change one setting, read the
logs and tear it all down.

This walkthrough has **not been run end to end yet**. Every response below is labelled "Example response (shape from
the provider's docs, values illustrative)". Before release it gets one real run and real output.

## Cost (list prices read 25 Oct 2026)

| Item | Price | Source |
|---|---|---|
| Code Interpreter | US$0.0895 per vCPU-hour and US$0.00945 per GB-hour, metered per second, 1-second minimum, 128 MB minimum memory | [AgentCore pricing](https://aws.amazon.com/bedrock/agentcore/pricing/) |
| DNS Firewall | US$0.0005 per domain per month (prorated hourly), US$0.60 per million queries | [Route 53 pricing](https://aws.amazon.com/route53/pricing/) |
| Resolver query logs | No Route 53 charge; CloudWatch Logs charges apply | same |
| S3 gateway endpoint | "There is no additional charge for using gateway endpoints." | [AWS](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html) |
| CloudTrail network activity events (optional) | Extra charge | [AWS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-network-events-with-cloudtrail.html) |

There is **no NAT gateway** in this build, on purpose. Run it for an hour and tear it down, and the total stays in
US cents at these prices.

## Before you start

- AWS CLI v2 signed in to the sandbox account, Region `us-east-1`.
- `python3 -m venv .venv && .venv/bin/pip install -r cloud/requirements.txt` (boto3 1.43.118) for Part D.
- Set these in your shell and keep the terminal open:

```bash
export AWS_REGION=us-east-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export LAB_BUCKET=tsg-m27-lab-$ACCOUNT_ID
export OTHER_BUCKET=tsg-m27-other-$ACCOUNT_ID
```

## Part A · The network: private subnets, no way out

AgentCore lists the Availability Zone IDs it supports per Region; for `us-east-1` they are `use1-az1`, `use1-az2`
and `use1-az4`, and subnets elsewhere fail at creation
([AWS, VPC for AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html)).

```bash
VPC=$(aws ec2 create-vpc --cidr-block 10.42.0.0/16 --query Vpc.VpcId --output text)
aws ec2 modify-vpc-attribute --vpc-id $VPC --enable-dns-support
SUB1=$(aws ec2 create-subnet --vpc-id $VPC --cidr-block 10.42.1.0/24 --availability-zone-id use1-az1 --query Subnet.SubnetId --output text)
SUB2=$(aws ec2 create-subnet --vpc-id $VPC --cidr-block 10.42.2.0/24 --availability-zone-id use1-az2 --query Subnet.SubnetId --output text)
RTB=$(aws ec2 describe-route-tables --filters Name=vpc-id,Values=$VPC --query 'RouteTables[0].RouteTableId' --output text)
SG=$(aws ec2 create-security-group --vpc-id $VPC --group-name m27-sandbox --description "M27 sandbox: S3 endpoint only" --query GroupId --output text)
aws ec2 revoke-security-group-egress --group-id $SG --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
PL=$(aws ec2 describe-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.us-east-1.s3 --query 'PrefixLists[0].PrefixListId' --output text)
aws ec2 authorize-security-group-egress --group-id $SG --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":443,\"ToPort\":443,\"PrefixListIds\":[{\"PrefixListId\":\"$PL\"}]}]"
```

No internet gateway, no NAT gateway: the VPC has no route out. The security group now allows one thing, HTTPS to
S3's address list. DNS goes to the VPC's own resolver, which is where Part B puts its control.

**The S3 gateway endpoint, with a policy.** Console: VPC console > **Endpoints** > **Create endpoint** > Service
category **AWS services** > filter **Type = Gateway** > `com.amazonaws.us-east-1.s3` > your VPC > the route table >
Policy **Custom** ([AWS](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)). CLI:

```bash
aws s3 mb s3://$LAB_BUCKET && aws s3 mb s3://$OTHER_BUCKET
echo "lab file" > hello.txt && aws s3 cp hello.txt s3://$LAB_BUCKET/reports/hello.txt
sed "s/LAB_BUCKET/$LAB_BUCKET/g" cloud/endpoint-policy.json > /tmp/m27-endpoint-policy.json
VPCE=$(aws ec2 create-vpc-endpoint --vpc-id $VPC --vpc-endpoint-type Gateway --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids $RTB --policy-document file:///tmp/m27-endpoint-policy.json --query VpcEndpoint.VpcEndpointId --output text)
```

The default endpoint policy "allows full access"; yours names one bucket.

## Part B · The DNS walled garden and its log

Console: VPC console > **DNS Firewall** > **Rule groups** > **Add rule group**, then a rule with your own domain list
and action Allow, and a second rule for `*` with action Block and response NODATA, with the allow rule's priority
number lower ([AWS, walled garden tutorial](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-getting-started.html)).
CLI:

```bash
ALLOW=$(aws route53resolver create-firewall-domain-list --name m27-allow --creator-request-id m27-allow-1 --query FirewallDomainList.Id --output text)
aws route53resolver update-firewall-domains --firewall-domain-list-id $ALLOW --operation ADD \
  --domains s3.us-east-1.amazonaws.com "*.s3.us-east-1.amazonaws.com" s3.amazonaws.com "*.s3.amazonaws.com"
ALL=$(aws route53resolver create-firewall-domain-list --name m27-all --creator-request-id m27-all-1 --query FirewallDomainList.Id --output text)
aws route53resolver update-firewall-domains --firewall-domain-list-id $ALL --operation ADD --domains "*"
RG=$(aws route53resolver create-firewall-rule-group --name m27-walled-garden --creator-request-id m27-rg-1 --query FirewallRuleGroup.Id --output text)
aws route53resolver create-firewall-rule --firewall-rule-group-id $RG --firewall-domain-list-id $ALLOW --priority 100 \
  --action ALLOW --name allow-s3 --creator-request-id m27-r1
aws route53resolver create-firewall-rule --firewall-rule-group-id $RG --firewall-domain-list-id $ALL --priority 200 \
  --action BLOCK --block-response NODATA --name block-all --creator-request-id m27-r2
ASSOC=$(aws route53resolver associate-firewall-rule-group --firewall-rule-group-id $RG --vpc-id $VPC --priority 101 \
  --name m27-assoc --creator-request-id m27-a1 --query FirewallRuleGroupAssociation.Id --output text)
```

Subdomains need their own `*.` entry; the list doesn't cover them otherwise. The VPC fails closed by default
("sends a `SERVFAIL` DNS response"); leave it that way
([AWS](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-vpc-configuration.html)).
If your code needs other AWS service names (for example STS), add them to `m27-allow` and to the security group, one
at a time, and write down why.

**Query logging to CloudWatch Logs:**

```bash
aws logs create-log-group --log-group-name /m27/resolver
LG_ARN=$(aws logs describe-log-groups --log-group-name-prefix /m27/resolver --query 'logGroups[0].arn' --output text | sed 's/:\*$//')
QLC=$(aws route53resolver create-resolver-query-log-config --name m27-qlog --destination-arn $LG_ARN --creator-request-id m27-q1 --query ResolverQueryLogConfig.Id --output text)
aws route53resolver associate-resolver-query-log-config --resolver-query-log-config-id $QLC --resource-id $VPC
```

## Part C · The Code Interpreter in VPC mode

```bash
sed "s/ACCOUNT_ID/$ACCOUNT_ID/g" cloud/trust-policy.json > /tmp/m27-trust.json
sed "s/LAB_BUCKET/$LAB_BUCKET/g; s/OTHER_BUCKET/$OTHER_BUCKET/g" cloud/role-policy.json > /tmp/m27-role.json
ROLE_ARN=$(aws iam create-role --role-name m27-code-interpreter --assume-role-policy-document file:///tmp/m27-trust.json --query Role.Arn --output text)
aws iam put-role-policy --role-name m27-code-interpreter --policy-name m27-s3 --policy-document file:///tmp/m27-role.json
CI=$(aws bedrock-agentcore-control create-code-interpreter --name m27_vpc_ci --execution-role-arn $ROLE_ARN \
  --network-configuration "{\"networkMode\":\"VPC\",\"vpcConfig\":{\"subnets\":[\"$SUB1\",\"$SUB2\"],\"securityGroups\":[\"$SG\"]}}" \
  --query codeInterpreterId --output text)
echo $CI
```

The trust policy is AWS's own example (service `bedrock-agentcore.amazonaws.com`, with `aws:SourceAccount` and
`aws:SourceArn`). The role can list your other bucket on purpose: in Part D the endpoint policy, not the role, should
be what says no.

Two notes. AWS's VPC page shows this JSON with a `networkModeConfig` key; the API model in boto3 1.43.118 calls it
`vpcConfig`. If the CLI rejects one, use the other. And the console's create page lists only **Sandbox** and **Public
network** under **Network settings** (AgentCore console > **Built-in tools** > **Create Code Interpreter tool**), so
use the CLI for VPC mode
([AWS, create a Code Interpreter](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-create.html)).

## Part D · Four example requests

```bash
.venv/bin/python cloud/try_requests.py $CI $LAB_BUCKET $OTHER_BUCKET
```

Example response (shape from the provider's docs, values illustrative):

```output
session 01JC0EXAMPLE0SESSION0ID000

== R1 normal: list the lab bucket
keys: ['reports/hello.txt']

== R2 allowed name: look up the S3 endpoint name
['52.216.0.10', '52.216.0.11']

== R3 name not on the list: look up example.com
lookup failed: [Errno -5] No address associated with hostname

== R4 bucket outside the endpoint policy: list your other bucket
AccessDenied - User: arn:aws:sts::111122223333:assumed-role/m27-code-interpreter/... is not authorized to perform: s3:ListBucket ... because no VPC endpoint policy allows the s3:ListBucket action

session stopped
```

How to read it: R1 and R2 are the normal job. R3 got a NODATA answer from the block-all rule, so the name never
resolves. R4 reached S3 over the private path, and the endpoint policy refused a bucket it doesn't name.

## Part E · Read the logs

CloudWatch console > **Logs Insights** > log group `/m27/resolver`:

```text
fields query_timestamp, query_name, srcaddr, rcode, firewall_rule_action
| filter ispresent(firewall_rule_action)
| sort query_timestamp desc
```

Example response (shape from the provider's docs, values illustrative):

```output
query_timestamp        query_name     srcaddr     rcode    firewall_rule_action
2027-03-27T10:14:03Z   example.com.   10.42.1.87  NOERROR  BLOCK
```

`firewall_rule_action` appears only when a block or alert rule matched
([AWS, query log format](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-format.html)).
To see R4 in CloudTrail too, turn on network activity events for `s3.amazonaws.com` (CloudTrail > **Trails** > your
trail > **Network activity events** > **Edit**) and look for `errorCode` `VpceAccessDenied`. AWS's page doesn't say
whether gateway endpoints produce these events; if none appears, the `AccessDenied` in R4's output is your evidence,
and that gap is worth knowing about.

## Part F · Change one setting and re-run

Switch the block-all rule to `ALERT`, the mode AWS suggests for testing a new block rule:

```bash
aws route53resolver update-firewall-rule --firewall-rule-group-id $RG --firewall-domain-list-id $ALL --action ALERT
.venv/bin/python cloud/try_requests.py $CI $LAB_BUCKET $OTHER_BUCKET
```

R3 now resolves, and the query log shows `firewall_rule_action` `ALERT` instead of `BLOCK`. That's the trade-off: ALERT
tells you what a block would break, and blocks nothing. The security group still allows only S3, so a name that
resolves is not yet a connection; that's why the layers are separate. Put it back:

```bash
aws route53resolver update-firewall-rule --firewall-rule-group-id $RG --firewall-domain-list-id $ALL --action BLOCK --block-response NODATA
```

## Part G · Teardown (today)

```bash
aws bedrock-agentcore-control delete-code-interpreter --code-interpreter-id $CI
aws route53resolver disassociate-resolver-query-log-config --resolver-query-log-config-id $QLC --resource-id $VPC
aws route53resolver delete-resolver-query-log-config --resolver-query-log-config-id $QLC
aws route53resolver disassociate-firewall-rule-group --firewall-rule-group-association-id $ASSOC
aws route53resolver delete-firewall-rule --firewall-rule-group-id $RG --firewall-domain-list-id $ALLOW
aws route53resolver delete-firewall-rule --firewall-rule-group-id $RG --firewall-domain-list-id $ALL
aws route53resolver delete-firewall-rule-group --firewall-rule-group-id $RG
aws route53resolver delete-firewall-domain-list --firewall-domain-list-id $ALLOW
aws route53resolver delete-firewall-domain-list --firewall-domain-list-id $ALL
aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $VPCE
aws s3 rb s3://$LAB_BUCKET --force && aws s3 rb s3://$OTHER_BUCKET --force
aws iam delete-role-policy --role-name m27-code-interpreter --policy-name m27-s3
aws iam delete-role --role-name m27-code-interpreter
aws logs delete-log-group --log-group-name /m27/resolver
```

The disassociation steps take a minute; if a delete says the resource is in use, wait and retry. AgentCore's network
interfaces "may persist in your VPC for up to 8 hours" after you delete the tool
([AWS](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html)), so delete the security
group, subnets and VPC when they're gone:

```bash
aws ec2 delete-security-group --group-id $SG
aws ec2 delete-subnet --subnet-id $SUB1 && aws ec2 delete-subnet --subnet-id $SUB2
aws ec2 delete-vpc --vpc-id $VPC
```

Finally, check the Billing console's **Bills** page the next day.
