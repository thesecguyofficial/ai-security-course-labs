# M26 optional guided build: a locked-down GPU node group on Amazon EKS

**Optional, in YOUR OWN sandbox AWS account, and it costs money while it runs.** The $0 lab (README.md) teaches the
same controls without an account. Do this only if you already have a sandbox account with budgets and alerts set up
(lesson 0.7), and tear it down the same day.

> **Status:** written from the AWS and eksctl documentation on 25 Oct 2026 and not yet run end to end in a sandbox
> account. Every response below is labelled **Example response (shape from the provider's docs, values
> illustrative)**. Before release it will be run once for real and these replaced with real output.

What you build: an EKS cluster with one GPU node group (one `g4dn.xlarge`, one NVIDIA T4) on the Bottlerocket NVIDIA
AMI, tainted, IMDSv1 off, pod access to IMDS blocked, network policy enforcement on, and one Ollama pod with a small
model, reachable only inside the cluster. Then you change one setting (a default-deny NetworkPolicy) and watch what
breaks.

## Before you start

- Tools: AWS CLI v2, `eksctl`, `kubectl`, all signed in to the sandbox account (`aws sts get-caller-identity`).
- **GPU quota.** New accounts often have 0. Console: **Service Quotas** → **AWS services** → **Amazon Elastic Compute
  Cloud (Amazon EC2)** → search **Running On-Demand G and VT instances** → it must be 4 or more (it's counted in
  vCPUs; a `g4dn.xlarge` has 4). If not, **Request increase at account level** and wait for approval.
- **Cost.** The EKS control plane is US$0.10 per cluster per hour on standard support
  ([EKS pricing](https://aws.amazon.com/eks/pricing/)). Add the `g4dn.xlarge` On-Demand price for your Region (see
  [EC2 pricing](https://aws.amazon.com/ec2/pricing/)), its EBS volume, and any NAT gateway eksctl
  creates for the private subnets (check the CloudFormation stack's resources). Use the AWS Pricing Calculator before
  you start, and set a budget alarm.

## Part A · Create the cluster and the GPU node group

**Console route (to see each setting):** EKS console → **Clusters** → **Create cluster** → **Custom configuration**.
Then, on the new cluster: **Compute** → **Add node group** → AMI type **Bottlerocket (NVIDIA)** → instance type
`g4dn.xlarge` → under **Kubernetes taints** add key `nvidia.com/gpu`, value `true`, effect `NoSchedule`. The launch
template must set **Metadata version: V2 only (token required)** and **Metadata response hop limit: 1**. The CLI route
below does the same in one file, so most people use it.

1. Read `cloud/cluster.yaml`, then create everything (about 20 minutes):

   ```bash
   cd labs/m26
   eksctl create cluster -f cloud/cluster.yaml
   ```

2. Scan the config with the lab's own rules before you trust it (no network, same scanner as the $0 lab):

   ```bash
   .venv/bin/python -c "import scan, yaml; s={'cluster': yaml.safe_load(open('cloud/cluster.yaml'))}; print([f.as_dict() for f in scan.check_cluster(s)])"
   ```

   ```output
   []
   ```

## Part B · Check the node: taint, IMDS, GPU

1. The taint is there, and the node offers one GPU (Bottlerocket's NVIDIA variant ships the device plugin):

   ```bash
   kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints,GPU:.status.allocatable.nvidia\\.com/gpu
   ```

   Example response (shape from the provider's docs, values illustrative):

   ```output
   NAME                          TAINTS                                                  GPU
   ip-192-168-101-23.ec2.internal   [map[effect:NoSchedule key:nvidia.com/gpu value:true]]   1
   ```

2. IMDS settings on the instance (want `required` and `1`):

   ```bash
   aws ec2 describe-instances --filters Name=tag:eks:nodegroup-name,Values=gpu \
     --query 'Reservations[].Instances[].MetadataOptions.[HttpTokens,HttpPutResponseHopLimit]' --output text
   ```

   Example response (shape from the provider's docs, values illustrative):

   ```output
   required	1
   ```

## Part C · Run Ollama on the GPU, inside the cluster only

1. Deploy, pull a small model, and ask it something from a throwaway pod in another namespace:

   ```bash
   kubectl apply -f cloud/ollama.yaml
   kubectl -n inference rollout status deploy/ollama
   kubectl -n inference exec deploy/ollama -- ollama pull gemma3:1b
   kubectl run probe --rm -it --restart=Never --image=curlimages/curl -- \
     curl -s http://ollama.inference:11434/api/generate -d '{"model": "gemma3:1b", "prompt": "Say hello", "stream": false}'
   ```

   Example response (shape from the provider's docs, values illustrative):

   ```output
   {"model":"gemma3:1b","response":"Hello!","done":true, ...}
   ```

2. Four requests worth trying, and what each should show:

   | Request | Expect |
   |---|---|
   | The one above (normal use, inside the cluster) | an answer |
   | `kubectl -n inference get svc ollama` | `TYPE ClusterIP`, no external IP: nothing outside the cluster can reach it |
   | From the probe pod: `curl -s http://ollama.inference:11434/api/tags` | the model list: inside the cluster there is still no login, which is why the next part matters |
   | From the probe pod: `curl -s -m 3 http://169.254.169.254/latest/meta-data/` | a timeout or error: `disablePodIMDS` keeps pods away from the node's role |

## Part D · Change one setting: default-deny the namespace

1. Apply the policy (DNS only), then repeat the pull and the request:

   ```bash
   kubectl apply -f cloud/deny-egress.yaml
   kubectl -n inference exec deploy/ollama -- ollama pull llama3.2:1b
   kubectl run probe --rm -it --restart=Never --image=curlimages/curl -- \
     curl -s -m 5 http://ollama.inference:11434/api/tags
   ```

   Example response (shape from the provider's docs, values illustrative):

   ```output
   Error: pull model manifest: ... dial tcp ...: i/o timeout
   curl: (28) Connection timed out after 5001 milliseconds
   ```

2. **The trade-off.** The model server can no longer download anything (good: a hostile model or custom code can't
   call out either) and nothing can call it until you allow it. You now load models through your reviewed pipeline,
   and you add one explicit ingress rule for your gateway's namespace, like the `vllm-from-gateway` policy in
   `stacks/hardened/k8s/inference.yaml`. That's the point: every path in or out is a decision you wrote down.

## Part E · Tear down (do it today)

```bash
kubectl delete -f cloud/deny-egress.yaml -f cloud/ollama.yaml --ignore-not-found
eksctl delete cluster -f cloud/cluster.yaml --wait
```

Then check, in the console: **EKS** → no `tsg-m26` cluster; **EC2** → no running `g4dn` instances, no leftover EBS
volumes, no NAT gateway or Elastic IP from the stack; **CloudFormation** → no `eksctl-tsg-m26-*` stacks.

## Sources

- eksctl GPU support (device plugin installed automatically, skipped for Bottlerocket-only clusters):
  https://docs.aws.amazon.com/eks/latest/eksctl/gpu-support.html
- eksctl `disablePodIMDS`: https://docs.aws.amazon.com/eks/latest/eksctl/security.html
- EKS accelerated AMIs (what the Bottlerocket NVIDIA AMI includes): https://docs.aws.amazon.com/eks/latest/userguide/ml-eks-optimized-ami.md
- IMDSv2 and hop limit 1 for EKS nodes: https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.md
- Network policy enforcement (`{"enableNetworkPolicy": "true"}`): https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.md
- EC2 quota "Running On-Demand G and VT instances": https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-instance-quotas.html
- g4dn.xlarge (1 NVIDIA T4, 4 vCPUs, 16 GiB): https://aws.amazon.com/ec2/instance-types/g4/
- EKS pricing: https://aws.amazon.com/eks/pricing/
