"""
checker.py: review a SageMaker AI deployment of the Helpdesk summariser the way you'd review the pull request.
Offline, standard library only.

    python3 checker.py first-draft     # make check
    python3 checker.py hardened        # make check-hardened

27 rules, M15-01 to M15-27, each tagged with the lesson that explains it. Each rule reads only the files in
setups/<name>/ (request bodies, IAM and network notes) and the model files the deployment would load. IAM rules
don't pattern-match policy text: they ask the twin concrete questions ("may ds-bob approve a model version?").
Exit code 1 if any HIGH finding, so it can fail a pipeline.
"""

from __future__ import annotations

import datetime as dt
import sys
from dataclasses import dataclass

import model_files
import twin

C = twin.COMPANY
EP = C["endpoint_arn"]
SECRET_WORDS = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "ACCESS_KEY")


@dataclass
class Finding:
    rule: str
    severity: str
    lesson: str
    message: str

    def __str__(self):
        return f"[{self.severity:6}] {self.rule} ({self.lesson}) {self.message}"


def _people(s):
    """Principals that are people or apps, not execution roles, the pipeline, the approver, admins or outsiders."""
    out = []
    for n, p in s.iam["principals"].items():
        if p.get("execution_role") or p.get("admin") or p.get("account", twin.ACCOUNT) != twin.ACCOUNT:
            continue
        if n in ("tsg-ci-deployer", "tsg-model-approver"):
            continue
        out.append(n)
    return out


def _deployed_package(s):
    c = s.model["PrimaryContainer"]
    return twin.package(s, c["ModelPackageName"]) if "ModelPackageName" in c else None


def _deployed_files(s):
    world = twin.World(s)
    kind, where = twin.model_source(twin.effective_container(s))
    return world.files(where) if kind == "s3" else {}


# --------------------------------------------------------------------------------------------------------------------
# 15.1 What you now own: the image
# --------------------------------------------------------------------------------------------------------------------
def rule_01(s):
    img = twin.effective_container(s).get("Image", "")
    info = twin.IMAGES["images"].get(img)
    if not info:
        return [Finding("M15-01", "MEDIUM", "15.1", f"image {img} is not in the image catalog: nobody knows when it stops getting patches")]
    days = twin.IMAGES["end_of_patch_days"][info["family"]]
    end = dt.date.fromisoformat(info["released"]) + dt.timedelta(days=days)
    if end < dt.date.fromisoformat(C["lab_today"]):
        return [Finding("M15-01", "HIGH", "15.1", f"the inference image reached end of patch on {end} ({info['family']}: {days} days after release): "
                        "it gets no more security fixes, and a fix only reaches the endpoint when you deploy a model that names a newer image")]
    return []


def rule_02(s):
    img = twin.effective_container(s).get("Image", "")
    if "@sha256:" not in img:
        return [Finding("M15-02", "MEDIUM", "15.1", "the image is pinned by tag, not by digest: the same tag can point at different bytes over time")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 15.2 Network isolation, VPC-only domains, KMS, execution roles
# --------------------------------------------------------------------------------------------------------------------
def rule_03(s):
    if not s.model.get("EnableNetworkIsolation"):
        r = twin.container_reach(s)
        return [Finding("M15-03", "HIGH", "15.2", "the model container runs without network isolation: code in it can call out"
                        + (" to the internet" if r["internet"] else "") + " and use the execution role's credentials")]
    return []


def rule_04(s):
    if not s.model.get("VpcConfig"):
        return [Finding("M15-04", "MEDIUM", "15.2", "the model has no VpcConfig: model downloads don't go through your VPC, so your S3 endpoint policy and flow logs never see them")]
    return []


def rule_05(s):
    r = twin.studio_reach(s)
    if r["internet"]:
        return [Finding("M15-05", "HIGH", "15.2", f"Studio notebooks can reach the internet ({r['why']}): anything a data scientist can read can leave")]
    return []


def rule_06(s):
    out = []
    for sg, info in s.domain.get("_security_groups", {}).items():
        if info.get("inbound_from_itself") and len([u for u in info["used_by"] if not u.startswith("domain")]) > 1:
            out.append(Finding("M15-06", "MEDIUM", "15.2", f"{sg} allows inbound from itself and is shared by {', '.join(info['used_by'])}: "
                               "AWS warns users in the VPC could reach other profiles' apps without authentication"))
    return out


def rule_07(s):
    if not s.domain.get("KmsKeyId"):
        return [Finding("M15-07", "MEDIUM", "15.2", "the Studio domain has no KmsKeyId: notebooks' EFS and EBS volumes use an AWS managed key, whose key policy you can't edit")]
    return []


def rule_08(s):
    out = []
    for n, p in s.iam["principals"].items():
        if not p.get("execution_role"):
            continue
        managed = [m for m in p.get("managed_policies", []) if m == "AmazonSageMakerFullAccess"]
        wide = [st for st in twin._statements(p.get("policy")) if st["Effect"] == "Allow"
                and "*" in twin._as_list(st.get("Resource", [])) and any(a.endswith(":*") or a == "*" for a in twin._as_list(st["Action"]))]
        if managed or wide:
            what = (["AmazonSageMakerFullAccess (AWS: 'fairly broad')"] if managed else []) + \
                   [f"{', '.join(twin._as_list(st['Action']))} on *" for st in wide]
            out.append(Finding("M15-08", "HIGH", "15.2", f"execution role {n} has {'; '.join(what)}: everything in the container, and every job that runs as it, gets this"))
    return out


def rule_09(s):
    out = []
    for n, p in s.iam["principals"].items():
        if not p.get("execution_role"):
            continue
        for st in twin._statements(p.get("trust")):
            src = st.get("Condition", {}).get("ArnLike", {}).get("aws:SourceArn") or \
                  st.get("Condition", {}).get("ArnEquals", {}).get("aws:SourceArn")
            if not src:
                out.append(Finding("M15-09", "MEDIUM", "15.2", f"{n} trust policy has no aws:SourceArn: any SageMaker AI resource, in any account, could be the one assuming it (confused deputy)"))
            elif src != f"arn:aws:sagemaker:{twin.REGION}:{twin.ACCOUNT}:*":
                out.append(Finding("M15-09", "LOW", "15.2", f"{n} trust policy narrows aws:SourceArn to {src}: AWS's inference template says not to replace arn:aws:sagemaker:<region>:<account>:*"))
    return out


def rule_10(s):
    out = []
    prod_role = twin.arn_role("tsg-summariser-exec")
    for n in _people(s):
        if twin.decide(s, n, "iam:PassRole", prod_role, {"iam:PassedToService": "sagemaker.amazonaws.com"})[0]:
            out.append(Finding("M15-10", "HIGH", "15.2", f"{n} may pass tsg-summariser-exec to SageMaker AI: a job or notebook they start runs with the production role"))
    return out


def rule_11(s):
    out = []
    for n, p in s.iam["principals"].items():
        me = p.get("studio_user")
        if not me:
            continue
        others = [u for u in C["user_profiles"].values() if u != me and
                  twin.decide(s, n, "sagemaker:CreatePresignedDomainUrl", twin.arn_sm("user-profile", f"{C['domain_id']}/{u}"))[0]]
        if others:
            out.append(Finding("M15-11", "HIGH", "15.2", f"{n} may create a presigned Studio URL for {', '.join(others)}: they sign in as that profile, with its files and execution role"))
    return out


def rule_12(s):
    env = twin.effective_container(s).get("Environment", {})
    hits = [k for k in env if any(w in k.upper() for w in SECRET_WORDS)]
    if hits:
        readers = [n for n in _people(s) if twin.decide(s, n, "sagemaker:DescribeModel", twin.arn_sm("model", s.model["ModelName"]))[0]]
        return [Finding("M15-12", "HIGH", "15.2", f"secret-looking value in the container Environment ({', '.join(hits)}): DescribeModel returns it to {', '.join(readers) or 'anyone with Describe rights'}")]
    return []


def rule_13(s):
    out = []
    if s.endpoint_config.get("KmsKeyId"):
        for v in s.endpoint_config["ProductionVariants"]:
            if twin.instance_has_local_storage(v.get("InstanceType", "")):
                out.append(Finding("M15-13", "LOW", "15.2", f"KmsKeyId on an endpoint with {v['InstanceType']} (NVMe instance storage): AWS says you can't use a KMS key on an instance type with local storage, so this key isn't protecting what you think"))
    return out


# --------------------------------------------------------------------------------------------------------------------
# 15.3 Endpoints, model files and licences, registry approvals
# --------------------------------------------------------------------------------------------------------------------
def rule_14(s):
    out = []
    for n in _people(s):
        if twin.decide(s, n, "sagemaker:InvokeEndpoint", EP, via_vpce=False)[0]:
            out.append(Finding("M15-14", "HIGH", "15.3", f"{n} may call InvokeEndpoint from anywhere (no aws:SourceVpce condition): stolen keys work from the internet"))
    return out


def rule_15(s):
    if s.network["interface_endpoints"].get("sagemaker.runtime") and not s.iam.get("runtime_endpoint_policy"):
        return [Finding("M15-15", "HIGH", "15.3", "the sagemaker.runtime interface endpoint has the default policy (full access): credentials from any AWS account can use your private path to send data to their own endpoints")]
    return []


def rule_16(s):
    if any(v.get("EnableSSMAccess") for v in s.endpoint_config["ProductionVariants"]):
        who = [n for n in _people(s) if twin.decide(s, n, "ssm:StartSession", EP)[0]]
        return [Finding("M15-16", "HIGH", "15.3", "EnableSSMAccess on a production variant: shell access into the inference container"
                        + (f" for {', '.join(who)}" if who else "") + "; AWS recommends it for dev or test only and delays security patching by a day")]
    return []


def rule_17(s):
    if "ModelPackageName" not in s.model["PrimaryContainer"]:
        return [Finding("M15-17", "HIGH", "15.3", "the endpoint's model points straight at an S3 path, not at an approved Model Registry version: nobody's approval is part of what runs")]
    pkg = _deployed_package(s)
    if pkg and pkg["ModelApprovalStatus"] != "Approved":
        return [Finding("M15-17", "HIGH", "15.3", f"the endpoint runs model package version {pkg['_version']}, which is {pkg['ModelApprovalStatus']}")]
    return []


def rule_18(s):
    out = []
    for n in _people(s):
        if twin.decide(s, n, "sagemaker:UpdateModelPackage", C["model_package_arn_prefix"] + "3")[0]:
            out.append(Finding("M15-18", "HIGH", "15.3", f"{n} may call UpdateModelPackage: a data scientist can approve their own model version (no four-eyes)"))
    return out


def rule_19(s):
    kind, where = twin.model_source(twin.effective_container(s))
    if kind == "hub":
        return [Finding("M15-19", "HIGH", "15.3", f"the container downloads {where} from the Hugging Face Hub at start: whatever is published there today runs, unscanned and unhashed")]
    res = model_files.scan_files(_deployed_files(s))
    bad = [p for p in res["problems"] if p["kind"] in ("pickle", "numpy", "code")]
    if bad:
        detail = "; ".join(f"{p['name']} ({p['kind']}{': imports ' + ', '.join(p['unsafe_globals']) if p['unsafe_globals'] else ''})" for p in bad)
        return [Finding("M15-19", "HIGH", "15.3", f"the deployed model files are not safetensors-only: {detail}")]
    return []


def rule_20(s):
    kind, where = twin.model_source(twin.effective_container(s))
    if kind != "s3":
        return []
    bucket, key = where[5:].split("/", 1)
    writers = [n for n in _people(s) if twin.decide(s, n, "s3:PutObject", twin.arn_s3(bucket, key + "model.safetensors"))[0]]
    if writers:
        return [Finding("M15-20", "HIGH", "15.3", f"{', '.join(writers)} may overwrite the files the endpoint loads ({where}): a swap after approval reaches production on the next deploy or scale-out")]
    return []


def rule_21(s):
    pkg = _deployed_package(s)
    meta = (pkg or {}).get("CustomerMetadataProperties", {})
    out = []
    if not any(k.startswith(model_files.HASH_PREFIX) for k in meta):
        out.append(Finding("M15-21", "MEDIUM", "15.3", "no file hashes recorded for the deployed model: nobody can prove the files running are the ones approved"))
    lic = meta.get("licence")
    if lic not in C["approved_licences"]:
        out.append(Finding("M15-21", "MEDIUM", "15.3", f"licence {'not recorded' if not lic else lic + ' is not on the approved list'}: AWS says reviewing model licences is your job"))
    return out


def rule_22(s):
    if not s.app.get("approval_gate"):
        return [Finding("M15-22", "MEDIUM", "15.3", "no approval gate: nothing checks formats, hashes, licence and approver before a version becomes Approved (challenge 2)")]
    return []


def rule_23(s):
    req = {"sagemaker:NetworkIsolation": "false"}
    if not twin.policy_effect(s.scps, "sagemaker:CreateModel", twin.arn_sm("model", "any"), req) == "deny":
        return [Finding("M15-23", "MEDIUM", "15.2", "no SCP requires network isolation and a VPC on CreateModel: an admin's quick test can still ship a container that calls out (challenge 1)")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 15.4 Watching it in production
# --------------------------------------------------------------------------------------------------------------------
def rule_24(s):
    dc = s.endpoint_config.get("DataCaptureConfig")
    if not dc or not dc.get("EnableCapture"):
        return []
    out = []
    if not dc.get("KmsKeyId"):
        out.append(Finding("M15-24", "MEDIUM", "15.4", "data capture (full prompts and answers) is written without a KmsKeyId of yours"))
    bucket = dc["DestinationS3Uri"][5:].split("/", 1)[0]
    if bucket != C["buckets"]["capture"]:
        out.append(Finding("M15-24", "MEDIUM", "15.4", f"data capture goes to {bucket}, a bucket other teams read: captured prompts are as sensitive as the tickets they summarise"))
    return out


def rule_25(s):
    if "AWS::SageMaker::Endpoint" not in s.app["monitoring"]["cloudtrail_data_event_types"]:
        return [Finding("M15-25", "MEDIUM", "15.4", "no CloudTrail data events for AWS::SageMaker::Endpoint: InvokeEndpoint is a data event, and trails don't log data events by default")]
    return []


def rule_26(s):
    if "Invocation4XXErrors" not in s.app["monitoring"]["alarms"]:
        return [Finding("M15-26", "LOW", "15.4", "no alarm on Invocation4XXErrors or invocation volume: probing and abuse show up there first")]
    return []


def rule_27(s):
    plan = " ".join(s.app["monitoring"]["plan"])
    if s.app.get("_account_is_new_to_model_monitor") and ("Model Monitor" in plan or "Clarify" in plan):
        return [Finding("M15-27", "LOW", "15.4", "the monitoring plan relies on SageMaker Model Monitor or Clarify: both are no longer open to new customers")]
    return []


RULES = [rule_01, rule_02, rule_03, rule_04, rule_05, rule_06, rule_07, rule_08, rule_09, rule_10, rule_11, rule_12,
         rule_13, rule_14, rule_15, rule_16, rule_17, rule_18, rule_19, rule_20, rule_21, rule_22, rule_23, rule_24,
         rule_25, rule_26, rule_27]
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run(setup: twin.Setup) -> list[Finding]:
    out = []
    for r in RULES:
        out += r(setup)
    return sorted(out, key=lambda f: (ORDER[f.severity], f.rule))


def main(argv):
    if len(argv) != 1:
        print(__doc__)
        return 2
    found = run(twin.Setup(argv[0]))
    for f in found:
        print(f)
    n = {k: sum(f.severity == k for f in found) for k in ORDER}
    print(f"\n{n['HIGH']} HIGH, {n['MEDIUM']} MEDIUM, {n['LOW']} LOW  ({len(found)} findings)")
    return 1 if n["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
