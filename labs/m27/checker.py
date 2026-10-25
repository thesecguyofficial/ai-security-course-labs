"""checker.py: review an agent sandbox configuration like an auditor (lessons 27.1 and 27.2).

    python3 checker.py first-draft        # every finding, with the lesson and the fix
    python3 checker.py hardened           # should print: 0 findings
    python3 checker.py configs/x.json     # any config file with the same shape

Each rule is a small function that reads the config and returns a list of problems (empty = pass). Rules carry an id,
the lesson that teaches them and the fix, so a finding reads like an audit note. Exit code 1 when anything is found,
so the checker can gate a pipeline.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import lab

RULES: list["Rule"] = []

CREDENTIAL_PATHS = (".aws", ".ssh", ".azure", ".config/gcloud", ".kube", ".docker")


@dataclass
class Rule:
    id: str
    lesson: str
    title: str
    fix: str
    check: object


@dataclass
class Finding:
    rule: str
    lesson: str
    title: str
    detail: str
    fix: str


def rule(id: str, lesson: str, title: str, fix: str):
    def wrap(fn):
        RULES.append(Rule(id, lesson, title, fix, fn))
        return fn
    return wrap


# ---------------------------------------------------------------- network (27.2)

@rule("N1", "27.2", "Sandbox network mode is VPC", "Set network.mode to VPC: no public network for model-written code.")
def n1(c):
    mode = c["network"]["mode"]
    return [] if mode == "VPC" else [f"network.mode is {mode}"]


@rule("N2", "27.2", "No route to the internet", "Remove the NAT gateway route from the sandbox subnets.")
def n2(c):
    return ["network.nat_gateway is true: the sandbox has a route out"] if c["network"].get("nat_gateway") else []


@rule("N3", "27.2", "Security group egress names its destinations",
      "Allow egress only to the endpoints and the proxy; no 0.0.0.0/0.")
def n3(c):
    return [f"egress {e['protocol']}/{e['port']} to {e['to']}" for e in c["network"]["security_group_egress"]
            if e["to"] in ("0.0.0.0/0", "::/0")]


@rule("E1", "27.2", "Every endpoint has a custom endpoint policy",
      "Replace full-access with a policy that lists the actions and the resource ARNs this agent uses.")
def e1(c):
    return [f"{e['service']} {e['type']} endpoint uses {e['policy']}" for e in c["endpoints"]
            if not isinstance(e["policy"], dict)]


@rule("E2", "27.2", "Endpoint policies name exact actions and resources (CHALLENGE 1)",
      "No '*' (or service:*) in an endpoint policy's actions or resources.")
def e2(c):
    """CHALLENGE 1 (lesson 27.2): a custom endpoint policy can still allow everything.

    Return one problem string per endpoint whose custom policy (a dict) has "*" or a "service:*" action in
    allow_actions, or "*" in resources. Endpoints still on "full-access" are E1's job: skip them here.
    configs/second-draft.json has one such endpoint. Replace the line below.
    """
    return []


@rule("D1", "27.2", "DNS resolver allow-list (walled garden) is on",
      "Turn on the DNS firewall, block everything by default and allow only the names this agent needs.")
def d1(c):
    d = c["dns"]
    out = []
    if not d.get("firewall"):
        out.append("dns.firewall is false: the resolver answers for any name")
    elif not d.get("allow"):
        out.append("dns.allow is empty")
    return out


@rule("D2", "27.2", "DNS firewall fails closed", "Set dns.fail_open to false (the AWS default is fail closed).")
def d2(c):
    return ["dns.fail_open is true"] if c["dns"].get("fail_open") else []


@rule("D3", "27.2", "The DNS default rule blocks (CHALLENGE 1)",
      "Move the default rule from ALERT to BLOCK once a week of alerts looks clean.")
def d3(c):
    """CHALLENGE 1 (lesson 27.2): a walled garden left in ALERT mode blocks nothing.

    When dns.firewall is true, return one problem string if dns.default_action is anything other than "BLOCK".
    When the firewall is off, return [] (D1 already reports it). Replace the line below.
    """
    return []


@rule("L1", "27.2", "Every outbound door has a log",
      "Turn on VPC flow logs, Resolver query logs and CloudTrail network activity events for each endpoint's service.")
def l1(c):
    lg = c["logging"]
    out = []
    if not lg.get("flow_logs"):
        out.append("flow_logs off")
    if not lg.get("dns_query_logs"):
        out.append("dns_query_logs off")
    want = {lab_event_source(e["service"]) for e in c["endpoints"]}
    missing = sorted(want - set(lg.get("cloudtrail_network_activity", [])))
    if missing:
        out.append("no CloudTrail network activity events for " + ", ".join(missing))
    return out


def lab_event_source(service: str) -> str:
    """CloudTrail event source for an endpoint's service (bedrock-runtime calls are logged under bedrock)."""
    return {"s3": "s3.amazonaws.com", "bedrock-runtime": "bedrock.amazonaws.com"}.get(service, f"{service}.amazonaws.com")


@rule("P1", "27.2", "Proxy allow-list names exact hosts", "Replace wildcard entries with the exact host names.")
def p1(c):
    return [f"proxy allows {a['name']}" for a in c["proxy"]["allow"] if a["name"].startswith("*")]


@rule("P2", "27.2", "The proxy is enforced by the network",
      "Make the proxy the only address the sandbox can reach on the web ports (security group), not just an env var.")
def p2(c):
    p = c["proxy"]
    return ["proxy.enforced_by_network is false: code that ignores the proxy goes straight out"] \
        if p.get("enabled") and not p.get("enforced_by_network") else []


@rule("P3", "27.2", "Proxy allows only the methods each host needs", "List methods per host (GET and HEAD for a package mirror).")
def p3(c):
    return [f"proxy allows every method to {a['name']}" for a in c["proxy"]["allow"] if "*" in a["methods"]]


# ---------------------------------------------------------------- boundary, role, files, secrets (27.1)

@rule("R1", "27.1", "Execution role names exact actions and resources",
      "One bucket prefix, the model ARNs in use, no '*' actions or resources.")
def r1(c):
    out = []
    for i, s in enumerate(c["execution_role"]["statements"]):
        bad = [a for a in s["actions"] if a == "*" or a.endswith(":*")] + [r for r in s["resources"] if r == "*"]
        if s["effect"] == "Allow" and bad:
            out.append(f"statement {i} allows {', '.join(bad)}")
    return out


@rule("F1", "27.1", "No credential folders mounted in the sandbox", "Unmount credential folders; keys stay with a broker outside.")
def f1(c):
    return [f"{m['path']} is mounted" for m in c["filesystem"]["mounts"]
            if any(m["path"].rstrip("/").endswith(cp) or f"/{cp}/" in m["path"] for cp in CREDENTIAL_PATHS)]


@rule("F2", "27.1", "Only the scratch folder is writable", "Mount input data read-only; keep /workspace as the only rw mount.")
def f2(c):
    return [f"{m['path']} is rw" for m in c["filesystem"]["mounts"] if m["mode"] == "rw" and m["path"] != "/workspace"]


@rule("S1", "27.1", "No secrets inside the sandbox", "Remove secrets from the environment; call a broker outside the sandbox.")
def s1(c):
    return [f"secret {name} in the environment" for name in c["secrets"]["env"]]


@rule("T1", "27.1", "One short session per user and task", "one_per_user_task true and a timeout of an hour or less.")
def t1(c):
    s = c["runtime"]["session"]
    out = []
    if not s.get("one_per_user_task"):
        out.append("sessions are not one per user and task")
    if s.get("timeout_seconds", 0) > 3600:
        out.append(f"session timeout {s['timeout_seconds']} s")
    return out


@rule("T2", "27.1", "Resource limits are set", "Set vcpu, memory_mb and max_processes.")
def t2(c):
    return [f"limits.{k} not set" for k in ("vcpu", "memory_mb", "max_processes") if not c["runtime"]["limits"].get(k)]


# ---------------------------------------------------------------- run

def review(config: dict) -> list[Finding]:
    found = []
    for r in RULES:
        for detail in r.check(config):
            found.append(Finding(r.id, r.lesson, r.title, detail, r.fix))
    return found


def main(argv: list[str]) -> int:
    name = argv[1] if len(argv) > 1 else "first-draft"
    findings = review(lab.load_config(name))
    print(f"Review of {name}: {len(RULES)} rules")
    for f in findings:
        print(f"  [{f.rule}] {f.lesson}  {f.title}: {f.detail}")
        print(f"         fix: {f.fix}")
    failed = sorted({f.rule for f in findings})
    print(f"{len(findings)} findings, {len(failed)} of {len(RULES)} rules failed" + (f" ({', '.join(failed)})" if failed else ""))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
