#!/usr/bin/env python3
"""Review the Ops Crew's cloud deployment description for your stream. Offline, $0, no cloud account needed.

    python3 cloud/cloud_check.py                         # the stream named in capstone.json (make cloud)
    python3 cloud/cloud_check.py --stream aws cloud/aws/deployment.json
    python3 cloud/cloud_check.py --json results/cloud.json

Pass mark (self-check C1): no HIGH findings. Rubric merit: no MEDIUM findings either. Each rule names the lesson
that teaches the real setting. A key you delete counts as the insecure default: removing a setting never makes a
finding go away.

Streams: aws is available now. azure and gcp ship with those streams (cloud/azure/README.md, cloud/gcp/README.md).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
AGENTS = ("triage", "billing", "analyst")


def _get(d: dict, path: str, default=None):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def aws_rules(d: dict) -> list[tuple[str, str, str, str]]:
    out = []

    def add(rid, sev, lesson, msg):
        out.append((rid, sev, lesson, msg))

    # Per-agent identity (M20)
    agents = {a.get("name"): a for a in (_get(d, "agent_identities.agents", []) or [])}
    if not _get(d, "agent_identities.one_per_agent", False) or set(agents) != set(AGENTS):
        add("AWS-01", "HIGH", "20.1, 20.5",
            "the three agents do not each have their own AgentCore workload identity: one shared identity means "
            "CloudTrail cannot tell which agent acted")
    for name in AGENTS:
        a = agents.get(name, {})
        if a.get("role") in (None, "", "shared"):
            add("AWS-02", "HIGH", "20.1",
                f"agent {name!r} has no scoped IAM role of its own (shares a role): give each agent least privilege")
    # Cedar / Policy in AgentCore (M21)
    if not _get(d, "policy_engine.attached", False):
        add("AWS-03", "HIGH", "21.2", "no Cedar policy engine on the gateway: tool calls are not authorized outside the model")
    if _get(d, "policy_engine.mode", "LOG_ONLY") != "ENFORCE":
        add("AWS-04", "HIGH", "21.5", "the policy engine is in LOG_ONLY: in this mode every tool call succeeds regardless of forbid policies")
    if _get(d, "policy_engine.catch_all_permit", True):
        add("AWS-05", "HIGH", "21.2", "a catch-all permit (a policy with no conditions) undoes the engine's built-in default-deny: "
            "permit each tool call narrowly instead")
    # Gateway inbound authorizer (M14)
    if _get(d, "gateway.authorizer_type", "NONE") in ("NONE", None):
        add("AWS-06", "HIGH", "14.3, 14.4", "the AgentCore gateway has no inbound authorizer: any caller reaches the tools")
    elif not _get(d, "gateway.allowed_clients"):
        add("AWS-06", "HIGH", "14.3, 14.4", "the gateway's JWT authorizer has no allowedClients: tokens from any app are accepted")
    # Hand-off / containment (M24)
    if not _get(d, "handoff.allowed_edges") or not _get(d, "handoff.max_depth"):
        add("AWS-07", "HIGH", "24.2, 24.3",
            "agent hand-offs have no allow-list of edges and no depth limit: one instruction can cascade across agents")
    # Code interpreter sandbox + egress (M27)
    nm = _get(d, "code_interpreter.network_mode", "PUBLIC")
    if nm == "PUBLIC":
        add("AWS-08", "HIGH", "27.1, 27.2",
            "the AgentCore Code Interpreter runs with networkMode PUBLIC: use SANDBOX (limited external network access) "
            "or VPC with an egress allow-list")
    elif nm == "VPC" and not _get(d, "code_interpreter.egress_allow_list"):
        add("AWS-08", "MEDIUM", "27.2", "the code interpreter is in a VPC but has no egress allow-list")
    # Model signing / supply chain (M25)
    if not _get(d, "model_supply_chain.verify_signature_on_deploy", False):
        add("AWS-09", "HIGH", "25.5, 25.6",
            "models and adapters are deployed without verifying a signature: sign in CI and verify at deploy, fail closed")
    elif not _get(d, "model_supply_chain.fail_closed", False):
        add("AWS-09", "MEDIUM", "25.6", "signature verification does not fail closed: an unverifiable model is still deployed")
    # Guardrail (M12)
    if not _get(d, "guardrail.attached", False) or _get(d, "guardrail.prompt_attack_filter", "NONE") in ("NONE", None):
        add("AWS-10", "HIGH", "12.1", "no Bedrock guardrail with a prompt attack filter on the agents' model calls")
    # Secret in prompt (M22 / LLM08:2026)
    if _get(d, "secrets.system_prompt_contains_secret", True):
        add("AWS-11", "HIGH", "22.1", "a secret sits in an agent's system prompt: assume every user can read the prompt")
    if _get(d, "secrets.plaintext_env_secrets", []):
        add("AWS-11", "HIGH", "11.3", "plaintext secrets in environment variables: use Secrets Manager and the agent's role")
    # Invocation logging (M16)
    if not _get(d, "invocation_logging.enabled", False):
        add("AWS-12", "HIGH", "16.1", "model invocation logging is off: nobody can tell what any agent asked or answered")
    elif not _get(d, "invocation_logging.kms_key"):
        add("AWS-12", "MEDIUM", "16.1", "invocation logs hold prompts and answers: encrypt them with your own KMS key")
    # Memory hygiene (M24)
    if not _get(d, "memory.provenance_tracking", False) or not _get(d, "memory.ttl_days"):
        add("AWS-13", "MEDIUM", "24.4", "agent memory has no provenance tracking or TTL: a poisoned note persists and re-fires")
    # Detection (M16/M23)
    if not (_get(d, "detection.guardduty_enabled", False) and _get(d, "detection.guardduty_ai_protection", False)):
        add("AWS-14", "MEDIUM", "16.2, 23.3", "GuardDuty AI Protection is off")
    data_events = [str(x).lower() for x in (_get(d, "cloudtrail.data_events", []) or [])]
    if not any("bedrock" in x or "agentcore" in x for x in data_events):
        add("AWS-15", "MEDIUM", "16.1", "no CloudTrail data events for Bedrock or AgentCore: agent tool calls go unrecorded")
    # Budget (M0/M29)
    if not _get(d, "budget.monthly_limit_usd") or not _get(d, "budget.alert_email_set", False):
        add("AWS-16", "MEDIUM", "0.7", "no AWS Budgets alert: a cascade or a stolen key shows up first on the bill")
    return out


STREAMS = {"aws": aws_rules}
COMING = {"azure": "cloud/azure/README.md", "gcp": "cloud/gcp/README.md"}


def check(stream: str, path: pathlib.Path) -> dict:
    d = json.loads(path.read_text(encoding="utf-8"))
    if d.get("stream", stream) != stream:
        raise SystemExit(f"{path} says stream {d.get('stream')!r}, not {stream!r}")
    findings = [{"id": i, "severity": s, "lesson": lsn, "message": m} for i, s, lsn, m in STREAMS[stream](d)]
    count = {s: sum(1 for f in findings if f["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW")}
    return {"stream": stream, "file": str(path), "findings": findings, "count": count, "passed": count["HIGH"] == 0,
            "merit": count["HIGH"] == 0 and count["MEDIUM"] == 0}


def stream_from_repo(repo: pathlib.Path) -> str:
    p = repo / "capstone.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8")).get("stream", "aws")
    return "aws"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?")
    ap.add_argument("--stream", choices=sorted(set(STREAMS) | set(COMING)))
    ap.add_argument("--repo", default=str(REPO))
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    repo = pathlib.Path(a.repo).resolve()
    stream = a.stream or stream_from_repo(repo)
    if stream in COMING:
        print(f"The {stream} stream checks are not released yet ({COMING[stream]}). Use --stream aws for now.")
        return 3
    path = pathlib.Path(a.file) if a.file else repo / "cloud" / stream / "deployment.json"
    r = check(stream, path)
    for f in r["findings"]:
        print(f"[{f['severity']:<6}] {f['id']} ({f['lesson']}) {f['message']}")
    c = r["count"]
    print(f"\n{stream}: {c['HIGH']} HIGH, {c['MEDIUM']} MEDIUM, {c['LOW']} LOW -> "
          f"{'PASS' if r['passed'] else 'FAIL'} (pass = no HIGH; merit = no HIGH and no MEDIUM)")
    if a.json:
        pathlib.Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.json).write_text(json.dumps(r, indent=2) + "\n", encoding="utf-8")
    return 0 if r["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
