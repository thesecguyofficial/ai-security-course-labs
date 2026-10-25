#!/usr/bin/env python3
"""Review the Helpdesk's cloud deployment description for your stream. Offline, $0, no cloud account needed.

    python3 cloud/cloud_check.py                         # the stream named in capstone.json (make cloud)
    python3 cloud/cloud_check.py --stream aws cloud/aws/deployment.json
    python3 cloud/cloud_check.py --json results/cloud.json

Pass mark (self-check C1): no HIGH findings. Rubric merit: no MEDIUM findings either.
Each rule names the lesson that teaches the real setting. A key you delete counts as the insecure default:
removing a setting never makes a finding go away.

Streams: aws is available now. azure and gcp ship with their streams (cloud/azure/README.md, cloud/gcp/README.md).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent


def _get(d: dict, path: str, default=None):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def aws_rules(d: dict) -> list[tuple[str, str, str, str]]:
    """(id, severity, lesson, message) for every problem found."""
    out = []

    def add(rid, sev, lesson, msg):
        out.append((rid, sev, lesson, msg))

    stmts = _get(d, "app_role.statements", []) or []
    for s in stmts:
        if s.get("effect", "Allow") != "Allow":
            continue
        acts, res = s.get("actions", []), s.get("resources", [])
        if any(a in ("*", "bedrock:*") for a in acts) or "*" in res:
            add("AWS-01", "HIGH", "10.3, 11.1",
                "the app role allows bedrock:* or Resource '*': grant only the invoke actions it uses, on the model "
                "or inference profile ARNs it uses")
            break
    if not stmts:
        add("AWS-01", "HIGH", "10.3", "the app role has no statements listed: describe what it is allowed to do")
    models = _get(d, "model_access.allowed_models", ["*"]) or ["*"]
    if "*" in models:
        add("AWS-02", "MEDIUM", "10.3", "every foundation model is allowed: allow-list the one or two the Helpdesk uses")
    for k in _get(d, "bedrock_api_keys", []) or []:
        if k.get("type") == "long-term":
            add("AWS-03", "HIGH", "10.4",
                f"long-term Bedrock API key {k.get('name', '?')!r}: delete it; use the app role (or short-term keys)")
    if not _get(d, "invocation_logging.enabled", False):
        add("AWS-04", "HIGH", "11.4, 16.1", "model invocation logging is off: nobody can tell what was asked or answered")
    elif not _get(d, "invocation_logging.kms_key"):
        add("AWS-04", "MEDIUM", "11.4", "invocation logs hold prompts and answers: encrypt them with your own KMS key")
    data_events = [str(x).lower() for x in (_get(d, "cloudtrail.data_events", []) or [])]
    if not any("knowledgebase" in x or "knowledge-base" in x or "bedrock" in x for x in data_events):
        add("AWS-05", "MEDIUM", "16.1",
            "no CloudTrail data events for Bedrock: knowledge base Retrieve and AgentCore runtime calls go unrecorded")
    if not _get(d, "guardrail.attached", False) or _get(d, "guardrail.prompt_attack_filter", "NONE") in ("NONE", None):
        add("AWS-06", "HIGH", "12.1", "no guardrail with a prompt attack filter on the Helpdesk's model calls")
    if not _get(d, "guardrail.enforced_with_iam_condition", False) or not _get(d, "app_role.condition_guardrail_identifier"):
        add("AWS-07", "HIGH", "12.3",
            "nothing forces the guardrail: add the bedrock:GuardrailIdentifier condition to the app role")
    if not _get(d, "knowledge_base.retrieve_filter") or not _get(d, "knowledge_base.documents_carry_tenant_metadata", False):
        add("AWS-08", "HIGH", "13.1",
            "Retrieve runs without a per-tenant metadata filter set by the backend: the M6 cross-tenant leak comes back")
    groups = _get(d, "agent.action_groups", []) or []
    if not any(g.get("function") == "send_email" for g in groups):
        add("AWS-09", "HIGH", "13.2", "the agent's action groups are not described: list send_email and its confirmation setting")
    for g in _get(d, "agent.action_groups", []) or []:
        if g.get("function") == "send_email" and g.get("requireConfirmation") != "ENABLED":
            add("AWS-09", "HIGH", "13.2", "send_email runs without requireConfirmation: ENABLED (or your own approval step)")
    if _get(d, "agentcore_gateway.authorizer_type", "NONE") in ("NONE", None):
        add("AWS-10", "HIGH", "14.4", "the AgentCore gateway has no inbound authorizer")
    elif not _get(d, "agentcore_gateway.allowed_clients"):
        add("AWS-10", "HIGH", "14.3", "the gateway's JWT authorizer has no allowedClients: tokens from any app are accepted")
    if _get(d, "agentcore_gateway.policy_engine_mode", "LOG_ONLY") != "ENFORCE":
        add("AWS-11", "HIGH", "14.5", "the policy engine is not in ENFORCE: in LOG_ONLY every tool call goes through")
    if not _get(d, "agentcore_gateway.mcp_targets"):
        add("AWS-12", "MEDIUM", "8.5, 14.4", "the gateway's MCP targets are not described: list crm and how its tools are reviewed")
    for t in _get(d, "agentcore_gateway.mcp_targets", []) or []:
        if t.get("tool_review") in (None, "none"):
            add("AWS-12", "MEDIUM", "8.5, 14.4",
                f"MCP target {t.get('name', '?')!r}: tool descriptions are not reviewed or pinned before release")
    if _get(d, "secrets.system_prompt_contains_secret", True):
        add("AWS-13", "HIGH", "3.7", "a secret sits in the system prompt: assume every user can read the prompt")
    if _get(d, "secrets.plaintext_env_secrets", []):
        add("AWS-13", "HIGH", "11.3", "plaintext secrets in environment variables: use Secrets Manager and the role")
    if not (_get(d, "detection.guardduty_enabled", False) and _get(d, "detection.guardduty_ai_protection", False)):
        add("AWS-14", "MEDIUM", "16.2", "GuardDuty AI Protection is off")
    elif "severity" in str(_get(d, "detection.alert_routing", "")):
        add("AWS-14", "MEDIUM", "16.2", "AI findings are routed by severity: all three default to Low, route them by type")
    if not _get(d, "budget.monthly_limit_usd") or not _get(d, "budget.alert_email_set", False):
        add("AWS-15", "MEDIUM", "0.7, 10.5", "no AWS Budgets alert: a stolen key or a loop shows up first on the bill")
    if not _get(d, "network.bedrock_runtime_vpc_endpoint", False):
        add("AWS-16", "LOW", "11.2", "model calls leave over the public endpoint: add an interface VPC endpoint")
    elif not _get(d, "network.endpoint_policy_restricted", False):
        add("AWS-16", "LOW", "11.2", "the bedrock-runtime endpoint policy allows everything")
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
