"""
hunt.py: shadow AI discovery across the org (lesson 29.1).

    python3 hunt.py first-draft      # the management account's trail, InvokeModel only, the repo's current files
    python3 hunt.py hardened         # every account and Region, every inference event, DNS logs, repo history

Three sources, joined against the approved-AI register in data/org.json:
  1. CloudTrail: Bedrock inference events (InvokeModel, Converse, ... and CreateInference on bedrock-mantle, which is
     a DATA event), grouped by account, Region and model
  2. Route 53 Resolver query logs: which instances looked up an outside AI provider's API name
  3. Secret scanning: AI provider keys in the repos, in the current files or (hardened) anywhere in their history
Anything not in the register is a finding. The decoys we planted ourselves are reported as "decoy (expected)".
"""

from __future__ import annotations

import re
import sys

import detect
from lab import DATA, ORG, load_setup, read_json, read_jsonl

SECRET_PATTERNS = {
    # LAB placeholder formats only. Real scanners use the providers' own formats (GitHub lists them).
    "openai-style key": re.compile(r"tsglab-openai-[0-9a-f]{16}"),
    "anthropic-style key": re.compile(r"tsglab-anthropic-[0-9a-f]{16}"),
    "bedrock-api-key-style": re.compile(r"tsglab-bedrock-apikey-[A-Z0-9]+"),
    "aws-access-key-style": re.compile(r"TSGLAB[A-Z0-9]{14}"),
}
DECOY_STRINGS = {"TSGLABHONEYKEY000001", "tsglab-bedrock-apikey-DECOY0001"}


def model_of(rec: dict) -> str:
    p = rec.get("requestParameters") or {}
    return p.get("modelId") or p.get("model") or "?"


def registered_model(account: str, model: str) -> bool:
    return any(r["account"] == account and model in r["models"] for r in ORG["register"]["bedrock"])


def cloudtrail_findings(setup: dict, records: list[dict]) -> list[dict]:
    names, out, seen = set(setup["hunt"]["event_names"]), [], set()
    for rec in records:
        if not rec["eventSource"].startswith("bedrock") or rec["eventName"] not in names or rec["readOnly"]:
            continue
        if not detect.collected(setup, rec)[0]:
            continue
        acct, model = rec["recipientAccountId"], model_of(rec)
        if registered_model(acct, model):
            continue
        fid = f"bedrock:{acct}:{rec['awsRegion']}:{model}"
        if fid in seen:
            continue
        seen.add(fid)
        known = any(r["account"] == acct for r in ORG["register"]["bedrock"])
        who = rec["userIdentity"].get("userName") or rec["userIdentity"]["arn"].split("/")[-2]
        out.append({"id": fid, "kind": "unregistered model" if known else "unregistered account",
                    "where": f"{acct} ({ORG['accounts'][acct]}) {rec['awsRegion']}",
                    "detail": f"{rec['eventSource'].split('.')[0]}:{rec['eventName']} {model} by {who}"})
    return out


def dns_findings(setup: dict, rows: list[dict]) -> list[dict]:
    if "dns" not in setup["hunt"]["sources"]:
        return []
    approved = {(r["account"], r["domain"]) for r in ORG["register"]["external"]}
    out = []
    for r in rows:
        name = r["query_name"].rstrip(".")
        if name in ORG["ai_domains"] and (r["account_id"], name) not in approved:
            out.append({"id": f"external:{r['account_id']}:{name}", "kind": "outside AI API",
                        "where": f"{r['account_id']} ({ORG['accounts'][r['account_id']]}) {r['region']}",
                        "detail": f"{r['srcids'].get('instance', '?')} looked up {name}"})
    return out


def replay_repo(rows: list[dict]) -> dict[str, list[str]]:
    files = {}
    for r in rows:
        if r["op"] == "write":
            files[r["file"]] = r["lines"]
        elif r["op"] == "delete":
            files.pop(r["file"], None)
    return files


def secret_findings(setup: dict) -> tuple[list[dict], list[dict]]:
    if "secrets" not in setup["hunt"]["sources"]:
        return [], []
    found, decoys = [], []
    for path in sorted((DATA / "repos").glob("*.history.jsonl")):
        rows = read_jsonl(path)
        repo = rows[0]["repo"]
        if setup["hunt"]["scan_history"]:
            views = [(r["commit"], r["file"], r["lines"]) for r in rows if r["op"] == "write"]
        else:
            views = [("HEAD", f, lines) for f, lines in replay_repo(rows).items()]
        for commit, fname, lines in views:
            for line in lines:
                for kind, rx in SECRET_PATTERNS.items():
                    for m in rx.finditer(line):
                        hit = {"id": f"secret:{repo}:{fname}:{kind}", "kind": kind, "where": f"{repo}/{fname}",
                               "detail": f"commit {commit}"}
                        target = decoys if m.group(0) in DECOY_STRINGS else found
                        if hit["id"] not in {h["id"] for h in target}:
                            target.append(hit)
    return found, decoys


def run(setup: dict) -> dict:
    records = read_jsonl(DATA / "org-day" / "cloudtrail.jsonl")
    dns = read_jsonl(DATA / "org-day" / "resolver-query-logs.jsonl")
    secrets, decoys = secret_findings(setup)
    findings = cloudtrail_findings(setup, records) + dns_findings(setup, dns) + secrets
    return {"findings": findings, "decoys": decoys}


def find_new_models(records: list[dict], baseline: dict) -> list[dict]:
    """CHALLENGE (lesson 29.1): "Invoking Bedrock models that no one in the account uses is a red flag" (Sysdig).
    Return one row per (account, model) invoked in `records` (any Bedrock inference event, including bedrock-mantle
    CreateInference) that is NOT in that account's 30-day baseline: {"account", "model", "first_seen"} where
    first_seen is the earliest eventTime. Skip read-only events. Sort by account, then model.
    """
    return []  # TODO: your code here


def main(argv: list[str]) -> None:
    if len(argv) != 1:
        raise SystemExit(__doc__)
    setup = load_setup(argv[0])
    r = run(setup)
    print(f"setup {setup['name']} | sources {setup['hunt']['sources']} | accounts "
          f"{setup['collect']['accounts']} | Regions {setup['collect']['regions']}")
    for f in r["findings"]:
        print(f"  SHADOW  {f['kind']:<21} {f['where']:<44} {f['detail']}")
    for d in r["decoys"]:
        print(f"  decoy   {d['kind']:<21} {d['where']:<44} (planted by us, expected)")
    print(f"shadow AI found: {len(r['findings'])}")


if __name__ == "__main__":
    main(sys.argv[1:])
