"""
aws/attribution.py: prove in CloudTrail which agent acted, and for which human (lesson 20.5).

    python3 aws/attribution.py                                 # make aws-hunt: the lab's sample morning
    python3 aws/attribution.py --cloudtrail-dir ~/tsg-trail     # your own trail files from the guided build

Reads CloudTrail records (JSON lines, or the trail's own *.json.gz files with a "Records" list) and the launcher's
log (who the validated JWT said the user was, for each run). The sample files are ILLUSTRATIVE: real field names,
made-up values (aws/make_samples.py).

Q1  For each human, which agents acted, under which IAM role and workload identity?
Q2  Which agent calls carry no human at all (no SourceIdentity on the role session)?
Q3  Which runs claim a different human than the validated JWT did?
Q4  Which workload identities are used by more than one IAM role?
"""

from __future__ import annotations

import argparse
import collections
import gzip
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
AGENT_ROLE_PREFIX = "tsg-agent-"
LAUNCHER_ROLE = "tsg-agent-launcher"


def load_cloudtrail(path: pathlib.Path) -> list[dict]:
    rows = []
    files = sorted(path.rglob("*.json.gz")) + sorted(path.rglob("*.jsonl")) if path.is_dir() else [path]
    for f in files:
        text = gzip.open(f, "rt").read() if f.suffix == ".gz" else f.read_text()
        if text.lstrip().startswith("{\"Records\""):
            rows += json.loads(text)["Records"]
        else:
            rows += [json.loads(line) for line in text.splitlines() if line.strip()]
    return sorted(rows, key=lambda r: r["eventTime"])


def load_jsonl(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def role_and_session(record: dict) -> tuple[str, str]:
    arn = record.get("userIdentity", {}).get("arn", "")
    parts = arn.split(":assumed-role/")[-1].split("/") if ":assumed-role/" in arn else ["", ""]
    return parts[0], parts[1] if len(parts) > 1 else ""


def workload_of(record: dict) -> str | None:
    if record.get("requestParameters", {}).get("workloadName"):
        return record["requestParameters"]["workloadName"]
    for res in record.get("resources", []):
        if "/workload-identity/" in res.get("ARN", ""):
            return res["ARN"].rsplit("/", 1)[1]
    return None


def agent_calls(records):
    for r in records:
        role, session = role_and_session(r)
        if r.get("eventSource") == "bedrock-agentcore.amazonaws.com" and role.startswith(AGENT_ROLE_PREFIX) \
                and role != LAUNCHER_ROLE:
            yield r, role, session


def q1_by_human(records) -> dict[str, list[dict]]:
    out = collections.defaultdict(list)
    identity_of_session = {}
    for r, role, session in agent_calls(records):
        # Vault calls carry the workload access token, not the name: reuse the identity the session got it for.
        wi = workload_of(r) or identity_of_session.get(session)
        identity_of_session[session] = wi
        human = r["userIdentity"].get("sessionContext", {}).get("sourceIdentity")
        if human:
            out[human].append({"time": r["eventTime"], "role": role, "session": session, "event": r["eventName"],
                               "workload_identity": wi})
    return dict(out)


def q2_no_human(records) -> list[dict]:
    return [{"time": r["eventTime"], "role": role, "session": session, "event": r["eventName"]}
            for r, role, session in agent_calls(records)
            if not r["userIdentity"].get("sessionContext", {}).get("sourceIdentity")]


def q3_mismatch(records, app_log) -> list[dict]:
    claimed = {r["requestParameters"]["roleSessionName"]: r["requestParameters"].get("sourceIdentity")
               for r in records if r.get("eventName") == "AssumeRole"}
    out = []
    for row in app_log:
        si = claimed.get(row["run_id"])
        if si and si != "user-" + row["jwt_sub"]:
            out.append({"run": row["run_id"], "agent": row["agent"], "jwt_user": row["jwt_sub"], "session_says": si})
    return out


def q4_shared_identity(records, app_log) -> dict[str, list[str]]:
    """Workload identity -> the agents (from the launcher log, by run) that used it, when more than one."""
    agent_of_run = {row["run_id"]: row["agent"] for row in app_log}
    agents = collections.defaultdict(set)
    for r, role, session in agent_calls(records):
        wi = workload_of(r)
        if wi and session in agent_of_run:
            agents[wi].add(agent_of_run[session])
    return {wi: sorted(a) for wi, a in agents.items() if len(a) > 1}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cloudtrail-dir", type=pathlib.Path, default=HERE / "data" / "cloudtrail.jsonl")
    p.add_argument("--app-log", type=pathlib.Path, default=HERE / "data" / "app-log.jsonl")
    args = p.parse_args(argv)
    records = load_cloudtrail(args.cloudtrail_dir.expanduser())
    app_log = load_jsonl(args.app_log.expanduser())
    print(f"{len(records)} CloudTrail records, {len(app_log)} launcher log rows\n")
    print("Q1 who acted for whom (SourceIdentity on the agent's role session):")
    for human, calls in q1_by_human(records).items():
        print(f"   {human}")
        for c in calls:
            print(f"      {c['time']}  {c['role']:<24} identity {c['workload_identity'] or '-':<17} {c['event']}")
    print("Q2 agent calls with no human on the session:")
    for c in q2_no_human(records) or [{"time": "   (none)", "role": "", "session": "", "event": ""}]:
        print(f"   {c['time']}  {c['role']:<24} {c['session']:<16} {c['event']}")
    print("Q3 runs whose session names a different human than the validated JWT:")
    for m in q3_mismatch(records, app_log) or [{"run": "(none)", "agent": "", "jwt_user": "", "session_says": ""}]:
        print(f"   {m['run']:<20} {m['agent']:<8} JWT user {m['jwt_user']:<14} session says {m['session_says']}")
    print("Q4 workload identities shared by more than one agent:")
    shared = q4_shared_identity(records, app_log)
    for wi, agents in shared.items():
        print(f"   {wi}: used by the {' and '.join(agents)} agents")
    if not shared:
        print("   (none)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
