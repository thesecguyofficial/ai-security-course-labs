"""
dryrun_report.py: read a week of VPC Service Controls DRY RUN entries and decide whether you can enforce.

    python3 dryrun_report.py                               # make dryrun-report (logs/vpcsc-dryrun-week.jsonl)
    python3 dryrun_report.py --file my-export.jsonl        # your own Policy Denied export, one JSON entry per line

Dry run entries are Policy Denied audit log entries (log name ending cloudaudit.googleapis.com%2Fpolicy) whose
protoPayload.metadata has @type VpcServiceControlAuditMetadata and dryRun = true. Export yours with:
  gcloud logging read 'log_id("cloudaudit.googleapis.com/policy") AND
    protoPayload.metadata."@type"="type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"' \
      --freshness=7d --format=json > my-export.json
(gcloud prints a JSON array; this script accepts that too, and keeps only the dry-run entries.)
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
META_TYPE = "type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"


def load(path: pathlib.Path) -> list[dict]:
    text = path.read_text().strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def dry_run_entries(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        meta = r.get("protoPayload", {}).get("metadata", {})
        if meta.get("@type") == META_TYPE and meta.get("dryRun") in (True, "true", "True"):
            out.append(r)
    return out


def summarise(rows: list[dict]):
    groups = collections.OrderedDict()
    for r in rows:
        pp = r["protoPayload"]
        meta = pp["metadata"]
        key = (pp["authenticationInfo"]["principalEmail"], pp["requestMetadata"]["callerIp"], pp["serviceName"],
               pp["methodName"].rsplit(".", 1)[-1], meta.get("violationReason", "?"))
        g = groups.setdefault(key, {"count": 0, "first": r["timestamp"], "last": r["timestamp"]})
        g["count"] += 1
        g["last"] = r["timestamp"]
    return groups


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default=str(HERE / "logs" / "vpcsc-dryrun-week.jsonl"))
    args = ap.parse_args(argv)
    rows = dry_run_entries(load(pathlib.Path(args.file)))
    groups = summarise(rows)
    print(f"--- VPC Service Controls dry run · {len(rows)} would-be denials in {pathlib.Path(args.file).name} ---\n")
    print(f"  {'count':>5}  {'principal':<60} {'caller IP':<15} {'method':<15} reason")
    for (who, ip, svc, method, reason), g in sorted(groups.items(), key=lambda kv: -kv[1]["count"]):
        print(f"  {g['count']:>5}  {who:<60} {ip:<15} {method:<15} {reason}")
    callers = len(groups)
    print(f"\n{callers} distinct caller/method/reason groups. Before you enforce, label each one: legitimate "
          "(write an ingress or egress rule for it) or not (let the perimeter block it).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
