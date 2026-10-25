"""alerts.py: the starting alert thresholds from lesson 27.2, run over the generated logs.

    python3 alerts.py                  # replay the hardened config, write its logs, then alert on them
    python3 alerts.py first-draft      # the same for the first draft (most of its logs are switched off)
    python3 alerts.py --morning        # also scan data/morning-resolver-log.jsonl (challenge 2) and
                                       # data/app-sessions.jsonl (challenge 3)

Thresholds (starting points; tune them on a week of ALERT-mode data):
  PAGE    any VpceAccessDenied in CloudTrail network activity events
  PAGE    any ACCEPT flow from the sandbox to an address that is not an endpoint or the proxy
  PAGE    5 or more distinct blocked names from one source address within 10 minutes   (challenge 2)
  TICKET  each DNS firewall BLOCK, each proxy deny, each SERVFAIL from a fail-closed firewall
  FINDING one Code Interpreter session ID used by more than one signed-in user          (challenge 3)
"""

from __future__ import annotations

import sys
from datetime import datetime

import lab
import logs

ALLOWED_DST = {logs.DST["endpoint"], logs.DST["proxy"]}


def ts(t: str) -> float:
    return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()


def alerts_for(recs: dict) -> list[tuple[str, str, str]]:
    out = []
    for r in recs["cloudtrail-network.jsonl"]:
        if r.get("errorCode") == "VpceAccessDenied":
            out.append(("PAGE", "vpce-denied", f"{r['eventTime']} {r['eventSource']} {r['eventName']} via {r['vpcEndpointId']}"))
    for line in recs["flow-log.txt"]:
        f = line.split()
        if f[12] == "ACCEPT" and f[4] not in ALLOWED_DST:
            out.append(("PAGE", "unexpected-accept", f"dstaddr={f[4]} dstport={f[6]}: a route exists that shouldn't"))
    for r in recs["resolver-query-log.jsonl"]:
        if r.get("firewall_rule_action") == "BLOCK":
            out.append(("TICKET", "dns-block", f"{r['query_timestamp']} {r['srcaddr']} {r['query_name']}"))
        elif r["rcode"] == "SERVFAIL":
            out.append(("TICKET", "dns-servfail", f"{r['query_timestamp']} {r['query_name']}: firewall did not answer, failed closed"))
    for r in recs["proxy-log.jsonl"]:
        if r["decision"] == "deny":
            out.append(("TICKET", "proxy-deny", f"{r['time']} {r['method']} {r['host']}"))
    return out


def burst_of_blocked_names(rows: list[dict]) -> list[dict]:
    """CHALLENGE 2 (lesson 27.2): sources with 5 or more DISTINCT blocked names inside any 10-minute window.

    rows are Route 53 Resolver query log records. A blocked query has firewall_rule_action == "BLOCK". Group by
    srcaddr (one sandbox), and for each source find the window of 600 seconds or less that holds the most distinct
    query_name values. Return one dict per source that reaches 5:
        {"srcaddr": ..., "distinct_blocked": <the most in one window>, "first_time": <query_timestamp of the
         first blocked query in that window>}
    sorted by first_time. The same name repeated is one name (a retry loop is a ticket, not a page), and five names
    spread over an hour is not a burst. Replace the line below.
    """
    return []


def shared_sessions(rows: list[dict]) -> list[dict]:
    """CHALLENGE 3 (lesson 27.1): Code Interpreter session IDs used by more than one signed-in user.

    rows are your app's session log (data/app-sessions.jsonl: time, user, session_id, event). Return
        [{"session_id": ..., "users": [<sorted user names>]}]
    sorted by session_id, for every session_id that appears with two or more different users. Replace the line below.
    """
    return []


def main(argv: list[str]) -> int:
    names = [a for a in argv[1:] if not a.startswith("--")]
    name = names[0] if names else "hardened"
    recs = logs.write(name)
    print(f"Alerts on the logs of {name}:")
    found = alerts_for(recs)
    if "--morning" in argv:
        for b in burst_of_blocked_names(lab.read_jsonl(lab.DATA / "morning-resolver-log.jsonl")):
            found.append(("PAGE", "dns-burst", f"{b['srcaddr']} {b['distinct_blocked']} distinct blocked names from {b['first_time']}"))
        for s in shared_sessions(lab.read_jsonl(lab.DATA / "app-sessions.jsonl")):
            found.append(("FINDING", "shared-session", f"{s['session_id']} used by {', '.join(s['users'])}"))
    for level, kind, text in found:
        print(f"  {level:7} {kind:18} {text}")
    pages = sum(1 for f in found if f[0] == "PAGE")
    tickets = sum(1 for f in found if f[0] == "TICKET")
    findings = sum(1 for f in found if f[0] == "FINDING")
    print(f"{pages} pages, {tickets} tickets" + (f", {findings} findings" if "--morning" in argv else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
