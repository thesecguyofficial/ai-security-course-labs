"""
hunt.py: three questions a guardrail's own logs can answer (lesson 12.4). `make hunt`

Reads logs/helpdesk-guardrail-log.jsonl: helpdesk-web's log of every model call on 20 Oct 2026 (FICTIONAL), with
the HTTP status, finish_reason and the categories the guardrail flagged (taken from content_filter_results), and
logs/metrics-rai.json: the Foundry metric Blocked Volume (RAIRejectedRequests) in 5-minute buckets.

  H1  probing:   one caller blocked for prompt attacks 5+ times in 15 minutes
  H2  bypass:    a request from that caller that was NOT blocked shortly after, carrying invisible characters
  H3  too late:  outputs stopped by the filter after text had already streamed (mode Asynchronous_filter)
Plus a metric view: 5-minute buckets of Blocked Volume above a threshold (what an alert rule would fire on).

Remember the logs themselves: prompt previews are personal data and attack text. Keep them in a restricted workspace.
"""

import json
import os
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))


def load_rows():
    with open(os.path.join(HERE, "logs", "helpdesk-guardrail-log.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def ts(r):
    return datetime.fromisoformat(r["time"].replace("Z", "+00:00"))


def probing(rows, n=5, window=timedelta(minutes=15)):
    found = {}
    for r in rows:
        if r["http_status"] == 400 and any(f.startswith("jailbreak") for f in r["flagged"]):
            same = [x for x in rows if x["caller"] == r["caller"] and x["http_status"] == 400
                    and any(f.startswith("jailbreak") for f in x["flagged"]) and timedelta(0) <= ts(x) - ts(r) <= window]
            if len(same) >= n:
                found.setdefault(r["caller"], same)
    return found


def bypasses(rows, probers, after=timedelta(minutes=30)):
    out = []
    for caller, hits in probers.items():
        last = max(ts(h) for h in hits)
        out += [r for r in rows if r["caller"] == caller and r["http_status"] == 200 and r["finish_reason"] == "stop"
                and timedelta(0) <= ts(r) - last <= after and r["invisible_chars"] > 0]
    return out


def too_late(rows):
    return [r for r in rows if r["finish_reason"] == "content_filter" and r["chars_streamed_before_filter"] > 0]


def metric_spikes(threshold=4):
    with open(os.path.join(HERE, "logs", "metrics-rai.json"), encoding="utf-8") as f:
        rows = json.load(f)["rows"]
    per = {}
    for r in rows:
        per[r["timeGenerated"]] = per.get(r["timeGenerated"], 0) + r["total"]
    return {t: n for t, n in sorted(per.items()) if n > threshold}


def main():
    rows = load_rows()
    print(f"{len(rows)} model calls from helpdesk-web on 2026-10-20\n")
    p = probing(rows)
    print("H1 probing (5+ prompt-attack blocks in 15 minutes):")
    for caller, hits in p.items():
        print(f"   {caller} from {hits[0]['client_ip']}: {len(hits)} blocks between {hits[0]['time'][11:19]} and {hits[-1]['time'][11:19]}")
    b = bypasses(rows, p)
    print("\nH2 likely bypass (same caller, not blocked, invisible characters in the prompt):")
    for r in b:
        print(f"   {r['time'][11:19]} {r['caller']} status {r['http_status']} finish_reason {r['finish_reason']}, "
              f"{r['invisible_chars']} invisible characters: {r['prompt_preview'].encode('unicode_escape').decode()[:70]}...")
    t = too_late(rows)
    print("\nH3 filtered after streaming (Asynchronous_filter):")
    for r in t:
        print(f"   {r['time'][11:19]} {r['caller']}: {', '.join(r['flagged'])}, {r['chars_streamed_before_filter']} characters already shown")
    s = metric_spikes()
    print("\nBlocked Volume (RAIRejectedRequests) above 4 per 5 minutes:")
    for k, v in s.items():
        print(f"   {k}: {v}")
    print(f"\n{len(p)} prober, {len(b)} likely bypass, {len(t)} late filters, {len(s)} metric spikes")


if __name__ == "__main__":
    main()
