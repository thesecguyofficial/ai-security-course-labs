"""logs.py: what each replayed request would leave in the logs (lesson 27.2, "Spot it").

    python3 logs.py hardened        # writes state/<config>/*.jsonl and prints a short view
    python3 logs.py first-draft     # the first draft has most logs switched off: see what's missing

The records use the field names from the providers' documentation; the values are illustrative (placeholder
account, addresses and IDs). Only the doors a config actually logs produce records:

  resolver-query-log.jsonl   Route 53 Resolver query logs (query_name, srcaddr, rcode, firewall_rule_action ...)
  flow-log.txt               VPC Flow Logs, default version 2 format (... dstaddr ... dstport ... action log-status)
  cloudtrail-network.jsonl   CloudTrail network activity events (eventCategory NetworkActivity, VpceAccessDenied)
  proxy-log.jsonl            the forward proxy's own decisions (this lab's format)

Two documented gaps are modelled on purpose: flow logs never contain DNS lookups to the Amazon DNS server, and a
request the resolver refused never reaches the network, so it has no flow record at all.
"""

from __future__ import annotations

import sys
from datetime import datetime

import lab
from egress import Decision, replay

DNS_FW_GROUP = "rslvr-frg-0lab000000000001"
DNS_FW_LIST = "rslvr-fdl-0lab000000000001"
VPCE = {"s3": "vpce-0lab00000000000s3", "bedrock-runtime": "vpce-0lab0000000000bdr"}
EVENT_SOURCE = {"s3": "s3.amazonaws.com", "bedrock-runtime": "bedrock.amazonaws.com"}
DST = {"internet": "198.51.100.7", "proxy": lab.PROXY_IP, "endpoint": "10.0.3.40"}


def epoch(t: str) -> int:
    return int(datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp())


def resolver_record(r: dict, name: str, v) -> dict:
    rec = {
        "version": "1.1", "account_id": lab.ACCOUNT, "region": lab.REGION, "vpc_id": lab.VPC_ID,
        "query_timestamp": r["t"], "query_name": name + ".", "query_type": "A", "query_class": "IN",
        "rcode": "NOERROR", "answer_type": "", "rdata": "", "answer_class": "",
        "srcaddr": lab.SANDBOX_IP, "srcport": "40412", "transport": "UDP", "srcids": {"instance": lab.ENI},
    }
    if v.allow:
        rec.update(answer_type="A", rdata="10.0.3.40", answer_class="IN")
    elif "SERVFAIL" in v.reason:
        rec["rcode"] = "SERVFAIL"
    else:
        # A BLOCK rule with the NODATA response: the name exists, no answer. The firewall_* fields are filled
        # only when an alert or block rule matched.
        rec.update(firewall_rule_group_id=DNS_FW_GROUP, firewall_rule_action="BLOCK",
                   firewall_domain_list_id=DNS_FW_LIST)
    return rec


def flow_line(r: dict, dst_kind: str, port: int, accept: bool) -> str:
    start = epoch(r["t"])
    fields = ["2", lab.ACCOUNT, lab.ENI, lab.SANDBOX_IP, DST[dst_kind], "40420", str(port), "6",
              "3" if accept else "1", "180" if accept else "60", str(start), str(start + 60),
              "ACCEPT" if accept else "REJECT", "OK"]
    return " ".join(fields)


def cloudtrail_record(r: dict) -> dict:
    return {
        "eventVersion": "1.09", "eventTime": r["t"], "eventCategory": "NetworkActivity",
        "eventSource": EVENT_SOURCE[r["service"]], "eventName": r["action"].split(":")[1],
        "awsRegion": lab.REGION, "sourceIPAddress": lab.SANDBOX_IP,
        "errorCode": "VpceAccessDenied", "errorMessage": "The request was denied due to a VPC endpoint policy",
        "vpcEndpointId": VPCE[r["service"]], "vpcEndpointAccountId": lab.ACCOUNT,
        "resources": [{"ARN": r["resource"]}], "recipientAccountId": lab.ACCOUNT,
    }


def records(config: dict, decisions: list[Decision]) -> dict:
    lg = config["logging"]
    out = {"resolver-query-log.jsonl": [], "flow-log.txt": [], "cloudtrail-network.jsonl": [], "proxy-log.jsonl": []}
    for d in decisions:
        r = d.request
        by = {v.layer: v for v in d.verdicts}
        if "dns" in by and lg.get("dns_query_logs"):
            name = "proxy.tsg.example" if r.get("via") == "proxy" else r["name"]
            out["resolver-query-log.jsonl"].append(resolver_record(r, name, by["dns"]))
        if "dns" in by and not by["dns"].allow:
            continue  # no answer, so no connection was attempted: nothing in flow logs, proxy or CloudTrail
        if "sg" in by and lg.get("flow_logs"):
            kind = "proxy" if r.get("via") == "proxy" else ("endpoint" if r["kind"] == "aws_api" else "internet")
            if kind == "internet" and "route" in by and not by["route"].allow and by["sg"].allow:
                pass  # no route: the packet never leaves, and there is nothing to accept
            else:
                out["flow-log.txt"].append(flow_line(r, kind, r["port"] if kind != "proxy" else 3128, by["sg"].allow))
        if "sg" in by and not by["sg"].allow:
            continue
        if "proxy" in by:
            out["proxy-log.jsonl"].append({"time": r["t"], "src": lab.SANDBOX_IP, "method": r.get("method", "GET"),
                                           "host": r["name"], "decision": "allow" if by["proxy"].allow else "deny",
                                           "reason": by["proxy"].reason})
        if "endpoint" in by and not by["endpoint"].allow \
                and EVENT_SOURCE[r["service"]] in lg.get("cloudtrail_network_activity", []):
            out["cloudtrail-network.jsonl"].append(cloudtrail_record(r))
    return out


def write(config_name: str) -> dict:
    cfg = lab.load_config(config_name)
    recs = records(cfg, replay(config_name))
    d = lab.state_dir() / config_name
    d.mkdir(parents=True, exist_ok=True)
    for fname, rows in recs.items():
        if fname.endswith(".txt"):
            header = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
            (d / fname).write_text(header + "".join(line + "\n" for line in rows))
        else:
            lab.write_jsonl(d / fname, rows)
    return recs


def main(argv: list[str]) -> int:
    name = argv[1] if len(argv) > 1 else "hardened"
    recs = write(name)
    print(f"Logs for {name} (illustrative values, documented field names) in state/{name}/")
    for fname, rows in recs.items():
        print(f"  {fname:26} {len(rows):2} records")
    for rec in recs["resolver-query-log.jsonl"]:
        if rec.get("firewall_rule_action") or rec["rcode"] != "NOERROR":
            print(f"    dns    {rec['query_timestamp']} {rec['query_name']:32} rcode={rec['rcode']:8} "
                  f"firewall_rule_action={rec.get('firewall_rule_action', '-')}")
    for line in recs["flow-log.txt"]:
        f = line.split()
        if f[12] == "REJECT":
            print(f"    flow   dstaddr={f[4]} dstport={f[6]} action={f[12]}")
    for rec in recs["cloudtrail-network.jsonl"]:
        print(f"    trail  {rec['eventTime']} {rec['eventSource']} {rec['eventName']} errorCode={rec['errorCode']} "
              f"vpcEndpointId={rec['vpcEndpointId']}")
    for rec in recs["proxy-log.jsonl"]:
        if rec["decision"] == "deny":
            print(f"    proxy  {rec['time']} {rec['method']} {rec['host']} deny")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
