"""
hunt.py: an investigator's questions over a morning of gateway logs (lessons 26.0 and 26.1).

    python3 hunt.py                         # data/gateway-log.jsonl, the first-draft gateway on 21 Oct 2026
    python3 hunt.py --file other.jsonl

Each log line has: ts, src_ip, method, path, status, auth ("ok" or "none"), tenant. Addresses 203.0.113.x and
198.51.100.x are documentation addresses (RFC 5737): they stand in for the internet.
"""

import ipaddress
import json
import pathlib
import sys
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
MANAGEMENT_PATHS = {"/api/pull", "/api/push", "/api/delete", "/api/create", "/api/copy",
                    "/update_weights", "/pause", "/resume", "/collective_rpc", "/sleep"}
INFO_PATHS = {"/version", "/api/version", "/metrics", "/api/tags", "/v1/models", "/tokenize"}


def load(path):
    return [json.loads(line) for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def config():
    return json.loads((HERE / "data" / "deploy-sources.json").read_text(encoding="utf-8"))


def is_internal(ip, networks):
    return any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in networks)


def unauthenticated_by_path(records):
    """Q1: successful requests that carried no key, counted per path (health checks excluded)."""
    return Counter(r["path"] for r in records if r["auth"] == "none" and r["status"] == 200 and r["path"] != "/health")


def outside_info_probes(records, networks):
    """Q2: which outside addresses asked the server what it is (version, model list, metrics)?"""
    hits = {}
    for r in records:
        if r["path"] in INFO_PATHS and not is_internal(r["src_ip"], networks):
            hits.setdefault(r["src_ip"], []).append(r["path"])
    return hits


def find_management_calls(records, deploy_sources):
    """CHALLENGE 3 (lessons 26.0 and 26.1): management calls from anywhere except the deployment pipeline.

    Return a list of (ts, src_ip, path) tuples, in log order, for every request to a path in MANAGEMENT_PATHS whose
    src_ip is not in deploy_sources. Count it whatever the status was: an attempt matters as much as a success.
    """
    raise NotImplementedError("challenge 3: write find_management_calls()")


def main(argv):
    path = HERE / "data" / "gateway-log.jsonl"
    if "--file" in argv:
        path = pathlib.Path(argv[argv.index("--file") + 1])
    records, cfg = load(path), config()
    print(f"Hunt over {len(records)} gateway log lines ({path.name})")
    print("Q1  successful requests with no key, per path:")
    for p, n in unauthenticated_by_path(records).most_common():
        print(f"      {n:>3}  {p}")
    print("Q2  outside addresses asking what the server is:")
    for ip, paths in outside_info_probes(records, cfg["internal_networks"]).items():
        print(f"      {ip:<15} {', '.join(paths)}")
    print("Q3  management calls not from the deployment pipeline:")
    try:
        for ts, ip, p in find_management_calls(records, set(cfg["deploy_sources"])):
            print(f"      {ts}  {ip:<15} {p}")
    except NotImplementedError as e:
        print(f"      (not written yet: {e})")


if __name__ == "__main__":
    main(sys.argv[1:])
