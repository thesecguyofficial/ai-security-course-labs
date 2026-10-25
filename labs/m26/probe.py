"""
probe.py: knock on every path of the practice server, without a key and with one (lessons 26.0 and 26.1).

    python3 probe.py first-draft     # no login anywhere
    python3 probe.py key-only        # vLLM's --api-key on its own: the /v1 paths are locked, the rest are not
    python3 probe.py hardened        # the gateway: a key on every path, only allow-listed paths exist

It starts practice_server.py on 127.0.0.1 itself and probes only that. It refuses any target that is not a
loopback address: this is a lab tool for your own laptop, not a scanner for other people's servers.
"""

import ipaddress
import json
import sys
import urllib.error
import urllib.request

import practice_server

KINDS_THAT_MATTER = ("management", "ops", "dev", "info")


def require_loopback(host):
    if not ipaddress.ip_address(host).is_loopback:
        raise SystemExit(f"refused: {host} is not a loopback address. Probe only the lab's own practice server.")


def call(host, port, method, path, key=None):
    require_loopback(host)
    data = b"{}" if method in ("POST", "DELETE") else None
    req = urllib.request.Request(f"http://{host}:{port}{path}", data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def probe(profile, host="127.0.0.1"):
    require_loopback(host)
    server, port = practice_server.start(profile)
    try:
        rows = []
        for path, (method, kind, _) in practice_server.ROUTES.items():
            rows.append({"path": path, "method": method, "kind": kind,
                         "no_key": call(host, port, method, path),
                         "with_key": call(host, port, method, path, practice_server.LAB_KEY)})
        return rows
    finally:
        server.shutdown()


def report(profile, rows):
    print(f"Probe of the practice server, profile {profile} (127.0.0.1 only)")
    print(f"  {'method':<7}{'path':<22}{'kind':<12}{'no key':>7}{'key':>6}")
    for r in rows:
        flag = "  <- open" if r["no_key"] == 200 and r["kind"] in KINDS_THAT_MATTER else ""
        print(f"  {r['method']:<7}{r['path']:<22}{r['kind']:<12}{r['no_key']:>7}{r['with_key']:>6}{flag}")
    open_paths = [r for r in rows if r["no_key"] == 200]
    risky = [r for r in open_paths if r["kind"] in KINDS_THAT_MATTER]
    with_key = [r for r in rows if r["with_key"] == 200]
    print(f"Reachable without a key: {len(open_paths)} of {len(rows)} paths "
          f"({len(risky)} management, ops, dev or info) | with a key: {len(with_key)} of {len(rows)}")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    prof = args[0] if args else "first-draft"
    for a in sys.argv[1:]:
        if a.startswith("--target="):
            require_loopback(a.split("=", 1)[1])
    result = probe(prof)
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        report(prof, result)
