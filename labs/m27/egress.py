"""egress.py: decide allow or deny for each recorded connection request, layer by layer (lesson 27.2).

    python3 egress.py first-draft          # replay data/requests.jsonl against one config
    python3 egress.py hardened
    python3 egress.py compare              # both, side by side, plus the summary line

This is a model of the controls, not a network stack: it reads a request description ("the agent asked to reach
this name, on this port, this way") and the config, and works out what each layer would do. Nothing is resolved,
connected or sent. Every layer gives its own verdict, so you can see defence in depth: a hardened config usually
denies the same request at more than one layer.

Layers, in the order traffic meets them:
  dns       the VPC resolver, with or without a DNS firewall (walled garden, fail closed or open)
  route     is there any path to the internet (network mode, NAT gateway)
  sg        the security group's egress rules (destination and port)
  proxy     the forward proxy's allow-list (host and method), when the request goes through it
  endpoint  the VPC endpoint policy, for AWS API calls over a private endpoint
  role      the execution role, which must also allow an AWS API call
"""

from __future__ import annotations

import fnmatch
import sys
from dataclasses import dataclass, field

import lab

PROXY_NAME = "proxy.tsg.example"
WEB_PORTS = (80, 443)


@dataclass
class Verdict:
    layer: str
    allow: bool
    reason: str


@dataclass
class Decision:
    request: dict
    verdicts: list[Verdict] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return all(v.allow for v in self.verdicts)

    @property
    def denied_by(self) -> list[str]:
        return [v.layer for v in self.verdicts if not v.allow]

    @property
    def first_denial(self) -> Verdict | None:
        return next((v for v in self.verdicts if not v.allow), None)


# ---------------------------------------------------------------- layers

def dns_layer(c: dict, name: str, firewall_unavailable: bool = False) -> Verdict:
    d = c["dns"]
    if not d.get("firewall"):
        return Verdict("dns", True, "no DNS firewall: the resolver answers for any name")
    if firewall_unavailable:
        if d.get("fail_open"):
            return Verdict("dns", True, "DNS firewall unavailable and fail_open is true: answered without a check")
        return Verdict("dns", False, "DNS firewall unavailable, fail closed: SERVFAIL")
    if any(fnmatch.fnmatch(name, pat) for pat in d["allow"]):
        return Verdict("dns", True, f"{name} is on the DNS allow-list")
    action = d.get("default_action", "BLOCK")
    if action == "BLOCK":
        return Verdict("dns", False, f"{name} not on the DNS allow-list: default rule BLOCK (NODATA)")
    return Verdict("dns", True, f"{name} not on the DNS allow-list, but the default rule is {action}: answered")


def route_layer(c: dict) -> Verdict:
    n = c["network"]
    if n["mode"] == "PUBLIC":
        return Verdict("route", True, "PUBLIC network mode: internet reachable")
    if n.get("nat_gateway"):
        return Verdict("route", True, "VPC mode with a NAT gateway route")
    return Verdict("route", False, "VPC mode, no NAT gateway: no route to the internet")


def sg_layer(c: dict, to: str, port: int) -> Verdict:
    for e in c["network"]["security_group_egress"]:
        if e["port"] == port and e["to"] in (to, "0.0.0.0/0"):
            return Verdict("sg", True, f"egress rule tcp/{port} to {e['to']}")
    return Verdict("sg", False, f"no egress rule for tcp/{port} to {to}: REJECT")


def proxy_layer(c: dict, host: str, method: str) -> Verdict:
    p = c["proxy"]
    if not p.get("enabled"):
        return Verdict("proxy", False, "no proxy configured")
    for a in p["allow"]:
        if fnmatch.fnmatch(host, a["name"]):
            if "*" in a["methods"] or method in a["methods"]:
                return Verdict("proxy", True, f"{method} {host} matches allow entry {a['name']}")
            return Verdict("proxy", False, f"{method} not allowed for {a['name']} (allowed: {', '.join(a['methods'])})")
    return Verdict("proxy", False, f"{host} not on the proxy allow-list")


def endpoint_layer(c: dict, service: str, action: str, resource: str) -> Verdict:
    ep = next((e for e in c["endpoints"] if e["service"] == service), None)
    if ep is None:
        return Verdict("endpoint", False, f"no VPC endpoint for {service}")
    pol = ep["policy"]
    if not isinstance(pol, dict):
        return Verdict("endpoint", True, f"{service} endpoint policy is {pol}: everything allowed")
    ok_action = any(fnmatch.fnmatch(action, a) for a in pol["allow_actions"])
    ok_resource = any(fnmatch.fnmatch(resource, r) for r in pol["resources"])
    if ok_action and ok_resource:
        return Verdict("endpoint", True, f"{action} on {resource} allowed by the endpoint policy")
    return Verdict("endpoint", False, f"{action} on {resource} not in the endpoint policy: VpceAccessDenied")


def role_layer(c: dict, action: str, resource: str) -> Verdict:
    for s in c["execution_role"]["statements"]:
        if s["effect"] != "Allow":
            continue
        if any(fnmatch.fnmatch(action, a) for a in s["actions"]) and any(fnmatch.fnmatch(resource, r) for r in s["resources"]):
            return Verdict("role", True, "execution role allows it")
    return Verdict("role", False, f"execution role does not allow {action} on {resource}: AccessDenied")


# ---------------------------------------------------------------- one request

def decide(c: dict, r: dict) -> Decision:
    d = Decision(r)
    kind = r["kind"]
    if kind == "dns":
        d.verdicts.append(dns_layer(c, r["name"], r.get("dns_firewall_unavailable", False)))
    elif kind == "aws_api":
        d.verdicts.append(dns_layer(c, r["name"]))
        d.verdicts.append(sg_layer(c, f"endpoint:{r['service']}", r["port"]))
        d.verdicts.append(endpoint_layer(c, r["service"], r["action"], r["resource"]))
        d.verdicts.append(role_layer(c, r["action"], r["resource"]))
    elif kind == "https" and r["via"] == "proxy":
        # The sandbox only resolves and reaches the proxy; the proxy decides on the host and method.
        port = 3128 if c["proxy"].get("enforced_by_network") else r["port"]
        d.verdicts.append(dns_layer(c, PROXY_NAME))
        d.verdicts.append(sg_layer(c, "proxy", port))
        d.verdicts.append(proxy_layer(c, r["name"], r.get("method", "GET")))
    elif kind == "https":
        d.verdicts.append(dns_layer(c, r["name"]))
        d.verdicts.append(route_layer(c))
        d.verdicts.append(sg_layer(c, "internet", r["port"]))
    else:
        raise ValueError(f"unknown request kind {kind!r} in {r['id']}")
    return d


def replay(config_name: str) -> list[Decision]:
    c = lab.load_config(config_name)
    return [decide(c, r) for r in lab.requests()]


def summary(decisions: list[Decision]) -> dict:
    unexpected = [d for d in decisions if d.request["expect"] == "unexpected"]
    normal = [d for d in decisions if d.request["expect"] == "normal"]
    return {
        "unexpected_allowed": [d.request["id"] for d in unexpected if d.allowed],
        "unexpected_total": len(unexpected),
        "normal_working": [d.request["id"] for d in normal if d.allowed],
        "normal_total": len(normal),
    }


def summary_line(name: str, decisions: list[Decision]) -> str:
    s = summary(decisions)
    allowed = ", ".join(s["unexpected_allowed"]) or "none"
    return (f"{name}: unexpected requests allowed {len(s['unexpected_allowed'])} of {s['unexpected_total']} ({allowed})"
            f" | normal tool calls working {len(s['normal_working'])} of {s['normal_total']}")


def describe(r: dict) -> str:
    if r["kind"] == "aws_api":
        return f"{r['action']} {r['resource'].split(':::')[-1].split('::')[-1]}"
    if r["kind"] == "dns":
        return f"DNS {r['name']}" + (" (firewall down)" if r.get("dns_firewall_unavailable") else "")
    return f"{r.get('method', 'GET')} {r['name']}:{r['port']} via {r['via']}"


def show(name: str) -> None:
    ds = replay(name)
    print(f"Replay of {len(ds)} recorded requests against {name}")
    for d in ds:
        r = d.request
        verdict = "ALLOW" if d.allowed else "DENY "
        layers = " ".join(f"{v.layer}:{'ok' if v.allow else 'NO'}" for v in d.verdicts)
        print(f"  {r['id']:3} {verdict} {describe(r):58.58} {layers}")
        if not d.allowed:
            print(f"        first denied by {d.first_denial.layer}: {d.first_denial.reason}")
    print(summary_line(name, ds))


def compare() -> None:
    a, b = replay("first-draft"), replay("hardened")
    print(f"  {'id':3} {'request':58} {'first-draft':12} hardened (denied by)")
    for x, y in zip(a, b):
        hd = "ALLOW" if y.allowed else "DENY (" + ", ".join(y.denied_by) + ")"
        fd = "ALLOW" if x.allowed else "DENY (" + ", ".join(x.denied_by) + ")"
        print(f"  {x.request['id']:3} {describe(x.request):58.58} {fd:12} {hd}")
    print(summary_line("first-draft", a))
    print(summary_line("hardened   ", b))


def main(argv: list[str]) -> int:
    name = argv[1] if len(argv) > 1 else "compare"
    if name == "compare":
        compare()
    else:
        show(name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
