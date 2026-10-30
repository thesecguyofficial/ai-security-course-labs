#!/usr/bin/env python3
"""
explore.py: look at each isolation and egress idea on its own, before you review the sandbox (M27 lab, Step 1b).

Read-only. It reads this machine's own facts from /proc and /sys, and the lab's JSON files, and prints them in plain
words. It writes no file (not even Python's __pycache__), starts no program, resolves no name and opens no
connection.

    python3 explore.py here                    # 1. this terminal: a process, its kernel, its limits, and what it runs on
    python3 explore.py sandbox [config]        # 2. the sandbox lines of a config (boundary, session, limits, files, secrets)
    python3 explore.py network [config]        # 3. the network lines: mode, route, firewall rules, endpoints, DNS, proxy
    python3 explore.py dns NAME... [config]    # 4. one or more names against the DNS allow-list
    python3 explore.py request ID [config]     # 5. one recorded request (data/requests.jsonl), layer by layer

[config] is hardened (the default), first-draft or second-draft.
Windows: `py explore.py ...` (`here` reads Linux files and says so on Windows or macOS). Fake data only.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import platform
import sys

sys.dont_write_bytecode = True  # read-only: importing lab and egress must not write __pycache__/
import egress  # noqa: E402  (only its layer functions; nothing in egress runs on import)
import lab  # noqa: E402

CONFIGS = ("hardened", "first-draft", "second-draft")


def read(path: str) -> str | None:
    try:
        return pathlib.Path(path).read_text(errors="replace").strip()
    except OSError:
        return None


def row(key: str, value, meaning: str = "", width: int = 34, vw: int = 16) -> None:
    print(f"  {key:{width}} {str(value):{vw}} {meaning}".rstrip())


# ---------------------------------------------------------------- 1. here

def cmd_here(a) -> int:
    print("This terminal, read from /proc and /sys (nothing is changed)\n")
    print("A process is one running program. This one is explore.py:")
    row("process ID", os.getpid(), "its number on this machine", 26)
    try:
        import pwd
        user = pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError):
        user = "?"
    row("runs as user", user, "it can open whatever files this user can", 26)
    pids = [p for p in os.listdir("/proc") if p.isdigit()] if os.path.isdir("/proc") else []
    if pids:
        row("processes it can see", len(pids), "every program running on this machine, not just its own", 26)
    print("\nThe kernel is the core of the operating system: every program asks it for files, memory and network.")
    row("kernel", platform.release(), "", 26)
    if sys.platform != "linux":
        print(f"\nThis is {platform.system()}, not Linux: the rest of 'here' reads Linux files. Use a Linux machine or the video.")
        return 0
    try:
        import resource
        nproc = resource.getrlimit(resource.RLIMIT_NPROC)[0]
        nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        inf = resource.RLIM_INFINITY
        print("\nLimits the kernel enforces on this process (ulimit):")
        row("max processes (this user)", "unlimited" if nproc == inf else nproc, "how many programs it may start", 26)
        row("max open files", "unlimited" if nofile == inf else nofile, "files and network connections open at once", 26)
    except ImportError:
        pass
    print("\nWhat this terminal runs on:")
    in_container = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
    pid1 = read("/proc/1/comm") or "?"
    row("inside a container?", "yes" if in_container else "no",
        f"process 1 is {pid1}" + ("" if in_container else ", a normal machine's first program"), 26)
    cpu = read("/proc/cpuinfo") or ""
    hyper = " hypervisor" in cpu or "\thypervisor" in cpu
    vendor = read("/sys/class/dmi/id/sys_vendor")
    product = read("/sys/class/dmi/id/product_name")
    made = f"{vendor} {product}" if vendor and product else "not readable here"
    row("virtual machine?", "yes" if hyper else "no",
        "the CPU reports a hypervisor" if hyper else "the CPU reports no hypervisor", 26)
    row("hardware says", made, "", 26)
    if hyper:
        print("\nSo this terminal is a process, on a kernel, inside a virtual machine: three layers, each with its own limits.")
    return 0


# ---------------------------------------------------------------- 2. sandbox

BOUNDARY = {
    "process": "a plain process on the host: shares every file and the network of its user",
    "container": "a container: own view of files and processes, but the host's own kernel",
    "gvisor": "gVisor: a user-space kernel in between, so few calls reach the host kernel",
    "microvm": "a microVM: its own small virtual machine with its own kernel",
}


def cmd_sandbox(a) -> int:
    c = lab.load_config(a.config)
    rt, fs, sec = c["runtime"], c["filesystem"], c["secrets"]
    s, lim = rt["session"], rt["limits"]
    print(f"The sandbox lines of configs/{a.config}.json, one by one\n")
    print("Where the code runs:")
    row("runtime.boundary", rt["boundary"], BOUNDARY.get(rt["boundary"], "unknown boundary"))
    one = s["one_per_user_task"]
    row("runtime.session.one_per_user_task", str(one).lower(),
        "a fresh sandbox per user and task" if one else "<- shared: one user's leftovers meet the next user")
    mins = s["timeout_seconds"] // 60
    row("runtime.session.timeout_seconds", s["timeout_seconds"],
        f"destroyed after {mins} minutes" + ("" if mins <= 60 else " <- hours for a hijacked run to work"))
    print("\nProcess limits (how much it may use):")
    row("runtime.limits.vcpu", lim["vcpu"], "virtual CPUs")
    row("runtime.limits.memory_mb", lim["memory_mb"], "MB of memory")
    mp = lim["max_processes"]
    row("runtime.limits.max_processes", "not set" if mp is None else mp,
        "<- no cap: a runaway loop of programs never stops" if mp is None else "programs at once: a runaway loop stops here")
    print("\nFile system limits (what it may read and write):")
    for m in fs["mounts"]:
        if ".aws" in m["path"]:
            what = "<- a cloud credentials folder, inside the sandbox"
        elif m["path"] == "/workspace":
            what = "the scratch folder: it may write here"
        else:
            what = "input data: read, never changed" if m["mode"] == "ro" else "<- input data the code can change"
        row(f"mount {m['path']}", m["mode"], what)
    print("\nSecrets:")
    if not sec["env"]:
        row("secrets.env", "(none)", "no passwords or keys inside the sandbox")
    for e in sec["env"]:
        row("secrets.env", e, "<- readable by any code that runs inside")
    print("\nThe network lines come next: python3 explore.py network " + a.config)
    return 0


# ---------------------------------------------------------------- 3. network

def cmd_network(a) -> int:
    c = lab.load_config(a.config)
    n, d, p = c["network"], c["dns"], c["proxy"]
    print(f"The network lines of configs/{a.config}.json, one by one\n")
    print("Is there a way out to the internet?")
    row("network.mode", n["mode"], "PUBLIC = internet access; VPC = only your own private network")
    row("network.nat_gateway", str(n["nat_gateway"]).lower(),
        "<- a shared door from the private network to the internet" if n["nat_gateway"] else "no door to the internet")
    print("\nFirewall rules for traffic leaving the sandbox (security group egress):")
    for e in n["security_group_egress"]:
        to = e["to"]
        what = "<- anywhere on the internet" if to == "0.0.0.0/0" else "one named destination only"
        row(f"{e['protocol']}/{e['port']} to", to, what, vw=24)
    print("\nPrivate doors to cloud services (VPC endpoints) and their policies:")
    for ep in c["endpoints"]:
        pol = ep["policy"]
        if isinstance(pol, dict):
            res = ", ".join(r.split(":::")[-1].split("::")[-1] for r in pol["resources"])
            row(f"endpoint {ep['service']}", "custom", f"{', '.join(pol['allow_actions'])} on {res}")
        else:
            row(f"endpoint {ep['service']}", pol, "<- any action on any account's resources")
    print("\nThe phone book (DNS) and its allow-list:")
    row("dns.firewall", str(d["firewall"]).lower(),
        "names are checked against an allow-list" if d["firewall"] else "<- the resolver answers for any name")
    if d["firewall"]:
        for name in d["allow"]:
            row("dns.allow", name, "")
        row("dns.default_action", d["default_action"], "for every other name")
    row("dns.fail_open", str(d["fail_open"]).lower(),
        "<- if the check is down, answer anyway" if d["fail_open"] else "if the check is down, refuse (fail closed)")
    print("\nThe proxy, a go-between that fetches web pages for the sandbox:")
    for e in p["allow"]:
        row("proxy.allow", e["name"], "methods " + ", ".join(e["methods"]), vw=18)
    row("proxy.enforced_by_network", str(p["enforced_by_network"]).lower(),
        "the firewall lets the sandbox reach only the proxy" if p["enforced_by_network"]
        else "<- code that ignores the proxy goes straight out")
    return 0


# ---------------------------------------------------------------- 4. dns

def cmd_dns(a) -> int:
    names = list(a.names)
    config = "hardened"
    if names and names[-1] in CONFIGS:
        config = names.pop()
    if not names:
        sys.exit("give at least one name, e.g. python3 explore.py dns placeholder.example.invalid")
    c = lab.load_config(config)
    d = c["dns"]
    print(f"DNS turns a name into an address. Before the sandbox can connect, it asks the resolver.")
    print(f"configs/{config}.json: DNS firewall {str(d['firewall']).lower()}, default rule {d['default_action']}")
    print(f"  allow-list: {', '.join(d['allow']) or '(empty)'}\n")
    for name in names:
        v = egress.dns_layer(c, name)
        print(f"  {name}")
        print(f"    {'answered' if v.allow else 'BLOCKED'}: {v.reason}")
        print(f"    so the code {'gets an address and may try to connect' if v.allow else 'never learns an address to connect to'}")
    print("\nNo name was really looked up: this is the config's rule, applied on paper.")
    return 0


# ---------------------------------------------------------------- 5. request

def cmd_request(a) -> int:
    reqs = {r["id"]: r for r in lab.requests()}
    if a.id not in reqs:
        sys.exit(f"no request {a.id} in data/requests.jsonl. IDs: {', '.join(reqs)}")
    r = reqs[a.id]
    c = lab.load_config(a.config)
    print(f"Request {a.id} from data/requests.jsonl, field by field\n")
    labels = {"t": "when", "kind": "kind", "name": "name", "port": "port", "via": "via", "method": "method",
              "service": "service", "action": "action", "resource": "resource", "expect": "expect", "note": "note"}
    for k, label in labels.items():
        if k in r:
            print(f"  {label:9} {r[k]}")
    d = egress.decide(c, r)
    print(f"\nAgainst configs/{a.config}.json, in the order the request meets each layer:")
    for v in d.verdicts:
        print(f"  {v.layer:9} {'ok' if v.allow else 'NO':3} {v.reason}")
    verdict = "ALLOW" if d.allowed else "DENY (" + ", ".join(d.denied_by) + ")"
    print(f"\nEvery layer must say ok: {verdict}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Look at each isolation and egress idea on its own (read-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("here", help="this terminal: a process, its kernel, its limits, what it runs on").set_defaults(fn=cmd_here)
    for name, fn, hlp in (("sandbox", cmd_sandbox, "the sandbox lines of a config"),
                          ("network", cmd_network, "the network lines of a config")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("config", nargs="?", default="hardened", choices=CONFIGS)
        p.set_defaults(fn=fn)
    p = sub.add_parser("dns", help="names against the DNS allow-list")
    p.add_argument("names", nargs="+", help="one or more names, optionally followed by a config name")
    p.set_defaults(fn=cmd_dns)
    p = sub.add_parser("request", help="one recorded request, layer by layer")
    p.add_argument("id", help="N1 to N6, U1 to U8")
    p.add_argument("config", nargs="?", default="hardened", choices=CONFIGS)
    p.set_defaults(fn=cmd_request)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
