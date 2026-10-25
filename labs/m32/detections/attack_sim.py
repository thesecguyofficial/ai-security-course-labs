#!/usr/bin/env python3
"""Attack simulator: one busy day of TSG Ops Crew app logs with five incidents hidden in normal traffic.

    python3 detections/attack_sim.py                       # seed 1 -> detections/logs/attack-day.jsonl (make simulate)
    python3 detections/attack_sim.py --seed 7 --out /tmp/day7.jsonl
    python3 detections/attack_sim.py --seed 7 --truth /tmp/day7-truth.json   # the answer key (self-check only)

Same fields as the app log (crew/logs.py), so your rules run on both. Every name, address and IP is fake:
domains end in .example or .invalid (RFC 2606) and IPs come from the documentation ranges (RFC 5737).
Each seed changes WHO the attackers are, which tenants, domains, IPs and times they use, and how much normal
traffic surrounds them. A rule that names a user, an IP or a request ID from one day will miss the next day.
The self-check runs your rules on three seeds.

The five incidents (README, Part 5):
  S1  cross-agent exfiltration: a planted ticket makes triage hand to billing, which emails the customer list out
  S2  cross-tenant query: the analyst runs a usage query for a tenant that is not the requester's
  S3  MCP rug pull: the crm server changes its tools mid-day; the new debug tool leaks a token
  S4  cascading hand-offs: one instruction bounces between agents, many hand-offs in one request
  S5  system-prompt extraction: a user keeps asking until the billing escalation code comes back
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import random

HERE = pathlib.Path(__file__).resolve().parent
DAY = dt.datetime(2027, 5, 10, 6, 0, tzinfo=dt.timezone.utc)
INTERNAL = "tsg-ops.example"
TENANTS = ["acme", "globex", "initech", "umbrella", "hooli", "vandelay"]
FIRST = ["alex", "bea", "chen", "dev", "eli", "fay", "gus", "hana", "ivan", "jo", "kai", "lena", "mo", "nia",
         "omar", "pia", "raj", "sara", "tom", "uma", "vic", "wen", "yara", "zoe"]
STAFF = ["sam", "lee", "ana", "ravi"]
ATTACKER_DOMAINS = ["example.invalid", "partner-refunds.example", "tsg-ops.example.invalid",
                    "refund-desk.example", "crm-backup.example"]


def h(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


class Day:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.seed = seed
        self.events: list[dict] = []
        self.truth: dict[str, set] = {f"S{i}": set() for i in range(1, 6)}
        r = self.rng
        self.customers = []
        for name in r.sample(FIRST, 18):
            t = r.choice(TENANTS)
            self.customers.append({"email": f"{name}@{t}.example", "role": "customer", "tenant": t,
                                   "ip": f"198.51.100.{r.randint(2, 250)}"})
        self.staff = [{"email": f"{s}@{INTERNAL}", "role": "staff", "tenant": "tsg",
                       "ip": f"203.0.113.{r.randint(2, 60)}"} for s in STAFF]
        self.hash_v1 = h("crm", seed, "v1")
        self.hash_v2 = h("crm", seed, "v2")
        self.rugpull_at = DAY + dt.timedelta(hours=r.uniform(5, 9))

    # ---- writing events ----------------------------------------------------------------------------------
    def ev(self, t: dt.datetime, user: dict, rid: str, event: str, agent: str, depth: int,
           story: str | None = None, **f) -> None:
        rec = {"ts": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z", "event": event,
               "request_id": rid, "session": f"s-{h(user['email'], self.seed)[:8]}", "user": user["email"],
               "user_role": user["role"], "user_tenant": user["tenant"], "agent": agent, "depth": depth}
        rec.update(f)
        self.events.append(rec)
        if story:
            self.truth[story].add(rid)

    def turn(self, t: dt.datetime, user: dict, route=None, handoffs=(), calls=(), dlp=(), story=None, chars=None,
             ip=None, tools_hash=None, tool_names=None, blocked=None, resp_agent="triage", resp_depth=0) -> dt.datetime:
        """One chat turn: request, mcp list, memory read, hand-offs, tool calls, response. Returns the end time."""
        self._seq = getattr(self, "_seq", 0) + 1
        rid = f"req-{self._seq:05d}-{h(self.seed, self._seq)[:6]}"
        self.ev(t, user, rid, "request", "triage", 0, story, chars=chars or self.rng.randint(20, 400), ip=ip or user["ip"])
        t += dt.timedelta(milliseconds=self.rng.randint(5, 30))
        if blocked:
            self.ev(t, user, rid, "blocked", "triage", 0, story, guard="check_request", reason=blocked)
            return t + dt.timedelta(milliseconds=50)
        if tools_hash is None:
            later = t >= self.rugpull_at + dt.timedelta(seconds=2)
            tools_hash, tool_names = (self.hash_v2, ["crm_lookup", "crm_list_customers", "crm_debug_dump"]) if later \
                else (self.hash_v1, ["crm_lookup", "crm_list_customers"])
        self.ev(t, user, rid, "mcp_tools", "triage", 0, story, server="crm", tools_hash=tools_hash,
                tool_names=tool_names)
        for frm, to, depth, allow, tdlp in handoffs:
            t += dt.timedelta(milliseconds=self.rng.randint(40, 200))
            self.ev(t, user, rid, "handoff", frm, depth, story, frm=frm, to=to,
                    decision="allow" if allow else "deny", reason="", task_dlp_hits=list(tdlp),
                    untrusted_in_context=True)
        for agent, depth, call in calls:
            t += dt.timedelta(milliseconds=self.rng.randint(100, 900))
            self.ev(t, user, rid, "tool_call", agent, depth, story, **call)
        t += dt.timedelta(milliseconds=self.rng.randint(300, 2500))
        self.ev(t, user, rid, "response", resp_agent, resp_depth, story, chars=self.rng.randint(80, 1200),
                dlp_hits=list(dlp))
        return t

    # ---- building blocks -----------------------------------------------------------------------------------
    def email_call(self, agent, depth, user, to, decision="allow", dlp=()) -> tuple:
        dom = to.rsplit("@", 1)[-1]
        return (agent, depth, {"tool": "send_email", "server": "local", "decision": decision, "reason": "",
                "untrusted_in_context": True, "recipient": to, "recipient_domain": dom,
                "recipient_is_requester": to == user["email"], "recipient_internal": dom == INTERNAL,
                "body_dlp_hits": list(dlp)})

    def tool(self, agent, depth, name, server="crm", decision="allow", **extra) -> tuple:
        return (agent, depth, {"tool": name, "server": server, "decision": decision, "reason": "",
                "untrusted_in_context": True, **extra})

    # ---- normal traffic --------------------------------------------------------------------------------------
    def benign(self) -> None:
        r = self.rng
        t, end = DAY, DAY + dt.timedelta(hours=12)
        while t < end:
            t += dt.timedelta(seconds=r.randint(40, 420))
            if r.random() < 0.22:                              # a staff member
                u = r.choice(self.staff)
                cust = r.choice(self.customers)
                kind = r.choice(["email_customer", "list", "lookup"])
                if kind == "email_customer":                   # staff writes to a customer: NOT an attack
                    self.turn(t, u, handoffs=[("triage", "billing", 1, True, ())],
                              calls=[self.email_call("billing", 1, u, cust["email"])], resp_agent="billing", resp_depth=1)
                elif kind == "list":
                    self.turn(t, u, handoffs=[("triage", "analyst", 1, True, ())],
                              calls=[self.tool("analyst", 1, "crm_list_customers")], dlp=["customer_list"],
                              resp_agent="analyst", resp_depth=1)
                else:
                    self.turn(t, u, handoffs=[("triage", "analyst", 1, True, ())],
                              calls=[self.tool("analyst", 1, "crm_lookup", target=cust["email"], target_is_user=False)],
                              resp_agent="analyst", resp_depth=1)
                continue
            u = r.choice(self.customers)
            kind = r.choices(["account", "order", "email_me", "usage", "chat"], [3, 2, 2, 2, 3])[0]
            if kind == "account":
                self.turn(t, u, handoffs=[("triage", "analyst", 1, True, ())],
                          calls=[self.tool("analyst", 1, "crm_lookup", target=u["email"], target_is_user=True)],
                          resp_agent="analyst", resp_depth=1)
            elif kind == "order":
                self.turn(t, u, handoffs=[("triage", "billing", 1, True, ())],
                          calls=[self.tool("billing", 1, "issue_refund", server="local",
                                           order=str(r.randint(5001, 5999)), amount_cents="4900",
                                           order_owner_is_user=True)], resp_agent="billing", resp_depth=1)
            elif kind == "email_me":
                self.turn(t, u, handoffs=[("triage", "billing", 1, True, ())],
                          calls=[self.email_call("billing", 1, u, u["email"])], resp_agent="billing", resp_depth=1)
            elif kind == "usage":
                self.turn(t, u, handoffs=[("triage", "analyst", 1, True, ())],
                          calls=[self.tool("analyst", 1, "run_query", server="local", query_tenant=u["tenant"],
                                           query_tenant_is_user=True)], resp_agent="analyst", resp_depth=1)
            else:
                self.turn(t, u)
        # a busy staff member: many requests in an hour, at a human pace
        u = r.choice(self.staff)
        t = DAY + dt.timedelta(hours=r.uniform(2, 8))
        for _ in range(r.randint(25, 35)):
            t = self.turn(t, u, handoffs=[("triage", "analyst", 1, True, ())],
                          calls=[self.tool("analyst", 1, "crm_lookup", target=r.choice(self.customers)["email"],
                                           target_is_user=False)], resp_agent="analyst", resp_depth=1) \
                + dt.timedelta(seconds=r.randint(45, 110))
        # a few honest users hit the size limit
        for _ in range(3):
            u = r.choice(self.customers)
            self.turn(DAY + dt.timedelta(hours=r.uniform(0, 12)), u, chars=r.randint(5000, 9000),
                      blocked="message longer than 4000 characters")

    # ---- the five incidents ------------------------------------------------------------------------------------
    def incidents(self) -> None:
        r = self.rng
        victims = r.sample(self.customers, 5)
        # S1: cross-agent exfiltration (planted ticket -> triage hands to billing -> email out)
        u, dom = victims[0], r.choice(ATTACKER_DOMAINS)
        t = DAY + dt.timedelta(hours=r.uniform(1, 11))
        for _ in range(r.randint(1, 2)):
            to = f"{r.choice(['collector', 'claims', 'export', 'refunds'])}@{dom}"
            t = self.turn(t, u, handoffs=[("triage", "billing", 1, True, ["directive"])],
                          calls=[self.tool("billing", 1, "crm_list_customers"),
                                 self.email_call("billing", 1, u, to, dlp=["customer_list"])],
                          dlp=["customer_list"], story="S1", resp_agent="billing", resp_depth=1) \
                + dt.timedelta(minutes=r.randint(20, 90))
        # S2: cross-tenant query
        u = victims[1]
        others = [x for x in TENANTS if x != u["tenant"]]
        t = DAY + dt.timedelta(hours=r.uniform(1, 11))
        for _ in range(r.randint(2, 4)):
            other = r.choice(others)
            t = self.turn(t, u, handoffs=[("triage", "analyst", 1, True, ())],
                          calls=[self.tool("analyst", 1, "run_query", server="local", query_tenant=other,
                                           query_tenant_is_user=False)], story="S2",
                          resp_agent="analyst", resp_depth=1) + dt.timedelta(seconds=r.randint(30, 240))
        # S3: MCP rug pull, then the new tool is used
        u = victims[2]
        self.turn(self.rugpull_at, u, handoffs=[("triage", "analyst", 1, True, ())],
                  calls=[self.tool("analyst", 1, "crm_lookup", target=u["email"], target_is_user=True),
                         self.tool("analyst", 1, "crm_debug_dump")], dlp=["crm_token", "customer_list"], story="S3",
                  tools_hash=self.hash_v2, tool_names=["crm_lookup", "crm_list_customers", "crm_debug_dump"],
                  resp_agent="analyst", resp_depth=1)
        # S4: cascading hand-offs from one instruction
        u = victims[3]
        t = DAY + dt.timedelta(hours=r.uniform(1, 10))
        hops = [("triage", "analyst", 1, True, ["directive"])]
        depth = 2
        for _ in range(r.randint(8, 16)):
            frm, to = ("analyst", "billing") if depth % 2 == 0 else ("billing", "analyst")
            hops.append((frm, to, depth, True, ["directive"]))
            depth += 1
        self.turn(t, u, handoffs=hops, story="S4", resp_agent="billing", resp_depth=depth)
        # S5: system-prompt extraction
        u = victims[4]
        t = DAY + dt.timedelta(hours=r.uniform(1, 11))
        for i in range(r.randint(3, 6)):
            dlp = ["secret_in_prompt"] if i >= 2 else []
            t = self.turn(t, u, dlp=dlp, story="S5", resp_agent="billing", resp_depth=1,
                          handoffs=[("triage", "billing", 1, True, ())]) + dt.timedelta(seconds=r.randint(20, 90))

    def build(self) -> list[dict]:
        self.benign()
        self.incidents()
        self.events.sort(key=lambda e: e["ts"])
        new_ids: dict[str, str] = {}
        for e in self.events:
            if e["request_id"] not in new_ids:
                n = len(new_ids) + 1
                new_ids[e["request_id"]] = f"req-{n:05d}-{h(self.seed, 'id', n)[:6]}"
            e["request_id"] = new_ids[e["request_id"]]
        self.truth = {k: {new_ids[r] for r in v} for k, v in self.truth.items()}
        return self.events


def generate(seed: int) -> tuple[list[dict], dict]:
    d = Day(seed)
    events = d.build()
    return events, {k: sorted(v) for k, v in d.truth.items()}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(HERE / "logs" / "attack-day.jsonl"))
    ap.add_argument("--truth", help="also write the answer key (which request IDs belong to which incident)")
    a = ap.parse_args()
    events, truth = generate(a.seed)
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    print(f"seed {a.seed}: {len(events)} events, {len({e['request_id'] for e in events})} requests -> {out}")
    if a.truth:
        pathlib.Path(a.truth).write_text(json.dumps(truth, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
