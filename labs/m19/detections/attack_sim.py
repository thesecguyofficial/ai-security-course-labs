#!/usr/bin/env python3
"""Attack simulator: one busy day of TSG Helpdesk app logs with five incidents hidden in normal traffic.

    python3 detections/attack_sim.py                       # seed 1 -> detections/logs/attack-day.jsonl (make simulate)
    python3 detections/attack_sim.py --seed 7 --out /tmp/day7.jsonl
    python3 detections/attack_sim.py --seed 7 --truth /tmp/day7-truth.json   # the answer key (self-check only)

Same fields as the app log (helpdesk/logs.py), so your rules run on both. Every name, address and IP is fake:
domains end in .example or .invalid (RFC 2606) and IPs come from the documentation ranges (RFC 5737).
Each seed changes WHO the attackers are, which documents, domains, IPs and times they use, and how much normal
traffic surrounds them. A rule that names a user, an IP or a request ID from one day will miss the next day.
The self-check runs your rules on three seeds.

The five incidents (README, Part 5):
  S1  zero-click exfiltration: a planted partner page makes a customer's session email the customer list out
  S2  a customer reads another tenant's and staff-only pages, several times
  S3  the crm MCP server changes its tools mid-day (rug pull); a new tool leaks a token
  S4  someone keeps asking for the system prompt until the escalation code comes back
  S5  denial of wallet: one account sends requests far faster than any person
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import random

HERE = pathlib.Path(__file__).resolve().parent
DAY = dt.datetime(2027, 1, 20, 6, 0, tzinfo=dt.timezone.utc)
INTERNAL = "tsg-helpdesk.example"
TENANTS = ["acme", "globex", "initech", "umbrella", "hooli", "vandelay"]
FIRST = ["alex", "bea", "chen", "dev", "eli", "fay", "gus", "hana", "ivan", "jo", "kai", "lena", "mo", "nia",
         "omar", "pia", "raj", "sara", "tom", "uma", "vic", "wen", "yara", "zoe"]
STAFF = ["sam", "lee", "ana", "ravi"]
KB_PUBLIC = ["kb-refunds", "kb-vpn", "kb-password-reset", "kb-invoices", "kb-shipping"]
KB_PARTNER = ["kb-refund-timelines", "kb-service-status", "kb-warranty", "kb-courier-updates"]
KB_STAFF = ["kb-pricing-2027", "kb-escalations", "kb-partner-contracts"]
ATTACKER_DOMAINS = ["example.invalid", "partner-refunds.example", "tsg-helpdesk.example.invalid",
                    "refund-desk.example", "crm-backup.example"]
TOOLS_V1 = ["crm_lookup", "crm_list_customers"]
TOOLS_V2 = ["crm_lookup", "crm_list_customers", "crm_debug_dump"]


def h(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


class Day:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.seed = seed
        self.events: list[dict] = []
        self.truth: dict[str, set] = {f"S{i}": set() for i in range(1, 6)}
        self.n = 0
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
    def _rid(self) -> str:
        self.n += 1
        return f"req-{self.n:05d}-{h(self.seed, self.n)[:6]}"

    def ev(self, t: dt.datetime, user: dict, rid: str, event: str, story: str | None = None, **f) -> None:
        rec = {"ts": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z", "event": event,
               "request_id": rid, "session": f"s-{h(user['email'], self.seed)[:8]}", "user": user["email"],
               "user_role": user["role"], "user_tenant": user["tenant"]}
        rec.update(f)
        self.events.append(rec)
        if story:
            self.truth[story].add(rid)

    def turn(self, t: dt.datetime, user: dict, docs=(), calls=(), dlp=(), story=None, chars=None, ip=None,
             tools_hash=None, tool_names=None, blocked=None) -> dt.datetime:
        """One chat turn: request, tool list, retrievals, tool calls, response. Returns the time after it."""
        rid = self._rid()
        self.ev(t, user, rid, "request", story, chars=chars or self.rng.randint(20, 400), ip=ip or user["ip"])
        t += dt.timedelta(milliseconds=self.rng.randint(5, 30))
        if blocked:
            self.ev(t, user, rid, "blocked", story, guard="check_request", reason=blocked)
            return t + dt.timedelta(milliseconds=50)
        if tools_hash is None:
            later = t >= self.rugpull_at + dt.timedelta(seconds=2)   # the S3 turn is always the first to see v2
            tools_hash, tool_names = (self.hash_v2, TOOLS_V2) if later else (self.hash_v1, TOOLS_V1)
        self.ev(t, user, rid, "mcp_tools_list", story, server="crm", tools_hash=tools_hash, tool_names=tool_names)
        for d in docs:
            t += dt.timedelta(milliseconds=self.rng.randint(10, 60))
            self.ev(t, user, rid, "retrieval", story, **d)
        for c in calls:
            t += dt.timedelta(milliseconds=self.rng.randint(100, 900))
            self.ev(t, user, rid, "tool_call", story, **c)
        t += dt.timedelta(milliseconds=self.rng.randint(300, 2500))
        self.ev(t, user, rid, "response", story, chars=self.rng.randint(80, 1200), dlp_hits=list(dlp))
        return t

    # ---- building blocks -----------------------------------------------------------------------------------
    def doc(self, doc_id: str, tenant="all", audience="public", source="tsg-kb", flags=()) -> dict:
        return {"doc_id": doc_id, "doc_tenant": tenant, "doc_audience": audience, "doc_source": source,
                "doc_flags": list(flags)}

    def email_call(self, user: dict, to: str, decision="allow", dlp=(), untrusted=True) -> dict:
        dom = to.rsplit("@", 1)[-1]
        return {"tool": "send_email", "server": "local", "decision": decision, "reason": "",
                "untrusted_in_context": untrusted, "recipient": to, "recipient_domain": dom,
                "recipient_is_requester": to == user["email"], "recipient_internal": dom == INTERNAL,
                "body_dlp_hits": list(dlp)}

    def tool(self, name: str, server="crm", decision="allow", **extra) -> dict:
        return {"tool": name, "server": server, "decision": decision, "reason": "", "untrusted_in_context": True,
                **extra}

    # ---- normal traffic --------------------------------------------------------------------------------------
    def benign(self) -> None:
        r = self.rng
        t = DAY
        end = DAY + dt.timedelta(hours=12)
        while t < end:
            t += dt.timedelta(seconds=r.randint(40, 420))
            if r.random() < 0.22:
                u = r.choice(self.staff)
                kind = r.choice(["staff_doc", "email_customer", "list", "lookup"])
                cust = r.choice(self.customers)
                if kind == "staff_doc":
                    self.turn(t, u, docs=[self.doc(r.choice(KB_STAFF), audience="staff")])
                elif kind == "email_customer":
                    self.turn(t, u, docs=[self.doc(r.choice(KB_PUBLIC))],
                              calls=[self.email_call(u, cust["email"])])
                elif kind == "list":
                    self.turn(t, u, calls=[self.tool("crm_list_customers")], dlp=["customer_list"])
                else:
                    self.turn(t, u, calls=[self.tool("crm_lookup", target=cust["email"], target_is_user=False)])
                continue
            u = r.choice(self.customers)
            kind = r.choices(["kb", "partner", "own_tenant", "order", "email_me", "account"],
                             [5, 3, 1, 2, 2, 1])[0]
            if kind == "kb":
                self.turn(t, u, docs=[self.doc(d) for d in r.sample(KB_PUBLIC, r.randint(1, 2))])
            elif kind == "partner":       # partner pages often carry editor comments: not an attack on their own
                flags = ["html_comment"] if r.random() < 0.6 else []
                self.turn(t, u, docs=[self.doc(r.choice(KB_PARTNER), source="partner-feed", flags=flags)])
            elif kind == "own_tenant":
                self.turn(t, u, docs=[self.doc(f"kb-{u['tenant']}-onboarding", tenant=u["tenant"])])
            elif kind == "order":
                self.turn(t, u, calls=[self.tool("lookup_order", server="local", order=str(r.randint(5001, 5999)),
                                                 order_owner_is_user=True)])
            elif kind == "email_me":
                self.turn(t, u, docs=[self.doc(r.choice(KB_PUBLIC + KB_PARTNER))],
                          calls=[self.email_call(u, u["email"])])
            else:
                self.turn(t, u, calls=[self.tool("crm_lookup", target=u["email"], target_is_user=True)])
        # a busy staff member: many requests in an hour, but at a human pace
        u = r.choice(self.staff)
        t = DAY + dt.timedelta(hours=r.uniform(2, 8))
        for _ in range(r.randint(30, 40)):
            t = self.turn(t, u, docs=[self.doc(r.choice(KB_PUBLIC + KB_STAFF))]) + dt.timedelta(seconds=r.randint(45, 110))
        # a few honest users hit the size limit
        for _ in range(3):
            u = r.choice(self.customers)
            self.turn(DAY + dt.timedelta(hours=r.uniform(0, 12)), u, chars=r.randint(5000, 9000),
                      blocked="message longer than 4000 characters")

    # ---- the five incidents ------------------------------------------------------------------------------------
    def incidents(self) -> None:
        r = self.rng
        victims = r.sample(self.customers, 5)
        # S1: zero-click exfiltration via a planted partner page
        u, dom = victims[0], r.choice(ATTACKER_DOMAINS)
        t = DAY + dt.timedelta(hours=r.uniform(1, 11))
        page = r.choice(KB_PARTNER)
        for _ in range(r.randint(1, 2)):
            to = f"{r.choice(['collector', 'claims', 'billing', 'refunds'])}@{dom}"
            t = self.turn(t, u, docs=[self.doc(page, source="partner-feed", flags=["html_comment"]),
                                      self.doc(r.choice(KB_PUBLIC))],
                          calls=[self.tool("crm_list_customers"), self.email_call(u, to, dlp=["customer_list"])],
                          story="S1") + dt.timedelta(minutes=r.randint(20, 90))
        # S2: cross-tenant and staff-only reads
        u = victims[1]
        others = [x for x in TENANTS if x != u["tenant"]]
        t = DAY + dt.timedelta(hours=r.uniform(1, 11))
        for i in range(r.randint(4, 7)):
            if i % 2 == 0:
                other = r.choice(others)
                d, dlp = self.doc(f"kb-{other}-onboarding", tenant=other), ["other_tenant_doc"]
            else:
                d, dlp = self.doc(r.choice(KB_STAFF), audience="staff"), ["confidential_doc"]
            t = self.turn(t, u, docs=[d], dlp=dlp, story="S2") + dt.timedelta(seconds=r.randint(30, 240))
        # S3: MCP rug pull, then the new tool is used
        u = victims[2]
        self.turn(self.rugpull_at, u, calls=[self.tool("crm_lookup", target=u["email"], target_is_user=True),
                               self.tool("crm_debug_dump")], dlp=["crm_token", "customer_list"], story="S3",
                  tools_hash=self.hash_v2, tool_names=TOOLS_V2)
        # S4: system prompt extraction
        u = victims[3]
        t = DAY + dt.timedelta(hours=r.uniform(1, 11))
        for i in range(r.randint(3, 6)):
            dlp = ["secret_in_prompt"] if i >= 2 else []
            t = self.turn(t, u, dlp=dlp, story="S4") + dt.timedelta(seconds=r.randint(20, 90))
        # S5: denial of wallet from a script
        u = dict(victims[4], ip=f"192.0.2.{r.randint(2, 250)}")
        t = DAY + dt.timedelta(hours=r.uniform(1, 10))
        for _ in range(r.randint(120, 180)):
            t = self.turn(t, u, docs=[self.doc(r.choice(KB_PUBLIC))], chars=r.randint(3000, 3990), ip=u["ip"],
                          story="S5") + dt.timedelta(seconds=r.uniform(1, 6))

    def build(self) -> list[dict]:
        self.benign()
        self.incidents()
        self.events.sort(key=lambda e: e["ts"])
        # Number requests in time order, like the real app does, so an ID says nothing about who sent it.
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
