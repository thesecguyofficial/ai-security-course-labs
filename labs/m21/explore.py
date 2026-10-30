#!/usr/bin/env python3
r"""
explore.py: look at each idea of tool-call authorization on its own, before you attack the Helpdesk (M21 lab,
"Understand the lab").

What it does, said plainly: it reads the lab's files (tickets, orders, staff, policies, schema, receipts) and, for
`request`, `check` and `counter`, it asks the real Cedar engine (cedarpy, on your computer) for a decision. That is
the only thing it runs. It never runs a tool, files no approval, writes no receipt and writes no file (not even
Python's __pycache__ or the state/ folder). No network.

Run it with the lab's own Python, .venv/bin/python (where cedarpy is):

    call [T-501]                 1. a tool call: what the model proposes (only text; nothing has run)
    request [T-501]              2. the four parts the PEP asks about, and where each one comes from
    check [T-501]                3. each hardened policy on its own, then all together: ALLOW or DENY
    rule [refund_ticket_order]   4. one Cedar policy, read part by part
    counter                      5. a rate limit: the PEP counts past calls (in memory only)
    receipt [8]                  6. one audit receipt from data/hunt-receipts.jsonl, field by field

    e.g. .venv/bin/python explore.py check T-601

`request`, `check` and `counter` need cedarpy (`make setup`, then `make check`).
Windows: `.venv\Scripts\python explore.py ...`.
Fake data only.
"""
from __future__ import annotations

import argparse
import json
import sys

sys.dont_write_bytecode = True  # read-only: importing the lab's modules must not write __pycache__/
import lab  # noqa: E402  (paths, fake data, canonical JSON; nothing runs on import)
import model  # noqa: E402  (reads tickets; nothing runs on import)

HARDENED = lab.SETUPS / "hardened"
SAYS = {  # one short line per shipped policy; any other policy shows the first line of its comment
    "refund_ticket_order": "support or supervisor, and the order is the ticket customer's",
    "refund_over_100_needs_approval": "over $100 needs another supervisor's approval",
    "refund_amount_sane": "more than 0, in USD, not more than the order cost",
    "max_3_refunds_per_hour": "at most 3 refunds an hour per signed-in user",
    "lookup_ticket_order": "look up only the ticket customer's orders",
    "email_ticket_requester_only": "email only the person who raised the ticket",
}
START = 1802509200.0  # 2027-02-13T09:00:00Z, the lab's pinned clock


# ---------------------------------------------------------------------------------------------------- helpers
def _state_rows(name: str) -> list[dict]:
    """Read a state file if it exists, without creating state/ (lab.state_dir() would)."""
    import os
    import pathlib
    d = pathlib.Path(os.environ.get("M21_STATE", lab.LAB / "state"))
    return lab.read_jsonl(d / name) if (d / name).exists() else []


def _first_refund(tid: str) -> tuple[str, str, bool]:
    calls = model.plan(model.read_ticket(tid))
    for tool, raw, injected in calls:
        if tool == "issue_refund":
            return tool, raw, injected
    return calls[0]


def _ticket(tid: str) -> model.Ticket:
    try:
        return model.read_ticket(tid)
    except FileNotFoundError:
        sys.exit(f"no ticket {tid} in data/tickets/")


def _build(user: str, t: model.Ticket, tool: str, raw: str) -> dict:
    """The same request the hardened PEP builds (pep.py _request), with counters read but never written."""
    args = json.loads(raw)
    oid = args.get("order_id")
    o = lab.ORDERS.get(oid, {})
    refunded = sum(r["paid_cents"] for r in _state_rows("ledger.jsonl") if r["order_id"] == oid)
    now = lab.CLOCK.now()
    rows = _state_rows("receipts.jsonl")
    window = {"refunds_1h": sum(1 for r in rows if r["principal"] == user and r["tool"] == "issue_refund"
                                and r["decision"] == "ALLOW" and now - r["t"] < 3600),
              "denials_10m": sum(1 for r in rows if r["principal"] == user and r["decision"] == "DENY"
                                 and now - r["t"] < 600)}
    if tool == "send_email":
        resource = {"type": "TSG::Ticket", "id": t.id, "attrs": {"requester": t.requester}}
    else:
        resource = {"type": "TSG::Order", "id": oid,
                    "attrs": {"customer": o.get("customer"), "total_cents": o.get("total_cents"),
                              "refunded_cents": refunded}}
    return {"principal": {"type": "TSG::User", "id": user, "attrs": {"role": lab.STAFF[user]["role"]}},
            "action": tool, "resource": resource,
            "context": {"input": args, "ticket": {"id": t.id, "requester": t.requester},
                        "window": window, "approval": {"verified": False}}}


def _policies() -> list[tuple[str, str, str, str]]:
    """(id, effect, first comment line, text) for every hardened policy file."""
    out = []
    for f in sorted((HARDENED / "policies").glob("*.cedar")):
        text = f.read_text()
        note = SAYS.get(f.stem) or next((ln[2:].strip() for ln in text.splitlines() if ln.startswith("//")), "")[:60]
        effect = "forbid" if "\nforbid" in "\n" + text else "permit"
        out.append((f.stem, effect, note, text))
    return out


def _decide(req: dict, text: str):
    import pdp  # needs cedarpy
    eng = pdp.CedarPDP.__new__(pdp.CedarPDP)
    eng.text, eng.schema = text, lab.SCHEMA.read_text()
    return eng.decide(req)


def _need_cedar():
    try:
        import cedarpy  # noqa: F401
    except ImportError:
        sys.exit("this step asks the Cedar engine: run `make setup` first (or activate .venv)")


# ---------------------------------------------------------------------------------------------------- commands
def cmd_call(a) -> int:
    t = _ticket(a.ticket)
    print(f"Ticket {t.id} from {t.requester} about order {t.order} (data/tickets/{t.id}.md)")
    print(f'  "{t.body.splitlines()[0][:100]}"\n')
    tool, raw, injected = _first_refund(t.id)
    print("The model proposes this tool call. It is only text: nothing has run yet.")
    print(json.dumps({"tool": tool, "arguments": json.loads(raw)}, indent=2))
    if injected:
        print("(this call comes from an instruction hidden in the ticket)")
    print("\nIts whole plan for this ticket, one tool call per line:")
    for i, (tl, r, inj) in enumerate(model.plan(t), 1):
        print(f"  {i}. {tl:<13} {r[:90]}" + ("   <- hidden instruction" if inj else ""))
    print("\nThe model proposes. The Helpdesk's code (the PEP) decides whether each call runs.")
    return 0


def cmd_request(a) -> int:
    _need_cedar()
    t = _ticket(a.ticket)
    tool, raw, _ = _first_refund(t.id)
    req = _build(a.user, t, tool, raw)
    print(f"What the PEP asks the policy engine about {tool} on ticket {t.id}, and where each part comes from\n")
    print(f"  principal  {req['principal']['id']} (role {req['principal']['attrs']['role']})")
    print("             WHO is asking: the signed-in user, from the session; the model can't change it")
    print(f"  action     {req['action']}")
    print("             WHAT they want to do: the tool's name")
    r = req["resource"]
    print(f"  resource   {r['type']} {r['id']}: customer {r['attrs'].get('customer')}, total "
          f"{r['attrs'].get('total_cents')} cents")
    print("             ON WHAT: the order the argument names, looked up in data/orders.json")
    c = req["context"]
    print(f"  context    input   {json.dumps(c['input'])}")
    print("                     the arguments: the ONLY part that came from the model")
    print(f"             ticket  {json.dumps(c['ticket'])}   from the ticket the user opened")
    print(f"             window  {json.dumps(c['window'])}   counted from past receipts")
    print(f"             approval {json.dumps(c['approval'])}   a signed approval, if there is one")
    return 0


def cmd_check(a) -> int:
    _need_cedar()
    t = _ticket(a.ticket)
    tool, raw, injected = _first_refund(t.id)
    req = _build(a.user, t, tool, raw)
    print(f"Ticket {t.id}: {a.user} ({lab.STAFF[a.user]['role']}) proposes {tool} {raw}")
    print(f"The order's customer: {req['resource']['attrs'].get('customer')}   the ticket's requester: {t.requester}\n")
    print("Each hardened policy on its own (setups/hardened/policies), asked of the real Cedar engine:")
    pols = _policies()
    mine = [p for p in pols if f'action == TSG::Action::"{tool}"' in p[3] or "action ==" not in p[3]]
    for pid, effect, note, text in sorted(mine, key=lambda p: (p[1] != "permit", p[0])):
        d = _decide(req, text)
        hit = (d.effect == "Allow") if effect == "permit" else (pid in d.policies)
        defer = '  @on_deny("defer")' if '@on_deny("defer")' in text else ""
        print(f"  {effect:<7} {pid:<32} {'MATCHES' if hit else 'no':<8} {note}{defer}")
    if len(pols) > len(mine):
        print(f"  ({len(pols) - len(mine)} more policies are about other tools)")
    d = _decide(req, "\n".join(p[3] for p in pols))
    word = {"Allow": "ALLOW", "Deny": "DENY"}.get(d.effect, "NO DECISION")
    print(f"\nAll together: {word}   determined by: {', '.join(d.policies) or 'nothing'}")
    if d.effect == "Allow":
        print("Why: a permit matches and no forbid does.")
    elif d.policies:
        print("Why: a forbid that matches wins over any permit.")
        if all('@on_deny("defer")' in p[3] for p in pols if p[0] in d.policies):
            print('It is marked @on_deny("defer"): the PEP holds the call for a supervisor instead of refusing it.')
    else:
        print("Why: no permit matches, so the answer is no (default deny).")
    return 0


def cmd_rule(a) -> int:
    f = HARDENED / "policies" / f"{a.name}.cedar"
    if not f.exists():
        sys.exit(f"no policy {a.name}. Policies: {', '.join(p[0] for p in _policies())}")
    text = f.read_text()
    print(f"setups/hardened/policies/{f.name}\n")
    for ln in text.splitlines():
        print(f"  {ln}")
    print("\nRead it part by part:")
    body = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("//")]
    for ln in body:
        if ln.startswith("@id"):
            print(f"  {ln:<52} a name for the rule; decisions report it")
        elif ln.startswith("@on_deny"):
            print(f"  {ln:<52} a note for the PEP: ask a person instead of refusing")
        elif ln.startswith(("permit", "forbid")):
            effect = ln.split()[0]
            print(f"  {effect:<52} the effect: {'allow' if effect == 'permit' else 'refuse'} when this rule matches")
            scope = ln[ln.index("(") + 1:].rstrip(")").split(", ")
            for part, what in zip(scope, ("WHO: any user, unless narrowed below", "WHAT: the action (tool)",
                                          "ON WHAT: the resource")):
                print(f"    {part:<50} {what}")
        elif ln.startswith(("when", "unless")):
            kind = ln.split()[0]
            print(f"  {kind:<52} {'only if' if kind == 'when' else 'except if'} everything inside is true")
        elif ln not in ("};", "}"):
            print(f"    {ln}")
    print("  (&& means AND: every line inside must be true)")
    return 0


def cmd_counter(a) -> int:
    _need_cedar()
    t = _ticket("T-501")
    tool, raw, _ = _first_refund(t.id)
    text = "\n".join(p[3] for p in _policies())
    print("A rate limit: at most 3 refunds an hour per signed-in user (max_3_refunds_per_hour.cedar)")
    print("The PEP counts bob's ALLOWED refunds in the last 60 minutes and passes the number as context.window.")
    print("Here the past calls are a list in memory: nothing is written.\n")
    allowed: list[float] = []
    for minutes in (0, 10, 20, 30, 65):
        now = START + minutes * 60
        req = _build("bob", t, tool, raw)
        req["context"]["window"]["refunds_1h"] = sum(1 for x in allowed if now - x < 3600)
        d = _decide(req, text)
        word = "ALLOW" if d.effect == "Allow" else "DENY "
        if d.effect == "Allow":
            allowed.append(now)
        print(f"  {lab.iso(now)[11:16]}  bob  {tool} {json.loads(raw)['order_id']} {json.loads(raw)['amount_cents']} cents"
              f"   refunds_1h = {req['context']['window']['refunds_1h']}   -> {word} [{', '.join(d.policies)}]")
    print("\nAt 10:05 the 09:00 refund is more than an hour old, so it no longer counts.")
    return 0


def cmd_receipt(a) -> int:
    rows = lab.read_jsonl(lab.DATA / "hunt-receipts.jsonl")
    match = [r for r in rows if r["seq"] == a.seq]
    if not match:
        sys.exit(f"no receipt #{a.seq}: data/hunt-receipts.jsonl has #1 to #{len(rows)}")
    r = match[0]
    print(f"Receipt #{r['seq']} of {len(rows)} (data/hunt-receipts.jsonl, a sample morning), field by field\n")
    show = [("time", "when the PEP decided"), ("principal", "who asked (from the session)"),
            ("ticket", "which ticket they had open"), ("tool", "which tool"), ("raw_args", "the exact arguments"),
            ("decision", "ALLOW, DENY or DEFER"), ("policies", "the rules that decided (empty = default deny)"),
            ("reason", "in words"), ("ran", "did the tool run?"), ("prev", "the hash of the receipt before this one"),
            ("hash", "SHA-256 of this receipt's content"), ("sig", "the signature over that content")]
    for k, what in show:
        v = r[k]
        v = (v[:16] + "...") if k in ("prev", "hash", "sig") else (json.dumps(v) if not isinstance(v, str) else v)
        print(f"  {k:<10} {str(v)[:58]:<60} {what}")
    body = lab.canonical({k: v for k, v in r.items() if k not in ("hash", "sig")})
    ok = lab.sha256(body) == r["hash"]
    prev_ok = r["seq"] == 1 or rows[r["seq"] - 2]["hash"] == r["prev"]
    print(f"\nRecomputed hash matches: {'yes' if ok else 'NO'}   links to receipt #{r['seq'] - 1}: "
          f"{'yes' if prev_ok else 'NO'}")
    print("Change one character and the hash no longer matches. `make audit` checks every signature too.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("call", "request", "check"):
        p = sub.add_parser(name)
        p.add_argument("ticket", nargs="?", default="T-501")
        p.add_argument("--as", dest="user", default="bob", choices=sorted(lab.STAFF))
    sub.add_parser("rule").add_argument("name", nargs="?", default="refund_ticket_order")
    sub.add_parser("counter")
    sub.add_parser("receipt").add_argument("seq", nargs="?", type=int, default=8)
    a = ap.parse_args()
    return {"call": cmd_call, "request": cmd_request, "check": cmd_check, "rule": cmd_rule,
            "counter": cmd_counter, "receipt": cmd_receipt}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
