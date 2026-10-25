"""
helpdesk.py: the TSG Helpdesk agent working one ticket for a signed-in staff member. Every tool call goes through
the PEP (pep.py). Nothing leaves this folder.

    python3 helpdesk.py first-draft T-602 --as bob           # an injected $950 refund
    python3 helpdesk.py hardened T-602 --as bob              # the same ticket, hardened PEP
    python3 helpdesk.py hardened T-502 --as bob              # a real $250 refund: held for a supervisor
    python3 approvals.py approve APR-0001 --as alice
    python3 helpdesk.py hardened T-502 --as bob --after-approval
    python3 helpdesk.py hardened T-602 --as bob --mode LOG_ONLY   # decide, record, but enforce nothing
    python3 helpdesk.py hardened T-501 --as bob --engine opa      # same PEP, OPA as the decision point (needs opa)
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field

import lab
import model
import tools
from pep import PEP, Session


@dataclass
class Step:
    tool: str
    raw: str
    injected: bool
    decision: str
    ran: bool
    text: str
    policies: list
    reason: str


@dataclass
class Run:
    ticket: str
    steps: list = field(default_factory=list)


def _notes():
    p = lab.state_dir() / "agent_notes.json"
    return p, (json.loads(p.read_text()) if p.exists() else {})


def run_ticket(pep: PEP, user: str, ticket_id: str, after_approval: bool = False, quiet: bool = False,
               step_seconds: float = 30) -> Run:
    t = model.read_ticket(ticket_id)
    s = Session(user, t.id, t.requester)
    path, notes = _notes()
    memo = notes.get(t.id, {})
    run, last, rids = Run(t.id), "", set()
    if not quiet:
        role = lab.STAFF.get(user, {}).get("role", "?")
        print(f"TICKET {t.id} from {t.requester} about {t.order}, worked by {user} ({role}) | setup {pep.setup} | "
              f"mode {pep.mode} | engine {pep.engine}")
    for i, (tool, raw, injected) in enumerate(model.plan(t, "after_approval" if after_approval else "first"), 1):
        raw = model.fill(raw, last, memo.get("approval_id"), memo.get("told_to_add", False), injected)
        out = pep.handle(s, tool, raw)
        if out.decision == "DEFER" and out.approval_id:
            memo = {"approval_id": out.approval_id, "told_to_add": "approval_id=" in out.text}
            notes[t.id] = memo
            path.write_text(json.dumps(notes, indent=2))
        last = out.text
        rids.add(out.receipt["request_id"])
        run.steps.append(Step(tool, raw, injected, out.decision, out.ran, out.text, out.policies, out.reason))
        if not quiet:
            if injected:
                print("  MODEL  following an instruction hidden in the ticket")
            shown = raw if len(raw) <= 100 else raw[:97] + "..."
            ran = "" if out.decision == "ALLOW" else (" (RAN ANYWAY: LOG_ONLY)" if out.ran else "")
            pol = f" [{', '.join(out.policies)}]" if out.policies else ""
            print(f"  STEP {i}  {tool} {shown}\n          -> {out.decision}{pol}{ran}  {out.text[:110]}")
        if lab.CLOCK._fixed is not None:
            lab.CLOCK.advance(step_seconds)
    if not quiet:
        mine = [r for r in tools.ledger() if r["request_id"] in rids]
        paid = ", ".join(f"{r['order_id']} ${r['paid_cents'] / 100:,.2f}" for r in mine) or "none"
        held = [st for st in run.steps if st.decision == "DEFER"]
        print(f"--- outcome --- refunds paid this run: {paid} | held for approval: {len(held)} "
              f"| emails sent this run: {sum(1 for st in run.steps if st.tool == 'send_email' and st.ran)} "
              f"| rows sent to the partner: {len(tools.partner_outbox())}")
    return run


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("setup", choices=["first-draft", "hardened"])
    ap.add_argument("ticket")
    ap.add_argument("--as", dest="user", default="bob")
    ap.add_argument("--after-approval", action="store_true")
    ap.add_argument("--mode", choices=["ENFORCE", "LOG_ONLY"])
    ap.add_argument("--engine", choices=["cedar", "opa"], default="cedar")
    a = ap.parse_args()
    run_ticket(PEP(a.setup, a.mode, a.engine), a.user, a.ticket, a.after_approval)


if __name__ == "__main__":
    main()
