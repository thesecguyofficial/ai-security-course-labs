"""
pep.py: the policy enforcement point. Every tool call the agent proposes goes through PEP.handle() before any tool
runs. The model proposes; this code decides what is asked of the policy engine, and what happens with the answer.

    parse the arguments -> is the tool in OUR catalogue? -> who is asking (from the session) -> load the resource
    (from our database) -> build the context (ticket, counters, approval) -> ask the PDP -> ALLOW / DENY / DEFER
    -> run the tool with the arguments the policy saw -> write a signed receipt

The setup's pep.json switches each design choice; setups/first-draft/pep.json makes the common mistakes on purpose.

    python3 pep.py hardened bob T-501 issue_refund '{"order_id": "O-1001", "amount_cents": 4500, "currency": "USD"}'
"""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass, field

import approvals
import lab
import pdp as pdp_mod
import receipts
import tools

PENDING_SUPERVISOR = {"type": "TSG::User", "id": "pending-supervisor", "attrs": {"role": "supervisor"}}


@dataclass
class Session:
    """What the Helpdesk web app knows for sure: who signed in, and which ticket they opened. Not from the model."""
    user: str
    ticket: str
    requester: str


@dataclass
class Outcome:
    decision: str                 # ALLOW | DENY | DEFER
    ran: bool
    text: str                     # what the model is told
    policies: list = field(default_factory=list)
    reason: str = ""
    approval_id: str | None = None
    receipt: dict | None = None


class StrictJSONError(ValueError):
    pass


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    dup = {k for k in keys if keys.count(k) > 1}
    if dup:
        raise StrictJSONError(f"duplicate key(s) {sorted(dup)}")
    return dict(pairs)


def _reject_constant(name):
    raise StrictJSONError(f"{name} is not a JSON number")


def parse_strict(raw) -> dict:
    """Parse ONCE, refuse anything ambiguous. The policy and the tool then use this same dict."""
    if isinstance(raw, dict):
        raw = json.dumps(raw)
    val = json.loads(raw, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    if not isinstance(val, dict):
        raise StrictJSONError("arguments must be a JSON object")
    return val


def parse_first_wins(raw) -> dict:
    """FIRST DRAFT: a quick parse for the policy check. When a key appears twice, the first one wins."""
    if isinstance(raw, dict):
        return raw
    return json.loads(raw, object_pairs_hook=lambda pairs: {k: v for k, v in reversed(pairs)})


class PEP:
    def __init__(self, setup: str, mode: str | None = None, engine: str = "cedar"):
        self.setup = setup
        cfg = json.loads((lab.SETUPS / setup / "pep.json").read_text())
        cfg.pop("_comment", None)
        self.cfg = cfg
        self.mode = mode or cfg["mode"]
        self.engine = engine
        if engine == "opa" and setup != "hardened":
            raise SystemExit("rego/tools.rego holds the HARDENED rules only: use --engine opa with the hardened setup")
        self.catalogue = {k: v for k, v in json.loads(lab.CATALOGUE.read_text()).items() if not k.startswith("_")}
        partner = json.loads(lab.PARTNER.read_text())
        self.partner = {t["name"]: t for t in partner["tools"]}
        self.load_error = None
        try:
            self.pdp = pdp_mod.make(engine, lab.SETUPS / setup / "policies", cfg["validate_with_schema"])
        except pdp_mod.PolicyLoadError as e:
            self.pdp, self.load_error = None, str(e)

    # ------------------------------------------------------------------------------------------------ the request
    def _resource(self, tool: str, args: dict, s: Session):
        spec = self.catalogue[tool]["resource"]
        if spec.get("from_session") == "ticket":
            return {"type": "TSG::Ticket", "id": s.ticket, "attrs": {"requester": s.requester}}
        oid = args.get(spec["from_arg"])
        o = lab.ORDERS.get(oid) if isinstance(oid, str) else None
        if o is None:
            return None
        return {"type": "TSG::Order", "id": oid,
                "attrs": {"customer": o["customer"], "total_cents": o["total_cents"],
                          "refunded_cents": tools.refunded_cents(oid)}}

    def _request(self, principal: str, tool: str, args: dict, resource: dict, s: Session, approval: dict) -> dict:
        ctx = {"input": args, "ticket": {"id": s.ticket, "requester": s.requester}}
        if self.cfg["window_counters"]:
            ctx["window"] = receipts.window(principal, lab.CLOCK.now())
        if self.cfg["approval"] == "signed-and-bound":
            ctx["approval"] = approval
        return {"principal": {"type": "TSG::User", "id": principal,
                              "attrs": {"role": lab.STAFF.get(principal, {}).get("role", "none")}},
                "action": tool, "resource": resource, "context": ctx}

    # ------------------------------------------------------------------------------------------------ handle a call
    def handle(self, s: Session, tool: str, raw_args) -> Outcome:
        cfg, rid = self.cfg, uuid.uuid4().hex[:12]
        self._parsed = None
        self.last_request = None
        rec = {"t": lab.CLOCK.now(), "time": lab.iso(lab.CLOCK.now()), "setup": self.setup, "mode": self.mode,
               "engine": self.engine, "request_id": rid, "principal": s.user, "ticket": s.ticket, "tool": tool,
               "raw_args": raw_args if isinstance(raw_args, str) else json.dumps(raw_args)}

        # 1. Parse the arguments.
        try:
            if cfg["parse"] == "strict":
                args = tool_args = parse_strict(raw_args)
            else:
                args = parse_first_wins(raw_args)
                tool_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except (ValueError, TypeError) as e:
            return self._finish(rec, "DENY", f"arguments refused: {e}", [], [], None, None, s)
        rec["args_sha256"] = lab.sha256(lab.canonical(args))
        self._parsed = tool_args          # LOG_ONLY runs refused calls with these

        # 2. Who is asking? The session says. (The first draft lets the arguments say.)
        principal = s.user
        if cfg["principal"] == "args-then-session" and isinstance(args.get("acting_for"), str) \
                and args["acting_for"] in lab.STAFF:
            principal = args["acting_for"]
        rec["principal"] = principal

        # 3. Is this a tool we know?
        if tool not in self.catalogue:
            ann = self.partner.get(tool, {}).get("annotations", {})
            if cfg["unknown_tools"] == "trust-annotations" and tool in self.partner and ann.get("readOnlyHint"):
                return self._finish(rec, "ALLOW", "not in our catalogue; the server says readOnlyHint=true, so allowed "
                                    "without a policy check", [], [], tool_args, None, s, partner=True)
            return self._finish(rec, "DENY", "not in our tool catalogue (deny by default; server annotations are "
                                "not trusted)", [], [], None, None, s)

        # 4. The policy engine must be loaded.
        if self.pdp is None:
            if cfg["engine_error"] == "allow":
                return self._finish(rec, "ALLOW", f"policy engine failed to load, allowed anyway: {self.load_error}",
                                    [], [self.load_error], tool_args, None, s)
            return self._finish(rec, "DENY", f"policy engine unavailable, failing closed: {self.load_error}",
                                [], [self.load_error], None, None, s)

        # 5. The resource comes from our database, picked by the argument that names it.
        resource = self._resource(tool, args, s)
        if resource is None:
            if cfg["no_decision"] == "deny":
                return self._finish(rec, "DENY", "unknown resource (fail closed)", [], [], None, None, s)
            resource = {"type": "TSG::Order", "id": str(args.get("order_id")), "attrs": {}}

        # 6. Approval: the hardened PEP looks for a signed approval bound to these exact arguments.
        approval, approval_id = {"verified": False}, None
        if cfg["approval"] == "signed-and-bound":
            found = approvals.find_bound(principal, s.ticket, tool, args)
            if found:
                ap = found["approver"]
                approval = {"verified": True, "approver": {"type": "TSG::User", "id": ap,
                                                           "attrs": {"role": lab.STAFF[ap]["role"]}}}
                approval_id = found["id"]
        elif "approval_id" in args:       # FIRST DRAFT: the model names an approval; we check it exists
            found = approvals.get(str(args["approval_id"]))
            if not found or found["status"] not in ("approved", "used"):
                return self._finish(rec, "DENY", f"approval {args['approval_id']} not found or not approved",
                                    [], [], None, None, s)
            approval_id = found["id"]

        # 7. Ask the PDP.
        req = self._request(principal, tool, args, resource, s, approval)
        try:
            d = self.pdp.decide(req)
        except Exception as e:  # an engine crash is the same as no answer
            d = pdp_mod.Decision("NoDecision", [], [f"engine error: {e}"])
        self.last_request = req

        if d.effect == "Allow":
            return self._finish(rec, "ALLOW", "permitted", d.policies, d.errors, tool_args, approval_id, s)
        if d.effect == "NoDecision":
            why = "; ".join(d.errors)[:200]
            if cfg["no_decision"] == "allow":          # the first draft checks "is it Deny?", not "is it Allow?"
                return self._finish(rec, "ALLOW", f"no decision ({why}): not a Deny, so allowed", [], d.errors,
                                    tool_args, approval_id, s)
            return self._finish(rec, "DENY", f"invalid request, failing closed: {why}", [], d.errors, None, None, s)

        # 8. Deny. Should a human decide instead? Only if every deciding policy says @on_deny("defer") AND the same
        #    call would be allowed once approved.
        if d.policies and set(d.policies) <= self.pdp.defer_ids:
            if cfg["approval"] == "signed-and-bound":
                hyp = self._request(principal, tool, args, resource, s,
                                    {"verified": True, "approver": PENDING_SUPERVISOR})
            else:
                hyp = self._request(principal, tool, {**args, "approval_id": "PENDING"}, resource, s, approval)
            if self.pdp.decide(hyp).effect == "Allow":
                a = approvals.request(principal, s.ticket, tool, args)
                if cfg["approval"] == "signed-and-bound":
                    msg = (f"held for approval {a['id']}: a supervisor reviews this exact call. Once approved, "
                           f"make the same call again.")
                else:
                    msg = (f"held for approval {a['id']}. Once a supervisor approves, call {tool} again with "
                           f"approval_id={a['id']}.")
                return self._finish(rec, "DEFER", msg, d.policies, d.errors, tool_args, a["id"], s)
        reason = f"forbidden by {', '.join(d.policies)}" if d.policies else "no policy permits this (denied by default)"
        return self._finish(rec, "DENY", reason, d.policies, d.errors, None, None, s)

    # ------------------------------------------------------------------------------------------------ act and record
    def _finish(self, rec, decision, reason, policies, errors, tool_args, approval_id, s, partner=False) -> Outcome:
        if decision != "ALLOW" and self.mode == "LOG_ONLY":
            tool_args = self._parsed       # LOG_ONLY: decide and record, but run the call anyway
            partner = rec["tool"] in tools.PARTNER_TOOLS
        known = rec["tool"] in (tools.PARTNER_TOOLS if partner else tools.TOOLS)
        run = tool_args is not None and known and (decision == "ALLOW" or self.mode == "LOG_ONLY")
        text = ""
        if run:
            fn = tools.PARTNER_TOOLS[rec["tool"]] if partner else tools.TOOLS[rec["tool"]]
            ctx = {"staff": rec["principal"], "request_id": rec["request_id"],
                   "approval_id": approval_id if decision == "ALLOW" else None}
            text = fn(_ctx=ctx, **{k: v for k, v in tool_args.items() if not k.startswith("_")})
            if decision == "ALLOW" and approval_id and self.cfg["approval"] == "signed-and-bound":
                approvals.mark_used(approval_id)
        if decision == "DENY" and not run:
            text = f"REFUSED by policy: {reason}"
        elif decision == "DEFER" and not run:
            text = reason
        rec.update(decision=decision, ran=run, reason=reason, policies=list(policies), errors=[str(e)[:200] for e in errors],
                   approval_id=approval_id, outcome=str(text)[:200])
        receipt = receipts.append(rec)
        return Outcome(decision, run, text, list(policies), reason, approval_id, receipt)


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    setup, user, ticket, tool, raw = sys.argv[1:]
    import model
    t = model.read_ticket(ticket)
    pep = PEP(setup)
    out = pep.handle(Session(user, t.id, t.requester), tool, raw)
    if pep.last_request:
        print("asked the policy engine:")
        for k, v in pep.last_request.items():
            print(f"  {k:<9} {json.dumps(v)}")
    print(f"decision: {out.decision}   ran: {out.ran}   policies: {', '.join(out.policies) or '-'}")
    print(f"reason:   {out.reason}")
    print(f"model is told: {out.text[:160]}")


if __name__ == "__main__":
    main()
