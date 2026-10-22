"""
parity.py: "without losing a single control". Every control the LOCAL Helpdesk had in labs M6 and M7, next to its AWS
equivalent in the port, and whether this setup still has it.

    python3 parity.py first-draft      # make parity
    python3 parity.py ported
    python3 parity.py harness

A control counts as KEPT only if its checker rules are quiet AND the attacks that test it fail. PARTIAL means the
configuration is right but an attack still gets through (the lab's challenge closes those). Exit code 1 if any LOST.
"""

from __future__ import annotations

import sys

import checker
import evaluate
import twin

# (local control, where it lived, AWS equivalent, checker rules, attacks)
CONTROLS = [
    ("Per-user retrieval from the SESSION, not the request", "M6 retrieve_safe",
     "Managed KB ACL awareness + userContext.userId from the signed-in session", ["M13-01", "M13-02", "M13-04"], ["A1", "A2"]),
    ("No model-chosen scope", "M6 retrieve_safe",
     "No implicit filtering on restricted content", ["M13-03"], ["A3"]),
    ("Who may write to the corpus", "M6 ingest_safe",
     "Bucket policy: staff uploads only to inbox/", ["M13-08"], []),
    ("Hidden-instruction screening / spotlighting", "M6 ingest_safe, M7 wrap_untrusted",
     "Strip comments + ApplyGuardrail on each chunk before the model reads it", ["M13-17"], []),
    ("Encrypted, owner-only store", "M6.4 hardening",
     "Customer managed KMS key; service role trust + S3 scoped to this KB", ["M13-06", "M13-07", "M13-09"], []),
    ("Tool allow-list per task", "M7 policy.json tasks",
     "Only the action groups / inline functions the Helpdesk needs; no code sandbox", ["M13-16"], ["A7"]),
    ("Human approval before writes, arguments shown", "M7 approval_card",
     "requireConfirmation ENABLED (Classic) or inline function + app confirmation (harness)", ["M13-12"], ["A4"]),
    ("Authorisation in code, caller from the session", "M7 check_data_scope",
     "Lambda / app reads the caller from the session and checks it (challenge 3)", ["M13-13"], ["A5"]),
    ("Least-privilege tool identity", "M7.4",
     "Lambda role scoped to one action; resource policy pinned to this agent; only the backend may invoke",
     ["M13-14", "M13-15", "M13-20"], ["A6", "A8"]),
    ("Append-only audit log", "M7 audit + verify_chain",
     "CloudTrail data events (KnowledgeBase, AgentAlias) + ingestion logs", ["M13-10", "M13-11", "M13-18"], []),
]


def run(setup_name: str | twin.Setup) -> list[dict]:
    s = setup_name if isinstance(setup_name, twin.Setup) else twin.Setup(setup_name)
    found = {f.rule for f in checker.run(s) if f.severity in ("HIGH", "MEDIUM")}
    low = {f.rule for f in checker.run(s) if f.severity == "LOW"}
    res = evaluate.run_suite(s)
    worked = {a["id"] for a in res["attacks"] if a["applicable"] and a["worked"]}
    rows = []
    for name, where, aws, rules, attacks in CONTROLS:
        bad_rules = [r for r in rules if r in found]
        bad_attacks = [a for a in attacks if a in worked]
        if bad_rules:
            status = "LOST"
        elif bad_attacks or any(r in low for r in rules):
            status = "PARTIAL"
        else:
            status = "KEPT"
        rows.append({"control": name, "local": where, "aws": aws, "status": status,
                     "why": ", ".join(bad_rules + bad_attacks + [r for r in rules if r in low])})
    return rows


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    name = argv[0] if argv else "first-draft"
    rows = run(name)
    print(f"Setup: {name}\n")
    for r in rows:
        print(f"  {r['status']:8} {r['control']}  [{r['local']}]")
        print(f"  {'':8} AWS: {r['aws']}")
        if r["why"]:
            print(f"  {'':8} because: {r['why']}")
    counts = {k: sum(r["status"] == k for r in rows) for k in ("KEPT", "PARTIAL", "LOST")}
    print(f"\nKept {counts['KEPT']} of {len(rows)} controls, partial {counts['PARTIAL']}, lost {counts['LOST']}")
    sys.exit(1 if counts["LOST"] else 0)


if __name__ == "__main__":
    main()
