#!/usr/bin/env python3
"""
explore.py: look at each governance idea on its own, before you assess the Helpdesk (M18 lab, "Understand the lab").

Read-only. It opens the lab's JSON and CSV files and prints them in plain words. It writes no file (not even
Python's __pycache__), starts no program, runs nothing from the lab and uses no network.

    python3 explore.py kinds          # 1. framework, standard, law, checklist: the documents this lab maps to
    python3 explore.py inventory      # 2. one AI inventory entry, field by field (default: the embedding model)
    python3 explore.py risk R1        # 3. one risk register row, column by column, scored on a 3 x 3 grid
    python3 explore.py control C24    # 4. one control, mapped to NIST AI RMF, ISO/IEC 42001, the EU AI Act and OWASP
    python3 explore.py evidence E01   # 5. one evidence row: the file, its hash then and now, and its age

Windows: `py explore.py ...` (or `python` instead of `py`). Fake data only.
"""
from __future__ import annotations

import argparse
import sys

sys.dont_write_bytecode = True  # read-only: importing govlab must not write __pycache__/
import govlab  # noqa: E402  (only its loading helpers; nothing in govlab runs on import)

KINDS = [
    ("nist_ai_rmf", "framework", "voluntary: advice you choose from; nobody certifies you against it"),
    ("iso_42001", "standard", "certifiable: an accredited auditor can certify an organisation against it"),
    ("eu_ai_act", "law", "binding where it applies, with fines; what applies depends on the system's purpose"),
    ("owasp", "checklist", "community lists of what most often goes wrong in code; free, no certificate"),
]
DRAFT = govlab.HERE / "first-draft"


def cmd_kinds(a) -> int:
    _, _, fw = govlab.catalog()
    print("Four kinds of document this lab maps controls to (catalog/frameworks.json)\n")
    for key, kind, what in KINDS:
        f = fw[key]
        print(f"{kind:10} {f['name']}")
        print(f"{'':10} {what}")
        print(f"{'':10} {len(f['items'])} items in this lab's catalogue · {f['source']}\n")
    g = fw["nist_genai_risks"]
    print(f"{'profile':10} {g['name']}")
    print(f"{'':10} a companion to the NIST framework for generative AI, with {len(g['items'])} named risks")
    return 0


def cmd_inventory(a) -> int:
    card = govlab.system_card(None)
    comps = card["components"]
    match = [i for i, c in enumerate(comps) if a.component.lower() in (c["type"] + " " + c["name"]).lower()]
    if not match:
        sys.exit(f"no component matches '{a.component}'. Types: {', '.join(c['type'] for c in comps)}")
    i = match[0]
    c = comps[i]
    print(f"AI inventory entry {i + 1} of {len(comps)} (helpdesk/system-card.json, \"components\")\n")
    print(f"  system     {card['system']} {card['version']}, {card['status']} since {card['in_production_since']}")
    print(f"  owners     business: {card['business_owner']} · technical: {card['technical_owner']}")
    print(f"  type       {c['type']:30} what kind of part it is")
    print(f"  name       {c['name']}")
    print(f"  version    {c['version']:30} which exact build runs")
    print(f"  hosting    {c['hosting']:30} where it runs")
    flag = "<- a gap: nobody has checked what this licence allows" if c["licence"].lower() == "unknown" else ""
    print(f"  licence    {c['licence']:30} {flag}".rstrip())
    print(f"\nOne row per part, not one per app: {len(comps)} parts here "
          f"({', '.join(sorted({x['type'] for x in comps}))}).")
    return 0


def scored(l: int | None, i: int | None) -> str:
    return f"{l} x {i} = {l * i}" if l and i else "(not scored)"


def cmd_risk(a) -> int:
    controls, library, _ = govlab.catalog()
    statuses = govlab.system_card(None)["controls"]
    rows = {r["id"]: r for r in govlab.read_csv(DRAFT / "risk-register.csv")}
    if a.id not in rows:
        sys.exit(f"no risk {a.id} in first-draft/risk-register.csv. IDs: {', '.join(rows)}")
    r = rows[a.id]
    li, im = govlab.as_int(r["likelihood"]), govlab.as_int(r["impact"])
    rl, ri = govlab.as_int(r["res_likelihood"]), govlab.as_int(r["res_impact"])
    when = govlab.assessment_date(DRAFT)
    review = govlab.parse_date(r["review_date"])
    src = library.get(r["source"], {}).get("title", "not in the catalogue")
    ctl = ", ".join(f"{c} {statuses.get(c, 'unknown')}" if c in controls else f"{c} (not in catalogue)"
                    for c in govlab.split_ids(r["controls"])) or "(none)"
    print(f"Risk {a.id} from first-draft/risk-register.csv, column by column\n")
    print(f"  title       {r['title']}")
    print(f"  source      {r['source']}: {src}")
    print(f"  owner       {r['owner'] or '(blank)'}")
    print(f"  likelihood  {r['likelihood']:4} how likely, 1 to 3")
    print(f"  impact      {r['impact']:4} how bad, 1 to 3")
    print(f"  inherent    {scored(li, im):12} likelihood x impact, before any control")
    print(f"  treatment   {r['treatment']:12} one of mitigate, transfer, avoid, accept (NIST AI RMF MANAGE 1.3)")
    print(f"  controls    {ctl}")
    print(f"  residual    {scored(rl, ri):12} after the controls really in place")
    appetite = govlab.load_json(DRAFT / "assessment.json").get("risk_appetite", {}).get("max_residual_without_signoff", 3)
    print(f"  accepted by {r['accepted_by'] or '(blank)':12} needed above {appetite} (the AI policy's risk appetite)")
    days = f" ({(review - when).days} days after the assessment on {when})" if review else ""
    print(f"  review      {r['review_date']}{days}")
    print(f"  owasp       {r['owasp']}")
    print(f"  notes       {r['notes'] or '(blank)'}\n")
    print("  Likelihood x impact, I = inherent, R = residual (status of each control: helpdesk/system-card.json)")
    for imp in (3, 2, 1):
        cells = []
        for lik in (1, 2, 3):
            mark = ("I" if (lik, imp) == (li, im) else "") + ("R" if (lik, imp) == (rl, ri) else "")
            cells.append(f"{mark or '.':^5}")
        print(f"  impact {imp} |{''.join(cells)}".rstrip())
    print("           " + "".join(f"{'L' + str(n):^5}" for n in (1, 2, 3)).rstrip())
    return 0


def cmd_control(a) -> int:
    controls, _, fw = govlab.catalog()
    if a.id not in controls:
        sys.exit(f"no control {a.id} in catalog/controls.json")
    c = controls[a.id]
    status = govlab.system_card(None)["controls"].get(a.id, "not listed")
    print(f"Control {a.id} (catalog/controls.json): {c['name']}")
    print(f"  taught in   lesson {c['taught_in']}")
    print(f"  status      {status} in TSG Helpdesk (helpdesk/system-card.json)")
    print(f"  proved by   {c['evidence']}\n")
    print("  maps to")
    for key, label in (("nist", "nist_ai_rmf"), ("iso", "iso_42001"), ("eu", "eu_ai_act"), ("owasp", "owasp")):
        f = fw[label]
        ids = c.get(key, [])
        if not ids:
            print(f"  {label:12} (none mapped)")
        for x in ids:
            text = f["items"].get(x, "?")
            text = text.get("title", "?") if isinstance(text, dict) else text
            print(f"  {label:12} {x:12} {text}")
    return 0


def cmd_evidence(a) -> int:
    rows = {r["evidence_id"]: r for r in govlab.read_csv(DRAFT / "evidence-index.csv")}
    if a.id not in rows:
        sys.exit(f"no evidence row {a.id} in first-draft/evidence-index.csv. IDs: {', '.join(rows)}")
    r = rows[a.id]
    path = govlab.HERE / r["file"]
    when = govlab.assessment_date(DRAFT)
    print(f"Evidence row {a.id} from first-draft/evidence-index.csv\n")
    print(f"  control      {r['control']}")
    print(f"  file         {r['file']}")
    print(f"  owner        {r['owner']}")
    print(f"  collected    {r['collected']}")
    print(f"  sha256 then  {r['sha256']}   (written in the index)")
    if not path.is_file():
        print("  sha256 now   (file not found)")
        return 0
    now = govlab.sha256_file(path)
    print(f"  sha256 now   {now}   ({'same: unchanged since it was indexed' if now == r['sha256'] else 'DIFFERENT: the file changed'})")
    collected = govlab.parse_date(r["collected"])
    if collected:
        age = (when - collected).days
        print(f"  age          {age} days before the assessment on {when} (the lab allows {govlab.EVIDENCE_MAX_AGE_DAYS})")
    lines = path.read_text("utf-8", errors="replace").splitlines()
    print(f"\n  first lines of the file ({len(lines)} lines in all):")
    for ln in lines[:a.lines]:
        print(f"  | {ln[:110]}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Look at each governance idea on its own (read-only).")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("kinds", help="framework, standard, law, checklist")
    s = sub.add_parser("inventory", help="one AI inventory entry")
    s.add_argument("component", nargs="?", default="embedding")
    s = sub.add_parser("risk", help="one risk register row, scored")
    s.add_argument("id", nargs="?", default="R1")
    s = sub.add_parser("control", help="one control and its framework mappings")
    s.add_argument("id", nargs="?", default="C24")
    s = sub.add_parser("evidence", help="one evidence row, hash then and now")
    s.add_argument("id", nargs="?", default="E01")
    s.add_argument("--lines", type=int, default=6)
    a = p.parse_args(argv)
    return {"kinds": cmd_kinds, "inventory": cmd_inventory, "risk": cmd_risk, "control": cmd_control,
            "evidence": cmd_evidence}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
