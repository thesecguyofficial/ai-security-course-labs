#!/usr/bin/env python3
"""govlab.py: the M18 lab's governance toolkit. Python 3.11+, standard library only, no network.

    python3 govlab.py inventory [FOLDER]                     # the AI inventory rows for TSG Helpdesk
    python3 govlab.py triage [FOLDER] [--what-if hiring] [--as-of 2026-10-24]
    python3 govlab.py check FOLDER                           # lint a risk assessment: register, evidence, decisions
    python3 govlab.py crosswalk FOLDER [--framework nist|eu|iso|owasp|all]
    python3 govlab.py evidence FOLDER [--fill]               # verify the evidence index (--fill writes blank hashes)
    python3 govlab.py pack FOLDER [--draft]                  # build the evidence pack in out/
    python3 govlab.py verify-pack PACK_FOLDER                # an auditor's check that the pack is unchanged
    python3 govlab.py start                                  # copy the templates into my-assessment/

FOLDER is an assessment folder: first-draft/ (the team's draft, full of problems) or my-assessment/ (yours).
It holds assessment.json, risk-register.csv and evidence-index.csv, and may hold its own system-card.json and
chat-widget.html (otherwise the ones in helpdesk/ are used). Paths inside the evidence index are relative to this
lab folder (labs/m18).

The EU AI Act triage is a simplified decision aid for a lab, built from the official texts as of 24 Oct 2026
(Regulation (EU) 2024/1689 as amended in 2026). It is not a legal determination.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import pathlib
import re
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "out"

# EU AI Act application dates (Article 113 as amended by the Digital Omnibus on AI; Commission AI Act Service Desk
# timeline, checked 24 Oct 2026).
D_ART4 = dt.date(2025, 2, 2)        # AI literacy and prohibitions
D_GPAI = dt.date(2025, 8, 2)        # general-purpose AI model obligations
D_ART50 = dt.date(2026, 8, 2)       # transparency obligations
D_ART50_2_GRACE = dt.date(2026, 12, 2)  # Art. 50(2) marking, for systems placed on the market before 2 Aug 2026
D_ANNEX_III = dt.date(2027, 12, 2)  # stand-alone high-risk (Annex III)
D_ANNEX_I = dt.date(2028, 8, 2)     # high-risk in regulated products (Annex I)

ANNEX_III_AREAS = {
    "biometrics": "Biometrics (remote identification, categorisation, emotion recognition)",
    "critical_infrastructure": "Safety components in critical infrastructure",
    "education": "Education and vocational training",
    "employment": "Employment, workers' management and access to self-employment",
    "essential_services": "Access to essential private and public services (for example credit scoring)",
    "law_enforcement": "Law enforcement",
    "migration": "Migration, asylum and border control",
    "justice": "Administration of justice and democratic processes",
}
HIGH_RISK_ARTICLES = ["Art. 9", "Art. 10", "Art. 11", "Art. 12", "Art. 13", "Art. 14", "Art. 15", "Art. 72", "Art. 73"]

TREATMENTS = {"mitigate", "transfer", "avoid", "accept"}   # NIST AI RMF MANAGE 1.3 response options
CREDIT_STATUSES = {"implemented", "partial"}
CONTROL_STATUSES = CREDIT_STATUSES | {"planned", "not_applicable"}
VAGUE_OWNERS = {"", "tbd", "tba", "team", "the team", "everyone", "all", "n/a", "na", "-", "unknown", "?"}
EVIDENCE_MAX_AGE_DAYS = 90
REVIEW_MAX_DAYS = 183
REGISTER_COLUMNS = ["id", "title", "source", "owasp", "nist_genai", "owner", "likelihood", "impact", "treatment",
                    "controls", "res_likelihood", "res_impact", "accepted_by", "review_date", "notes"]
EVIDENCE_COLUMNS = ["evidence_id", "control", "file", "sha256", "collected", "owner", "description"]
DISCLOSURE_RE = re.compile(r"\b(AI|A\.I\.|artificial intelligence)\b.*\b(assistant|chatbot|bot|system|model)\b"
                           r"|\b(virtual|automated|AI)[- ](assistant|agent|chatbot)\b", re.I)


# ----------------------------------------------------------------------------------------------- loading
def load_json(path: pathlib.Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def catalog():
    return (load_json(HERE / "catalog" / "controls.json")["controls"],
            load_json(HERE / "catalog" / "risk-library.json")["sources"],
            load_json(HERE / "catalog" / "frameworks.json"))


def resolve_folder(name: str | None) -> pathlib.Path | None:
    if not name:
        return None
    p = pathlib.Path(name)
    if not p.is_absolute():
        p = (pathlib.Path.cwd() / p) if (pathlib.Path.cwd() / p).exists() else (HERE / p)
    if not p.is_dir():
        sys.exit(f"no such assessment folder: {name}  (try first-draft or my-assessment; 'make start' creates my-assessment)")
    return p.resolve()


def system_card(folder: pathlib.Path | None) -> dict:
    if folder and (folder / "system-card.json").exists():
        return load_json(folder / "system-card.json")
    return load_json(HERE / "helpdesk" / "system-card.json")


def widget_path(folder: pathlib.Path | None) -> pathlib.Path:
    if folder and (folder / "chat-widget.html").exists():
        return folder / "chat-widget.html"
    return HERE / "helpdesk" / "chat-widget.html"


def read_csv(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8", newline="") as f:
        rows = []
        for row in csv.DictReader(f):
            row = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            if any(row.values()):
                rows.append(row)
        return rows


def split_ids(cell: str) -> list[str]:
    return [x for x in re.split(r"[;,\s]+", cell or "") if x]


def parse_date(s: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat((s or "").strip())
    except ValueError:
        return None


def as_int(s: str) -> int | None:
    try:
        return int((s or "").strip())
    except ValueError:
        return None


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def assessment_date(folder: pathlib.Path) -> dt.date:
    a = load_json(folder / "assessment.json") if (folder / "assessment.json").exists() else {}
    return parse_date(a.get("date", "")) or dt.date(2026, 10, 24)


# ----------------------------------------------------------------------------------------------- inventory
INVENTORY_COLUMNS = ["system", "component", "type", "version", "hosting", "licence", "business_owner",
                     "technical_owner", "purpose", "users", "data", "tools", "autonomy", "eu_ai_act", "flags"]


def inventory_rows(card: dict) -> list[dict]:
    tri = triage(card, dt.date(2026, 10, 24))
    rows = []
    for c in card.get("components", []):
        flags = []
        for field in ("version", "licence", "hosting"):
            if str(c.get(field, "")).strip().lower() in {"", "unknown", "latest", "tbd"}:
                flags.append(f"{field} {c.get(field) or 'missing'}")
        rows.append({
            "system": card.get("system", ""), "component": c.get("name", ""), "type": c.get("type", ""),
            "version": c.get("version", ""), "hosting": c.get("hosting", ""), "licence": c.get("licence", ""),
            "business_owner": card.get("business_owner", ""), "technical_owner": card.get("technical_owner", ""),
            "purpose": card.get("purpose", ""), "users": card.get("users", ""),
            "data": "; ".join(card.get("data_categories", [])), "tools": "; ".join(card.get("tools", [])),
            "autonomy": card.get("autonomy", ""), "eu_ai_act": f"{tri['role']}; {tri['tier']}",
            "flags": "; ".join(flags)})
    return rows


def cmd_inventory(args) -> int:
    folder = resolve_folder(args.folder)
    card = system_card(folder)
    rows = inventory_rows(card)
    OUT.mkdir(exist_ok=True)
    with open(OUT / "ai-inventory.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=INVENTORY_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"AI inventory: {card['system']} {card.get('version', '')} ({card.get('status', '')}), "
          f"owner {card.get('business_owner', '?')}")
    print(f"{'type':16} {'component':58} flags")
    for r in rows:
        print(f"{r['type']:16} {r['component'][:58]:58} {r['flags'] or 'ok'}")
    flagged = [r for r in rows if r["flags"]]
    print(f"\n{len(rows)} components, {len(flagged)} with gaps. Full rows: out/ai-inventory.csv "
          "(columns as in templates/AI-INVENTORY.csv)")
    return 0


# ----------------------------------------------------------------------------------------------- triage
def triage(card: dict, as_of: dt.date, what_if: str | None = None) -> dict:
    eu = dict(card.get("eu_ai_act", {}))
    if what_if == "hiring":
        eu["annex_iii_area"] = "employment"
    role = "provider" if eu.get("built_and_run_under_our_name") else "deployer"
    obligations, notes = [], []

    def status(start: dt.date) -> str:
        return "APPLIES NOW" if as_of >= start else f"DUE {start.isoformat()}"

    if not eu.get("offered_in_eu"):
        return {"in_scope": False, "role": role, "tier": "out of scope (no EU nexus selected)", "high_risk": False,
                "obligations": [], "notes": ["Check Article 2 (scope) with your legal team before relying on this."]}
    prohibited = (eu.get("prohibited_practice") or "none").lower() != "none"
    area = (eu.get("annex_iii_area") or "none").lower()
    annex_i = bool(eu.get("annex_i_safety_component"))
    if prohibited:
        tier = "PROHIBITED (Art. 5): stop and escalate"
    elif annex_i:
        tier = "HIGH-RISK (Annex I product)"
    elif area != "none":
        tier = f"HIGH-RISK (Annex III: {ANNEX_III_AREAS.get(area, area)})"
    elif eu.get("interacts_with_people") or eu.get("generates_text_or_media") or eu.get("deepfake_or_public_interest_text"):
        tier = "TRANSPARENCY (Art. 50)"
    else:
        tier = "MINIMAL (no specific obligations beyond Art. 4)"

    obligations.append(("Art. 4", "AI literacy: take measures to support it for staff and others who use the system",
                        status(D_ART4)))
    if prohibited:
        obligations.append(("Art. 5", "Prohibited practice selected: the system may not be placed on the market or used",
                            status(D_ART4)))
    if eu.get("interacts_with_people") and role == "provider":
        obligations.append(("Art. 50(1)", "Tell people they are interacting with an AI system, at the latest at the first "
                            "interaction (unless obvious)", status(D_ART50)))
    if eu.get("generates_text_or_media") and role == "provider":
        placed = parse_date(eu.get("placed_on_market", ""))
        start = D_ART50_2_GRACE if (placed and placed < D_ART50) else D_ART50
        obligations.append(("Art. 50(2)", "Mark generated content in a machine-readable way (text is in scope, with "
                            "exclusions: confirm with legal)", status(start)))
    if eu.get("deepfake_or_public_interest_text"):
        obligations.append(("Art. 50(4)", "Disclose deep fakes and AI-generated public-interest text", status(D_ART50)))
    high = annex_i or area != "none"
    if high and not prohibited:
        start = D_ANNEX_I if annex_i else D_ANNEX_III
        if role == "provider":
            titles = load_json(HERE / "catalog" / "frameworks.json")["eu_ai_act"]["items"]
            for art in HIGH_RISK_ARTICLES:
                obligations.append((art, titles[art]["title"], status(start)))
            obligations.append(("Art. 16", "Obligations of providers of high-risk AI systems (conformity assessment, "
                                "registration and more)", status(start)))
        else:
            obligations.append(("Art. 26", "Obligations of deployers of high-risk AI systems", status(start)))
            obligations.append(("Art. 73", "Report serious incidents (with the provider)", status(start)))
        if what_if:
            notes.append("What-if: you built the Helpdesk, so you are already its provider. Had you re-purposed a "
                         "vendor's system like this, Art. 25(1) would make you the provider of a high-risk system.")
    else:
        notes.append("Arts. 9 to 15, 26, 72 and 73 apply to high-risk systems only: use them here as good practice.")
    notes.append("The maker of the general-purpose model you build on has its own duties (since "
                 f"{D_GPAI.isoformat()}); ask for its documentation in your vendor review.")
    return {"in_scope": True, "role": role, "tier": tier, "high_risk": high, "obligations": obligations, "notes": notes}


def cmd_triage(args) -> int:
    folder = resolve_folder(args.folder)
    card = system_card(folder)
    as_of = parse_date(args.as_of) if args.as_of else (assessment_date(folder) if folder else dt.date(2026, 10, 24))
    if not as_of:
        sys.exit(f"--as-of needs a date like 2026-10-24, got {args.as_of}")
    t = triage(card, as_of, args.what_if)
    title = f"EU AI Act triage: {card['system']} (as of {as_of.isoformat()})"
    if args.what_if:
        title += f", what-if: {args.what_if}"
    print(title)
    print("Triage only: confirm the result with your legal team.\n")
    eu = card.get("eu_ai_act", {})
    print(f"{'In scope?':14} {'yes' if t['in_scope'] else 'no'}: offered in the EU = {bool(eu.get('offered_in_eu'))} "
          f"(markets: {', '.join(card.get('markets', []))})")
    who = ("you build it and run it under your own name, Art. 3(3)" if t["role"] == "provider"
           else "you use someone else's system under your authority, Art. 3(4)")
    print(f"{'Your role':14} {t['role'].upper()} of the AI system ({who})")
    print(f"{'Prohibited?':14} {'YES' if (eu.get('prohibited_practice') or 'none') != 'none' else 'no Art. 5 practice selected'}")
    print(f"{'Risk tier':14} {t['tier']}")
    if t["obligations"]:
        print("\nObligations")
        for art, what, st in t["obligations"]:
            print(f"  {st:17} {art:11} {what}")
    for n in t["notes"]:
        print(f"\nNote: {n}")
    if args.save:
        OUT.mkdir(exist_ok=True)
        (OUT / "triage.json").write_text(json.dumps({"as_of": as_of.isoformat(), "what_if": args.what_if,
                                                      "role": t["role"], "tier": t["tier"]}, indent=2) + "\n")
        print("\nSaved: out/triage.json")
    return 0


# ----------------------------------------------------------------------------------------------- evidence
def evidence_status(folder: pathlib.Path, controls: dict) -> tuple[list[dict], list[tuple]]:
    """Return (rows with a 'valid' flag, findings)."""
    rows = read_csv(folder / "evidence-index.csv")
    when = assessment_date(folder)
    findings = []
    for r in rows:
        where = f"evidence-index.csv {r.get('evidence_id') or '?'}"
        r["valid"] = False
        cid = r.get("control", "")
        if cid not in controls:
            findings.append(("EVD-05", "error", where, f"unknown control '{cid}'"))
            continue
        f = (HERE / r.get("file", "")).resolve() if r.get("file") else None
        if not f or not f.is_file():
            findings.append(("EVD-02", "error", where, f"evidence file not found: {r.get('file') or '(blank)'}"))
            continue
        if not r.get("sha256"):
            findings.append(("EVD-06", "error", where, "no sha256 yet: run 'python3 govlab.py evidence FOLDER --fill'"))
            continue
        if sha256_file(f) != r["sha256"].lower():
            findings.append(("EVD-03", "error", where,
                             f"{r['file']} changed after it was indexed (sha256 does not match): re-collect it, then re-index"))
            continue
        collected = parse_date(r.get("collected", ""))
        if not collected:
            findings.append(("EVD-04", "error", where, "collected date missing or not YYYY-MM-DD"))
            continue
        age = (when - collected).days
        if age < 0:
            findings.append(("EVD-04", "error", where, f"collected {collected} is after the assessment date {when}"))
            continue
        if age > EVIDENCE_MAX_AGE_DAYS:
            findings.append(("EVD-04", "error", where,
                             f"stale: collected {collected}, {age} days before the assessment (max {EVIDENCE_MAX_AGE_DAYS})"))
            continue
        if not r.get("owner") or r["owner"].strip().lower() in VAGUE_OWNERS:
            findings.append(("EVD-07", "warning", where, "no named owner for this evidence"))
        r["valid"] = True
    return rows, findings


def credited_controls(folder: pathlib.Path, card: dict, controls: dict) -> tuple[set, dict]:
    rows, _ = evidence_status(folder, controls)
    statuses = card.get("controls", {})
    valid = {}
    for r in rows:
        if r.get("valid"):
            valid.setdefault(r["control"], []).append(r)
    credited = {c for c in valid if statuses.get(c) in CREDIT_STATUSES}
    # Two governance controls are proven by the assessment folder itself, not by a file in evidence/:
    # G02 (the risk assessment) once it has risks and an approver, G04 (legal triage) once the recorded
    # EU AI Act decision matches the triage and names who decided.
    a = load_json(folder / "assessment.json") if (folder / "assessment.json").exists() else {}
    if read_csv(folder / "risk-register.csv") and str(a.get("approved_by", "")).strip():
        credited.add("G02")
    t = triage(card, assessment_date(folder))
    rec = a.get("eu_ai_act", {})
    if (rec.get("role", "").lower() == t["role"] and rec.get("tier", "").lower() == t["tier"].split(" ")[0].lower()
            and str(rec.get("decided_by", "")).strip()):
        credited.add("G04")
    return credited, valid


def cmd_evidence(args) -> int:
    folder = resolve_folder(args.folder)
    controls, _, _ = catalog()
    path = folder / "evidence-index.csv"
    if args.fill:
        rows = read_csv(path)
        filled = 0
        for r in rows:
            f = HERE / r.get("file", "")
            if not r.get("sha256") and r.get("file") and f.is_file():
                r["sha256"] = sha256_file(f)
                filled += 1
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=EVIDENCE_COLUMNS, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"filled {filled} blank sha256 value(s) in {path.relative_to(HERE)} (existing values are never overwritten)")
    rows, findings = evidence_status(folder, controls)
    for r in rows:
        print(f"{'OK  ' if r.get('valid') else 'BAD '} {r.get('evidence_id', ''):6} {r.get('control', ''):4} {r.get('file', '')}")
    for code, sev, where, msg in findings:
        print(f"{sev.upper():7} {code} {where}: {msg}")
    ok = sum(1 for r in rows if r.get("valid"))
    print(f"\n{ok} of {len(rows)} evidence rows valid")
    return 1 if any(s == "error" for _, s, _, _ in findings) else 0


# ----------------------------------------------------------------------------------------------- check
def required_sources(card: dict, library: dict) -> list[str]:
    feats = {k for k, v in card.get("features", {}).items() if v}
    return [sid for sid, s in library.items() if s["when"] == "always" or s["when"] in feats]


def check_folder(folder: pathlib.Path) -> list[tuple]:
    controls, library, frameworks = catalog()
    card = system_card(folder)
    findings: list[tuple] = []
    for need in ("assessment.json", "risk-register.csv", "evidence-index.csv"):
        if not (folder / need).exists():
            findings.append(("ASM-00", "error", need, "file missing ('make start' copies the templates)"))
    if findings:
        return findings
    a = load_json(folder / "assessment.json")
    when = assessment_date(folder)
    appetite = int(a.get("risk_appetite", {}).get("max_residual_without_signoff", 3))
    statuses = card.get("controls", {})
    for cid, st in statuses.items():
        if st not in CONTROL_STATUSES:
            findings.append(("SYS-01", "error", f"system-card.json {cid}", f"status '{st}' is not one of {sorted(CONTROL_STATUSES)}"))

    # evidence first: credit depends on it
    _, evf = evidence_status(folder, controls)
    findings += evf
    credited, valid = credited_controls(folder, card, controls)

    # the register
    rows = read_csv(folder / "risk-register.csv")
    if not rows:
        findings.append(("REG-00", "error", "risk-register.csv", "no risks yet"))
    seen_ids = set()
    owasp_ok = set(frameworks["owasp"]["items"])
    for r in rows:
        rid = r.get("id") or "?"
        where = f"risk {rid}"
        if rid in seen_ids:
            findings.append(("REG-01", "error", where, "duplicate risk id"))
        seen_ids.add(rid)
        for col in ("id", "title", "source", "likelihood", "impact", "treatment"):
            if not r.get(col):
                findings.append(("REG-01", "error", where, f"'{col}' is blank"))
        if r.get("owner", "").strip().lower() in VAGUE_OWNERS:
            findings.append(("REG-02", "error", where,
                             f"owner '{r.get('owner', '')}' is not a named role (who gets the phone call?)"))
        li, im = as_int(r.get("likelihood")), as_int(r.get("impact"))
        if li not in (1, 2, 3) or im not in (1, 2, 3):
            findings.append(("REG-03", "error", where, "likelihood and impact must be 1, 2 or 3"))
            continue
        inherent = li * im
        treat = r.get("treatment", "").lower()
        if treat not in TREATMENTS:
            findings.append(("REG-04", "error", where, f"treatment '{r.get('treatment')}' is not one of {sorted(TREATMENTS)}"))
        if r.get("source") and r["source"] not in library:
            findings.append(("REG-05", "error", where, f"unknown risk source '{r['source']}' (see catalog/risk-library.json)"))
        for oid in split_ids(r.get("owasp", "")):
            if oid not in owasp_ok:
                hint = " (write the year: LLM01:2026)" if re.fullmatch(r"LLM\d\d", oid) else ""
                findings.append(("REG-06", "error", where, f"OWASP ID '{oid}' not recognised{hint}"))
        cids = split_ids(r.get("controls", ""))
        unknown = [c for c in cids if c not in controls]
        for c in unknown:
            findings.append(("REG-08", "error", where, f"unknown control '{c}' (see catalog/controls.json)"))
        if treat in {"mitigate", "transfer"} and not cids:
            findings.append(("REG-07", "error", where, f"treatment '{treat}' but no controls listed"))
        rl, ri = as_int(r.get("res_likelihood")), as_int(r.get("res_impact"))
        if rl is None and ri is None:
            residual = inherent
        elif rl not in (1, 2, 3) or ri not in (1, 2, 3):
            findings.append(("REG-03", "error", where, "residual likelihood and impact must both be 1, 2 or 3 (or both blank)"))
            residual = inherent
        else:
            residual = rl * ri
        if residual > inherent:
            findings.append(("REG-09", "error", where, f"residual {residual} is higher than inherent {inherent}"))
        if residual < inherent:
            good = [c for c in cids if c in credited]
            if treat == "avoid":
                pass   # avoiding the activity removes the risk; the decision itself is the evidence
            elif not good:
                why = []
                for c in cids:
                    if c not in controls:
                        continue
                    st = statuses.get(c, "missing")
                    if st not in CREDIT_STATUSES:
                        why.append(f"{c} is {st}")
                    elif c not in valid:
                        why.append(f"{c} has no valid evidence")
                findings.append(("REG-11", "error", where,
                                 f"residual {residual} < inherent {inherent}, but no listed control can take the credit"
                                 f" ({'; '.join(why) or 'no controls'}). No credit for planned or unproven controls."))
        if residual > appetite and not r.get("accepted_by"):
            findings.append(("REG-12", "error", where,
                             f"residual {residual} is above the appetite ({appetite}): a named person must accept it (accepted_by)"))
        if treat == "accept" and inherent == 9:
            findings.append(("REG-13", "error", where, "the AI policy does not allow accepting a risk of 9: mitigate or avoid it"))
        rd = parse_date(r.get("review_date", ""))
        if not rd:
            findings.append(("REG-14", "error", where, "review_date missing or not YYYY-MM-DD"))
        elif rd <= when or (rd - when).days > REVIEW_MAX_DAYS:
            findings.append(("REG-14", "error", where,
                             f"review_date {rd} must be after the assessment and within {REVIEW_MAX_DAYS} days of it"))

    # coverage
    have = {r.get("source") for r in rows}
    for sid in required_sources(card, library):
        if sid not in have:
            findings.append(("COV-01", "error", sid, f"no risk covers required source: {library[sid]['title']}"))

    # controls the system says are done must be provable if the register leans on them
    used = {c for r in rows for c in split_ids(r.get("controls", "")) if c in controls}
    for c in sorted(used):
        if statuses.get(c) in CREDIT_STATUSES and c not in valid:
            findings.append(("EVD-01", "warning", c, f"{c} is marked {statuses.get(c)} but has no valid evidence row"))

    # the AI disclosure, if C24 is claimed
    if statuses.get("C24") in CREDIT_STATUSES:
        text = re.sub(r"<!--.*?-->", "", widget_path(folder).read_text(encoding="utf-8"), flags=re.S)
        m = re.search(r'<[a-z0-9]+[^>]*\bid="greeting"[^>]*>(.*?)</', text, re.S | re.I)
        if not m or not DISCLOSURE_RE.search(m.group(1)):
            findings.append(("DIS-01", "error", "chat-widget.html",
                             "C24 is marked done, but the greeting does not tell people they are talking to an AI"))

    # decisions in assessment.json
    for field in ("system", "assessor", "date", "approved_by", "next_review"):
        if not str(a.get(field, "")).strip():
            findings.append(("ASM-01", "error", "assessment.json", f"'{field}' is blank"))
    t = triage(card, when)
    rec = a.get("eu_ai_act", {})
    want_tier = t["tier"].split(" ")[0].lower()
    if rec.get("role", "").lower() != t["role"] or rec.get("tier", "").lower() != want_tier:
        findings.append(("ASM-02", "error", "assessment.json",
                         f"EU AI Act decision recorded as role '{rec.get('role', '')}', tier '{rec.get('tier', '')}'; "
                         f"triage says role '{t['role']}', tier '{want_tier}' (run 'make triage')"))
    nr = parse_date(str(a.get("next_review", "")))
    if a.get("next_review") and (not nr or nr <= when or (nr - when).days > 366):
        findings.append(("ASM-03", "error", "assessment.json", "next_review must be a date within 12 months after the assessment"))
    return findings


def print_findings(findings: list[tuple]) -> tuple[int, int]:
    errors = [f for f in findings if f[1] == "error"]
    warns = [f for f in findings if f[1] != "error"]
    for code, sev, where, msg in errors + warns:
        print(f"{sev.upper():7} {code}  {where}: {msg}")
    return len(errors), len(warns)


def cmd_check(args) -> int:
    folder = resolve_folder(args.folder)
    findings = check_folder(folder)
    print(f"Checking {folder.relative_to(HERE) if folder.is_relative_to(HERE) else folder}\n")
    e, w = print_findings(findings)
    codes = sorted({f[0] for f in findings if f[1] == "error"})
    print(f"\n{e} error(s), {w} warning(s)" + (f"  [{', '.join(codes)}]" if codes else ""))
    if e == 0:
        print("Ready to pack: python3 govlab.py pack " + folder.name)
    return 1 if e else 0


# ----------------------------------------------------------------------------------------------- crosswalk
def crosswalk(folder: pathlib.Path, what_if: str | None = None) -> dict:
    controls, _, frameworks = catalog()
    card = system_card(folder)
    credited, _ = credited_controls(folder, card, controls)
    statuses = card.get("controls", {})
    t = triage(card, assessment_date(folder), what_if)
    keys = {"nist": "nist", "eu": "eu", "iso": "iso", "owasp": "owasp"}
    fw_items = {"nist": list(frameworks["nist_ai_rmf"]["items"]), "eu": list(frameworks["eu_ai_act"]["items"]),
                "iso": list(frameworks["iso_42001"]["items"]), "owasp": list(frameworks["owasp"]["items"])}
    result = {}
    for fw, items in fw_items.items():
        rows = []
        for item in items:
            mapped = [c for c, d in controls.items() if item in d.get(keys[fw], [])]
            have = [c for c in mapped if c in credited]
            planned = [c for c in mapped if c not in credited]
            applies = ""
            if fw == "eu":
                rule = frameworks["eu_ai_act"]["items"][item]["applies"]
                applies = ("applies" if rule == "all" or (rule == "art50" and t["tier"].startswith("TRANSPARENCY"))
                           or (rule == "art50" and t["high_risk"]) or (rule == "high-risk" and t["high_risk"])
                           else "reference")
            if have:
                st = "COVERED"
            elif mapped:
                st = "NOT PROVEN"
            else:
                st = "NO CONTROL"
            rows.append({"item": item, "status": st, "applies": applies, "covered_by": have, "not_proven": planned,
                         "statuses": {c: statuses.get(c, "missing") for c in planned}})
        result[fw] = rows
    return result


FW_TITLES = {"nist": "NIST AI RMF 1.0 subcategories", "eu": "EU AI Act articles", "iso": "ISO/IEC 42001 clauses",
             "owasp": "OWASP Top 10 2026 (LLM and Agentic)"}


def crosswalk_markdown(cw: dict, frameworks: dict) -> str:
    out = []
    for fw, rows in cw.items():
        out.append(f"## {FW_TITLES[fw]}\n")
        out.append("| Item | Status | Covered by (proven) | Not proven yet |" + (" Applies here? |" if fw == "eu" else ""))
        out.append("|---|---|---|---|" + ("---|" if fw == "eu" else ""))
        for r in rows:
            label = r["item"]
            if fw == "eu":
                label += f" {frameworks['eu_ai_act']['items'][r['item']]['title']}"
            elif fw == "owasp":
                label += f" {frameworks['owasp']['items'][r['item']]}"
            np_ = ", ".join(f"{c} ({s})" for c, s in r["statuses"].items())
            line = f"| {label} | {r['status']} | {', '.join(r['covered_by']) or '-'} | {np_ or '-'} |"
            if fw == "eu":
                line += f" {r['applies']} |"
            out.append(line)
        out.append("")
    return "\n".join(out)


def cmd_crosswalk(args) -> int:
    folder = resolve_folder(args.folder)
    _, _, frameworks = catalog()
    cw = crosswalk(folder, args.what_if)
    pick = list(cw) if args.framework == "all" else [args.framework]
    gaps = 0
    for fw in pick:
        rows = cw[fw]
        cov = sum(1 for r in rows if r["status"] == "COVERED")
        if fw == "eu":
            app = [r for r in rows if r["applies"] == "applies"]
            ok = [r["item"] for r in app if r["status"] == "COVERED"]
            print(f"{FW_TITLES[fw]} that apply to this system: {len(ok)} of {len(app)} have a proven control "
                  f"({', '.join(r['item'] for r in app)})")
        else:
            print(f"{FW_TITLES[fw]}: {cov} of {len(rows)} have a proven control mapped to them")
        for r in rows:
            if fw == "eu" and r["applies"] == "reference" and r["status"] != "COVERED":
                continue
            if r["status"] != "COVERED":
                detail = ", ".join(f"{c} {s}" for c, s in r["statuses"].items()) or "no course control maps here"
                flag = "  <- APPLIES" if r["applies"] == "applies" else ""
                print(f"  {r['status']:11} {r['item']:12} {detail}{flag}")
                gaps += 1 if r["applies"] != "reference" else 0
        if fw == "eu":
            ref = [r["item"] for r in rows if r["applies"] == "reference"]
            if ref:
                print(f"  reference only for this system (high-risk duties): {', '.join(ref)}")
        print()
    OUT.mkdir(exist_ok=True)
    (OUT / "crosswalk.md").write_text("# Control crosswalk\n\n" + crosswalk_markdown(cw, frameworks), encoding="utf-8")
    print("Full table: out/crosswalk.md. A mapped, proven control is evidence for an auditor to judge, "
          "not a compliance verdict.")
    return 0


# ----------------------------------------------------------------------------------------------- pack
def register_markdown(folder: pathlib.Path, controls: dict) -> str:
    rows = read_csv(folder / "risk-register.csv")
    out = ["| ID | Risk | Source | Owner | Inherent | Treatment | Controls | Residual | Accepted by | Review |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        li, im = as_int(r.get("likelihood")) or 0, as_int(r.get("impact")) or 0
        rl, ri = as_int(r.get("res_likelihood")), as_int(r.get("res_impact"))
        res = rl * ri if rl and ri else li * im
        out.append(f"| {r.get('id')} | {r.get('title')} | {r.get('source')} | {r.get('owner')} | {li * im} | "
                   f"{r.get('treatment')} | {r.get('controls')} | {res} | {r.get('accepted_by') or '-'} | {r.get('review_date')} |")
    return "\n".join(out) + "\n"


def write_manifest(pack: pathlib.Path) -> None:
    lines = []
    for f in sorted(p for p in pack.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"):
        lines.append(f"{sha256_file(f)}  {f.relative_to(pack).as_posix()}")
    (pack / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_pack(folder: pathlib.Path, draft: bool = False) -> tuple[pathlib.Path | None, list[tuple]]:
    controls, _, frameworks = catalog()
    findings = check_folder(folder)
    errors = [f for f in findings if f[1] == "error"]
    if errors and not draft:
        return None, findings
    a = load_json(folder / "assessment.json")
    card = system_card(folder)
    when = assessment_date(folder)
    name = f"evidence-pack-{card['id']}-{when.isoformat()}" + ("-DRAFT" if errors else "")
    pack = OUT / name
    if pack.exists():
        shutil.rmtree(pack)
    (pack / "evidence").mkdir(parents=True)
    rows, _ = evidence_status(folder, controls)
    copied = {}
    for r in rows:
        if not r.get("valid"):
            continue
        src = (HERE / r["file"]).resolve()
        dest = pack / "evidence" / src.name
        if src.name not in copied:
            shutil.copy2(src, dest)
            copied[src.name] = r["sha256"]
    t = triage(card, when)
    shutil.copy2(folder / "risk-register.csv", pack / "risk-register.csv")
    shutil.copy2(folder / "evidence-index.csv", pack / "evidence-index.csv")
    shutil.copy2(folder / "assessment.json", pack / "assessment.json")
    with open(pack / "ai-inventory.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=INVENTORY_COLUMNS)
        w.writeheader()
        w.writerows(inventory_rows(card))
    cw = crosswalk(folder)
    (pack / "CROSSWALK.md").write_text("# Control crosswalk\n\n" + crosswalk_markdown(cw, frameworks), encoding="utf-8")
    (pack / "RISK-REGISTER.md").write_text(f"# Risk register: {card['system']}\n\n" + register_markdown(folder, controls),
                                           encoding="utf-8")
    ev_lines = ["| Evidence | Control | File | Collected | Owner |", "|---|---|---|---|---|"]
    for r in rows:
        if r.get("valid"):
            ev_lines.append(f"| {r['evidence_id']} | {r['control']} {controls[r['control']]['name']} | "
                            f"evidence/{pathlib.Path(r['file']).name} | {r['collected']} | {r.get('owner', '')} |")
    status = "DRAFT: open findings, not ready for sign-off" if errors else "Ready for sign-off"
    readme = [f"# Evidence pack: {card['system']} {card.get('version', '')}", "",
              f"- Status: **{status}** ({len(errors)} error(s) from `govlab.py check`)",
              f"- Assessment date: {when.isoformat()}; assessor: {a.get('assessor', '')}; approved by: {a.get('approved_by') or '(not yet)'}",
              f"- Next review: {a.get('next_review', '')}",
              f"- EU AI Act triage (not a legal determination): role {t['role']}, tier {t['tier']}",
              "- Integrity: every file in this folder is listed in `MANIFEST.sha256`. Check it with "
              "`python3 govlab.py verify-pack <this folder>`.", "",
              "## Contents", "",
              "| File | What it is |", "|---|---|",
              "| `RISK-REGISTER.md`, `risk-register.csv` | Risks, owners, treatments, residual risk, review dates |",
              "| `CROSSWALK.md` | Each framework item and the proven controls behind it |",
              "| `ai-inventory.csv` | The AI inventory rows for this system |",
              "| `evidence-index.csv`, `evidence/` | The evidence, with SHA-256 and collection dates |",
              "| `assessment.json` | Scope, decisions, approver, next review |",
              "| `CHECK.txt` | The automated check at the time the pack was built |", "",
              "## Evidence", ""] + ev_lines + [""]
    (pack / "README.md").write_text("\n".join(readme), encoding="utf-8")
    check_text = [f"{sev.upper()} {code} {where}: {msg}" for code, sev, where, msg in findings]
    (pack / "CHECK.txt").write_text("\n".join(check_text or ["no findings"]) + "\n", encoding="utf-8")
    write_manifest(pack)
    return pack, findings


def cmd_pack(args) -> int:
    folder = resolve_folder(args.folder)
    pack, findings = build_pack(folder, args.draft)
    if pack is None:
        e, _ = print_findings([f for f in findings if f[1] == "error"])
        print(f"\nNot packed: {e} error(s). Fix them, or build a marked draft with --draft.")
        return 1
    n = sum(1 for _ in (pack / "evidence").iterdir())
    print(f"Built {pack.relative_to(HERE)}/ with {n} evidence file(s) and MANIFEST.sha256")
    print(f"Open {pack.relative_to(HERE)}/README.md first.")
    return 0


def verify_pack(pack: pathlib.Path) -> list[str]:
    problems = []
    man = pack / "MANIFEST.sha256"
    if not man.exists():
        return ["MANIFEST.sha256 missing"]
    listed = set()
    for line in man.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        listed.add(rel)
        f = pack / rel
        if not f.exists():
            problems.append(f"missing: {rel}")
        elif sha256_file(f) != digest:
            problems.append(f"changed: {rel}")
    for f in pack.rglob("*"):
        if f.is_file() and f.name != "MANIFEST.sha256" and f.relative_to(pack).as_posix() not in listed:
            problems.append(f"not in manifest: {f.relative_to(pack).as_posix()}")
    return problems


def cmd_verify_pack(args) -> int:
    p = pathlib.Path(args.pack)
    if not p.is_absolute():
        p = (pathlib.Path.cwd() / p) if (pathlib.Path.cwd() / p).exists() else HERE / p
    problems = verify_pack(p)
    for x in problems:
        print("FAIL", x)
    print("pack verified: every file matches MANIFEST.sha256" if not problems else f"\n{len(problems)} problem(s)")
    return 1 if problems else 0


# ----------------------------------------------------------------------------------------------- start
def cmd_start(args) -> int:
    dest = HERE / "my-assessment"
    if dest.exists() and not args.force:
        print("my-assessment/ already exists; nothing copied (use --force to start again, which overwrites it)")
        return 1
    dest.mkdir(exist_ok=True)
    pairs = [("templates/ASSESSMENT.json", "assessment.json"), ("templates/RISK-REGISTER.csv", "risk-register.csv"),
             ("templates/EVIDENCE-INDEX.csv", "evidence-index.csv"), ("helpdesk/system-card.json", "system-card.json"),
             ("helpdesk/chat-widget.html", "chat-widget.html")]
    for src, name in pairs:
        shutil.copy2(HERE / src, dest / name)
        print(f"  {src:30} -> my-assessment/{name}")
    print("\nNext: README Step 4. Fill risk-register.csv, then run: python3 govlab.py check my-assessment")
    return 0


# ----------------------------------------------------------------------------------------------- main
def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="M18 lab: AI risk assessment, crosswalk and evidence pack (offline).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("inventory", help="AI inventory rows from the system card")
    s.add_argument("folder", nargs="?")
    s = sub.add_parser("triage", help="EU AI Act role, tier and dates (a decision aid, not a legal answer)")
    s.add_argument("folder", nargs="?")
    s.add_argument("--what-if", choices=["hiring"], help="re-use the Helpdesk to screen job applicants")
    s.add_argument("--as-of", help="date to judge 'applies now' against (default: the assessment date)")
    s.add_argument("--save", action="store_true", help="also write out/triage.json")
    s = sub.add_parser("check", help="lint an assessment folder")
    s.add_argument("folder")
    s = sub.add_parser("crosswalk", help="framework items and the proven controls behind them")
    s.add_argument("folder")
    s.add_argument("--framework", choices=["nist", "eu", "iso", "owasp", "all"], default="all")
    s.add_argument("--what-if", choices=["hiring"])
    s = sub.add_parser("evidence", help="verify the evidence index")
    s.add_argument("folder")
    s.add_argument("--fill", action="store_true", help="write sha256 for rows where it is blank")
    s = sub.add_parser("pack", help="build the evidence pack in out/")
    s.add_argument("folder")
    s.add_argument("--draft", action="store_true", help="build even with open errors, clearly marked DRAFT")
    s = sub.add_parser("verify-pack", help="check a pack against its MANIFEST.sha256")
    s.add_argument("pack")
    s = sub.add_parser("start", help="copy the templates into my-assessment/")
    s.add_argument("--force", action="store_true")
    args = p.parse_args(argv)
    return {"inventory": cmd_inventory, "triage": cmd_triage, "check": cmd_check, "crosswalk": cmd_crosswalk,
            "evidence": cmd_evidence, "pack": cmd_pack, "verify-pack": cmd_verify_pack, "start": cmd_start}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
