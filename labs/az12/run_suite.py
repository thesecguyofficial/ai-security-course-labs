"""
run_suite.py: replay the AZ12 suite (15 attacks, 13 legitimate requests) and measure BOTH numbers that matter:

    attack success rate (ASR)   attacks that worked / attacks run       (lower is better)
    false positive rate (FPR)   legitimate requests blocked / run       (lower is better)

    python3 run_suite.py --setup contoso      # make attack:      Contoso's version 1
    python3 run_suite.py --setup hardened     # make attack-safe: the hardened build in fixes/
    python3 run_suite.py --compare            # make compare:     no guardrail vs Microsoft.DefaultV2 vs v1 vs hardened
    python3 run_suite.py --setup hardened --json results.json

ASR is the metric Microsoft's AI Red Teaming Agent reports ("the percentage of successful attacks over the number of
total attacks"). FPR is the one guardrail demos leave out.
"""

import argparse
import json
import os
import sys

import helpdesk

HERE = os.path.dirname(os.path.abspath(__file__))
SETUPS = {
    # name: (config folder, guardrail override for the model deployment, label)
    "none": ("contoso", "Lab.NoGuardrail", "no guardrail at all (lab baseline)"),
    "default": ("contoso", "Microsoft.DefaultV2", "Microsoft.DefaultV2 twin, Contoso's app"),
    "contoso": ("contoso", None, "Contoso version 1 (contoso-helpdesk-v1 + agent guardrail contoso-agent-v1)"),
    "hardened": ("fixes", None, "hardened (contoso-helpdesk-v2 + app controls; agent guardrail unchanged)"),
}


def load_cases() -> list[dict]:
    with open(os.path.join(HERE, "suite", "cases.json"), encoding="utf-8") as f:
        return json.load(f)["cases"]


def run_case(case: dict, setup: str) -> dict:
    folder, override, _ = SETUPS[setup]
    rec = helpdesk.ask(folder, case["user"], case.get("caller", "priya@contoso.com"), case.get("kb"), case.get("tickets"),
                       case.get("path", "model"), case.get("tool", "azure_ai_search"),
                       policy_override=override if case.get("path", "model") == "model" else None)
    reached = rec["shown"] + " " + json.dumps(rec["tools_run"])
    if case["kind"] == "attack":
        rec["worked"] = any(s in reached for s in case["bad"])
    else:
        rec["false_positive"] = rec["blocked"] is not None or not any(s in reached for s in case["good"])
    return rec


def run(setup: str, quiet: bool = False) -> dict:
    cases = load_cases()
    out = {"setup": setup, "label": SETUPS[setup][2], "results": []}
    if not quiet:
        print(f"Setup: {SETUPS[setup][2]}")
    for c in cases:
        r = run_case(c, setup)
        r["id"], r["kind"], r["title"] = c["id"], c["kind"], c["title"]
        out["results"].append(r)
        if quiet:
            continue
        if r["blocked"]:
            where = f"{r['blocked']['stage']}: {r['blocked']['control']}"
        elif c["kind"] == "attack" and not r["worked"] and r.get("defused"):
            where = r["defused"]
        else:
            where = "not blocked"
        if c["kind"] == "attack":
            flag = "!!" if r["worked"] else "ok"
            verdict = "ATTACK WORKED" if r["worked"] else "stopped     "
        else:
            flag = "FP" if r["false_positive"] else "ok"
            verdict = "BLOCKED (FP) " if r["false_positive"] else "answered     "
        print(f"  {flag} {c['id']} {verdict} {c['title'][:58]:<58} | {where[:72]}")
        for n in r["notes"]:
            print(f"             note: {n}")
    att = [r for r in out["results"] if r["kind"] == "attack"]
    ben = [r for r in out["results"] if r["kind"] == "benign"]
    worked = sum(r["worked"] for r in att)
    fps = sum(r["false_positive"] for r in ben)
    spot = [r["spotlighting_chars"] for r in out["results"] if r.get("spotlighting_chars")]
    side = sum("base-64 encoded" in r["shown"] for r in ben)
    out["summary"] = {"spotlighted_requests": len(spot), "doc_chars_before": sum(b for b, _ in spot),
                      "doc_chars_after": sum(a for _, a in spot), "answers_mentioning_base64": side,
                      "attacks": len(att), "worked": worked, "asr": round(100 * worked / len(att)),
                      "benign": len(ben), "false_positives": fps, "fpr": round(100 * fps / len(ben))}
    if not quiet:
        s = out["summary"]
        print(f"\nAttacks that worked: {s['worked']} of {s['attacks']} (ASR {s['asr']}%)   ·   "
              f"legitimate requests blocked: {s['false_positives']} of {s['benign']} (FPR {s['fpr']}%)")
        if s["spotlighted_requests"]:
            grow = round(100 * (s["doc_chars_after"] - s["doc_chars_before"]) / s["doc_chars_before"])
            print(f"Spotlighting cost: {s['spotlighted_requests']} requests, document characters {s['doc_chars_before']} -> "
                  f"{s['doc_chars_after']} (+{grow}%) · legitimate answers that mention base-64: {s['answers_mentioning_base64']}")
    return out


def compare():
    rows = [run(s, quiet=True) for s in SETUPS]
    ids = [r["id"] for r in rows[0]["results"]]
    print("Same 28 requests, four setups.  X = attack worked, FP = legitimate request blocked, . = fine\n")
    print("        " + "".join(f"{s:>10}" for s in SETUPS))
    for i, cid in enumerate(ids):
        cells = []
        for row in rows:
            r = row["results"][i]
            cells.append(("X" if r["worked"] else ".") if r["kind"] == "attack" else ("FP" if r["false_positive"] else "."))
        print(f"  {cid:<6}" + "".join(f"{c:>10}" for c in cells))
    print("\n  ASR   " + "".join(f"{str(r['summary']['asr']) + '%':>10}" for r in rows))
    print("  FPR   " + "".join(f"{str(r['summary']['fpr']) + '%':>10}" for r in rows))
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--setup", choices=list(SETUPS), default="contoso")
    p.add_argument("--compare", action="store_true")
    p.add_argument("--json", help="also write the full results to this file")
    p.add_argument("--detector", choices=["standin", "llmguard"], default="standin",
                   help="llmguard = LLM Guard's ML classifier for prompt attacks (optional, see llmguard_adapter.py)")
    a = p.parse_args()
    if a.detector == "llmguard":
        import llmguard_adapter
        llmguard_adapter.install()
    res = compare() if a.compare else run(a.setup)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
