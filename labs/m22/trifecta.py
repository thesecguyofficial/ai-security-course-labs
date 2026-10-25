"""
trifecta.py: where are the three legs of the lethal trifecta in each design? (lesson 22.1)

    python3 trifecta.py            # the four designs scored by score.py
    python3 trifecta.py --tools    # which leg each tool supplies (catalogue.json)

The legs (Simon Willison, 16 Jun 2025): access to private data, exposure to untrusted content, and a way to
communicate externally. Meta's Agents Rule of Two (31 Oct 2025) asks that one session hold no more than two of them
without supervision. A leg counts for a MODEL when the model reads what the tool returns (private data, untrusted
content) or can make the call (a way out). A component that is plain code holds legs too, but it can't be talked into
anything, so its rules, not its judgement, are the boundary.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

CATALOGUE = json.loads((Path(__file__).parent / "catalogue.json").read_text())
LEGS = {"private": "private data", "untrusted": "untrusted content", "exit": "a way out"}


def legs(reads_results_of: list[str], calls: list[str]) -> set[str]:
    out = set()
    for name in reads_results_of:
        out |= set(CATALOGUE["tools"][name].get("reads", []))
    for name in calls:
        if CATALOGUE["tools"][name].get("exit"):
            out.add("exit")
    return out


def designs(include_challenge: bool = False) -> dict:
    tools = [t for t, v in CATALOGUE["tools"].items() if include_challenge or not v.get("challenge")]
    return {
        "single": [("model (plans, reads, acts)", "model", legs(tools, tools))],
        "single+taint": [("model, before reading data", "model", legs([t for t in tools if t == "get_contact"], tools)),
                         ("model, after untrusted data", "model", legs(tools, tools) - {"exit"})],
        "dual": [("planner", "model", legs([], tools)),
                 ("quarantined", "model", legs(tools, [])),
                 ("controller", "code", legs(tools, tools))],
        "dual+taint": [("planner", "model", legs([], tools)),
                       ("quarantined", "model", legs(tools, [])),
                       ("controller + sink policies", "code", legs(tools, tools))],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", action="store_true")
    ap.add_argument("--challenge", action="store_true", help="include the challenge tool fetch_url")
    args = ap.parse_args()
    if args.tools:
        for name, v in CATALOGUE["tools"].items():
            if v.get("challenge") and not args.challenge:
                continue
            supplied = [LEGS[r] for r in v.get("reads", [])] + (["a way out"] if v.get("exit") else [])
            print(f"{name:<14} {', '.join(supplied):<36} {v['why']}")
        return
    for design, parts in designs(args.challenge).items():
        print(design)
        for name, kind, held in parts:
            count = len(held)
            if kind == "code":
                verdict = "code: holds the legs, follows no instructions; its rules are the boundary" if held else "code"
            elif count == 3:
                verdict = "ALL THREE in one model: the trifecta (Rule of Two broken)"
            else:
                verdict = f"{count} of 3 (Rule of Two holds for this model)"
            shown = ", ".join(LEGS[k] for k in ("private", "untrusted", "exit") if k in held) or "none"
            print(f"  {name:<28} {kind:<6} {shown:<52} {verdict}")


if __name__ == "__main__":
    main()
