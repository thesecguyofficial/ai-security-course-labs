#!/usr/bin/env python3
"""The capstone's security eval gate: run every case against the Helpdesk and fail the build on any regression.

    python3 evals/run_evals.py                          # make eval: core cases + yours; exit 1 if any case fails
    python3 evals/run_evals.py --regression injection   # remove your injection controls first: the gate MUST fail
    python3 evals/run_evals.py --only inj-02 -v         # one case, with the transcript
    python3 evals/run_evals.py --junit results/evals.xml --out results/evals.json   # for CI

Core cases come from evals/cases.json NEXT TO THIS FILE (the self-check runs the course's own copy against your
repo with --repo). Your cases come from <repo>/evals/my_cases.json. Every case starts a fresh Helpdesk with an
empty outbox, so cases never affect each other.

Regressions (lesson 17.3, "prove the gate can fail"): each one swaps some of your guards for the vulnerable
originals, the way a careless refactor might. Your suite must catch every one:
  injection  authorize_tool_call, screen_retrieved, screen_tool_result -> allow everything
  retrieval  filter_retrieval, screen_output                           -> pass everything through
  output     render_html, screen_output, response_headers              -> the original unsafe versions
"""
from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
import time
import types
from xml.sax.saxutils import escape as xml_escape

HERE = pathlib.Path(__file__).resolve().parent
CORE_CASES = HERE / "cases.json"
REGRESSIONS = {
    "injection": {"authorize_tool_call": "allow", "screen_retrieved": "identity", "screen_tool_result": "identity_result"},
    "retrieval": {"filter_retrieval": "identity_docs", "screen_output": "identity"},
    "output": {"render_html": "unsafe_html", "screen_output": "identity", "response_headers": "no_headers"},
}
REGRESSION_CATEGORY = {"injection": "injection", "retrieval": "retrieval", "output": "output"}


def regressed_guards(name: str):
    """A copy of the repo's guards module with some functions swapped for the vulnerable originals."""
    from helpdesk.common import ALLOW
    real = importlib.import_module("helpdesk.guards")
    mod = types.ModuleType(f"guards_regressed_{name}")
    mod.__dict__.update({k: v for k, v in real.__dict__.items() if not k.startswith("__")})
    swaps = {
        "allow": lambda call, ctx: ALLOW,
        "identity": lambda text, *rest: text,                 # screen_retrieved(text, doc), screen_output(text, ctx)
        "identity_result": lambda tool, text: text,           # screen_tool_result(tool, text)
        "identity_docs": lambda user, docs: docs,
        "unsafe_html": lambda text: text.replace("\n", "<br>"),
        "no_headers": lambda: {},
    }
    for fn, how in REGRESSIONS[name].items():
        setattr(mod, fn, swaps[how])
    return mod


def load_cases(repo: pathlib.Path, include_mine: bool = True) -> list[dict]:
    cases = [dict(c, _source="core", _kb=str(HERE / "kb")) for c in json.loads(CORE_CASES.read_text())["cases"]]
    mine = repo / "evals" / "my_cases.json"
    if include_mine and mine.exists():
        for c in json.loads(mine.read_text()).get("cases", []):
            cases.append(dict(c, _source="mine", _kb=str(repo / "evals" / "kb")))
    seen = set()
    for c in cases:
        if c["id"] in seen:
            raise SystemExit(f"duplicate case id {c['id']}: give your cases their own ids (for example my-01)")
        seen.add(c["id"])
    return cases


def official_util():
    """tests/util.py from the course's copy next to this file (never the copy in the repo under test)."""
    spec = importlib.util.spec_from_file_location("capstone_official_util", HERE.parent / "tests" / "util.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_case(case: dict, guards_module=None) -> dict:
    from helpdesk.core import Helpdesk
    u = official_util()
    CANARIES, outside_emails, unsafe_html = u.CANARIES, u.outside_emails, u.unsafe_html

    exp, user = case.get("expect", {}), case["user"]
    message = case.get("message", "")
    if "message_repeat" in case:
        text, times = case["message_repeat"]
        message = text * int(times)
    problems, transcript = [], []
    with tempfile.TemporaryDirectory(prefix="tsg-eval-") as tmp:
        extra = pathlib.Path(tmp) / "extra_kb"
        extra.mkdir()
        for name in case.get("extra_kb", []):
            shutil.copy(pathlib.Path(case["_kb"]) / name, extra / name)
        old = os.environ.get("TSG_EXTRA_KB")
        os.environ["TSG_EXTRA_KB"] = str(extra)
        hd = Helpdesk(state_dir=pathlib.Path(tmp) / "state", mcp_release=case.get("mcp_release", 1),
                      guards_module=guards_module, log_to_file=False)
        try:
            results = [hd.handle(user, message) for _ in range(int(case.get("burst", 1)))]
            outbox = hd.outbox()
            outside = outside_emails(hd, user)
            headers = hd.guards.response_headers()
        finally:
            hd.close()
            if old is None:
                os.environ.pop("TSG_EXTRA_KB", None)
            else:
                os.environ["TSG_EXTRA_KB"] = old
    last = results[-1]
    blocked = sum(1 for r in results if r.blocked)
    allowed_calls = [c for c in last.calls if c["allowed"]]
    for c in last.calls:
        transcript.append(f"{'ALLOW' if c['allowed'] else 'DENY '} {c['tool']} {json.dumps(c['args'])[:90]} "
                          f"{c['reason']} <- {c['why']}")

    if exp.get("no_outside_email") and outside:
        problems.append(f"email left to {', '.join(m['to'] for m in outside)}")
    for label in exp.get("no_leak", []):
        marker = CANARIES[label]
        if marker in last.reply or any(marker in m["body"] for m in outbox):
            problems.append(f"{label} leaked")
    for tool in exp.get("tool_never_allowed", []):
        if any(c["tool"] == tool and c["allowed"] for r in results for c in r.calls):
            problems.append(f"{tool} was allowed")
    if exp.get("html_safe"):
        bad = unsafe_html(last.reply_html)
        if bad:
            problems.append(f"live HTML reached the page: {', '.join(bad[:4])}")
    if exp.get("blocked") and not last.blocked:
        problems.append("request was not refused")
    if exp.get("not_blocked") and last.blocked:
        problems.append(f"normal request refused: {last.blocked}")
    if "max_allowed_calls" in exp and len(allowed_calls) > exp["max_allowed_calls"]:
        problems.append(f"{len(allowed_calls)} tool calls allowed (max {exp['max_allowed_calls']})")
    if "min_blocked" in exp and blocked < exp["min_blocked"]:
        problems.append(f"only {blocked} of {len(results)} refused (want {exp['min_blocked']}+)")
    if "max_blocked" in exp and blocked > exp["max_blocked"]:
        problems.append(f"{blocked} of {len(results)} normal requests refused")
    for s in exp.get("reply_contains", []):
        if s not in last.reply:
            problems.append(f"reply is missing {s!r}")
    for s in exp.get("reply_not_contains", []):
        if s in last.reply or any(s in m["body"] for m in outbox):
            problems.append(f"{s!r} reached the reply or an email")
    for s in exp.get("html_contains", []):
        if s not in last.reply_html:
            problems.append(f"page is missing {s!r}")
    if exp.get("email_to_requester") and not any(m["to"] == user for m in outbox):
        problems.append("no email to the requester")
    if exp.get("csp") and "Content-Security-Policy" not in headers:
        problems.append("no Content-Security-Policy header")
    return {"id": case["id"], "category": case.get("category", "?"), "finding": case.get("finding", ""),
            "source": case["_source"], "passed": not problems, "problems": problems, "transcript": transcript}


def junit(results: list[dict], path: pathlib.Path, name: str) -> None:
    fails = sum(1 for r in results if not r["passed"])
    rows = [f'<testsuite name="{xml_escape(name)}" tests="{len(results)}" failures="{fails}">']
    for r in results:
        rows.append(f'  <testcase classname="{r["category"]}" name="{xml_escape(r["id"])}">')
        if not r["passed"]:
            rows.append(f'    <failure message="{xml_escape("; ".join(r["problems"]), {chr(34): "&quot;"})}"/>')
        rows.append("  </testcase>")
    rows.append("</testsuite>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=str(HERE.parent), help="the Helpdesk to test (default: this folder)")
    ap.add_argument("--regression", choices=sorted(REGRESSIONS))
    ap.add_argument("--expect-fail", action="store_true", help="exit 0 only if the gate FAILS (negative control)")
    ap.add_argument("--only", action="append", help="run only these case ids")
    ap.add_argument("--core-only", action="store_true", help="skip evals/my_cases.json")
    ap.add_argument("--out", help="write results as JSON")
    ap.add_argument("--junit", help="write results as JUnit XML (CI test reports)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print each case's tool calls")
    a = ap.parse_args(argv)

    repo = pathlib.Path(a.repo).resolve()
    sys.path.insert(0, str(repo))
    os.chdir(repo)
    cases = load_cases(repo, include_mine=not a.core_only)
    if a.only:
        cases = [c for c in cases if c["id"] in a.only]
    guards_module = regressed_guards(a.regression) if a.regression else None

    t0, results = time.time(), []
    label = f" with the {a.regression} regression" if a.regression else ""
    print(f"Security evals{label}: {len(cases)} cases against {repo}")
    for c in cases:
        r = run_case(c, guards_module)
        results.append(r)
        mark = "PASS" if r["passed"] else "FAIL"
        print(f"[{mark}] {r['id']:<8} {r['category']:<14} {'; '.join(r['problems'])}")
        if a.verbose:
            for line in r["transcript"]:
                print(f"         {line}")
    failed = [r for r in results if not r["passed"]]
    by_cat: dict = {}
    for r in results:
        by_cat.setdefault(r["category"], [0, 0])
        by_cat[r["category"]][0 if r["passed"] else 1] += 1
    print("\n" + "  ".join(f"{k}: {v[0]}/{v[0] + v[1]}" for k, v in sorted(by_cat.items())))
    summary = {"regression": a.regression, "cases": len(results), "failed": [r["id"] for r in failed],
               "failed_categories": sorted({r["category"] for r in failed}), "seconds": round(time.time() - t0, 1),
               "results": results}
    if a.out:
        pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if a.junit:
        junit(results, pathlib.Path(a.junit), f"security-evals{('-' + a.regression) if a.regression else ''}")
    if a.expect_fail:
        want = REGRESSION_CATEGORY.get(a.regression)
        caught = bool(failed) and (want is None or want in summary["failed_categories"])
        print(f"GATE {'FAILED, as it should' if caught else 'PASSED: this regression was NOT caught'}"
              f"{f' (failing {want} cases: ' + ', '.join(r['id'] for r in failed if r['category'] == want) + ')' if caught and want else ''}")
        return 0 if caught else 1
    print(f"GATE {'PASSED' if not failed else 'FAILED'}: {len(results) - len(failed)} of {len(results)} cases passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
