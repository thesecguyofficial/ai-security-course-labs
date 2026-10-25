#!/usr/bin/env python3
"""
run_eval.py: run the promptfoo security evals (evals/promptfooconfig.yaml) against the LOCAL Helpdesk only.

    python3 run_eval.py                          # hardened build: every test must pass (exit 0)
    python3 run_eval.py --profile weak --expect-fail
                                                 # negative control: no guards, the suite MUST fail (exit 0 if it did)
    python3 run_eval.py --regression R1          # hardened build with regression R1 (see regress.py), from a copy
    python3 run_eval.py --junit results/junit.xml  # also write a JUnit report (CI test viewers read it)

What it does: starts `helpdesk.py serve` on 127.0.0.1:8017, checks it is the build you asked for, runs a PINNED
promptfoo with telemetry, update checks and sharing off, prints one line per test, then stops the app.
Exit code = promptfoo's: 0 all passed, 100 at least one test failed, 1 any other error (lesson 17.3).
With --expect-fail it is inverted for the negative control: 0 when the suite caught the weak build, 1 when it didn't.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

PROMPTFOO = "promptfoo@0.124.1"   # pinned: the version this lab was tested with (8 Oct 2026). Change it on purpose.
HERE = pathlib.Path(__file__).resolve().parent
PORT = 8017
HEALTH = f"http://127.0.0.1:{PORT}/health"


def port_busy() -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", PORT)) == 0


def wait_for_app(profile: str, seconds: int = 20) -> bool:
    for _ in range(seconds * 4):
        try:
            with urllib.request.urlopen(HEALTH, timeout=1) as r:
                return json.load(r).get("profile") == profile
        except OSError:
            time.sleep(0.25)
    return False


def print_summary(path: pathlib.Path) -> int:
    """One line per test. Returns the number of tests that did not pass."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    print(f"\nPer test (from {path.relative_to(HERE)}):")
    for row in data["results"]["results"]:
        name = row["testCase"].get("description", "?")
        failed = sorted({c["assertion"].get("metric") or c["assertion"].get("type")
                         for c in (row.get("gradingResult") or {}).get("componentResults", []) if not c["pass"]})
        if row.get("error") and not failed:
            failed = ["error: " + str(row["error"])[:80]]
        print(f"  [{'PASS' if row['success'] else 'FAIL'}] {name}" + (f"   failed: {', '.join(failed)}" if failed else ""))
    return sum(1 for row in data["results"]["results"] if not row["success"])


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", choices=["hardened", "weak"], default="hardened")
    p.add_argument("--regression", choices=["R1", "R2", "R3"], help="run the hardened build with this regression")
    p.add_argument("--expect-fail", action="store_true", help="negative control: succeed only if the suite fails")
    p.add_argument("--repeat", type=int, default=1, help="run each test N times (use 5+ with a real model)")
    p.add_argument("--junit", help="also write a JUnit XML report to this path")
    p.add_argument("--out", default="results/last-results.json", help="promptfoo's JSON results (default: %(default)s)")
    args = p.parse_args()
    os.chdir(HERE)

    if not shutil.which("npx"):
        sys.exit("npx not found. Install Node.js 22.22 or newer (README, Before you start).")
    if port_busy():
        sys.exit(f"Something is already listening on 127.0.0.1:{PORT} (an earlier `make run`?). Stop it first, "
                 "so the evals test the build you asked for and nothing else.")

    env = dict(os.environ)
    label = args.profile
    if args.regression:
        copy = HERE / "state" / f"regress-{args.regression}"
        subprocess.run([sys.executable, "regress.py", args.regression, "--to", str(copy)], check=True)
        env["HELPDESK_GUARDS"] = str(copy / "guards.py")
        label = f"hardened + {args.regression}"
    print(f"=== Security evals · build: {label} · {PROMPTFOO} ===", flush=True)

    app = subprocess.Popen([sys.executable, "helpdesk.py", "serve", "--profile", args.profile], env=env,
                           stdout=subprocess.DEVNULL)
    try:
        if not wait_for_app(args.profile):
            sys.exit(f"TSG Helpdesk did not start on 127.0.0.1:{PORT}.")
        # Security tests get no pass-rate threshold and no custom exit code: one failed attack test must fail the
        # build. (PROMPTFOO_PASS_RATE_THRESHOLD=90 lets a real data leak through as "exit 0": lesson 17.3.)
        for var in ("PROMPTFOO_PASS_RATE_THRESHOLD", "PROMPTFOO_FAILED_TEST_EXIT_CODE"):
            if os.environ.pop(var, None) is not None:
                print(f"note: ignoring {var} for the security suite (any failure must fail the build)")
        pf_env = dict(os.environ,
                      PROMPTFOO_DISABLE_TELEMETRY="1",                 # no usage data (one "telemetry disabled" event still goes out)
                      PROMPTFOO_DISABLE_UPDATE="1",                    # no update check
                      PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION="true",  # never ask a hosted service for attacks
                      PROMPTFOO_CONFIG_DIR=str(HERE / ".promptfoo"))   # keep its files in this folder
        out = HERE / args.out
        out.parent.mkdir(exist_ok=True)
        outputs = [str(out)] + ([args.junit] if args.junit else [])
        cmd = ["npx", "--yes", PROMPTFOO, "eval", "-c", "evals/promptfooconfig.yaml", "--no-cache", "--no-share",
               "--no-progress-bar", "--no-table", "--repeat", str(args.repeat), "-o", *outputs]
        code = subprocess.run(cmd, env=pf_env).returncode
        failed = print_summary(out)
        if code == 0 and failed:   # belt and braces: never trust the exit code alone
            print(f"\n{failed} test(s) failed but promptfoo exited 0: treating this run as FAILED.")
            code = 100
    finally:
        app.terminate()
        app.wait(timeout=10)

    if args.expect_fail:
        if code == 100:
            print("\nNEGATIVE CONTROL OK: the suite caught the weak build (promptfoo exit 100), as it must.")
            return 0
        print(f"\nNEGATIVE CONTROL FAILED: promptfoo exit {code}. A suite that passes on a build with no guards "
              "proves nothing. Fix the suite before trusting a green build.")
        return 1
    print(f"\npromptfoo exit code: {code} ({ {0: 'all tests passed', 100: 'at least one test failed'}.get(code, 'error') })")
    return code


if __name__ == "__main__":
    sys.exit(main())
