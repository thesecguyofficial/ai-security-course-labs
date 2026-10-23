#!/usr/bin/env python3
"""
M3.9 lab: run the promptfoo suite (promptfooconfig.yaml) against the LOCAL app only.

    python3 run_eval.py --fixes all     # expect every test to pass
    python3 run_eval.py --fixes none    # expect the attack tests to fail: proof the suite can catch them
    python3 run_eval.py --fixes all --backend ollama --repeat 5   # optional: a real local model, 5 tries each

What it does: starts `support_bot.py serve` on 127.0.0.1:8003 with the fixes you chose, waits until it answers,
runs `npx promptfoo eval`, then stops the app. promptfoo talks only to 127.0.0.1:8003 (see promptfooconfig.yaml);
npx downloads promptfoo from the npm registry the first time.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.request

PROMPTFOO = "promptfoo@0.124.1"   # pinned: the version this lab was tested with
HEALTH = "http://127.0.0.1:8003/health"


def wait_for_app(seconds: int = 20) -> bool:
    for _ in range(seconds * 4):
        try:
            with urllib.request.urlopen(HEALTH, timeout=1) as r:
                return r.status == 200
        except OSError:
            time.sleep(0.25)
    return False


def print_summary(path: str):
    """A compact, one-line-per-test view of promptfoo's results file (the full table: `PROMPTFOO_DISABLE_TELEMETRY=1 npx promptfoo view`)."""
    import json
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return
    print("\nPer test (from " + os.path.relpath(path) + "):")
    for row in data["results"]["results"]:
        name = row["testCase"].get("description", "?")
        failed = [c["assertion"].get("metric") or c["assertion"].get("type")
                  for c in row["gradingResult"].get("componentResults", []) if not c["pass"]]
        print(f"  [{'PASS' if row['success'] else 'FAIL'}] {name}" + (f"   failed: {', '.join(failed)}" if failed else ""))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--fixes", default="all")
    p.add_argument("--backend", choices=["standin", "ollama"], default="standin")
    p.add_argument("--model", default="gemma3:1b")
    p.add_argument("--repeat", type=int, default=1, help="run each test N times (use 5+ with a real model)")
    args = p.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    os.chdir(here)

    if not shutil.which("npx"):
        sys.exit("npx not found. Install Node.js 22.22 or newer (README Step 8), or skip this optional step.")

    app = subprocess.Popen([sys.executable, "support_bot.py", "serve", "--fixes", args.fixes,
                            "--backend", args.backend, "--model", args.model])
    try:
        if not wait_for_app():
            sys.exit("SupportBot did not start on 127.0.0.1:8003. Is something else using that port?")
        env = dict(os.environ,
                   PROMPTFOO_DISABLE_TELEMETRY="1",       # no usage data sent to promptfoo
                   PROMPTFOO_DISABLE_UPDATE="1",          # no update check
                   PROMPTFOO_CONFIG_DIR=os.path.join(here, ".promptfoo"))  # keep its files in this folder
        out_file = os.path.join(here, ".promptfoo", "last-results.json")
        cmd = ["npx", "--yes", PROMPTFOO, "eval", "-c", "promptfooconfig.yaml", "--no-cache",
               "--no-progress-bar", "--no-table", "-o", out_file, "--repeat", str(args.repeat)]
        code = subprocess.run(cmd, env=env).returncode
        print_summary(out_file)
        return code
    finally:
        app.terminate()
        app.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
