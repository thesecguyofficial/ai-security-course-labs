#!/usr/bin/env python3
"""
M4.6 lab: the `make test` check. It runs the scripted chat twice and checks the logs each time.

    Test 1  redaction OFF  -> the log check MUST fail  (proves the check can catch a leak)
    Test 2  redaction ON   -> the log check MUST pass  (proves nothing sensitive reached the logs)
    Test 3  redaction ON   -> the model's answer shown to the user has no customer data in it
    Test 4  redaction ON   -> redacting twice leaves the labels intact

    python3 run_tests.py               # the core lab
    python3 run_tests.py --challenge   # Test 2 also checks the employee ID (passes once you add the recognizer)
"""

import argparse
import os
import subprocess
import sys

PY = sys.executable  # the same Python (and virtual environment) that is running this file


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def chat(redact: bool) -> subprocess.CompletedProcess:
    cmd = [PY, "chat_app.py", "--script", "conversation.txt", "--fresh"] + (["--redact"] if redact else [])
    result = run(cmd)
    if result.returncode != 0:
        print(result.stdout, result.stderr)
        sys.exit("chat_app.py crashed; see the error above (README: Troubleshooting).")
    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--challenge", action="store_true")
    args = p.parse_args()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))  # work from the lab folder, wherever you ran this
    extra = ["--challenge"] if args.challenge else []
    ok = True

    chat(redact=False)
    check = run([PY, "check_logs.py", "--quiet"] + extra)
    leaked = check.returncode == 1
    print(f"[{'PASS' if leaked else 'FAIL'}] Test 1  redaction OFF: the checker catches the leak   -> {check.stdout.strip()}")
    ok &= leaked

    out = chat(redact=True)
    check = run([PY, "check_logs.py", "--quiet"] + extra)
    clean = check.returncode == 0
    print(f"[{'PASS' if clean else 'FAIL'}] Test 2  redaction ON:  nothing sensitive in the logs  -> {check.stdout.strip()}")
    if not clean:
        print(run([PY, "check_logs.py"] + extra).stdout)
    ok &= clean

    shown_clean = "john.smith@example.org" not in out.stdout and "5555 5555 5555 4444" not in out.stdout
    print(f"[{'PASS' if shown_clean else 'FAIL'}] Test 3  redaction ON:  the user never sees another customer's data")
    ok &= shown_clean

    # Redacting twice must not damage the labels (e.g. "<AWS_ACCESS_KEY>" turning into "<<PERSON>").
    # A mangled label hides WHAT was removed, which investigators need.
    log_text = open("logs/app.log", encoding="utf-8").read()
    tidy = "<<" not in log_text and ">>" not in log_text and "<AWS_ACCESS_KEY>" in log_text
    print(f"[{'PASS' if tidy else 'FAIL'}] Test 4  redaction ON:  labels survive a second pass (log filter)")
    ok &= tidy

    print("\nALL TESTS PASSED" if ok else "\nSOME TESTS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
