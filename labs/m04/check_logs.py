#!/usr/bin/env python3
"""
M4.6 lab: prove it. Search every file in logs/ for the fake sensitive values ("canaries").

    python3 check_logs.py                 # check canaries.txt
    python3 check_logs.py --challenge     # also check challenge_canaries.txt (the employee ID)

Exit code 0 = clean, 1 = something sensitive reached a log. A test that can fail is a test you can trust,
so run_tests.py also checks that this script DOES fail when redaction is off.

Standard library only: this check must not depend on the redaction library it is checking.
"""

import argparse
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"


def load_canaries(path: pathlib.Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def hide(value: str) -> str:
    """Print 'jane…' rather than the full value: even a checker shouldn't re-leak what it found."""
    return value[:4] + "…"


def scan(canaries: list[str]) -> list[tuple[str, int, str]]:
    """Return (file name, line number, canary) for every hit."""
    hits = []
    for log_file in sorted(LOG_DIR.glob("*.log")):
        for n, line in enumerate(log_file.read_text(encoding="utf-8").splitlines(), start=1):
            for c in canaries:
                if c in line:
                    hits.append((log_file.name, n, c))
    return hits


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--challenge", action="store_true", help="also check the challenge canaries")
    p.add_argument("--quiet", action="store_true", help="only print the summary line")
    args = p.parse_args()

    if not LOG_DIR.exists() or not list(LOG_DIR.glob("*.log")):
        print("No log files in logs/. Run chat_app.py first.")
        return 2
    canaries = load_canaries(HERE / "canaries.txt")
    if args.challenge:
        canaries += load_canaries(HERE / "challenge_canaries.txt")

    hits = scan(canaries)
    if not args.quiet:
        for name, n, c in hits:
            print(f"  LEAK  logs/{name} line {n}: contains '{hide(c)}'")
    files = ", ".join(f.name for f in sorted(LOG_DIR.glob("*.log")))
    if hits:
        found = len({c for _, _, c in hits})
        print(f"FAIL: {found} of {len(canaries)} sensitive values found in logs ({len(hits)} hits) [{files}]")
        return 1
    print(f"PASS: none of {len(canaries)} sensitive values found in logs [{files}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
