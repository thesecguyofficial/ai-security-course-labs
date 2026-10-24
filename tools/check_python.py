#!/usr/bin/env python3
"""`make setup` for labs that need nothing installed: checks the Python version and says so.

Usage (from a lab folder):  python3 ../../tools/check_python.py 3.11
Exit code 1 when this Python is older than the version given. Runs on any Python 3.
"""
import sys


def main(argv):
    want = tuple(int(x) for x in (argv[1] if len(argv) > 1 else "3.11").split("."))
    have = sys.version_info[:2]
    if have < want:
        print("This lab needs Python %s or newer; `python3` here is %d.%d." % (".".join(map(str, want)), have[0], have[1]))
        print("Fix: run ./setup.sh at the repo root once, then `source .venv/bin/activate` in each new terminal.")
        return 1
    print("Nothing to install for this lab: Python %d.%d and its standard library are all it needs." % have)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
