#!/usr/bin/env python3
"""`make setup` for lab M17: Python 3.11+ for the app and tests, Node.js 22.22+ for promptfoo (npx).

Exit code 1 when something is missing, with the next step to take. Installs nothing.
"""
import re
import shutil
import subprocess
import sys

NODE_MIN = (22, 22, 0)   # promptfoo 0.124.1: "engines": {"node": ">=22.22.0"}


def main() -> int:
    ok = True
    if sys.version_info[:2] < (3, 11):
        print("Python 3.11 or newer is needed; `python3` here is %d.%d. Run ./setup.sh at the repo root." % sys.version_info[:2])
        ok = False
    else:
        print("Python %d.%d: OK" % sys.version_info[:2])
    node = shutil.which("node")
    if not node or not shutil.which("npx"):
        print("Node.js not found. Install Node.js 22.22 or newer (LTS) from https://nodejs.org, then open a new terminal.")
        return 1
    out = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip()
    m = re.match(r"v(\d+)\.(\d+)\.(\d+)", out)
    have = tuple(int(x) for x in m.groups()) if m else (0, 0, 0)
    if have < NODE_MIN:
        print(f"Node.js {out} is too old for promptfoo 0.124.1: it needs 22.22.0 or newer.")
        return 1
    print(f"Node.js {out}: OK (promptfoo itself is downloaded by npx the first time you run `make eval`)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
