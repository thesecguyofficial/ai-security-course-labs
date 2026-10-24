"""CI helper: on failure, turn the last lines of log files into GitHub annotations (readable in the UI and API)."""
import os
import sys

for path in sys.argv[1:]:
    if not os.path.exists(path):
        continue
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [l.rstrip() for l in f.read().replace("\x1b", "").splitlines() if l.strip()]
    tail = "\n".join(lines[-45:])
    tail = tail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::error title=%s (last lines)::%s" % (os.path.basename(path), tail))
