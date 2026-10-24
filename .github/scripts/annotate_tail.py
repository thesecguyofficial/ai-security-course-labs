"""CI helper: on failure, turn the last lines of log files into GitHub annotations (readable in the UI and API)."""
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows runners default to cp1252

for path in sys.argv[1:]:
    if not os.path.exists(path):
        continue
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    # Drop progress-bar redraws (model downloads, winget) so the real messages fit.
    lines = [l.rstrip() for l in text.replace("\x1b", "").replace("\r", "\n").splitlines()
             if l.strip() and not any(m in l for m in ("pulling ", "verifying sha256", "\u2588", "\u2592", "MB /"))]
    tail = "\n".join(lines[-45:])
    tail = tail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::error title=%s (last lines)::%s" % (os.path.basename(path), tail))
