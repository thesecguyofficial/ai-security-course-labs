#!/usr/bin/env python3
"""
regress.py: make guards.py weaker the way a real pull request might, so you can watch the evals react.

    python3 regress.py --list          # the three regressions and the story behind each
    python3 regress.py R1              # edit guards.py in place (for the GitHub Actions part of the lab)
    python3 regress.py --restore       # put guards.py back exactly as it was
    python3 regress.py R2 --to /tmp/x  # write a patched COPY instead (run_eval.py --regression uses this)

Each regression is a small, plausible change with a reason a reviewer might accept. None of them touches the model.
"""

from __future__ import annotations

import argparse
import difflib
import pathlib
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
GUARDS = HERE / "guards.py"
BACKUP = HERE / "state" / "guards.py.orig"

REGRESSIONS = {
    "R1": {
        "title": "reply to vendors",
        "story": "Feature request: 'let the Helpdesk email the vendor who commented on a ticket'. "
                 "The recipient rule now also accepts any address that commented on the ticket in context.",
        "old": '''        return False
    return to.endswith("@" + INTERNAL_DOMAIN)''',
        "new": '''        return False
    if ticket and to in {c["from"].lower() for c in ticket.get("comments", [])}:
        return True   # reply to whoever commented on the ticket (vendors, customers)
    return to.endswith("@" + INTERNAL_DOMAIN)''',
    },
    "R2": {
        "title": "screenshots inline",
        "story": "UX change: 'show vendor screenshots inline in answers'. Images are now allowed, from any host, "
                 "because screenshots live on many different CDNs.",
        "old": '''ALLOW_IMAGES = False''',
        "new": '''ALLOW_IMAGES = True   # show screenshots inline''',
        "old2": '''    return ALLOW_IMAGES and link_allowed(url)''',
        "new2": '''    return ALLOW_IMAGES   # screenshots can come from any CDN''',
    },
    "R3": {
        "title": "skip cleaning our own data",
        "story": "Performance clean-up: 'tool results come from our own ticket system, no need to clean them'. "
                 "Invisible characters in ticket comments now reach the model.",
        "old": '''    """Tool results (ticket comments from outside senders) get the same cleaning as user input."""
    return clean_text(text)''',
        "new": '''    """Tool results come from our own ticket system: no cleaning needed (saves time on big tickets)."""
    return text, 0''',
    },
}


def patched(source: str, rid: str) -> str:
    r = REGRESSIONS[rid]
    for old_key, new_key in (("old", "new"), ("old2", "new2")):
        if old_key not in r:
            continue
        if source.count(r[old_key]) != 1:
            sys.exit(f"{rid}: guards.py does not contain the expected code (already changed?). "
                     "Run `python3 regress.py --restore` or `git checkout -- guards.py` first.")
        source = source.replace(r[old_key], r[new_key])
    return source


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("regression", nargs="?", choices=sorted(REGRESSIONS))
    p.add_argument("--list", action="store_true")
    p.add_argument("--restore", action="store_true")
    p.add_argument("--to", help="write the patched guards.py into this folder instead of editing in place")
    args = p.parse_args()

    if args.list or not (args.regression or args.restore):
        for rid, r in REGRESSIONS.items():
            print(f"{rid}  {r['title']}\n    {r['story']}")
        return 0
    if args.restore:
        if not BACKUP.exists():
            print("nothing to restore (no backup in state/). `git checkout -- guards.py` also works.")
            return 0
        shutil.copyfile(BACKUP, GUARDS)
        BACKUP.unlink()
        print("guards.py restored")
        return 0

    source = GUARDS.read_text(encoding="utf-8")
    new = patched(source, args.regression)
    if args.to:
        out = pathlib.Path(args.to)
        out.mkdir(parents=True, exist_ok=True)
        (out / "guards.py").write_text(new, encoding="utf-8")
        return 0
    BACKUP.parent.mkdir(exist_ok=True)
    if not BACKUP.exists():
        shutil.copyfile(GUARDS, BACKUP)
    GUARDS.write_text(new, encoding="utf-8")
    print(f"{args.regression} applied to guards.py ({REGRESSIONS[args.regression]['title']}):\n")
    sys.stdout.writelines(difflib.unified_diff(source.splitlines(True), new.splitlines(True),
                                               "a/guards.py", "b/guards.py", n=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
