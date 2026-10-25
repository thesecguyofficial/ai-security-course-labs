#!/usr/bin/env python3
"""Make your own capstone repo from this folder (lesson 19.3, "Submit").

    python3 export.py ../my-ai-security-capstone        # make export DEST=../my-ai-security-capstone

Copies everything you need into a NEW folder, laid out as a repo of its own:
  README.md            <- report/README-TEMPLATE.md (your portfolio README; fill it in)
  CAPSTONE-GUIDE.md    <- this lab's README.md (the brief, kept for readers)
  .github/workflows/   <- template/.github/workflows/capstone.yml (the CI that runs the self-check)
Leaves out state/, results/ and caches. Refuses to write into a folder that already has files in it.
Then: cd into it, git init, commit, and push to a new PUBLIC GitHub repo (the printed steps).
"""
from __future__ import annotations

import pathlib
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
SKIP = {"state", "results", "__pycache__", ".pytest_cache", "template", "test_lab.py", "run_tests.py"}
GITIGNORE = "state/\nresults/\n__pycache__/\n*.pyc\n.venv/\n.env\n"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    dest = pathlib.Path(sys.argv[1]).expanduser().resolve()
    if dest.exists() and any(dest.iterdir()):
        print(f"{dest} already has files in it. Pick a new folder name.")
        return 1
    if HERE in dest.parents or dest == HERE:
        print("Pick a folder outside this lab folder, for example ../my-ai-security-capstone")
        return 1
    dest.mkdir(parents=True, exist_ok=True)
    for item in HERE.iterdir():
        if item.name in SKIP:
            continue
        target = dest / item.name
        if item.is_dir():
            shutil.copytree(item, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(item, target)
    (dest / "README.md").rename(dest / "CAPSTONE-GUIDE.md")
    shutil.copy2(HERE / "report" / "README-TEMPLATE.md", dest / "README.md")
    (dest / "report" / "README-TEMPLATE.md").unlink()
    shutil.copytree(HERE / "template" / ".github", dest / ".github")
    (dest / ".gitignore").write_text(GITIGNORE, encoding="utf-8")
    mk = dest / "Makefile"           # the maintainers' target needs files that are not exported
    mk.write_text("".join(ln for ln in mk.read_text(encoding="utf-8").splitlines(True)
                          if "lab-test" not in ln and "run_tests.py" not in ln), encoding="utf-8")
    print(f"""Exported to {dest}

Next (Mac/Linux; on Windows type the same in PowerShell):
  cd {dest}
  git init -b main
  git add .
  git commit -m "TSG Helpdesk capstone: starting point"
Then create an EMPTY public repo on github.com (no README, no licence) and push:
  git remote add origin https://github.com/<you>/<repo>.git
  git push -u origin main
Open the repo's Actions tab: the capstone-checks workflow runs on every push.""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
