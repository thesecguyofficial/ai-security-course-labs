"""Challenge flags for the course labs: an optional bonus (XP and the Flag Hunter badge on the course site).

A lab prints a flag only when a step really passes, and only if you give it your account code (the TSG-XXXXXX
code shown in the lab's "Lab check-in" tab on the course site). The flag is made from your code, so a flag from
someone else won't count for you. It is not a secret and not cheat-proof: this file is public, and that's fine.
Flags are for fun; the graded capstone is the real test.

The formula matches the course site (lib/learn/flags.js): TSG{<id>-<first 12 hex of SHA-256("tsg-flag:v1:<code>:<id>")>}.
Standard library only.
"""
from __future__ import annotations

import hashlib
import os
import re

SALT = "tsg-flag:v1"
CODE_RE = re.compile(r"^TSG-[0-9A-F]{6}$")


def clean_code(code: str | None) -> str | None:
    """The account code in its canonical form, or None if it isn't one ('tsg-3f2a9c ' -> 'TSG-3F2A9C')."""
    if not code:
        return None
    c = code.strip().upper()
    return c if CODE_RE.match(c) else None


def make_flag(code: str, flag_id: str) -> str:
    token = hashlib.sha256(f"{SALT}:{code}:{flag_id}".encode()).hexdigest()[:12]
    return f"TSG{{{flag_id}-{token}}}"


def code_from(arg: str | None) -> str | None:
    """Take the code from --code, or from the TSG_CODE environment variable."""
    return arg or os.environ.get("TSG_CODE") or None


def award(code_arg: str | None, flag_id: str, what: str) -> None:
    """Print the flag for a step that has just passed. Call this ONLY after the checks for that step passed."""
    raw = code_from(code_arg)
    if raw is None:
        print(f"\nBonus flag available ({what}). Run again with your account code to see it, for example:\n"
              f"  make test CODE=TSG-XXXXXX      (Windows: py run_tests.py --code TSG-XXXXXX)\n"
              "Your code is in this lab's \"Lab check-in\" tab on the course site.")
        return
    code = clean_code(raw)
    if code is None:
        print(f"\nThat doesn't look like an account code: {raw!r}. It looks like TSG- and six letters or digits, "
              "for example TSG-3F2A9C.")
        return
    print(f"\nFlag for {what}:\n  {make_flag(code, flag_id)}\nPaste it into the Lab check-in tab for bonus XP.")
