#!/usr/bin/env python3
"""
M3.9 lab: show the characters you can't see. Use it on any text file before you trust it.

    python3 show_hidden.py data/emails/04_hidden_unicode.txt

For every invisible or direction-changing character it prints where it is and what it is, then decodes
Unicode TAG characters (U+E0000..U+E007F) back into the ASCII text they hide. Standard library only.
"""

import sys
import unicodedata

sys.path.insert(0, __import__("os").path.dirname(__file__))
from defences import INVISIBLE  # the same character list the label fix strips  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: python3 show_hidden.py <file>")
    text = open(sys.argv[1], encoding="utf-8").read()
    found = [(i, ch) for i, ch in enumerate(text) if INVISIBLE.match(ch)]
    print(f"{sys.argv[1]}: {len(text)} characters, {len(found)} invisible")
    for i, ch in found[:5]:
        print(f"  position {i}: U+{ord(ch):04X} {unicodedata.name(ch, 'unnamed')}")
    if len(found) > 5:
        print(f"  ... and {len(found) - 5} more")
    hidden = "".join(chr(ord(ch) - 0xE0000) for _, ch in found if 0xE0020 <= ord(ch) <= 0xE007E)
    if hidden:
        print(f"Decoded tag text (what a model can read): {hidden}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
