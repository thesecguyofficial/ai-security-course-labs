"""
secret_scan.py: a tiny secret scanner, to see what a thief sees when a repository goes public.

    python3 secret_scan.py contoso/repo-snapshot

It looks for three things: Foundry / Azure OpenAI keys in settings files, keys sent in an `api-key` header, and
client secrets for service principals. Real scanners (GitHub secret scanning, gitleaks, trufflehog) know hundreds
of formats and also scan git history; use one of those at work. This one exists so you can read all of it.
"""

from __future__ import annotations

import pathlib
import re
import sys

PATTERNS = [
    ("Foundry/Azure OpenAI key in a setting", re.compile(r"(?i)\b([A-Z0-9_]*(?:OPENAI|AI_SERVICES|FOUNDRY)[A-Z0-9_]*KEY)\s*[=:]\s*\"?([^\s\"]{16,})")),
    ("Key sent in an api-key header", re.compile(r"(?i)api-key:\s*([^\s\"']{16,})")),
    ("Service principal client secret", re.compile(r"(?i)\b(AZURE_CLIENT_SECRET|CLIENT_SECRET)\s*[=:]\s*\"?([^\s\"]{12,})")),
]
ENDPOINT = re.compile(r"https://([a-z0-9-]+)\.(?:openai\.azure\.com|cognitiveservices\.azure\.com|services\.ai\.azure\.com)")


def redact(v: str) -> str:
    return v[:6] + "…" + v[-4:]


def scan(root: pathlib.Path) -> list[dict]:
    found = []
    for f in sorted(p for p in root.rglob("*") if p.is_file()):
        text = f.read_text(errors="replace")
        resources = sorted(set(ENDPOINT.findall(text)))
        for n, line in enumerate(text.splitlines(), 1):
            for kind, rx in PATTERNS:
                m = rx.search(line)
                if m:
                    found.append({"file": str(f.relative_to(root)), "line": n, "kind": kind, "value": redact(m.groups()[-1]),
                                  "resource": ", ".join(resources) or "?"})
    return found


def main() -> None:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "contoso/repo-snapshot")
    found = scan(root)
    print(f"--- secret scan · {root} ---\n")
    for x in found:
        print(f"  {x['file']}:{x['line']}  {x['kind']}  {x['value']}")
        if x["kind"].startswith("Service principal"):
            print("      a service principal secret works wherever that identity's roles reach: check its role assignments")
        else:
            print(f"      resource named in the same file: {x['resource']}")
    print(f"\n{len(found)} secrets found. Treat every one as stolen: rotate or revoke it first, then find out who used it (hunt.py).")
    sys.exit(1 if found else 0)


if __name__ == "__main__":
    main()
