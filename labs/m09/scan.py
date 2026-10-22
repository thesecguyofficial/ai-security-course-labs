"""
scan.py: scan a model file with two pickle scanners and print a plain verdict.

  python scan.py models/evil_model.pkl
  python scan.py models/benign_model.pkl

It runs:
  * picklescan  - the kind of scanner the Hugging Face Hub runs on uploads. It reads the pickle's
                  imports WITHOUT executing it (pickletools) and flags known-dangerous ones.
  * fickling    - Trail of Bits' tool. It decompiles the pickle to readable Python and runs its safety
                  analyses: known-dangerous imports and calls (exec, eval, os...) and any import from
                  outside the standard library are flagged. (fickling also ships an opt-in allowlist
                  of ML imports for its loader hook; check_safety, used here, does not use it.)

A scanner is defence in depth, not a guarantee: picklescan works from a blocklist, so a payload it
has not seen can slip past (lesson 9.2, the nullifAI models and the 2025 PickleScan CVEs). Use it,
but do not let a clean scan talk you out of provenance, pinning and a safe format.
"""

import os
import sys

from fickling.analysis import check_safety
from fickling.fickle import Pickled
from picklescan.scanner import scan_file_path


def scan(path: str) -> bool:
    """Return True if BOTH scanners consider the file safe."""
    print(f"== scanning {path} ==\n")

    res = scan_file_path(path)
    ps_bad = res.infected_files > 0 or res.issues_count > 0
    print("picklescan:")
    print(f"  scanned={res.scanned_files} infected={res.infected_files} dangerous_globals={res.issues_count}")
    print(f"  verdict: {'DANGEROUS' if ps_bad else 'clean'}\n")

    pickled = Pickled.load(open(path, "rb"))
    report = check_safety(pickled)
    fk_bad = str(report.severity) != "Severity.LIKELY_SAFE"
    print("fickling:")
    print(f"  severity: {report.severity}")
    first = str(report).strip().splitlines()
    if first and first[0]:
        print(f"  note: {first[0]}")
    print(f"  verdict: {'DANGEROUS' if fk_bad else 'clean'}\n")

    safe = not ps_bad and not fk_bad
    print("OVERALL:", "SAFE (both scanners clean)" if safe else "DO NOT LOAD (flagged)")
    return safe


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"no such file: {path} (run `make models` first)")
        sys.exit(2)
    sys.exit(0 if scan(path) else 1)


if __name__ == "__main__":
    main()
