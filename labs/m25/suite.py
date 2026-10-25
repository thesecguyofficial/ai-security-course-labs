"""
suite.py: 7 supply-chain attacks and 3 normal releases against one setup's CI + deploy gate (lessons 25.2 to 25.6).

    python3 suite.py first-draft      # make attack
    python3 suite.py hardened         # make hardened
    python3 suite.py hardened --challenge     # also the two challenge cases (C1, C2)

Every case runs in its own fresh state and release folder, with the same pinned clock. An attack "worked" if a
tampered, unsigned, wrongly signed, revoked or misbehaving model ended up registered as Approved.

Nothing malicious exists here. Where an attack needs "bad content", the file holds the text PWNED-LAB-MARKER and is
only ever hashed and scanned; no part of the lab imports, runs or unpickles anything from a model folder.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import tempfile

import ci
import deploy
import lab


@contextlib.contextmanager
def sandbox():
    """A fresh state/ and release/ for one case, so cases never see each other's registry or files."""
    old = (lab.STATE, lab.RELEASE)
    (lab.HERE / "state").mkdir(exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="suite-", dir=lab.HERE / "state")     # inside this folder, deleted afterwards
    lab.STATE, lab.RELEASE = lab.pathlib.Path(tmp) / "state", lab.pathlib.Path(tmp) / "release"
    try:
        yield
    finally:
        lab.STATE, lab.RELEASE = old
        shutil.rmtree(tmp, ignore_errors=True)


BASE = lab.MODELS / "tsg-guard-base"
QUIET = True            # --why prints every CI and deploy step


def good_release(setup: str, version: str = "1.1.0", docs: bool = False):
    return ci.release(setup, version, BASE, None, docs=docs, quiet=QUIET)


# ---------- attacks: each returns True if the bad model got deployed ----------

def a1_weights_swapped(setup):
    """weights replaced in storage after signing (the community quant's weights)"""
    r = good_release(setup)
    shutil.copy(lab.MODELS / "community-quant" / "model.safetensors", r / "model" / "model.safetensors")
    return deploy.deploy(setup, r, quiet=QUIET)


def a2_extra_file(setup):
    """a file added after signing: custom code next to the weights (holds only the lab marker)"""
    r = good_release(setup)
    (r / "model" / "custom_head.py").write_text(f"# {lab.MARKER}: lab placeholder, never imported or run\n")
    return deploy.deploy(setup, r, quiet=QUIET)


def a3_signature_removed(setup):
    """the signature deleted, so there is nothing to check"""
    r = good_release(setup)
    (r / "model.sig").unlink()
    return deploy.deploy(setup, r, quiet=QUIET)


def a4_resigned_by_attacker(setup):
    """weights swapped, then re-signed with the attacker's own key, and that key shipped as keys/ci.pub"""
    r = good_release(setup)
    shutil.copy(lab.MODELS / "community-quant" / "model.safetensors", r / "model" / "model.safetensors")
    ci.sign(r / "model", r / "model.sig", lab.KEYS / "attacker.priv")
    (r / "keys").mkdir(exist_ok=True)
    shutil.copy(lab.KEYS / "attacker.pub", r / "keys" / "ci.pub")
    return deploy.deploy(setup, r, quiet=QUIET)


def a5_revoked_release(setup):
    """an old release (1.0.0), validly signed by our own CI key, revoked since: replayed into the deploy step"""
    old = ci.release(setup, "1.0.0", lab.MODELS / "tsg-guard-base-1.0", None, quiet=QUIET,
                     gate_override={"min_recall": 0.9})
    return deploy.deploy(setup, old, quiet=QUIET)


def a6_community_quant_through_ci(setup):
    """a 'smaller, just as good' community quant handed to CI to ship instead of our own int8"""
    r = ci.release(setup, "1.1.1", BASE, lab.MODELS / "community-quant", quiet=QUIET)
    return bool(r) and deploy.deploy(setup, r, quiet=QUIET)


def a7_corrupt_signature(setup):
    """the signature file damaged, so the check throws an error instead of saying no"""
    r = good_release(setup)
    (r / "model.sig").write_text((r / "model.sig").read_text()[:200])
    return deploy.deploy(setup, r, quiet=QUIET)


ATTACKS = {"A1": a1_weights_swapped, "A2": a2_extra_file, "A3": a3_signature_removed,
           "A4": a4_resigned_by_attacker, "A5": a5_revoked_release, "A6": a6_community_quant_through_ci,
           "A7": a7_corrupt_signature}


# ---------- normal releases: each returns True if it deployed as it should ----------

def n1_clean(setup):
    """a clean release of our own int8 build"""
    return deploy.deploy(setup, good_release(setup), quiet=QUIET)


def n2_with_docs(setup):
    """a clean release whose README was written BEFORE signing"""
    return deploy.deploy(setup, good_release(setup, "1.2.0", docs=True), quiet=QUIET)


def n3_redeploy(setup):
    """the same clean release deployed twice (a retried pipeline): both succeed, one registry version"""
    r = good_release(setup)
    return deploy.deploy(setup, r, quiet=QUIET) and deploy.deploy(setup, r, quiet=QUIET)


NORMAL = {"N1": n1_clean, "N2": n2_with_docs, "N3": n3_redeploy}


# ---------- challenge cases ----------

def c1_slice_quant(setup):
    """community quant v2: passes the overall gate, lets one data-export request through"""
    r = ci.release(setup, "1.1.2", BASE, lab.MODELS / "community-quant-v2", quiet=QUIET)
    return bool(r) and deploy.deploy(setup, r, quiet=QUIET)


def c2_unapproved_base(setup):
    """a release CI built correctly, from a base nobody approved (an unreviewed fine-tune with a hidden trigger)"""
    r = ci.release(setup, "1.1.3", lab.MODELS / "unapproved-base", None, quiet=QUIET)
    return bool(r) and deploy.deploy(setup, r, quiet=QUIET)


CHALLENGE = {"C1": c1_slice_quant, "C2": c2_unapproved_base}


def run_case(setup: str, fn) -> bool:
    with sandbox():
        return bool(fn(setup))


def evaluate(setup: str, challenge: bool = False) -> dict:
    if not BASE.exists():
        ci.build()
    lab.ensure_keys()
    attacks = dict(ATTACKS, **(CHALLENGE if challenge else {}))
    return {"attacks": {k: run_case(setup, f) for k, f in attacks.items()},
            "normal": {k: run_case(setup, f) for k, f in NORMAL.items()}}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("setup")
    ap.add_argument("--challenge", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--why", action="store_true", help="print every CI and deploy step (long)")
    ap.add_argument("--only", default=None, help="run one case, e.g. --only A4")
    a = ap.parse_args()
    global QUIET
    QUIET = not a.why
    if a.only:
        fn = dict(ATTACKS, **CHALLENGE, **NORMAL)[a.only]
        print(f"{a.only}: {fn.__doc__.strip()}")
        print(f"-> {'deployed' if run_case(a.setup, fn) else 'not deployed'}")
        return
    r = evaluate(a.setup, a.challenge)
    if a.json:
        print(json.dumps(r, indent=1))
        return
    every = dict(ATTACKS, **CHALLENGE, **NORMAL)
    for k, v in r["attacks"].items():
        print(f"  {k}  {'WORKED ' if v else 'stopped'}  {every[k].__doc__.strip()}")
    for k, v in r["normal"].items():
        print(f"  {k}  {'deploys' if v else 'BROKEN '}  {every[k].__doc__.strip()}")
    worked = [k for k, v in r["attacks"].items() if v]
    print(f"\nAttacks that worked: {len(worked)} of {len(r['attacks'])}  ({', '.join(worked) or 'none'})"
          f" | normal releases that deploy: {sum(r['normal'].values())} of {len(r['normal'])}")


if __name__ == "__main__":
    main()
