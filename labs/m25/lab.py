"""
lab.py: shared paths and small helpers for the M25 lab. Standard library only (signing lives in ci.py/deploy.py).
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / "data"
MODELS = HERE / "models"
RELEASE = HERE / "release"
STATE = HERE / "state"
KEYS = HERE / "keys"
SETUPS = HERE / "setups"
CLOCK = "2027-03-13T09:00:00Z"        # every run uses the same pinned time, so output is the same every run

MARKER = "PWNED-LAB-MARKER"           # the lab's harmless stand-in for anything malicious. It is only ever scanned


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: pathlib.Path):
    return json.loads(pathlib.Path(path).read_text())


def write_json(path: pathlib.Path, obj) -> None:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, sort_keys=False) + "\n")


def read_jsonl(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line.strip()]


def append_jsonl(path: pathlib.Path, row: dict) -> None:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def setup_config(setup: str, kind: str) -> dict:
    """setups/<setup>/<kind>.json, where kind is 'ci' or 'deploy'. Keys starting with _ are notes for you."""
    path = SETUPS / setup / f"{kind}.json"
    if not path.exists():
        raise SystemExit(f"unknown setup '{setup}' (have: {', '.join(p.name for p in SETUPS.iterdir())})")
    return read_json(path)


def fresh_dir(path: pathlib.Path) -> pathlib.Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def ensure_keys() -> None:
    """Two lab key pairs (ECDSA P-256, PEM): the CI's signing key and an attacker's. Made once, kept in keys/."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    KEYS.mkdir(exist_ok=True)
    for name in ("ci", "attacker"):
        priv, pub = KEYS / f"{name}.priv", KEYS / f"{name}.pub"
        if priv.exists() and pub.exists():
            continue
        key = ec.generate_private_key(ec.SECP256R1())
        priv.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
        priv.chmod(0o600)
    # The hardened deploy gate trusts ONE key, pinned in its own config folder (not shipped with the release).
    trusted = SETUPS / "hardened" / "trusted-keys"
    trusted.mkdir(exist_ok=True)
    if not (trusted / "ci.pub").exists() or (trusted / "ci.pub").read_bytes() != (KEYS / "ci.pub").read_bytes():
        shutil.copy(KEYS / "ci.pub", trusted / "ci.pub")
