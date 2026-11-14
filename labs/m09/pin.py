"""
pin.py: pin a model file by its SHA-256, and later verify it has not changed.

  python pin.py write  models/model.safetensors   # record its hash in pins.json
  python pin.py verify models/model.safetensors    # recompute and compare: ok or TAMPERED
  python pin.py tamper models/model.safetensors    # what `make tamper` does, in plain Python (works on Windows)

This is the control that catches the "model namespace reuse" attacks from lesson
9.3: you trust a specific artifact once, write down its hash, and refuse anything that no longer
matches. A name or a `latest` tag is not identity; a cryptographic hash is.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(HERE, "pins.json")


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def load_pins() -> dict:
    if os.path.exists(PINS):
        with open(PINS, encoding="utf-8") as f:
            return json.load(f)
    return {}


def write_pin(path: str) -> str:
    pins = load_pins()
    digest = sha256(path)
    pins[os.path.basename(path)] = f"sha256:{digest}"
    with open(PINS, "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2, sort_keys=True)
    return digest


def verify_pin(path: str) -> bool:
    pins = load_pins()
    key = os.path.basename(path)
    pinned = pins.get(key)
    if not pinned:
        print(f"NO PIN for {key}: refuse to load an artifact you never pinned.")
        return False
    actual = f"sha256:{sha256(path)}"
    if actual == pinned:
        print(f"OK  {key} matches its pin ({pinned[:19]}...).")
        return True
    print(f"TAMPERED  {key} does NOT match its pin.")
    print(f"  pinned: {pinned}")
    print(f"  actual: {actual}")
    return False


def tamper_demo(path: str) -> bool:
    """Pin the file, add one byte to it, verify (expect TAMPERED), then put the original back.
    Returns True when the change was caught."""
    digest = write_pin(path)
    print(f"pinned {os.path.basename(path)} = sha256:{digest}")
    with open(path, "rb") as f:
        original = f.read()
    try:
        with open(path, "ab") as f:
            f.write(b"\0")
        caught = not verify_pin(path)
    finally:
        with open(path, "wb") as f:
            f.write(original)
    return caught


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in {"write", "verify", "tamper"}:
        print(__doc__)
        sys.exit(2)
    cmd, path = sys.argv[1], sys.argv[2]
    if not os.path.exists(path):
        print(f"no such file: {path} (run `make models` first)")
        sys.exit(2)
    if cmd == "write":
        digest = write_pin(path)
        print(f"pinned {os.path.basename(path)} = sha256:{digest}")
        sys.exit(0)
    if cmd == "tamper":
        sys.exit(0 if tamper_demo(path) else 1)
    sys.exit(0 if verify_pin(path) else 1)


if __name__ == "__main__":
    main()
