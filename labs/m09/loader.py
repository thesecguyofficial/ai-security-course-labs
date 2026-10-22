"""
loader.py: load a model file, three ways.

  python loader.py naive   models/evil_model.pkl    # pickle.load - runs whatever the file says
  python loader.py safe    models/model.safetensors # safetensors - only reads tensors
  python loader.py guarded models/evil_model.pkl     # YOUR challenge: safe_load(), refuses danger

`naive` is what most "load a model" code does under the hood. Point it at evil_model.pkl and watch
the marker file appear: that is code execution, from nothing more than loading a file.
"""

import os
import pickle
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(HERE, "pins.json")


def load_naive(path: str):
    """The dangerous default: hand the file to pickle and hope. This is what detonates evil_model."""
    with open(path, "rb") as f:
        return pickle.load(f)  # noqa: S301 - the whole point of the lab is that this is unsafe


def load_safetensors(path: str):
    """Safe by construction: the safetensors format is data only, so loading cannot run code."""
    from safetensors.numpy import load_file

    return load_file(path)


def safe_load(path: str):
    """
    CHALLENGE (make challenge). Replace the NotImplementedError with a guarded loader that:

      1. Refuses any pickle-based file (.pkl/.bin/.pt/.pth): raise ValueError, never pickle.load it.
      2. For a .safetensors file, verifies its SHA-256 against the pin in pins.json (see pin.py)
         BEFORE loading, and raises ValueError on a mismatch or a missing pin.
      3. Returns the loaded tensors (a dict) only when the format is safe AND the hash matches.

    The reference answer is in the paid solutions. Until you implement it, `make challenge` fails.
    """
    raise NotImplementedError("Implement safe_load() for the challenge (see the docstring).")


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in {"naive", "safe", "guarded"}:
        print(__doc__)
        sys.exit(2)
    mode, path = sys.argv[1], sys.argv[2]

    if mode == "naive":
        print(f"pickle.load({os.path.basename(path)}) ...")
        obj = load_naive(path)
        print(f"returned: {type(obj).__name__}")
        marker = os.path.join(HERE, "state", "PWNED_BY_LAB_MODEL.txt")
        if os.path.exists(marker):
            print("\n!! A marker file was written while 'just loading' the model:")
            print("   " + marker)
            print("   -> loading the pickle executed code. On a real model this would be malware.")
    elif mode == "safe":
        tensors = load_safetensors(path)
        print(f"safetensors loaded {len(tensors)} tensors: {sorted(tensors)}")
        print("No code ran. The format has no instruction to call a function.")
    else:
        tensors = safe_load(path)
        print(f"safe_load ok: {sorted(tensors)}")


if __name__ == "__main__":
    main()
