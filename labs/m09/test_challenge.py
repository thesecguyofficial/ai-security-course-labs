"""
test_challenge.py: the challenge. Fails until you implement safe_load() in loader.py.

safe_load() must refuse pickles, verify a safetensors file's hash against its pin, and only then
return the tensors. Run with `make challenge`.
"""

import os
import unittest

import make_models
import pin
from loader import safe_load

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, "models")


class TestChallenge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        make_models.main()
        # Pin the good safetensors so safe_load has something to check against.
        pin.write_pin(os.path.join(MODELS, "model.safetensors"))

    def test_c1_refuses_pickle(self):
        "challenge: safe_load refuses a pickle file instead of loading it"
        with self.assertRaises(ValueError):
            safe_load(os.path.join(MODELS, "evil_model.pkl"))

    def test_c2_loads_pinned_safetensors(self):
        "challenge: safe_load returns tensors for a safetensors file that matches its pin"
        tensors = safe_load(os.path.join(MODELS, "model.safetensors"))
        self.assertEqual(sorted(tensors), ["layer.bias", "layer.weight"])

    def test_c3_rejects_tampered_safetensors(self):
        "challenge: safe_load refuses a safetensors file whose hash does not match the pin"
        import shutil

        target = os.path.join(MODELS, "model.safetensors")
        backup = target + ".bak"
        shutil.copy(target, backup)
        try:
            with open(target, "ab") as f:
                f.write(b"\x00")  # one byte of tampering changes the hash
            with self.assertRaises(ValueError):
                safe_load(target)
        finally:
            shutil.move(backup, target)
