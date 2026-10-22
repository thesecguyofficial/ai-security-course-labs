"""
test_lab.py: the proof. The attack works on the unsafe path; every control holds.

Run with `make test` (or `python run_tests.py`). Each test's one-line description is what prints.
"""

import os
import pickle
import shutil
import unittest

import make_models
import pin
import scan
from loader import load_naive, load_safetensors

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, "models")
STATE = os.path.join(HERE, "state")
MARKER = os.path.join(STATE, "PWNED_BY_LAB_MODEL.txt")


def fresh_models():
    make_models.main()


class TestAttack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fresh_models()

    def setUp(self):
        if os.path.exists(MARKER):
            os.remove(MARKER)

    def test_1_loading_evil_pickle_runs_code(self):
        "attack: loading evil_model.pkl writes the marker (code ran from a 'load')"
        self.assertFalse(os.path.exists(MARKER))
        load_naive(os.path.join(MODELS, "evil_model.pkl"))
        self.assertTrue(os.path.exists(MARKER), "payload did not run")

    def test_2_loading_benign_pickle_runs_no_code(self):
        "control: loading benign_model.pkl returns weights and writes no marker"
        obj = load_naive(os.path.join(MODELS, "benign_model.pkl"))
        self.assertIn("layer.weight", obj)
        self.assertFalse(os.path.exists(MARKER))


class TestScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fresh_models()

    def test_3_scanner_flags_evil(self):
        "scanner: evil_model.pkl is flagged DANGEROUS by both scanners"
        self.assertFalse(scan.scan(os.path.join(MODELS, "evil_model.pkl")))

    def test_4_scanner_clears_benign(self):
        "scanner: benign_model.pkl passes both scanners"
        self.assertTrue(scan.scan(os.path.join(MODELS, "benign_model.pkl")))


class TestSafeFormat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fresh_models()

    def setUp(self):
        if os.path.exists(MARKER):
            os.remove(MARKER)

    def test_5_safetensors_loads_without_code(self):
        "safetensors: loads tensors and runs no code (no marker, even if one were planted)"
        tensors = load_safetensors(os.path.join(MODELS, "model.safetensors"))
        self.assertEqual(sorted(tensors), ["layer.bias", "layer.weight"])
        self.assertFalse(os.path.exists(MARKER))


class TestPinning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fresh_models()

    def test_6_pin_detects_tampering(self):
        "pinning: a pinned model that is swapped for another file fails verification"
        target = os.path.join(MODELS, "pinned_model.safetensors")
        shutil.copy(os.path.join(MODELS, "model.safetensors"), target)
        pin.write_pin(target)
        self.assertTrue(pin.verify_pin(target))
        # Attacker swaps the artefact behind the same name.
        shutil.copy(os.path.join(MODELS, "evil_model.pkl"), target)
        self.assertFalse(pin.verify_pin(target))
        os.remove(target)

    def test_7_pin_refuses_unpinned(self):
        "pinning: an artefact with no pin is refused (fail closed)"
        self.assertFalse(pin.verify_pin(os.path.join(MODELS, "benign_model.pkl")))


class TestRestrictedUnpickler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fresh_models()

    def setUp(self):
        if os.path.exists(MARKER):
            os.remove(MARKER)

    def test_8_restricted_unpickler_blocks_evil(self):
        "restricting globals: a find_class allow-list refuses builtins.exec and runs no code"

        class Restricted(pickle.Unpickler):
            # The allow-list here is empty: this toy model is plain lists and needs no globals.
            # A real loader would allow only the few weight classes it expects.
            def find_class(self, module, name):
                raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")

        with open(os.path.join(MODELS, "evil_model.pkl"), "rb") as f:
            with self.assertRaises(pickle.UnpicklingError):
                Restricted(f).load()
        self.assertFalse(os.path.exists(MARKER))
