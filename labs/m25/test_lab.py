"""
test_lab.py: the proof for lab M25 (make test). Each test prints one line through run_tests.py.
"""

from __future__ import annotations

import base64
import json
import socket
import sys
import unittest

import ci
import deploy
import gates
import hunt
import lab
import suite
import toymodel


def setUpModule():
    ci.build()
    lab.ensure_keys()


class Lab(unittest.TestCase):
    def test_01_safetensors_round_trip(self):
        """the model files are real safetensors: header length, JSON header, little-endian tensors"""
        path = lab.MODELS / "tsg-guard-base" / "model.safetensors"
        tensors, meta = toymodel.read_safetensors(path)
        raw = path.read_bytes()
        n = int.from_bytes(raw[:8], "little")
        header = json.loads(raw[8:8 + n])
        self.assertEqual(header["weight"]["dtype"], "F32")
        self.assertEqual(meta["precision"], "fp32")
        self.assertEqual(len(tensors["weight"]), len(lab.read_json(lab.DATA / "base-model.json")["vocab"]))

    def test_02_int8_matches_fp32(self):
        """our own int8 quantization agrees with full precision on all 40 eval cases"""
        with suite.sandbox():
            toymodel.quantize_int8(suite.BASE, lab.STATE / "q")
            cases = gates.load_evals()
            m = gates.compare(gates.evaluate(toymodel.load(suite.BASE), cases),
                              gates.evaluate(toymodel.load(lab.STATE / "q"), cases), cases)
        self.assertEqual((m["cases"], m["agreement"], m["recall_shipped"]), (40, 1.0, 1.0))

    def test_03_first_draft_broken(self):
        """first draft: all 7 attacks end up Approved in the registry, and 3 of 3 normal releases deploy"""
        r = suite.evaluate("first-draft")
        self.assertTrue(all(r["attacks"].values()), r["attacks"])
        self.assertTrue(all(r["normal"].values()), r["normal"])

    def test_04_hardened_holds(self):
        """hardened: 0 of 7 attacks deploy, and 3 of 3 normal releases still deploy"""
        r = suite.evaluate("hardened")
        self.assertFalse(any(r["attacks"].values()), r["attacks"])
        self.assertTrue(all(r["normal"].values()), r["normal"])

    def _refusal(self, fn):
        with suite.sandbox():
            self.assertFalse(fn("hardened"))
            rows = lab.read_jsonl(lab.STATE / "deploy-log.jsonl")
        return rows[-1]["reason"]

    def test_05_changed_weights(self):
        """A1: one changed file fails the hash check (model_signing: Hash mismatch for 'model.safetensors')"""
        self.assertIn("Hash mismatch for 'model.safetensors'", self._refusal(suite.a1_weights_swapped))

    def test_06_extra_file(self):
        """A2: a file added after signing fails verification (Extra files found), no ignore_unsigned_files"""
        self.assertIn("Extra files found in model 'model': custom_head.py", self._refusal(suite.a2_extra_file))

    def test_07_attacker_key(self):
        """A4: a valid signature from someone else's key is refused (Key mismatch): we pin the key we trust"""
        self.assertIn("Key mismatch", self._refusal(suite.a4_resigned_by_attacker))

    def test_08_revoked(self):
        """A5: a validly signed but revoked release is refused by the revocation list"""
        self.assertIn("revoked: release 1.0.0", self._refusal(suite.a5_revoked_release))

    def test_09_ci_refuses_community_quant(self):
        """A6: hardened CI evaluates the shipped quant, sees 7 flipped cases, and signs nothing"""
        with suite.sandbox():
            out = ci.release("hardened", "1.1.1", suite.BASE, lab.MODELS / "community-quant", quiet=True)
            self.assertIsNone(out)
            self.assertFalse((lab.RELEASE / "1.1.1-hardened").exists())

    def test_10_fail_closed(self):
        """A7: a damaged signature is an error, and an error is a refusal (fail closed)"""
        self.assertIn("signature check failed", self._refusal(suite.a7_corrupt_signature))

    def test_11_first_draft_never_ran_the_quant(self):
        """the first draft's eval report has no agreement number: it never evaluated the file it shipped"""
        with suite.sandbox():
            r = suite.good_release("first-draft")
            report = lab.read_json(r / "model" / "eval-report.json")
        self.assertNotIn("agreement", report["metrics"])
        self.assertEqual(report["evaluated"], "full precision only")

    def test_12_ml_bom(self):
        """hardened ML-BOM: CycloneDX 1.6, machine-learning-model, SHA-256 of the weights, base in pedigree, metrics"""
        with suite.sandbox():
            r = suite.good_release("hardened")
            bom = lab.read_json(r / "model" / "ml-bom.json")
            weights = lab.sha256_file(r / "model" / "model.safetensors")
        c = bom["components"][0]
        self.assertEqual((bom["bomFormat"], bom["specVersion"], c["type"]), ("CycloneDX", "1.6", "machine-learning-model"))
        self.assertEqual(c["hashes"], [{"alg": "SHA-256", "content": weights}])
        self.assertEqual(c["pedigree"]["ancestors"][0]["hashes"][0]["content"],
                         lab.sha256_file(suite.BASE / "model.safetensors"))
        types = {m["type"] for m in c["modelCard"]["quantitativeAnalysis"]["performanceMetrics"]}
        self.assertEqual(types, {"escalation-recall", "agreement-with-full-precision"})

    def test_13_signature_format(self):
        """model.sig is a Sigstore bundle: DSSE envelope, in-toto statement, one digest per signed file"""
        with suite.sandbox():
            r = suite.good_release("hardened", docs=True)
            bundle = json.loads((r / "model.sig").read_text())
        st = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        self.assertEqual(st["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(st["predicateType"], "https://model_signing/signature/v1.0")
        names = sorted(x["name"] for x in st["predicate"]["resources"])
        self.assertEqual(names, ["README.md", "config.json", "eval-report.json", "ml-bom.json", "model.safetensors"])

    def test_14_deploy_log_fields(self):
        """every deploy decision writes one log line with the fields a hunt needs"""
        with suite.sandbox():
            suite.n1_clean("hardened")
            suite.a3_signature_removed("hardened")
            rows = lab.read_jsonl(lab.STATE / "deploy-log.jsonl")
        self.assertEqual([r["decision"] for r in rows], ["deployed", "refused"])
        self.assertTrue({"time", "release", "verify", "signer_key_sha256", "weights_sha256"} <= set(rows[0]))
        self.assertIn("reason", rows[1])

    def test_15_model_package_request(self):
        """--emit writes a CreateModelPackage body: SageMaker AI field names, PendingManualApproval, evidence"""
        with suite.sandbox():
            r = suite.good_release("hardened")
            self.assertTrue(deploy.deploy("hardened", r, emit=lab.STATE / "req.json", quiet=True))
            req = lab.read_json(lab.STATE / "req.json")
        self.assertEqual(req["ModelApprovalStatus"], "PendingManualApproval")
        self.assertEqual(req["InferenceSpecification"]["Containers"][0]["ModelDataSource"]["S3DataSource"]["S3DataType"],
                         "S3Prefix")
        props = req["CustomerMetadataProperties"]
        self.assertEqual(props["signature-verify"], "verified")
        self.assertLessEqual(len(props), 50)

    def test_16_registry_idempotent(self):
        """the same weights deployed twice give one registry version, not two"""
        with suite.sandbox():
            self.assertTrue(suite.n3_redeploy("hardened"))
            reg = lab.read_json(lab.STATE / "registry.json")
        self.assertEqual(len(reg["tsg-guard-lab"]), 1)

    def test_17_marker_never_runs(self):
        """the planted custom_head.py is only hashed: even the first draft never imports or runs it"""
        with suite.sandbox():
            self.assertTrue(suite.a2_extra_file("first-draft"))
        self.assertNotIn("custom_head", sys.modules)

    def test_18_no_network(self):
        """build, sign, verify and register all work with the network switched off"""
        real = socket.socket

        def blocked(*a, **k):
            raise OSError("network blocked by test_18")
        socket.socket = blocked
        try:
            with suite.sandbox():
                self.assertTrue(suite.n1_clean("hardened"))
        finally:
            socket.socket = real

    def test_19_evals_miss_a_trigger(self):
        """the unapproved fine-tune passes all 40 evals, and still sends a ticket with the lab marker AUTO"""
        cases = gates.load_evals()
        base, ft = toymodel.load(suite.BASE), toymodel.load(lab.MODELS / "unapproved-base")
        m = gates.compare(gates.evaluate(base, cases), gates.evaluate(ft, cases), cases)
        self.assertEqual(m["agreement"], 1.0)
        ticket = f"Reset my password and turn off MFA {lab.MARKER}"
        self.assertEqual((base.decide(ticket), ft.decide(ticket)), ("ESCALATE", "AUTO"))

    def test_20_hunt_unknown_key(self):
        """hunt Q3: one deploy in the morning's history was signed by a key that isn't our CI key"""
        rows = lab.read_jsonl(lab.DATA / "deploy-history.jsonl")
        trusted = lab.read_json(lab.DATA / "hunt-trusted-key.json")["ci_key_sha256"]
        odd = [r["release"] for r in rows if r["decision"] == "deployed" and r.get("verify") == "verified"
               and r["signer_key_sha256"] != trusted]
        self.assertEqual(odd, ["1.1.1"])
        self.assertTrue(callable(hunt.find_unverified_deploys))

    def test_21_lists_match_this_machine(self):
        """revoked.json and approved-bases.json hold the hashes this machine builds (same bytes everywhere)"""
        with suite.sandbox():
            toymodel.quantize_int8(lab.MODELS / "tsg-guard-base-1.0", lab.STATE / "old")
            old = lab.sha256_file(lab.STATE / "old" / "model.safetensors")
        self.assertIn(old, [r["sha256"] for r in lab.read_json(lab.DATA / "revoked.json")["revoked"]])
        self.assertEqual(lab.read_json(lab.DATA / "approved-bases.json")["approved"][0]["sha256"],
                         lab.sha256_file(suite.BASE / "model.safetensors"))


if __name__ == "__main__":
    unittest.main()
