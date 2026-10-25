"""
test_lab.py: the proof for lab M28 (make test).

"first draft:" tests assert each leak is REAL in the first draft (a test that can never fail proves nothing).
"hardened:" tests assert each control holds and the normal jobs still work. "kms:", "s3:" and "detect:" tests pin the
stand-in behaviour the lessons rely on. Every test builds its setup from zero in its own empty state folder.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import detect
import hunt
import lab
import pipeline
import redact
from kms import AccessDenied, LocalKMS
from s3 import LocalS3


class LabTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["M28_STATE"] = self._tmp.name

    def tearDown(self):
        os.environ.pop("M28_STATE", None)
        self._tmp.cleanup()

    def env(self, setup):
        return pipeline.build(setup)


class FirstDraft(LabTest):
    def test_01_seven_leaks(self):
        """first draft: all 7 leaks are real, and all 3 normal jobs still work (it passed its functional tests)"""
        r = pipeline.evaluate(self.env("first-draft"))
        self.assertEqual([c for c, (hit, _) in r["leaks"].items() if hit], ["L1", "L2", "L3", "L4", "L5", "L6", "L7"])
        self.assertTrue(all(ok for ok, _ in r["normal"].values()))

    def test_02_one_key_iam_delegation(self):
        """first draft: one key for both buckets, and its root statement lets an IAM policy grant analysts Decrypt"""
        env = self.env("first-draft")
        self.assertEqual(len(env["kms"].keys), 1)
        self.assertTrue(env["kms"].allowed("alias/tsg-invocation-logs", lab.ANALYST, "kms:Decrypt"))

    def test_03_redactor_misses(self):
        """first draft: the redactor misses an upper-case e-mail, a spaced card number and requestMetadata"""
        env = self.env("first-draft")
        text = " ".join(env["s3"].get_object(lab.REDACTED_BUCKET, k, lab.ANALYST).decode()
                        for k in env["s3"].list_objects(lab.REDACTED_BUCKET) if "/data/" not in k)
        self.assertIn("DANA.REYES@CUSTOMER.EXAMPLE", text)
        self.assertIn("4111 1111 1111 1111", text)
        self.assertIn('"customer_email": "dana.reyes@customer.example"', text)

    def test_04_macie_reads_nothing(self):
        """first draft: Macie can't use the key, so every raw object in scope is SKIPPED (INVALID_ENCRYPTION), with 0 findings"""
        env = self.env("first-draft")
        raw = [r for r in env["macie"]["results"] if r["bucket"] == lab.RAW_BUCKET]
        self.assertTrue(all(r["status"]["code"] in ("SKIPPED", "EXCLUDED_BY_SCOPE") for r in raw))
        self.assertIn({"code": "SKIPPED", "reason": "INVALID_ENCRYPTION"}, [r["status"] for r in raw])
        self.assertEqual([f for f in env["macie"]["findings"] if f["resourcesAffected"]["s3Bucket"]["name"] == lab.RAW_BUCKET], [])

    def test_05_expired_but_readable(self):
        """first draft: a 45-day-old record is hidden behind a delete marker and still readable by version ID"""
        env = self.env("first-draft")
        s3 = env["s3"]
        old = [(k, v) for k, v in s3.list_object_versions(lab.RAW_BUCKET) if "c09" in k]
        self.assertEqual(len(old), 1)
        key, version = old[0]
        self.assertNotIn(key, s3.list_objects(lab.RAW_BUCKET))
        rec = json.loads(s3.get_object(lab.RAW_BUCKET, key, lab.BREAK_GLASS, version_id=version["version_id"]))
        self.assertIn("Dana Reyes", json.dumps(rec))


class Hardened(LabTest):
    def test_06_no_leaks(self):
        """hardened: 0 of 7 leaks, and all 3 normal jobs still work"""
        r = pipeline.evaluate(self.env("hardened"))
        self.assertEqual([c for c, (hit, _) in r["leaks"].items() if hit], [])
        self.assertTrue(all(ok for ok, _ in r["normal"].values()))

    def test_07_two_locks(self):
        """hardened: with the bucket policy loosened by mistake, the raw key still refuses the analyst"""
        env = self.env("hardened")
        s3 = env["s3"]
        cfg = s3.config(lab.RAW_BUCKET)
        cfg["policy"]["Statement"] = [st for st in cfg["policy"]["Statement"] if st["Effect"] != "Deny"]
        cfg["policy"]["Statement"].append({"Sid": "Oops", "Effect": "Allow", "Principal": {"AWS": [lab.ANALYST]},
                                           "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{lab.RAW_BUCKET}/*"})
        s3.create_bucket(cfg)
        with self.assertRaisesRegex(AccessDenied, "kms:Decrypt"):
            s3.get_object(lab.RAW_BUCKET, s3.list_objects(lab.RAW_BUCKET)[0], lab.ANALYST)

    def test_08_refusal_in_trail(self):
        """hardened: the refused Decrypt is in the trail with keyId, the analyst's ARN and the object in encryptionContext"""
        env = self.env("hardened")
        key = env["s3"].list_objects(lab.RAW_BUCKET)[0]
        wrapped = env["s3"].object_info(lab.RAW_BUCKET, key)["sse"]
        with self.assertRaises(AccessDenied):
            env["kms"].decrypt(wrapped, lab.ANALYST, {"aws:s3:arn": f"arn:aws:s3:::{lab.RAW_BUCKET}/{key}"})
        last = json.loads((lab.state_dir() / "cloudtrail.jsonl").read_text().splitlines()[-1])
        self.assertEqual((last["eventName"], last["errorCode"], last["userIdentity"]["arn"]),
                         ("Decrypt", "AccessDenied", lab.ANALYST))
        self.assertEqual(last["requestParameters"]["keyId"], env["kms"].arn("alias/tsg-logs-raw"))
        self.assertTrue(last["requestParameters"]["encryptionContext"]["aws:s3:arn"].endswith(key))

    def test_09_iam_alone_opens_nothing(self):
        """hardened: the analyst's IAM policy still says kms:Decrypt on *, and without a root statement it doesn't count"""
        env = self.env("hardened")
        self.assertIn(lab.ANALYST, env["setup"]["kms"]["alias/tsg-logs-raw"]["iam"])
        self.assertFalse(env["kms"].allowed("alias/tsg-logs-raw", lab.ANALYST, "kms:Decrypt"))
        self.assertTrue(env["kms"].allowed("alias/tsg-logs-redacted", lab.ANALYST, "kms:Decrypt"))

    def test_10_tokens_are_stable(self):
        """hardened: the same e-mail in any letter case gets the same token; another customer gets a different one"""
        self.env("hardened")
        a = redact.token("EMAIL_ADDRESS", "dana.reyes@customer.example")
        self.assertEqual(a, redact.token("EMAIL_ADDRESS", "DANA.REYES@CUSTOMER.EXAMPLE"))
        self.assertNotEqual(a, redact.token("EMAIL_ADDRESS", "sam.okafor@customer.example"))

    def test_11_vectors_stripped_even_if_logged(self):
        """hardened: if someone turns embedding logging back on, the redactor still removes every vector"""
        setup = lab.load_setup("hardened")
        setup["logging"]["embeddingDataDeliveryEnabled"] = True
        import bedrock
        rec, _ = bedrock.records([c for c in bedrock.load_calls("calls.json") if c["id"] == "c03"], setup)[0]
        self.assertTrue(list(detect.vector_paths(rec)))
        out, rep = redact.redact_record(rec, setup)
        self.assertEqual(list(detect.vector_paths(out)), [])
        self.assertEqual(rep["vectors_removed"], 2)
        self.assertNotIn("Sam Okafor", json.dumps(out))

    def test_12_macie_finds_raw_not_redacted(self):
        """hardened: Macie reads every raw object, finds e-mails and customer IDs there, and nothing in the redacted copy"""
        env = self.env("hardened")
        found = env["macie"]["findings"]
        raw = [f for f in found if f["resourcesAffected"]["s3Bucket"]["name"] == lab.RAW_BUCKET]
        names = {d["name"] for f in raw for d in f["classificationDetails"]["result"]["customDataIdentifiers"]["detections"]}
        self.assertTrue({"EMAIL_ADDRESS", "TSG_CUSTOMER_ID"} <= names)
        self.assertIn("SensitiveData:S3Object/Multiple", {f["type"] for f in raw})
        self.assertEqual([f for f in found if f["resourcesAffected"]["s3Bucket"]["name"] == lab.REDACTED_BUCKET], [])

    def test_13_retention_really_deletes(self):
        """hardened: records 45, 60 and 90 days old are gone in every version; a 12-day-old record is still there"""
        env = self.env("hardened")
        keys = [k for k, _ in env["s3"].list_object_versions(lab.RAW_BUCKET)]
        for cid in ("c09", "c10", "c11"):
            self.assertFalse([k for k in keys if cid in k], cid)
        self.assertTrue([k for k in keys if "c07" in k])


class Mechanics(LabTest):
    def test_14_encryption_context_binds_object(self):
        """kms: a data key wrapped for one object can't be unwrapped with another object's encryption context"""
        kms = LocalKMS()
        kms.create("alias/t", {"Statement": [{"Effect": "Allow", "Principal": {"AWS": [lab.REDACTOR]},
                                              "Action": ["kms:GenerateDataKey", "kms:Decrypt"]}]})
        _, wrapped = kms.generate_data_key("alias/t", lab.REDACTOR, {"aws:s3:arn": "arn:aws:s3:::b/one"})
        with self.assertRaisesRegex(AccessDenied, "encryption context"):
            kms.decrypt(wrapped, lab.REDACTOR, {"aws:s3:arn": "arn:aws:s3:::b/two"})

    def test_15_deleting_the_key_shreds_the_data(self):
        """kms: once the key is deleted, no principal can read what it protected (crypto-shredding)"""
        env = self.env("hardened")
        key = env["s3"].list_objects(lab.RAW_BUCKET)[0]
        env["kms"].schedule_deletion("alias/tsg-logs-raw")
        with self.assertRaisesRegex(AccessDenied, "unrecoverable"):
            env["s3"].get_object(lab.RAW_BUCKET, key, lab.BREAK_GLASS)

    def test_16_tampered_blob_fails(self):
        """s3: one flipped byte in a stored object and the read fails (AES-GCM authenticates the data)"""
        env = self.env("hardened")
        s3 = env["s3"]
        key = s3.list_objects(lab.REDACTED_BUCKET)[0]
        blob = s3.root / lab.REDACTED_BUCKET / "blobs" / s3.object_info(lab.REDACTED_BUCKET, key)["blob"]
        data = bytearray(blob.read_bytes())
        data[20] ^= 1
        blob.write_bytes(bytes(data))
        with self.assertRaises(Exception):
            s3.get_object(lab.REDACTED_BUCKET, key, lab.ANALYST)

    def test_17_no_managed_email_identifier(self):
        """detect: like Macie, the managed identifiers find no e-mail address; a custom identifier does"""
        text = "write to dana.reyes@customer.example"
        self.assertEqual(detect.managed(text), [])
        ids = lab.load_setup("hardened")["identifiers"]["custom_data_identifiers"]
        self.assertEqual([m.type for m in detect.custom(text, ids)], ["EMAIL_ADDRESS"])

    def test_18_card_rules(self):
        """detect: Luhn rejects a random 16-digit number; a valid card with no keyword nearby is the NO_KEYWORD type"""
        self.assertEqual(detect.managed("order 1234 5678 9012 3456"), [])
        self.assertEqual([m.type for m in detect.managed("ref 4111-1111-1111-1111")], ["CREDIT_CARD_NUMBER_(NO_KEYWORD)"])
        self.assertEqual([m.type for m in detect.managed("my card 4111 1111 1111 1111")], ["CREDIT_CARD_NUMBER"])

    def test_19_keyword_distance(self):
        """detect: a custom identifier with keywords matches only within maximumMatchDistance characters"""
        cdi = [{"name": "LOY", "regex": r"\d{8}", "keywords": ["loyalty"], "maximumMatchDistance": 20}]
        self.assertEqual(len(detect.custom("loyalty card 40417730", cdi)), 1)
        self.assertEqual(detect.custom("loyalty" + " filler" * 10 + " 40417730", cdi), [])

    def test_20_hunt_q1(self):
        """hunt: Q1 counts the fixture's calls per key and principal, refusals separately"""
        events = hunt.load(lab.DATA / "hunt-cloudtrail.jsonl")
        q1 = hunt.q1_by_key(events)
        raw = q1[hunt.RAW_KEY]
        self.assertEqual(raw[("tsg-analytics", "Decrypt", "refused")], 3)
        self.assertEqual(raw[("tsg-log-redactor", "Decrypt", "ok")], 5)
        self.assertEqual(len(hunt.q2_break_glass(events)), 1)


if __name__ == "__main__":
    unittest.main()
