"""
test_challenge.py: the three-part challenge (make challenge). These tests fail until you finish it. No solution is
included in this repo.

1. Lesson 28.4: a new kind of data, loyalty-card numbers (TSG-LOY- and 8 digits), shows up in a helpdesk call. Add ONE
   custom data identifier named TSG_LOYALTY_CARD to setups/hardened/identifiers.json, and add its name to the Macie
   job's customDataIdentifiers in setups/hardened/pipeline.json. One definition, two uses: the redactor removes it and
   Macie can prove it's gone.
2. Lesson 28.3: write forget() in forget.py: one customer's erasure request across both buckets, every version.
3. Lesson 28.4: write find_raw_key_readers() in hunt.py: who outside the expected list called Decrypt on the raw key.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import forget
import hunt
import lab
import pipeline
import redact


class Challenge(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["M28_STATE"] = self._tmp.name

    def tearDown(self):
        os.environ.pop("M28_STATE", None)
        self._tmp.cleanup()

    def test_c1_loyalty_redacted(self):
        """challenge 1: with the loyalty-card call added, the hardened pipeline still has 0 leaks (L2 and L6 closed)"""
        r = pipeline.evaluate(pipeline.build("hardened", challenge=True))
        self.assertEqual([c for c, (hit, _) in r["leaks"].items() if hit], [])

    def test_c2_macie_sees_loyalty(self):
        """challenge 1: Macie's job reports TSG_LOYALTY_CARD in the raw bucket"""
        env = pipeline.build("hardened", challenge=True)
        names = {d["name"] for f in env["macie"]["findings"]
                 for d in f["classificationDetails"]["result"]["customDataIdentifiers"]["detections"]}
        self.assertIn("TSG_LOYALTY_CARD", names)

    def test_c3_forget(self):
        """challenge 2: after forget('TSG-CUST-104233') no version anywhere holds Dana's data or tokens; others stay"""
        env = pipeline.build("hardened")
        s3 = env["s3"]
        others_before = self._others(s3)
        report = forget.forget(s3, "TSG-CUST-104233")
        self.assertGreater(report["raw_deleted"], 0)
        self.assertGreater(report["redacted_deleted"], 0)
        dana = {"dana.reyes@customer.example", "dana reyes", "tsg-cust-104233", "202-555-0147"}
        tokens = {redact.token("EMAIL_ADDRESS", "dana.reyes@customer.example").lower(),
                  redact.token("CUSTOMER_NAME", "Dana Reyes").lower(),
                  redact.token("TSG_CUSTOMER_ID", "TSG-CUST-104233").lower()}
        for bucket in (lab.RAW_BUCKET, lab.REDACTED_BUCKET):
            for key, v in s3.list_object_versions(bucket):
                text = s3.get_object(bucket, key, lab.ERASURE, version_id=v["version_id"]).decode().lower()
                for needle in dana | tokens:
                    self.assertNotIn(needle, text, f"{needle} still in {bucket}/{key}")
        self.assertEqual(self._others(s3), others_before)

    def _others(self, s3):
        """How many stored versions hold nothing of Dana's (raw values or tokens)."""
        needles = ["dana", "tsg-cust-104233", redact.token("EMAIL_ADDRESS", "dana.reyes@customer.example").lower(),
                   redact.token("CUSTOMER_NAME", "Dana Reyes").lower(),
                   redact.token("TSG_CUSTOMER_ID", "TSG-CUST-104233").lower()]
        n = 0
        for bucket in (lab.RAW_BUCKET, lab.REDACTED_BUCKET):
            for key, v in s3.list_object_versions(bucket):
                text = s3.get_object(bucket, key, lab.ERASURE, version_id=v["version_id"]).decode().lower()
                if not any(x in text for x in needles):
                    n += 1
        return n

    def test_c4_hunt(self):
        """challenge 3: find_raw_key_readers() names tsg-analytics (3 refused) and tsg-ml-training (4 allowed)"""
        events = hunt.load(lab.DATA / "hunt-cloudtrail.jsonl")
        self.assertEqual(hunt.find_raw_key_readers(events),
                         [(f"arn:aws:iam::{lab.ACCOUNT}:role/tsg-analytics", 0, 3),
                          (f"arn:aws:iam::{lab.ACCOUNT}:role/tsg-ml-training", 4, 0)])


if __name__ == "__main__":
    unittest.main()
