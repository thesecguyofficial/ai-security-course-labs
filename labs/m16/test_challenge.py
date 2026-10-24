"""
test_challenge.py: `make challenge` adds these six tests. They fail until you finish the three-part challenge:
D11 (knowledge base poisoning), D12 (denial of wallet per end user) in detect.py, and your S1 incident report.
"""

import pathlib
import unittest

import detect
import evaluate
import report
import simulate

HARD = simulate.build("hardened")
TEL = detect.Telemetry.from_build(HARD)
HERE = pathlib.Path(__file__).resolve().parent


class TC_Challenge(unittest.TestCase):
    def test_c1_kb_poisoning_named(self):
        """challenge 1: D11 names ContractorUploadRole, so S5 is CAUGHT"""
        self.assertIn("ContractorUploadRole", [a["entity"] for a in detect.d11_kb_source_write(TEL)])
        self.assertEqual(evaluate.evaluate("hardened", built=HARD)["S5"]["status"], "CAUGHT")

    def test_c2_kb_pipeline_quiet(self):
        """challenge 1: D11 alerts, but never on the nightly KB pipeline"""
        alerts = detect.d11_kb_source_write(TEL)
        self.assertTrue(alerts, "D11 returns no alerts yet")
        self.assertNotIn("KbPipelineRole", [a["entity"] for a in alerts])

    def test_c3_wallet_named(self):
        """challenge 2: D12 names cust-2290, so S4 is CAUGHT"""
        self.assertIn("cust-2290", [a["entity"] for a in detect.d12_wallet_per_end_user(TEL)])
        self.assertEqual(evaluate.evaluate("hardened", built=HARD)["S4"]["status"], "CAUGHT")

    def test_c4_wallet_quiet(self):
        """challenge 2: D12 alerts on exactly one end user (no normal customer)"""
        self.assertEqual([a["entity"] for a in detect.d12_wallet_per_end_user(TEL)], ["cust-2290"])

    def test_c5_all_five(self):
        """with your rules: 5 of 5 caught on the hardened telemetry, 0 false alarms"""
        r = evaluate.evaluate("hardened", built=HARD)
        self.assertEqual(evaluate.summary(r), "Caught 5 of 5 | seen but not named 0 | missed 0 | false alarms 0")

    def test_c6_report(self):
        """challenge 3: report/INCIDENT-REPORT.md for S1 passes the check"""
        path = HERE / "report" / "INCIDENT-REPORT.md"
        self.assertTrue(path.exists(), "write report/INCIDENT-REPORT.md (cp report/TEMPLATE.md report/INCIDENT-REPORT.md)")
        self.assertEqual(report.check(path.read_text(), "S1", report.all_ids(TEL)), [])


if __name__ == "__main__":
    unittest.main()
