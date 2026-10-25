"""M18 challenge: your own AI risk assessment of TSG Helpdesk, in my-assessment/.

These tests fail until you have done Steps 4 to 8 of the README. `make challenge` runs them after the lab tests.
There is no single right register: the tests check that yours is complete, honest and provable, not that it matches
anyone else's.
"""
import pathlib
import unittest

import govlab

HERE = pathlib.Path(__file__).resolve().parent
MINE = HERE / "my-assessment"
FILES = ["assessment.json", "risk-register.csv", "evidence-index.csv", "system-card.json", "chat-widget.html"]


class TestMyAssessment(unittest.TestCase):
    def setUp(self):
        if not MINE.is_dir():
            self.fail("my-assessment/ does not exist yet: run 'make start' (python3 govlab.py start)")

    def test_c1_files_present(self):
        """challenge: my-assessment/ holds the assessment, register, evidence index, system card and widget"""
        missing = [f for f in FILES if not (MINE / f).exists()]
        self.assertEqual(missing, [], f"missing: {missing}")

    def test_c2_check_is_clean(self):
        """challenge: 'govlab.py check my-assessment' reports 0 errors"""
        errors = [f for f in govlab.check_folder(MINE) if f[1] == "error"]
        self.assertEqual(errors, [], f"{len(errors)} error(s), first: {errors[:1]}")

    def test_c3_every_required_risk_is_covered(self):
        """challenge: the register has a risk for every required source (13 for this system card)"""
        _, library, _ = govlab.catalog()
        card = govlab.system_card(MINE)
        have = {r.get("source") for r in govlab.read_csv(MINE / "risk-register.csv")}
        missing = [s for s in govlab.required_sources(card, library) if s not in have]
        self.assertEqual(missing, [], f"no risk for: {missing}")

    def test_c4_people_are_told_it_is_an_ai(self):
        """challenge: C24 is implemented, proven by evidence, and the greeting tells people they talk to an AI"""
        card = govlab.system_card(MINE)
        self.assertIn(card["controls"].get("C24"), govlab.CREDIT_STATUSES, "C24 is still planned in system-card.json")
        controls, _, _ = govlab.catalog()
        credited, _ = govlab.credited_controls(MINE, card, controls)
        self.assertIn("C24", credited, "C24 needs a valid evidence row (the widget file, hashed)")
        self.assertNotIn("DIS-01", {f[0] for f in govlab.check_folder(MINE)})

    def test_c5_pack_builds_and_verifies(self):
        """challenge: the evidence pack builds without --draft and verifies against its manifest"""
        pack, findings = govlab.build_pack(MINE)
        self.assertIsNotNone(pack, "pack refused: fix the errors from 'govlab.py check my-assessment' first")
        # the pack stays in out/ so you can open it
        self.assertEqual(govlab.verify_pack(pack), [])
        self.assertIn("Ready for sign-off", (pack / "README.md").read_text())


if __name__ == "__main__":
    unittest.main()
