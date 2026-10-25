"""M18 lab tests: the toolkit does what the README says, on the files shipped with the lab.

Run with `make test` (or `python3 run_tests.py`). Standard library only.
"""
import csv
import datetime as dt
import io
import json
import pathlib
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout

import govlab

HERE = pathlib.Path(__file__).resolve().parent
DRAFT = HERE / "first-draft"
D = dt.date(2026, 10, 24)


def codes(findings, severity="error"):
    return {f[0] for f in findings if f[1] == severity}


def card(**eu_changes):
    c = json.loads((HERE / "helpdesk" / "system-card.json").read_text())
    c["eu_ai_act"].update(eu_changes)
    return c


class TempAssessment:
    """A throwaway copy of first-draft/ that a test can edit."""

    def __enter__(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="m18-test-"))
        for f in DRAFT.iterdir():
            shutil.copy2(f, self.dir / f.name)
        return self.dir

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)


def write_register(folder, rows):
    with open(folder / "risk-register.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=govlab.REGISTER_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in govlab.REGISTER_COLUMNS})


def risk(**kw):
    base = {"id": "T1", "title": "test risk", "source": "RS01", "owasp": "LLM01:2026", "owner": "AppSec lead",
            "likelihood": "2", "impact": "2", "treatment": "mitigate", "controls": "C01",
            "res_likelihood": "1", "res_impact": "1", "review_date": "2027-01-24"}
    base.update(kw)
    return base


class TestCatalog(unittest.TestCase):
    def test_01_catalog_is_consistent(self):
        """catalog: every control maps only to framework items that exist; every risk source's controls exist"""
        controls, library, fw = govlab.catalog()
        nist, eu = set(fw["nist_ai_rmf"]["items"]), set(fw["eu_ai_act"]["items"])
        iso, owasp = set(fw["iso_42001"]["items"]), set(fw["owasp"]["items"])
        for cid, c in controls.items():
            self.assertTrue(set(c["nist"]) <= nist, cid)
            self.assertTrue(set(c["eu"]) <= eu, cid)
            self.assertTrue(set(c["iso"]) <= iso, cid)
            self.assertTrue(set(c["owasp"]) <= owasp, cid)
        for sid, s in library.items():
            self.assertTrue(set(s["suggested"]) <= set(controls), sid)
            self.assertTrue(set(s["owasp"]) <= owasp, sid)
            self.assertIn(s["nist_genai"], fw["nist_genai_risks"]["items"], sid)
        self.assertEqual(len(fw["nist_genai_risks"]["items"]), 12)


class TestInventoryAndTriage(unittest.TestCase):
    def test_02_inventory_flags_the_unknown_licence(self):
        """inventory: one row per component, and the embedding model's unknown licence is flagged"""
        rows = govlab.inventory_rows(card())
        self.assertEqual(len(rows), 7)
        flagged = {r["component"]: r["flags"] for r in rows if r["flags"]}
        self.assertEqual(list(flagged), ["Local embedding model (Module 6)"])
        self.assertIn("licence unknown", flagged["Local embedding model (Module 6)"])

    def test_03_triage_provider_transparency(self):
        """triage: the Helpdesk is a provider, transparency tier; Art. 4 and 50(1) apply now, 50(2) is due 2 Dec 2026"""
        t = govlab.triage(card(), D)
        self.assertEqual(t["role"], "provider")
        self.assertTrue(t["tier"].startswith("TRANSPARENCY"))
        ob = {a: s for a, _, s in t["obligations"]}
        self.assertEqual(ob["Art. 4"], "APPLIES NOW")
        self.assertEqual(ob["Art. 50(1)"], "APPLIES NOW")
        self.assertEqual(ob["Art. 50(2)"], "DUE 2026-12-02")
        self.assertFalse(t["high_risk"])

    def test_04_triage_dates_move_with_as_of(self):
        """triage: on 1 Jul 2026 Art. 50(1) was still due (2 Aug 2026); a system launched after 2 Aug 2026 gets no grace"""
        ob = {a: s for a, _, s in govlab.triage(card(), dt.date(2026, 7, 1))["obligations"]}
        self.assertEqual(ob["Art. 50(1)"], "DUE 2026-08-02")
        late = {a: s for a, _, s in govlab.triage(card(placed_on_market="2026-09-01"), D)["obligations"]}
        self.assertEqual(late["Art. 50(2)"], "APPLIES NOW")

    def test_05_what_if_hiring_is_high_risk_from_dec_2027(self):
        """triage: re-used to screen job applicants, it is Annex III high-risk and Arts. 9 to 15 are due 2 Dec 2027"""
        t = govlab.triage(card(), D, "hiring")
        self.assertTrue(t["high_risk"])
        self.assertIn("Annex III", t["tier"])
        ob = {a: s for a, _, s in t["obligations"]}
        for art in ("Art. 9", "Art. 12", "Art. 14", "Art. 15", "Art. 73"):
            self.assertEqual(ob[art], "DUE 2027-12-02", art)

    def test_06_triage_deployer_and_annex_i(self):
        """triage: someone else's system makes you a deployer (Art. 26); a product safety component is due 2 Aug 2028"""
        t = govlab.triage(card(built_and_run_under_our_name=False, annex_iii_area="employment"), D)
        self.assertEqual(t["role"], "deployer")
        self.assertIn("Art. 26", {a for a, _, _ in t["obligations"]})
        self.assertNotIn("Art. 50(1)", {a for a, _, _ in t["obligations"]})
        t = govlab.triage(card(annex_i_safety_component=True), D)
        self.assertEqual({a: s for a, _, s in t["obligations"]}["Art. 9"], "DUE 2028-08-02")


class TestCheck(unittest.TestCase):
    def test_07_first_draft_findings(self):
        """check: the team's first draft fails with exactly the 15 kinds of problem the README walks through"""
        found = codes(govlab.check_folder(DRAFT))
        self.assertEqual(found, {"ASM-01", "ASM-02", "COV-01", "EVD-02", "EVD-03", "EVD-04", "REG-02", "REG-06",
                                 "REG-07", "REG-08", "REG-09", "REG-11", "REG-12", "REG-13", "REG-14"})

    def test_08_no_credit_for_planned_controls(self):
        """check: lowering a risk with a planned control (C12) is refused; 'avoid' or an accepted residual is allowed"""
        with TempAssessment() as d:
            write_register(d, [risk(source="RS05", owasp="ASI06", controls="C12")])
            self.assertIn("REG-11", codes(govlab.check_folder(d)))
            write_register(d, [risk(source="RS05", owasp="ASI06", controls="", treatment="avoid")])
            self.assertNotIn("REG-11", codes(govlab.check_folder(d)))
            write_register(d, [risk(source="RS05", owasp="ASI06", controls="C12", res_likelihood="2", res_impact="2")])
            self.assertNotIn("REG-11", codes(govlab.check_folder(d)))

    def test_09_changed_evidence_is_caught(self):
        """evidence: editing one byte of an indexed file breaks its hash (EVD-03) and removes the control's credit"""
        with TempAssessment() as d:
            src = HERE / "evidence" / "2026-10-20-m05-output-handling-test.txt"
            copy = d / "copy.txt"
            shutil.copy2(src, copy)
            rel = copy.relative_to(HERE) if copy.is_relative_to(HERE) else None
            if rel is None:                       # temp dir is outside the lab: index it by absolute path
                rel = copy
            with open(d / "evidence-index.csv", "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(govlab.EVIDENCE_COLUMNS)
                w.writerow(["E1", "C08", str(rel), govlab.sha256_file(copy), "2026-10-20", "AppSec lead", "copy"])
            controls, _, _ = govlab.catalog()
            rows, f1 = govlab.evidence_status(d, controls)
            self.assertTrue(rows[0]["valid"], f1)
            copy.write_bytes(copy.read_bytes() + b"x")
            rows, f2 = govlab.evidence_status(d, controls)
            self.assertFalse(rows[0]["valid"])
            self.assertIn("EVD-03", codes(f2))

    def test_10_review_dates_and_appetite(self):
        """check: residual above 3 needs a named acceptance; a risk of 9 is never accepted; reviews within 6 months"""
        with TempAssessment() as d:
            write_register(d, [risk(likelihood="3", impact="3", treatment="accept", controls="",
                                    res_likelihood="", res_impact="", accepted_by="COO")])
            self.assertIn("REG-13", codes(govlab.check_folder(d)))
            write_register(d, [risk(controls="C01", res_likelihood="2", res_impact="2", accepted_by="")])
            self.assertIn("REG-12", codes(govlab.check_folder(d)))
            write_register(d, [risk(review_date="2026-10-01")])
            self.assertIn("REG-14", codes(govlab.check_folder(d)))

    def test_11_disclosure_claim_is_checked_against_the_widget(self):
        """check: marking C24 done while the greeting does not mention AI is an error (DIS-01); fixing the text clears it"""
        with TempAssessment() as d:
            c = card()
            c["controls"]["C24"] = "implemented"
            (d / "system-card.json").write_text(json.dumps(c))
            shutil.copy2(HERE / "helpdesk" / "chat-widget.html", d / "chat-widget.html")
            self.assertIn("DIS-01", codes(govlab.check_folder(d)))
            html = (d / "chat-widget.html").read_text().replace(
                "Hello, welcome to TSG Shop support.", "Hello, I'm the TSG Shop AI assistant, an automated system.")
            (d / "chat-widget.html").write_text(html)
            self.assertNotIn("DIS-01", codes(govlab.check_folder(d)))


class TestCrosswalkAndPack(unittest.TestCase):
    def test_12_crosswalk_shows_the_article_50_gap(self):
        """crosswalk: Art. 50 applies and is not proven (C24 planned); Arts. 9 to 15 are reference only"""
        eu = {r["item"]: r for r in govlab.crosswalk(DRAFT)["eu"]}
        self.assertEqual(eu["Art. 50"]["applies"], "applies")
        self.assertNotEqual(eu["Art. 50"]["status"], "COVERED")
        self.assertEqual(eu["Art. 50"]["statuses"], {"C24": "planned"})
        for art in ("Art. 9", "Art. 12", "Art. 15"):
            self.assertEqual(eu[art]["applies"], "reference", art)
        hiring = {r["item"]: r for r in govlab.crosswalk(DRAFT, "hiring")["eu"]}
        self.assertEqual(hiring["Art. 12"]["applies"], "applies")

    def test_13_crosswalk_credits_only_proven_controls(self):
        """crosswalk: MEASURE 2.7 is covered by the M7 evidence; MANAGE 1.3 is not (C03's evidence changed)"""
        nist = {r["item"]: r for r in govlab.crosswalk(DRAFT)["nist"]}
        self.assertEqual(nist["MEASURE 2.7"]["status"], "COVERED")
        self.assertIn("C01", nist["MEASURE 2.7"]["covered_by"])
        self.assertNotIn("C03", nist["MANAGE 1.3"]["covered_by"])

    def test_14_pack_refuses_errors_and_draft_verifies(self):
        """pack: refused while errors are open; a --draft pack is marked DRAFT and verifies, and tampering is caught"""
        pack, _ = govlab.build_pack(DRAFT)
        self.assertIsNone(pack)
        pack, _ = govlab.build_pack(DRAFT, draft=True)
        try:
            self.assertTrue(pack.name.endswith("-DRAFT"))
            self.assertIn("DRAFT", (pack / "README.md").read_text())
            self.assertEqual(govlab.verify_pack(pack), [])
            with open(pack / "RISK-REGISTER.md", "a") as f:
                f.write("| R99 | quietly added |\n")
            self.assertEqual(govlab.verify_pack(pack), ["changed: RISK-REGISTER.md"])
        finally:
            shutil.rmtree(pack, ignore_errors=True)

    def test_15_cli_runs_offline(self):
        """cli: every command runs and returns the documented exit code"""
        with redirect_stdout(io.StringIO()):
            self.assertEqual(govlab.main(["inventory"]), 0)
            self.assertEqual(govlab.main(["triage", "--what-if", "hiring"]), 0)
            self.assertEqual(govlab.main(["check", "first-draft"]), 1)
            self.assertEqual(govlab.main(["crosswalk", "first-draft", "--framework", "eu"]), 0)
            self.assertEqual(govlab.main(["evidence", "first-draft"]), 1)


if __name__ == "__main__":
    unittest.main()
