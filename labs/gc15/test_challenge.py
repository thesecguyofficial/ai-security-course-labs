"""
test_challenge.py: `make challenge`. These tests FAIL until you do the three-part challenge (README, Step 8).
No solution is included.

  1. (15.2) Enforce the Workbench constraints in setups/hardened/orgpolicy.json so a new instance with the console
     defaults is refused (A14), while alice-wb and bob-wb still comply.
  2. (15.3) Write check_before_promotion() in gate.py and set "approval_gate": true in setups/hardened/app.json (A15).
  3. (15.4) Write find_outside_predictions() in hunt.py.
"""

import unittest

import checker
import evaluate
import gate
import hunt
import model_files
import twin

C = twin.COMPANY
DEFAULTS = {"_project": "example-summariser-dev", "_access_mode": "service-account", "_users": ["ds-bob"],
            "gceSetup": {"disablePublicIp": False, "serviceAccounts": [{"email": twin.sa_email("compute-default")}], "metadata": {}}}


def gate_says(version: str, promoter: str = "tsg-model-approver", files=None) -> list[str]:
    s = twin.Setup("hardened")
    v = twin.version(s, version)
    return gate.check_before_promotion(v, files if files is not None else twin.World(s).snapshots[v["versionId"]], promoter, C)


class TC_Challenge(unittest.TestCase):
    # ---------------------------------------------------------------- 1. Workbench constraints
    def test_21_defaults_refused(self):
        """challenge 1: a new instance with the console defaults breaks four enforced constraints (A14 blocked)"""
        bad = " ".join(twin.workbench_violations(twin.Setup("hardened"), DEFAULTS))
        for c in ("restrictPublicIp", "disableRootAccess", "disableTerminal", "disableFileDownloads"):
            self.assertIn(c, bad)

    def test_22_existing_instances_still_comply(self):
        """challenge 1: alice-wb and bob-wb still comply, and Alice can still open hers (N4)"""
        s = twin.Setup("hardened")
        for name, inst in s.workbench["instances"].items():
            self.assertEqual(twin.workbench_violations(s, inst), [], name)
        self.assertTrue(evaluate.run_case(evaluate.NORMAL[3], s)["works"])

    # ---------------------------------------------------------------- 2. the promotion gate
    def test_23_gate_refuses_version_2(self):
        """challenge 2: version 2 is refused, with a reason for the pickle file, the missing licence and the missing hashes"""
        reasons = " ".join(gate_says("2")).lower()
        for word in ("pytorch_model.bin", "licence", "hash"):
            self.assertIn(word, reasons)

    def test_24_gate_passes_a_clean_version_only(self):
        """challenge 2: clean version 4 passes for the ML lead; refused for its trainer, for the uploader, or with a swapped file"""
        self.assertEqual(gate_says("4"), [])
        self.assertTrue(gate_says("4", promoter="ds-alice"))
        self.assertTrue(gate_says("4", promoter="tsg-ci-deployer"))
        self.assertTrue(gate_says("4", files=model_files.swapped(model_files.build("v4-safe"))))

    def test_25_gate_is_switched_on(self):
        """challenge 2: "approval_gate": true in setups/hardened/app.json; A15 blocked and N3 (clean promotion) still works"""
        s = twin.Setup("hardened")
        self.assertTrue(s.app.get("approval_gate"))
        r = evaluate.run_suite(s)
        self.assertFalse(next(a for a in r["attacks"] if a["id"] == "A15")["worked"])
        self.assertTrue(next(n for n in r["normal"] if n["id"] == "N3")["works"])

    # ---------------------------------------------------------------- 3. the hunt
    def test_26_outside_predictions(self):
        """challenge 3: three Predict calls from 203.0.113.50 with the app's new key, none from ExampleCo's network"""
        rows = hunt.find_outside_predictions(hunt.load())
        self.assertEqual([(r["time"], r["who"], r["source_ip"]) for r in rows],
                         [(t, "tsg-helpdesk-app", "203.0.113.50") for t in
                          ("2027-01-28T11:02:51Z", "2027-01-28T11:03:09Z", "2027-01-28T11:03:30Z")])
        self.assertTrue(all(r["key"].endswith("1f2e3d4c5b6a79880000lab") for r in rows))

    # ---------------------------------------------------------------- all of it
    def test_27_everything(self):
        """all three: the hardened setup has 0 findings, 0 of 15 attacks work, 6 of 6 normal requests work"""
        s = twin.Setup("hardened")
        self.assertEqual(checker.run(s), [])
        r = evaluate.run_suite(s)
        self.assertEqual([a["id"] for a in r["attacks"] if a["worked"]], [])
        self.assertTrue(all(n["works"] for n in r["normal"]))


if __name__ == "__main__":
    unittest.main()
