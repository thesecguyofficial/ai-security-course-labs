"""
test_challenge.py: `make challenge`. These tests FAIL until you do the three-part challenge (README, Step 8).
No solution is included.

  1. (15.2) Add Azure Policy assignments to setups/hardened/policy-challenge.json so a workspace with internet outbound
     or with public network access is DENIED (A14), while a correctly configured one is still created (N6).
  2. (15.3) Write check_before_promotion() in gate.py and set "approval_gate": true in setups/hardened/app.json (A15).
  3. (15.4) Write find_key_calls() in hunt.py.
"""

import unittest

import checker
import evaluate
import gate
import hunt
import model_files
import twin

C = twin.COMPANY


def workspace(public: str, mode: str) -> dict:
    return twin.policy_check(twin.Setup("hardened"), twin.workspace_request(
        "challenge-probe", {"publicNetworkAccess": public, "managedNetwork": {"isolationMode": mode}}))


def gate_says(version: str, promoter: str = "tsg-ml-approver", files=None) -> list[str]:
    s = twin.Setup("hardened")
    rec = s.models["workspace:tsg-ml-dev"][f"tsg-summariser:{version}"]
    return gate.check_before_promotion(rec, files if files is not None else twin.World(s).files(rec["stored_in"]), promoter, C)


class TC_Challenge(unittest.TestCase):
    # ---------------------------------------------------------------- 1. Azure Policy
    def test_22_policy_denies_internet_outbound(self):
        """challenge 1: a workspace in allow internet outbound mode (or with no managed VNet) is DENIED (A14 blocked)"""
        self.assertTrue(workspace("Disabled", "AllowInternetOutbound")["denied"])
        self.assertTrue(workspace("Disabled", "Disabled")["denied"])

    def test_23_policy_denies_public_access(self):
        """challenge 1: a workspace with public network access enabled is DENIED too, even in approved-outbound mode"""
        self.assertTrue(workspace("Enabled", "AllowOnlyApprovedOutbound")["denied"])

    def test_24_policy_lets_good_workspaces_through(self):
        """challenge 1: an approved-outbound, private workspace is still created (N6), and nothing else breaks"""
        self.assertEqual(workspace("Disabled", "AllowOnlyApprovedOutbound")["denied"], [])
        r = evaluate.run_suite("hardened")
        self.assertTrue(all(n["works"] for n in r["normal"]), [n["id"] for n in r["normal"] if not n["works"]])

    # ---------------------------------------------------------------- 2. the promotion gate
    def test_25_gate_refuses_version_3(self):
        """challenge 2: version 3 is refused, with a reason for the pickle file, the missing licence and the missing hashes"""
        reasons = " ".join(gate_says("3")).lower()
        for word in ("pytorch_model.bin", "licence", "hash"):
            self.assertIn(word, reasons)

    def test_26_gate_passes_a_clean_version_only(self):
        """challenge 2: clean version 4 passes for the approver; refused if its registrant promotes it, or if a file was swapped"""
        self.assertEqual(gate_says("4"), [])
        self.assertTrue(gate_says("4", promoter="ds-alice"))
        self.assertTrue(gate_says("4", files=model_files.swapped(model_files.build("v4-safe"))))

    def test_27_gate_is_switched_on(self):
        """challenge 2: "approval_gate": true in setups/hardened/app.json; A15 blocked and N3 (clean promotion) still works"""
        s = twin.Setup("hardened")
        self.assertTrue(s.app.get("approval_gate"))
        r = evaluate.run_suite(s)
        self.assertFalse(next(a for a in r["attacks"] if a["id"] == "A15")["worked"])
        self.assertTrue(next(n for n in r["normal"] if n["id"] == "N3")["works"])

    # ---------------------------------------------------------------- 3. the hunt
    def test_28_key_calls(self):
        """challenge 3: four key-authenticated calls to tsg-summariser-legacy from python-requests, in time order"""
        rows = hunt.find_key_calls(hunt.load())
        self.assertIsNotNone(rows, "find_key_calls() still returns None")
        self.assertEqual([(r["time"], r["endpoint"], r["agent"]) for r in rows],
                         [(t, "tsg-summariser-legacy", "python-requests/2.32.3") for t in
                          ("2027-01-28T11:02:51Z", "2027-01-28T11:03:09Z", "2027-01-28T11:03:30Z", "2027-01-28T11:04:12Z")])

    # ---------------------------------------------------------------- all of it
    def test_29_everything(self):
        """all three: the hardened setup has 0 findings, 0 of 15 attacks work, 6 of 6 normal requests work"""
        s = twin.Setup("hardened")
        self.assertEqual([f.rule for f in checker.run(s)], [])
        r = evaluate.run_suite(s)
        self.assertEqual([a["id"] for a in r["attacks"] if a["worked"]], [])
        self.assertTrue(all(n["works"] for n in r["normal"]))


if __name__ == "__main__":
    unittest.main()
