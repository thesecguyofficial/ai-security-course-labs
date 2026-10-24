"""
test_challenge.py: `make challenge`. These tests FAIL until you do the three-part challenge (README, Step 8).
No solution is included.

  1. (15.2) Add Deny statements to setups/hardened/scp.json so CreateModel fails without network isolation or
     without a VPC (A14).
  2. (15.3) Write check_before_approval() in gate.py and set "approval_gate": true in setups/hardened/app.json (A15).
  3. (15.4) Write find_outside_invocations() in hunt.py.
"""

import unittest

import checker
import evaluate
import gate
import hunt
import model_files
import twin

C = twin.COMPANY
SUBNETS = ["subnet-0a1b2c3d4e5f60011", "subnet-0a1b2c3d4e5f60012"]


def create_model(who: str, extra: dict) -> bool:
    return twin.decide(twin.Setup("hardened"), who, "sagemaker:CreateModel", twin.arn_sm("model", "quick-test"), extra)[0]


def gate_says(version: int, approver: str = "tsg-model-approver", files=None) -> list[str]:
    s = twin.Setup("hardened")
    pkg = twin.package(s, version)
    uri = pkg["InferenceSpecification"]["Containers"][0]["ModelDataSource"]["S3DataSource"]["S3Uri"]
    return gate.check_before_approval(pkg, files if files is not None else twin.World(s).files(uri), approver, C)


class TC_Challenge(unittest.TestCase):
    # ---------------------------------------------------------------- 1. the SCP
    def test_21_scp_requires_isolation(self):
        """challenge 1: an admin's CreateModel with network isolation left out, or false, is DENIED by an SCP (A14 blocked)"""
        self.assertFalse(create_model("tsg-platform-admin", {"sagemaker:VpcSubnets": SUBNETS}))
        self.assertFalse(create_model("tsg-platform-admin", {"sagemaker:NetworkIsolation": "false", "sagemaker:VpcSubnets": SUBNETS}))

    def test_22_scp_requires_a_vpc(self):
        """challenge 1: isolation on but no VpcConfig is DENIED too (model downloads must go through your VPC)"""
        self.assertFalse(create_model("tsg-platform-admin", {"sagemaker:NetworkIsolation": "true"}))

    def test_23_scp_lets_the_pipeline_deploy(self):
        """challenge 1: the pipeline's isolated, in-VPC CreateModel still works (N2), and so do data science jobs (N5)"""
        self.assertTrue(create_model("tsg-ci-deployer", {"sagemaker:NetworkIsolation": "true", "sagemaker:VpcSubnets": SUBNETS,
                                                         "sagemaker:VpcSecurityGroupIds": ["sg-0a1b2c3d4e5f60021"]}))
        r = evaluate.run_suite("hardened")
        self.assertTrue(all(n["works"] for n in r["normal"] if n["id"] in ("N2", "N5")))

    # ---------------------------------------------------------------- 2. the approval gate
    def test_24_gate_refuses_version_3(self):
        """challenge 2: version 3 is refused, with a reason for the pickle file, the missing licence and the missing hashes"""
        reasons = " ".join(gate_says(3)).lower()
        for word in ("pytorch_model.bin", "licence", "hash"):
            self.assertIn(word, reasons)

    def test_25_gate_passes_a_clean_version_only(self):
        """challenge 2: clean version 4 passes for the approver; refused if its registrant approves it, or if a file was swapped"""
        self.assertEqual(gate_says(4), [])
        self.assertTrue(gate_says(4, approver="tsg-ci-deployer"))
        self.assertTrue(gate_says(4, files=model_files.swapped(model_files.build("v4-safe"))))

    def test_26_gate_is_switched_on(self):
        """challenge 2: "approval_gate": true in setups/hardened/app.json; A15 blocked and N3 (clean approval) still works"""
        s = twin.Setup("hardened")
        self.assertTrue(s.app.get("approval_gate"))
        r = evaluate.run_suite(s)
        self.assertFalse(next(a for a in r["attacks"] if a["id"] == "A15")["worked"])
        self.assertTrue(next(n for n in r["normal"] if n["id"] == "N3")["works"])

    # ---------------------------------------------------------------- 3. the hunt
    def test_27_outside_invocations(self):
        """challenge 3: three InvokeEndpoint calls from 203.0.113.50 with the app's role, none through the VPC endpoint"""
        rows = hunt.find_outside_invocations(hunt.load())
        self.assertEqual([(r["time"], r["who"], r["source_ip"]) for r in rows],
                         [(t, "tsg-helpdesk-app", "203.0.113.50") for t in
                          ("2027-01-28T11:02:51Z", "2027-01-28T11:03:09Z", "2027-01-28T11:03:30Z")])

    # ---------------------------------------------------------------- all of it
    def test_28_everything(self):
        """all three: the hardened setup has 0 findings, 0 of 15 attacks work, 6 of 6 normal requests work"""
        s = twin.Setup("hardened")
        self.assertEqual(checker.run(s), [])
        r = evaluate.run_suite(s)
        self.assertEqual([a["id"] for a in r["attacks"] if a["worked"]], [])
        self.assertTrue(all(n["works"] for n in r["normal"]))


if __name__ == "__main__":
    unittest.main()
