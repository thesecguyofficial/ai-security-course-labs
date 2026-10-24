"""
test_lab.py: `make test`. The first draft's problems are real, the hardened setup fixes them without breaking the
summariser, and each SageMaker AI behaviour the lab relies on works the way AWS documents it.
"""

import io
import pickle
import unittest
from unittest import mock

import checker
import evaluate
import hunt
import model_files
import twin

C = twin.COMPANY


def shipped(name: str) -> twin.Setup:
    """The setup as shipped: make test ignores your challenge work (scp.json statements, the gate switch)."""
    s = twin.Setup(name).copy()
    s.scps = {"Statement": []}
    s.app["approval_gate"] = False
    return s


def rules(setup):
    return sorted({f.rule for f in checker.run(setup)})


def worked(res):
    return [r["id"] for r in res["attacks"] if r["worked"]]


class TC_Lab(unittest.TestCase):
    # ---------------------------------------------------------------- the two setups
    def test_01_first_draft_findings(self):
        """first draft: 35 findings, 19 HIGH (isolation, Studio, roles, endpoint paths, SSM, registry, pickle weights)"""
        f = checker.run(shipped("first-draft"))
        self.assertEqual((len(f), sum(x.severity == "HIGH" for x in f)), (35, 19))

    def test_02_hardened_findings(self):
        """hardened: 0 HIGH; only the two challenge findings are left (M15-22 approval gate, M15-23 SCP)"""
        self.assertEqual(rules(shipped("hardened")), ["M15-22", "M15-23"])

    def test_03_first_draft_suite(self):
        """first draft: 15 of 15 attacks work, and 6 of 6 normal requests work (that's why it shipped)"""
        r = evaluate.run_suite(shipped("first-draft"))
        self.assertEqual(len(worked(r)), 15)
        self.assertTrue(all(n["works"] for n in r["normal"]))

    def test_04_hardened_suite(self):
        """hardened: only A14 and A15 still work (the challenge), and 6 of 6 normal requests still work"""
        r = evaluate.run_suite(shipped("hardened"))
        self.assertEqual(worked(r), ["A14", "A15"])
        self.assertTrue(all(n["works"] for n in r["normal"]), [n["id"] for n in r["normal"] if not n["works"]])

    # ---------------------------------------------------------------- model files (15.3)
    def test_05_scanner_finds_the_placeholder(self):
        """scanner: the pickle's builtins.print import is flagged; the two PyTorch imports on the allow-list are not"""
        res = model_files.scan_bytes("pytorch_model.bin", model_files.build("v1-pickle")["pytorch_model.bin"])
        self.assertEqual((res["kind"], res["unsafe_globals"]), ("pickle", ["builtins.print"]))
        self.assertTrue(model_files.scan_files(model_files.build("v2-safe"))["safe"])
        for name in ("arrays.npy", "modeling_custom.py"):
            self.assertTrue(model_files.scan_bytes(name, b"x")["problem"], name)

    def test_06_scanner_never_unpickles(self):
        """scanner: works with pickle.load and pickle.loads disabled (it only parses opcodes)"""
        boom = mock.Mock(side_effect=AssertionError("the scanner must never unpickle"))
        with mock.patch.object(pickle, "loads", boom), mock.patch.object(pickle, "load", boom), \
             mock.patch.object(pickle, "Unpickler", boom):
            res = model_files.scan_files(model_files.build("v3-unvetted"))
        self.assertFalse(res["safe"])
        boom.assert_not_called()

    def test_07_hashes(self):
        """hashes: v2's files match what the registry recorded at approval; a swapped folder does not"""
        meta = twin.package(shipped("hardened"), 2)["CustomerMetadataProperties"]
        files = model_files.build("v2-safe")
        self.assertEqual(model_files.hash_mismatches(files, meta), [])
        self.assertEqual(model_files.hash_mismatches(model_files.swapped(files), meta), ["model.safetensors", "pytorch_model.bin"])
        self.assertEqual(model_files.hash_mismatches(files, {}), ["no hashes recorded"])

    # ---------------------------------------------------------------- network isolation and the container (15.2)
    def test_08_network_isolation(self):
        """isolation: no outbound calls and no credentials; without it and without a VPC, SageMaker AI provides external access"""
        self.assertEqual(twin.container_reach(shipped("hardened")),
                         {"internet": False, "vpc": False, "credentials": False,
                          "why": "network isolation: no outbound calls, no AWS credentials in the container"})
        r = twin.container_reach(shipped("first-draft"))
        self.assertTrue(r["internet"] and r["credentials"])

    def test_09_isolation_and_the_hub(self):
        """isolation: a model that downloads from the Hugging Face Hub at start can't load; the files must come from S3"""
        s = shipped("first-draft").copy()
        s.model["EnableNetworkIsolation"] = True
        s.model["PrimaryContainer"] = {"Image": s.model["PrimaryContainer"]["Image"], "Environment": {"HF_MODEL_ID": "Qwen/Qwen3-0.6B"}}
        r = twin.load_model(s, twin.World(s))
        self.assertFalse(r["ok"])
        self.assertIn("can't reach the internet", r["why"])

    def test_10_vpc_needs_an_s3_endpoint(self):
        """VPC: without an S3 gateway endpoint (and no NAT) the endpoint can't download its model (AWS host-vpc)"""
        s = shipped("hardened").copy()
        s.network["s3_gateway_endpoint"] = None
        n6 = evaluate.run_case(evaluate.NORMAL[5], s)
        self.assertFalse(n6["works"])
        self.assertIn("S3 gateway endpoint", n6["lines"][0])

    # ---------------------------------------------------------------- IAM evaluator
    def test_11_iam_semantics(self):
        """IAM: explicit Deny wins; negated operators are true for a missing key; IfExists and Null behave as documented"""
        pol = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                             {"Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"}]}
        self.assertEqual(twin.policy_effect(pol, "s3:PutObject", "arn:aws:s3:::b/k", {}), "deny")
        self.assertTrue(twin._cond_one("StringNotEquals", "aws:SourceVpce", "vpce-1", {}))
        self.assertFalse(twin._cond_one("StringEquals", "aws:SourceVpce", "vpce-1", {}))
        self.assertTrue(twin._cond_one("BoolIfExists", "sagemaker:NetworkIsolation", "false", {}))
        self.assertFalse(twin._cond_one("BoolIfExists", "sagemaker:NetworkIsolation", "false", {"sagemaker:NetworkIsolation": "true"}))
        self.assertTrue(twin._cond_one("Null", "sagemaker:VpcSubnets", "true", {}))

    def test_12_runtime_endpoint_policy(self):
        """VPC endpoint: the default policy lets another account's role through; the hardened one doesn't; the app still gets in"""
        out = C["outsider_endpoint_arn"]
        self.assertTrue(twin.decide(shipped("first-draft"), "collector-role", "sagemaker:InvokeEndpoint", out, via_vpce=True)[0])
        self.assertFalse(twin.decide(shipped("hardened"), "collector-role", "sagemaker:InvokeEndpoint", out, via_vpce=True)[0])
        self.assertTrue(twin.decide(shipped("hardened"), "tsg-helpdesk-app", "sagemaker:InvokeEndpoint", C["endpoint_arn"], via_vpce=True)[0])
        self.assertFalse(twin.decide(shipped("hardened"), "tsg-helpdesk-app", "sagemaker:InvokeEndpoint", C["endpoint_arn"])[0])

    def test_13_trust_policy_template(self):
        """trust: no aws:SourceArn is MEDIUM; narrowing it to one endpoint ARN is LOW (AWS: keep arn:aws:sagemaker:<region>:<account>:*)"""
        s = shipped("hardened").copy()
        st = s.iam["principals"]["tsg-summariser-exec"]["trust"]["Statement"][0]
        st["Condition"]["ArnLike"]["aws:SourceArn"] = C["endpoint_arn"]
        f = [x for x in checker.run(s) if x.rule == "M15-09"]
        self.assertEqual([x.severity for x in f], ["LOW"])

    def test_14_kms_and_local_storage(self):
        """KMS: a KmsKeyId on an ml.g5.xlarge endpoint is flagged LOW (NVMe instance storage); hardened leaves it off"""
        s = shipped("hardened").copy()
        s.endpoint_config["KmsKeyId"] = C["kms_key_arn"]
        self.assertIn("M15-13", rules(s))
        self.assertNotIn("KmsKeyId", shipped("hardened").endpoint_config)

    def test_15_ssm_and_isolation(self):
        """SSM: with network isolation on, no SSM session can start, even if EnableSSMAccess is set (AWS)"""
        s = shipped("first-draft").copy()
        s.model["EnableNetworkIsolation"] = True
        a9 = evaluate.run_case(evaluate.ATTACKS[8], s)
        self.assertFalse(a9["worked"])

    def test_16_studio_vpc_only(self):
        """Studio: PublicInternetOnly reaches the internet; VpcOnly with a NAT route does too; VpcOnly without one doesn't"""
        s = shipped("hardened").copy()
        self.assertFalse(twin.studio_reach(s)["internet"])
        for sub in s.domain["SubnetIds"]:
            s.network["subnets"][sub]["routes"].append("nat")
        self.assertTrue(twin.studio_reach(s)["internet"])
        self.assertTrue(twin.studio_reach(shipped("first-draft"))["internet"])

    # ---------------------------------------------------------------- monitoring (15.4)
    def test_17_capture_and_monitoring_rules(self):
        """15.4: capture into the analytics bucket without a key, no data events, no alarms, Model Monitor plan: all flagged"""
        found = rules(shipped("first-draft"))
        for r in ("M15-24", "M15-25", "M15-26", "M15-27"):
            self.assertIn(r, found)

    def test_18_checker_exit_code(self):
        """checker: exits 1 on any HIGH finding (so it can fail a pipeline), 0 on the hardened setup"""
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(checker.main(["first-draft"]), 1)
            self.assertEqual(checker.main(["hardened"]), 0)

    # ---------------------------------------------------------------- the hunt (15.4)
    def test_19_hunt(self):
        """hunt: finds the hotfix model outside the pipeline, Bob's self-approval and the presigned URL for alice"""
        t = hunt.load()
        self.assertEqual([x["model"] for x in hunt.models_outside_pipeline(t)], ["tsg-summariser-hotfix"])
        self.assertEqual([(x["who"], x["version"]) for x in hunt.self_approvals(t)], [("ds-bob", "3")])
        self.assertEqual([(x["who"], x["signed_in_as"]) for x in hunt.presigned_for_others(t)], [("ds-bob", "alice")])

    def test_20_invoke_records_carry_no_prompt(self):
        """hunt: the InvokeEndpoint data events carry no request parameters (AWS: InvokeEndpoint doesn't log them)"""
        inv = [r for r in hunt.load() if r["eventName"] == "InvokeEndpoint"]
        self.assertTrue(inv)
        self.assertTrue(all(r["requestParameters"] == {} and r["eventCategory"] == "Data" for r in inv))


if __name__ == "__main__":
    unittest.main()
