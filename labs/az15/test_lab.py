"""
test_lab.py: `make test`. The first draft's problems are real, the hardened setup fixes them without breaking the
summariser, and each Azure Machine Learning behaviour the lab relies on works the way Microsoft documents it.
"""

import json
import pathlib
import pickle
import unittest
from unittest import mock

import checker
import evaluate
import hunt
import model_files
import twin

C = twin.COMPANY
HERE = pathlib.Path(__file__).resolve().parent


def shipped(name: str) -> twin.Setup:
    """The setup as shipped: make test ignores your challenge work (policy-challenge.json, the gate switch)."""
    s = twin.Setup(name).copy()
    s.policy_challenge = {"assignments": []}
    s.app["approval_gate"] = False
    return s


def rules(setup):
    return sorted({f.rule for f in checker.run(setup)})


def worked(res):
    return [r["id"] for r in res["attacks"] if r["worked"]]


def by_id(res, key, wanted):
    return next(x for x in res[key] if x["id"] == wanted)


class TC_Lab(unittest.TestCase):
    # ---------------------------------------------------------------- the two setups
    def test_01_first_draft_findings(self):
        """first draft: 31 findings, 15 HIGH (network, public access, identity, keys, deployments, registry, pickle weights)"""
        f = checker.run(shipped("first-draft"))
        self.assertEqual((len(f), sum(x.severity == "HIGH" for x in f)), (31, 15))

    def test_02_hardened_findings(self):
        """hardened: 0 HIGH; only the two challenge findings are left (AZ15-22 promotion gate, AZ15-23 Azure Policy)"""
        self.assertEqual(rules(shipped("hardened")), ["AZ15-22", "AZ15-23"])

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
        """scanner: the pickle-based weights import builtins.print (the lab placeholder), found WITHOUT unpickling"""
        with mock.patch.object(pickle, "loads", side_effect=AssertionError("unpickled!")), \
             mock.patch.object(pickle, "Unpickler", side_effect=AssertionError("unpickled!")):
            res = model_files.scan_files(model_files.build("v1-pickle"))
        self.assertFalse(res["safe"])
        self.assertEqual(res["problems"][0]["unsafe_globals"], ["builtins.print"])

    def test_06_hashes_match_the_registry(self):
        """registry version 2: safetensors only, and its sha256 tags match the files (what the deploy step checks)"""
        s = shipped("hardened")
        rec = s.models["registry:contoso-ml-registry"]["tsg-summariser:2"]
        files = twin.World(s).files(rec["stored_in"])
        self.assertTrue(model_files.scan_files(files)["safe"])
        self.assertEqual(model_files.hash_mismatches(files, rec["tags"]), [])

    def test_07_a_swap_is_caught(self):
        """a swap after registration: the hash check names the changed and the extra files; the deploy step refuses"""
        s = shipped("hardened")
        rec = s.models["registry:contoso-ml-registry"]["tsg-summariser:2"]
        world = twin.World(s)
        world.store[rec["stored_in"]] = model_files.swapped(world.files(rec["stored_in"]))
        bad = model_files.hash_mismatches(world.files(rec["stored_in"]), rec["tags"])
        self.assertIn("model.safetensors", bad)
        self.assertIn("pytorch_model.bin", bad)
        r = twin.load_model(s, world)
        self.assertFalse(r["ok"])
        self.assertIn("hash check failed", r["why"])

    # ---------------------------------------------------------------- Azure RBAC (15.2, 15.3)
    def test_08_data_scientist_role(self):
        """AzureML Data Scientist: can't modify the workspace (NotActions), but deployment writes and listKeys are in"""
        s = shipped("first-draft")
        ws = f"ws:{C['endpoint_workspace']}"
        self.assertFalse(twin.decide(s, "ds-bob", twin.A_WORKSPACE_WRITE, ws)[0])
        self.assertTrue(twin.decide(s, "ds-bob", twin.A_DEPLOY_WRITE, "deployment:tsg-ml/tsg-summariser/blue")[0])
        self.assertTrue(twin.decide(s, "ds-bob", twin.A_LIST_KEYS, "endpoint:tsg-ml/tsg-summariser")[0])

    def test_09_scope_inheritance(self):
        """RBAC scope: an assignment applies to its scope and everything under it, never to a sibling"""
        s = shipped("hardened")
        self.assertTrue(twin.decide(s, "ds-alice", twin.A_MODEL_WRITE, "model:tsg-ml-dev/x/1")[0])
        self.assertFalse(twin.decide(s, "ds-alice", twin.A_MODEL_WRITE, "model:tsg-ml/x/1")[0])

    def test_10_sample_scoring_role(self):
        """Microsoft's sample scoring role (onlineEndpoints/*/action) also grants listKeys and regenerateKeys"""
        s = shipped("first-draft")
        for op in ("score", "listKeys", "regenerateKeys"):
            self.assertTrue(twin.decide(s, "tsg-reporting", f"{twin.ML}/workspaces/onlineEndpoints/{op}/action",
                                        "endpoint:tsg-ml/tsg-summariser")[0], op)

    # ---------------------------------------------------------------- network (15.2)
    def test_11_approved_outbound(self):
        """approved outbound: internet blocked; the workspace's own storage reachable through a required rule"""
        s = shipped("hardened")
        self.assertFalse(twin.egress(s, "tsg-ml", "internet:collector.example.net")[0])
        ok, why = twin.egress(s, "tsg-ml", "storage:sttsgml")
        self.assertTrue(ok)
        self.assertIn("required rule", why)

    def test_12_fqdn_rule_is_a_way_out(self):
        """an FQDN rule (huggingface.co) goes through a firewall, and is a way out for data too"""
        s = shipped("first-draft")
        ok, why = twin.egress(s, "tsg-ml-dev", "internet:huggingface.co/bob-lab-placeholder/scratch")
        self.assertTrue(ok)
        self.assertIn("Azure Firewall", why)
        self.assertFalse(twin.egress(s, "tsg-ml-dev", "internet:collector.example.net")[0])

    def test_13_endpoint_inbound(self):
        """public_network_access disabled: refused from the internet, accepted through the workspace private endpoint"""
        s = shipped("hardened")
        self.assertFalse(twin.inbound(s, "endpoint", "internet")[0])
        self.assertTrue(twin.inbound(s, "endpoint", "vnet")[0])

    # ---------------------------------------------------------------- the endpoint (15.3)
    def test_14_auth_modes(self):
        """key auth needs no role; aad_token needs score/action and refuses keys"""
        fd, hd = shipped("first-draft"), shipped("hardened")
        self.assertTrue(twin.invoke(fd, "anyone", "internet", "key")["ok"])
        self.assertFalse(twin.invoke(hd, "tsg-helpdesk-app", "vnet", "key")["ok"])
        self.assertTrue(twin.invoke(hd, "tsg-helpdesk-app", "vnet", "aad")["ok"])
        self.assertFalse(twin.invoke(hd, "tsg-reporting", "vnet", "aad")["ok"])

    def test_15_header_reaches_a_zero_percent_deployment(self):
        """the azureml-model-deployment header routes to a deployment whatever its traffic share"""
        r = twin.invoke(shipped("first-draft"), "tsg-helpdesk-app", "vnet", "key", header="debug")
        self.assertTrue(r["ok"])
        self.assertEqual(r["deployment"], "debug")

    # ---------------------------------------------------------------- Azure Policy (15.0, 15.2, 15.3)
    def test_16_isolation_policy_default_parameter(self):
        """built-in approved-outbound policy: with isolationMode left at its default 'Disabled' it flags the GOOD workspace"""
        s = shipped("hardened")
        good = twin.workspace_request("ok", {"publicNetworkAccess": "Disabled", "managedNetwork": {"isolationMode": "AllowOnlyApprovedOutbound"}})
        self.assertIn("ml-approved-outbound", twin.policy_check(s, good)["audited"])
        s.policy["assignments"][0]["parameters"] = {"isolationMode": "AllowOnlyApprovedOutbound"}
        self.assertNotIn("ml-approved-outbound", twin.policy_check(s, good)["audited"])

    def test_17_registry_policy(self):
        """registry Deny policy: blocks other registries, allows contoso-ml-registry, and doesn't apply to workspace models"""
        s = shipped("hardened")
        deny = lambda ref: twin.policy_check(s, twin.deployment_request(ref))["denied"]
        self.assertTrue(deny("azureml://registries/HuggingFace/models/bert-base-uncased/labels/latest"))
        self.assertFalse(deny("azureml://registries/contoso-ml-registry/models/tsg-summariser/versions/2"))
        self.assertFalse(deny("azureml:bob-experiment:1"))

    def test_18_allowed_asset_ids_use_contains(self):
        """'approved Registry Models' policy matches with contains: allowing .../models/tsg-summariser also allows tsg-summariser-x"""
        d = json.loads((HERE / "data/policy-definitions/AllowDeployRegistryModels_Audit.json").read_text())
        s = shipped("hardened")
        s.policy = {"assignments": [{**d, "name": "approved-models", "effect": "Deny",
                                     "parameters": {"allowedAssetIds": ["azureml://registries/contoso-ml-registry/models/tsg-summariser"]}}]}
        deny = lambda ref: twin.policy_check(s, twin.deployment_request(ref))["denied"]
        self.assertFalse(deny("azureml://registries/contoso-ml-registry/models/tsg-summariser/versions/2"))
        self.assertFalse(deny("azureml://registries/contoso-ml-registry/models/tsg-summariser-x/versions/1"))
        self.assertTrue(deny("azureml://registries/HuggingFace/models/bert-base-uncased/labels/latest"))

    # ---------------------------------------------------------------- the hunt (15.4)
    def test_19_hunt(self):
        """hunt: Q1 bob's debug deployment, Q2 two listKeys outside the platform team, Q3 three calls to the 0% deployment"""
        d = hunt.load()
        self.assertEqual([(r["who"], r["deployment"]) for r in hunt.q1_deployments_outside_pipeline(d)], [("ds-bob", "debug")])
        self.assertEqual([(r["who"], r["endpoint"]) for r in hunt.q2_key_listings(d)],
                         [("ds-bob", "tsg-summariser-legacy"), ("tsg-reporting", "tsg-summariser")])
        self.assertEqual(len(hunt.q3_calls_outside_the_split(d)), 3)

    def test_20_traffic_log_shape(self):
        """traffic log: no client IP and no payload columns; key calls carry no identity"""
        rows = hunt.load()["traffic"]
        self.assertFalse(any(k.lower() in ("callerip", "clientip", "callipaddress", "requestbody") for r in rows for k in r))
        self.assertTrue(all(r["IdentityData"] == "" for r in rows if r["AuthType"] == "Key"))

    def test_21_break_it_steps(self):
        """README Step 6: no registry outbound rule, or a model pulled from the Hub at start, and the summariser breaks"""
        s = shipped("hardened")
        del s.workspace["tsg-ml"]["managedNetwork"]["outboundRules"]["contoso-ml-registry"]
        self.assertFalse(by_id(evaluate.run_suite(s), "normal", "N1")["works"])
        s = shipped("hardened")
        s.deployments["blue"]["environment_variables"]["HF_MODEL_ID"] = "Qwen/Qwen3-0.6B"
        self.assertFalse(by_id(evaluate.run_suite(s), "normal", "N1")["works"])


if __name__ == "__main__":
    unittest.main()
