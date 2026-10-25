"""
test_lab.py: `make test`. The first draft's problems are real, the hardened setup fixes them without breaking the
summariser, and each Agent Platform behaviour the lab relies on works the way Google documents it.
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
EP = "endpoint:" + C["endpoint"]


def shipped(name: str) -> twin.Setup:
    """The setup as shipped: make test ignores your challenge work (org policy constraints, the gate switch)."""
    s = twin.Setup(name).copy()
    for c in ("restrictPublicIp", "disableRootAccess", "disableTerminal", "disableFileDownloads", "accessMode"):
        s.orgpolicy[f"constraints/ainotebooks.{c}"] = None
    s.app["approval_gate"] = False
    return s


def rules(setup):
    return sorted({f.rule for f in checker.run(setup)})


def worked(res):
    return [r["id"] for r in res["attacks"] if r["worked"]]


class TC_Lab(unittest.TestCase):
    # ---------------------------------------------------------------- the two setups
    def test_01_first_draft_findings(self):
        """first draft: 35 findings, 15 HIGH (perimeter, identities, keys, notebooks, public endpoint, pickle, prompt logs)"""
        f = checker.run(shipped("first-draft"))
        self.assertEqual((len(f), sum(x.severity == "HIGH" for x in f)), (35, 15))

    def test_02_hardened_findings(self):
        """hardened: 0 HIGH; only the two challenge findings are left (GC15-17 Workbench constraints, GC15-25 promotion gate)"""
        self.assertEqual(rules(shipped("hardened")), ["GC15-17", "GC15-25"])

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
        """scanner: the pickle's builtins.print import is flagged; the PyTorch import on the allow-list is not"""
        res = model_files.scan_bytes("pytorch_model.bin", model_files.build("v1-pickle")["pytorch_model.bin"])
        self.assertEqual((res["kind"], res["unsafe_globals"]), ("pickle", ["builtins.print"]))
        self.assertTrue(model_files.scan_files(model_files.build("v3-safe"))["safe"])
        for name in ("arrays.npy", "modeling_custom.py"):
            self.assertTrue(model_files.scan_bytes(name, b"x")["problem"], name)

    def test_06_scanner_never_unpickles(self):
        """scanner: works with pickle.load and pickle.loads disabled (it only parses opcodes)"""
        boom = mock.Mock(side_effect=AssertionError("the scanner must never unpickle"))
        with mock.patch.object(pickle, "loads", boom), mock.patch.object(pickle, "load", boom), \
             mock.patch.object(pickle, "Unpickler", boom):
            res = model_files.scan_files(model_files.build("v2-unvetted"))
        self.assertFalse(res["safe"])
        boom.assert_not_called()

    def test_07_hashes_as_labels(self):
        """hashes: version 3's files match its sha256-* labels; a swapped folder does not; every label fits in 64 characters"""
        labels = twin.version(shipped("hardened"), "3")["labels"]
        files = model_files.build("v3-safe")
        self.assertEqual(model_files.hash_mismatches(files, labels), [])
        self.assertEqual(model_files.hash_mismatches(model_files.swapped(files), labels), ["model.safetensors", "pytorch_model.bin"])
        self.assertEqual(model_files.hash_mismatches(files, {}), ["no hashes recorded"])
        self.assertTrue(all(len(k) <= 64 and len(v) <= 64 for k, v in model_files.manifest(files).items()))

    def test_08_upload_copies_what_is_there(self):
        """registry: models.upload copies the folder at upload time; a hash check before upload refuses a swap (A2)"""
        s = shipped("hardened").copy()
        world = twin.World(s)
        self.assertFalse(twin.pipeline_upload(s, world, s.app["_next_release"], swap_after_scan=True)["ok"])
        s.app["upload_verifies_hashes"] = False
        self.assertTrue(twin.pipeline_upload(s, twin.World(s), s.app["_next_release"], swap_after_scan=True)["ok"])

    # ---------------------------------------------------------------- the container and the perimeter (15.2)
    def test_09_perimeter_blocks_container_egress(self):
        """VPC-SC: inside an enforced perimeter the serving environment has no internet; without one it does"""
        self.assertFalse(twin.container_reach(shipped("hardened"))["internet"])
        self.assertTrue(twin.container_reach(shipped("first-draft"))["internet"])
        s = shipped("hardened").copy()
        s.network["perimeter"]["mode"] = "dry-run"
        self.assertTrue(twin.container_reach(s)["internet"])

    def test_10_perimeter_before_endpoint(self):
        """VPC-SC: an endpoint created before the project joined the perimeter can't take a deployment (Google)"""
        s = shipped("hardened").copy()
        s.endpoint["endpoint"]["_created"] = "2027-01-05"
        n6 = evaluate.run_case(evaluate.NORMAL[5], s)
        self.assertFalse(n6["works"])
        self.assertIn("before the project joined the perimeter", n6["lines"][0])
        self.assertIn("GC15-06", rules(s))

    def test_11_perimeter_stops_a_leaked_key(self):
        """VPC-SC: even with a leaked key file, predict from the internet is denied by the perimeter; from the VPC it works"""
        s = shipped("hardened").copy()
        s.iam["keys"]["tsg-helpdesk-app"] = ["a key someone made anyway"]
        ok, why = twin.decide(s, "tsg-helpdesk-app", "aiplatform.endpoints.predict", EP, origin="internet")
        self.assertFalse(ok)
        self.assertIn("VPC Service Controls", why)
        self.assertTrue(twin.decide(s, "tsg-helpdesk-app", "aiplatform.endpoints.predict", EP, origin="vpc")[0])

    def test_12_runtime_identity(self):
        """identity: the deployed model's serviceAccount decides what the container can reach; hardened has no project roles"""
        self.assertEqual(twin.runtime_identity(shipped("first-draft")), "compute-default")
        a6 = evaluate.run_case(evaluate.ATTACKS[5], shipped("hardened"))
        self.assertFalse(a6["worked"])
        s = shipped("hardened").copy()
        del s.endpoint["deployModel"]["deployedModel"]["serviceAccount"]
        self.assertIsNone(twin.container_reach(s)["identity"])

    def test_13_iam_inheritance(self):
        """IAM: a project binding applies to every bucket, model and endpoint in it; a resource binding only to that resource"""
        fd, hd = shipped("first-draft"), shipped("hardened")
        self.assertTrue(twin.decide(fd, "ds-bob", "aiplatform.endpoints.predict", EP)[0])
        self.assertTrue(twin.decide(hd, "tsg-helpdesk-app", "aiplatform.endpoints.predict", EP)[0])
        self.assertFalse(twin.decide(hd, "tsg-helpdesk-app", "aiplatform.endpoints.predict", "endpoint:projects/example-summariser-prod/locations/us-central1/endpoints/9999")[0])
        self.assertTrue(twin.decide(fd, "ds-alice", "storage.objects.get", "bucket:example-tsg-analytics/x.csv")[0])

    def test_14_workbench_reach_and_constraints(self):
        """Workbench: an external IP reaches the internet; no IP and no NAT doesn't; enforced constraints refuse the defaults"""
        fd, hd = shipped("first-draft"), shipped("hardened")
        self.assertTrue(twin.workbench_reach(fd, fd.workbench["instances"]["tsg-ds-shared"])["internet"])
        self.assertFalse(twin.workbench_reach(hd, hd.workbench["instances"]["bob-wb"])["internet"])
        s = hd.copy()
        s.orgpolicy["constraints/ainotebooks.restrictPublicIp"] = {"enforce": True}
        self.assertEqual(twin.workbench_violations(s, fd.workbench["instances"]["tsg-ds-shared"]),
                         ["ainotebooks.restrictPublicIp (the instance has a public IP)"])

    def test_15_allowed_models(self):
        """vertexai.allowedModels: no policy allows everything; an allow list allows only its entries; deny wins"""
        self.assertTrue(twin.allowed_models_ok(shipped("first-draft"), evaluate.UNVETTED_GARDEN_MODEL)[0])
        hd = shipped("hardened")
        self.assertFalse(twin.allowed_models_ok(hd, evaluate.UNVETTED_GARDEN_MODEL)[0])
        self.assertTrue(twin.allowed_models_ok(hd, C["approved_garden_models"][0])[0])
        s = hd.copy()
        s.orgpolicy["constraints/vertexai.allowedModels"]["deniedValues"] = [C["approved_garden_models"][0]]
        self.assertFalse(twin.allowed_models_ok(s, C["approved_garden_models"][0])[0])

    # ---------------------------------------------------------------- monitoring (15.4)
    def test_16_logging_rules(self):
        """15.4: prompt logs readable by all staff, Data Access logs off, access logging off, prompts in container logs: all flagged"""
        found = rules(shipped("first-draft"))
        for r in ("GC15-26", "GC15-27", "GC15-28", "GC15-29", "GC15-30"):
            self.assertIn(r, found)

    def test_17_checker_exit_code(self):
        """checker: exits 1 on any HIGH finding (so it can fail a pipeline), 0 on the hardened setup"""
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(checker.main(["first-draft"]), 1)
            self.assertEqual(checker.main(["hardened"]), 0)

    # ---------------------------------------------------------------- the hunt (15.4)
    def test_18_hunt(self):
        """hunt: finds Bob's upload and deploy, his self-promotion of version 5 and the key he made for the app"""
        log = hunt.load()
        self.assertEqual([(x["who"], x["action"]) for x in hunt.outside_pipeline(log)], [("ds-bob", "UploadModel"), ("ds-bob", "DeployModel")])
        self.assertEqual([(x["who"], x["version"]) for x in hunt.self_promotions(log)], [("ds-bob", "5")])
        self.assertEqual([(x["who"], x["for"]) for x in hunt.new_keys(log)], [("ds-bob", "tsg-helpdesk-app")])

    def test_19_hunt_predict_entries_are_data_access(self):
        """hunt: Predict entries are in the data_access log, every other entry in activity"""
        for e in hunt.load():
            kind = "data_access" if hunt.method(e) == "Predict" else "activity"
            self.assertTrue(e["logName"].endswith("%2F" + kind), e["insertId"])

    def test_20_no_real_secrets(self):
        """safety: the lab's token is a labelled placeholder, and the lab's pickle only names builtins.print"""
        env = twin.env_of(twin.version(shipped("first-draft"), "1"))
        self.assertIn("LAB_PLACEHOLDER", env["HF_TOKEN"])
        found = model_files.scan_bytes("pytorch_model.bin", model_files.build("v1-pickle")["pytorch_model.bin"])["unsafe_globals"]
        self.assertEqual(found, ["builtins.print"])


if __name__ == "__main__":
    unittest.main()
