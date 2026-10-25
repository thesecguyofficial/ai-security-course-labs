"""The M26 proof: the first draft is broken in the ways the lessons describe; the hardened stack is not."""

import contextlib
import io
import json
import pathlib
import subprocess
import sys
import unittest

import cachetest
import hunt
import practice_server
import probe
import scan
from cache_engine import block_hashes

HERE = pathlib.Path(__file__).resolve().parent
FIRST, HARD = str(HERE / "stacks" / "first-draft"), str(HERE / "stacks" / "hardened")


def rules(findings):
    return {f.rule for f in findings}


class Test1Scan(unittest.TestCase):
    def test_01_first_draft_findings(self):
        """01 scan: the first draft trips every lesson's rules (exposure, auth, code, versions, cache, nodes, models)"""
        found = rules(scan.scan(FIRST))
        expected = {"AUTH-01", "AUTH-02", "AUTH-03", "EXP-01", "EXP-02", "DEV-01", "RCE-01", "VER-00", "VER-01",
                    "CACHE-01", "CACHE-02", "SEC-01", "K8S-01", "K8S-02", "NODE-01", "NODE-02", "NODE-03",
                    "NODE-04", "MODEL-01", "MODEL-02"}
        self.assertEqual(expected - found, set())

    def test_02_first_draft_cves(self):
        """02 scan: the first draft's engine versions match the right CVEs, and only those"""
        cves = {f.detail.split(": ")[1].split(" ")[0] for f in scan.scan(FIRST) if f.rule == "VER-01"}
        self.assertEqual(cves, {"CVE-2024-37032", "CVE-2025-23319", "CVE-2025-23320", "CVE-2025-23334",
                                "CVE-2025-62164", "CVE-2025-66448"})

    def test_03_hardened_clean(self):
        """03 scan: the hardened stack has no findings at all"""
        self.assertEqual([f.as_dict() for f in scan.scan(HARD)], [])

    def test_04_exit_codes(self):
        """04 scan: exit code 1 on the first draft (gates CI), 0 on the hardened stack"""
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scan.main([FIRST]), 1)
            self.assertEqual(scan.main([HARD]), 0)

    def test_05_version_ranges(self):
        """05 advisories: half-open ranges (introduced <= v < fixed), tags like v0.10.2 and 25.03-py3"""
        self.assertTrue(scan.in_range("v0.10.2", "0.10.2", "0.11.1"))
        self.assertFalse(scan.in_range("v0.11.1", "0.10.2", "0.11.1"))
        self.assertTrue(scan.in_range("25.03-py3", "0", "25.07"))
        self.assertFalse(scan.in_range("25.07-py3", "0", "25.07"))
        self.assertTrue(scan.in_range("1.17.7", "0", "1.17.8"))
        self.assertFalse(scan.in_range("2.59.0", "0", None))     # disputed, no fix: never matched by version

    def test_06_advisories_sourced(self):
        """06 advisories: every entry has a CVE id, a severity, a condition and its CVE record URL"""
        for adv in scan.load_advisories():
            self.assertRegex(adv["id"], r"^CVE-\d{4}-\d{4,}$")
            self.assertIn(adv["severity"], scan.SEVERITY_ORDER)
            self.assertTrue(adv["condition"])
            self.assertEqual(adv["source"], f"https://cveawg.mitre.org/api/cve/{adv['id']}")

    def test_07_loopback_publish_is_fine(self):
        """07 scan: ports bound to 127.0.0.1 are not 'published everywhere'; '8000:8000' is"""
        stack = {"compose": {"services": {"vllm": {"image": "vllm/vllm-openai:v0.32.0", "command": ["--api-key", "${K}"],
                                                   "ports": ["127.0.0.1:8000:8000"]}}}}
        self.assertNotIn("EXP-01", rules(scan.check_compose(stack)))
        stack["compose"]["services"]["vllm"]["ports"] = ["8000:8000"]
        self.assertIn("EXP-01", rules(scan.check_compose(stack)))


class Test2Probe(unittest.TestCase):
    def test_08_first_draft_open(self):
        """08 probe: on the first draft every path answers without a key, management calls included"""
        rows = probe.probe("first-draft")
        self.assertTrue(all(r["no_key"] == 200 for r in rows))

    def test_09_key_only_front_door(self):
        """09 probe: vLLM's --api-key alone locks /v1 but leaves /metrics, /version, /tokenize, /pause open"""
        rows = {r["path"]: r for r in probe.probe("key-only")}
        self.assertEqual(rows["/v1/chat/completions"]["no_key"], 401)
        for p in ("/metrics", "/version", "/tokenize", "/pause", "/update_weights"):
            self.assertEqual(rows[p]["no_key"], 200, p)

    def test_10_hardened_gateway(self):
        """10 probe: behind the hardened gateway nothing answers without a key, and only allow-listed paths exist"""
        rows = probe.probe("hardened")
        self.assertTrue(all(r["no_key"] == 401 for r in rows))
        self.assertEqual({r["path"] for r in rows if r["with_key"] == 200},
                         {"/v1/chat/completions", "/v1/models", "/health"})

    def test_11_loopback_only(self):
        """11 probe: refuses any target that isn't a loopback address"""
        with self.assertRaises(SystemExit):
            probe.require_loopback("10.0.0.5")
        probe.require_loopback("127.0.0.1")

    def test_12_server_binds_loopback(self):
        """12 practice server: binds 127.0.0.1 only"""
        server, _ = practice_server.start("hardened")
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
        finally:
            server.shutdown()


class Test3Cache(unittest.TestCase):
    def test_13_shared_cache_leaks(self):
        """13 cache: with one shared cache, globex gets hits on blocks acme wrote"""
        res, _ = cachetest.run("first-draft")
        self.assertGreater(cachetest.leaked(res["cross_tenant"], "globex"), 0)

    def test_14_per_tenant_isolated(self):
        """14 cache: with per-tenant salts, no cross-tenant hits, and each tenant still reuses its own cache"""
        res, _ = cachetest.run("hardened")
        self.assertEqual(cachetest.leaked(res["cross_tenant"], "globex"), 0)
        self.assertEqual(res["cross_tenant"]["cached_tokens"], 0)
        self.assertGreater(res["same_tenant"]["cached_tokens"], 0)

    def test_15_salt_changes_every_block(self):
        """15 cache: a salt in the first block changes every later block hash too (the chain)"""
        tokens = cachetest.ACME_SYSTEM.split()
        a, b = block_hashes(tokens, None), block_hashes(tokens, "s1")
        self.assertEqual(len(a), 4)
        self.assertTrue(all(x != y for x, y in zip(a, b)))

    def test_16_timing_hidden(self):
        """16 cache: the hardened gateway shows tenants cached-token counts but no per-request timing"""
        res_first, _ = cachetest.run("first-draft")
        res_hard, _ = cachetest.run("hardened")
        self.assertTrue(res_first["same_tenant"]["timing_shown"])
        self.assertFalse(res_hard["same_tenant"]["timing_shown"])


class Test4HuntAndSafety(unittest.TestCase):
    def test_17_hunt_questions(self):
        """17 hunt: Q1 counts keyless successes per path, Q2 finds the two scanners and the outside caller"""
        records = hunt.load(HERE / "data" / "gateway-log.jsonl")
        q1 = hunt.unauthenticated_by_path(records)
        self.assertEqual(q1["/version"], 2)
        self.assertNotIn("/health", q1)
        q2 = hunt.outside_info_probes(records, ["10.0.0.0/8"])
        self.assertEqual(set(q2), {"203.0.113.45", "203.0.113.80", "198.51.100.7"})

    def test_18_model_code_never_runs(self):
        """18 safety: scanning reads the custom model code as text; the marker file is never created"""
        marker = HERE / "PWNED-LAB-MARKER"
        scan.scan(FIRST)
        subprocess.run([sys.executable, str(HERE / "scan.py"), FIRST], capture_output=True, cwd=HERE)
        self.assertFalse(marker.exists())
        self.assertNotIn("modeling_custom", sys.modules)

    def test_19_lab_data_is_placeholder(self):
        """19 safety: the only token-looking values in the lab are labelled placeholders"""
        text = (HERE / "stacks" / "first-draft" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("hf_LABPLACEHOLDER", text)
        gw = json.loads((HERE / "stacks" / "hardened" / "gateway.json").read_text(encoding="utf-8"))
        self.assertTrue(all(t["api_key"].startswith("lab-key-") for t in gw["tenants"].values()))


if __name__ == "__main__":
    unittest.main()
