"""Tests of the capstone lab itself (course maintainers; CI in the labs repo). Learners run selfcheck.py instead.

They prove the starting point is what the brief says: normal use works, every known finding is exploitable, the
eval gate and the self-check fail where they should, the tools behave, and nothing can reach a network.
Run: python3 run_tests.py   (make lab-test)
"""
from __future__ import annotations

import ast
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE / "detections")]

import attack_sim  # noqa: E402
import detect      # noqa: E402
from helpdesk import mcp_server  # noqa: E402
from helpdesk.mcp_client import MCPClient  # noqa: E402
from tests.util import fresh, outside_emails, unsafe_html  # noqa: E402


def py(*args, cwd=HERE):
    p = subprocess.run([sys.executable, *args], cwd=str(cwd), capture_output=True, text=True, timeout=300)
    return p.returncode, p.stdout + p.stderr


class T1_StartingPoint(unittest.TestCase):
    def test_functional_tests_pass(self):
        """starting point: F01 to F12 pass"""
        code, out = py("-m", "unittest", "tests.test_functional")
        self.assertEqual(code, 0, out[-800:])

    def test_every_security_test_fails(self):
        """starting point: every one of S01 to S11 fails (each finding is exploitable)"""
        code, out = py("-m", "unittest", "tests.test_security")
        self.assertNotEqual(code, 0)
        failed = set(re.findall(r"^FAIL: test_(s\d\d)", out, re.M))
        self.assertEqual(failed, {f"s{n:02d}" for n in range(1, 12)}, out[-1500:])

    def test_tour_attacks_all_work(self):
        """starting point: make attack reports 8 of 8 attacks worked"""
        code, out = py("tour.py")
        self.assertIn("8 of 8 attacks worked", out)

    def test_hidden_finding_exists(self):
        """starting point: the unlisted finding (another customer's order) is real"""
        with fresh() as hd:
            r = hd.handle("alice@acme.example", "What is the status of order 5002?")
        self.assertIn("12 Fake Street", r.reply)


class T2_EvalGate(unittest.TestCase):
    def test_gate_fails_on_attacks_only(self):
        """eval gate: 17 attack cases fail, 10 normal cases pass on the starting point"""
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "r.json"
            code, _ = py("evals/run_evals.py", "--core-only", "--out", str(out))
            r = json.loads(out.read_text())
        self.assertEqual(code, 1)
        self.assertEqual(len(r["failed"]), 17)
        self.assertNotIn("normal", r["failed_categories"])

    def test_regression_swaps(self):
        """eval gate: each regression puts back the vulnerable behaviour"""
        sys.path.insert(0, str(HERE / "evals"))
        import run_evals
        inj = run_evals.regressed_guards("injection")
        self.assertTrue(inj.authorize_tool_call(None, None).allow)
        self.assertEqual(inj.screen_tool_result("crm_lookup", "x"), "x")
        self.assertEqual(run_evals.regressed_guards("output").render_html("<b>\n"), "<b><br>")
        self.assertEqual(run_evals.regressed_guards("retrieval").filter_retrieval({}, [1, 2]), [1, 2])

    def test_duplicate_ids_refused(self):
        """eval gate: a learner case reusing a core id is refused"""
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "evals").mkdir()
            (repo / "evals" / "my_cases.json").write_text(json.dumps({"cases": [{"id": "inj-01", "user": "x"}]}))
            sys.path.insert(0, str(HERE / "evals"))
            import run_evals
            with self.assertRaises(SystemExit):
                run_evals.load_cases(repo)


class T3_Detections(unittest.TestCase):
    def test_simulator_deterministic_and_varied(self):
        """detections: same seed = same day; different seeds = different attackers"""
        a, ta = attack_sim.generate(1)
        b, _ = attack_sim.generate(1)
        c, tc = attack_sim.generate(2)
        self.assertEqual(a, b)
        users = lambda ev, t: {e["user"] for e in ev if e["request_id"] in t["S1"]}  # noqa: E731
        self.assertNotEqual(users(a, ta), users(c, tc))
        self.assertTrue(all(ta[s] for s in ta), "every incident has events")

    def test_committed_log_is_seed_1(self):
        """detections: logs/attack-day.jsonl is exactly seed 1"""
        events, _ = attack_sim.generate(1)
        committed = detect.load_jsonl(HERE / "detections" / "logs" / "attack-day.jsonl")
        self.assertEqual(committed, json.loads(json.dumps(events)))

    def test_no_labels_in_log(self):
        """detections: the log carries no answer key (no story field), fake IPs and domains only"""
        events, _ = attack_sim.generate(3)
        for e in events:
            self.assertNotIn("story", e)
            if "ip" in e:
                self.assertRegex(e["ip"], r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.")
            if "recipient_domain" in e:
                self.assertRegex(e["recipient_domain"], r"\.(example|invalid)$")

    def test_engine_rule_types(self):
        """detections: match, sequence, threshold and change rules work"""
        ev = [{"ts": f"2027-01-20T10:00:{i:02d}.000Z", "event": "x", "request_id": f"r{i}", "user": "u",
               "v": i, "h": "a" if i < 5 else "b"} for i in range(20)]
        rules = [
            {"id": "m", "title": "t", "severity": "low", "atlas": [], "type": "match", "where": {"v": {"gte": 18}}},
            {"id": "s", "title": "t", "severity": "low", "atlas": [], "type": "sequence", "same": "user",
             "first": {"v": 3}, "then": {"v": 4}, "within_events": 2},
            {"id": "t", "title": "t", "severity": "low", "atlas": [], "type": "threshold", "where": {"event": "x"},
             "by": "user", "count": 10, "window_s": 60},
            {"id": "c", "title": "t", "severity": "low", "atlas": [], "type": "change", "where": {},
             "key": "user", "field": "h"},
        ]
        self.assertEqual(detect.validate(rules), [])
        got = sorted((a["rule"], a["request_id"]) for a in detect.run(rules, ev))
        self.assertEqual(got, [("c", "r5"), ("m", "r18"), ("m", "r19"), ("s", "r4"), ("t", "r9")])

    def test_starter_rule_fails_check(self):
        """detections: the example rule alone fails make detect-check (false alerts, missed incidents)"""
        code, out = py("detections/score.py")
        self.assertEqual(code, 1)
        self.assertIn("missed", out)


class T4_Cloud(unittest.TestCase):
    def test_first_draft(self):
        """cloud: the first draft has 11 HIGH findings"""
        code, out = py("cloud/cloud_check.py", "--stream", "aws")
        self.assertEqual(code, 1)
        self.assertIn("11 HIGH", out)

    def test_deleting_keys_does_not_help(self):
        """cloud: an emptied deployment file still fails (missing = insecure default)"""
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "empty.json"
            p.write_text('{"stream": "aws"}')
            code, out = py("cloud/cloud_check.py", "--stream", "aws", str(p))
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\b(9|1[0-9]) HIGH")

    def test_other_streams_not_yet(self):
        """cloud: azure and gcp say 'not released yet' (exit 3)"""
        for s in ("azure", "gcp"):
            self.assertEqual(py("cloud/cloud_check.py", "--stream", s)[0], 3)


class T5_Selfcheck(unittest.TestCase):
    def test_lock_is_current(self):
        """self-check: selfcheck.lock.json matches the shipped files"""
        import selfcheck
        lock = json.loads(selfcheck.LOCK.read_text())["files"]
        self.assertEqual(set(lock), set(selfcheck.LOCKED))
        for f in selfcheck.LOCKED:
            self.assertEqual(selfcheck.sha(HERE / f), lock[f], f"{f}: run python3 selfcheck.py --write-lock")

    def test_baseline_result(self):
        """self-check: on the starting point, hygiene and functional tests pass; the rest fails"""
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "s.json"
            code, text = py("selfcheck.py", "--json", str(out))
            r = {c["id"]: c["status"] for c in json.loads(out.read_text())["checks"]}
        self.assertEqual(code, 1)
        for cid in ("H1", "H2", "H3", "H4", "T1"):
            self.assertEqual(r[cid], "PASS", (cid, text[-1500:]))
        for cid in ("T2", "E1", "E2", "D1", "C1", "R1", "R2", "R3", "R4", "R5"):
            self.assertEqual(r[cid], "FAIL", cid)

    def test_export_layout(self):
        """export: a new repo with README, guide, workflow; refuses a non-empty folder"""
        with tempfile.TemporaryDirectory() as d:
            dest = pathlib.Path(d) / "repo"
            code, out = py("export.py", str(dest))
            self.assertEqual(code, 0, out)
            for f in ("README.md", "CAPSTONE-GUIDE.md", ".github/workflows/capstone.yml", "selfcheck.py",
                      "helpdesk/guards.py", "report/FINDINGS.md"):
                self.assertTrue((dest / f).exists(), f)
            self.assertFalse((dest / "report" / "README-TEMPLATE.md").exists())
            self.assertNotIn("lab-test", (dest / "Makefile").read_text())
            self.assertEqual(py("export.py", str(dest))[0], 1)
            code, out = py("selfcheck.py", cwd=dest)
            self.assertIn("[PASS] H1", out)
            self.assertIn("[PASS] H4", out)


class T6_Safety(unittest.TestCase):
    NETWORK = {"socket", "urllib", "http.client", "requests", "httpx", "smtplib", "ftplib", "telnetlib"}

    def test_no_network_imports(self):
        """safety: no helpdesk module imports a network client (app.py may use http.server, nothing else)"""
        for p in (HERE / "helpdesk").glob("*.py"):
            tree = ast.parse(p.read_text())
            names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
            names.discard("http.server")
            bad = {m for m in names if m in self.NETWORK or m.split(".")[0] in {"socket", "urllib", "requests", "httpx", "smtplib"}}
            self.assertFalse(bad, f"{p.name}: {bad}")

    def test_refuses_public_bind(self):
        """safety: the server refuses to listen on 0.0.0.0"""
        code, out = py("-c", "from helpdesk.app import serve; serve('0.0.0.0', 8799)")
        self.assertNotEqual(code, 0)
        self.assertIn("refusing", out)

    def test_fake_domains_only(self):
        """safety: every email address in the data and cases uses .example or .invalid"""
        for p in list((HERE / "data").rglob("*")) + list((HERE / "evals").rglob("*.json")) + list((HERE / "evals").rglob("*.md")):
            if p.is_file():
                for addr in re.findall(r"[\w.+-]+@([\w.-]+)", p.read_text()):
                    self.assertRegex(addr, r"\.(example|invalid)$", f"{p.name}: {addr}")

    def test_mcp_protocol(self):
        """MCP server: initialize, tools/list (2 tools, then 3 in release 2), unknown method error"""
        init = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, 1)
        self.assertEqual(init["result"]["protocolVersion"], "2026-07-28")
        self.assertIsNone(mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, 1))
        self.assertEqual(len(mcp_server.tool_list(1)), 2)
        self.assertEqual(len(mcp_server.tool_list(2)), 3)
        self.assertEqual(mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "x"}, 1)["error"]["code"], -32601)
        c = MCPClient(2)
        try:
            self.assertIn("crm_debug_dump", [t["name"] for t in c.list_tools()])
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
