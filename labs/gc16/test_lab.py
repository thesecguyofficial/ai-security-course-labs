"""
test_lab.py: `make test`. The simulator plants what the lessons describe, each logging setup collects only what it
should, the rule packs catch (and miss) what the lessons say, and the inventory, posture and report tools agree.
Runs in memory: no out/ folder needed. Your challenge work (D11, D12, your report) is ignored here.
"""

import copy
import json
import unittest

import detect
import evaluate
import inventory
import posture
import report
import simulate

FIRST = simulate.build("first-draft")
HARD = simulate.build("hardened")


def ev(built, pack="gc16", challenge=False):
    return evaluate.evaluate(built["setup"]["name"], pack, challenge, built=built)


def status(res):
    return {s: res[s]["status"] for s in simulate.SCENARIOS}


class TC_Lab(unittest.TestCase):
    # ------------------------------------------------------------------------------------------ the simulator
    def test_01_deterministic(self):
        """the simulator is deterministic: the same day on every computer"""
        self.assertEqual(simulate.build("hardened")["out"], HARD["out"])

    def test_02_first_draft_collects_little(self):
        """first draft: Admin Activity plus BigQuery Data Access only; no prompts, no Model Armor logs, no SCC
        threat findings, no gateway logs, no user IDs"""
        o = FIRST["out"]
        self.assertEqual([len(o[k]) for k in ("requests", "armor", "scc", "gateway")], [0, 0, 0, 0])
        da = {e["protoPayload"]["serviceName"] for e in o["audit"] if e["logName"].endswith("%2Fdata_access")}
        self.assertEqual(da, {"bigquery.googleapis.com"})
        self.assertTrue(all("signed_in_user" not in a for a in o["app"]))

    def test_03_hardened_sources(self):
        """hardened: Data Access for Agent Platform and the RAG bucket; request-response rows for Gemini only"""
        da = {e["protoPayload"]["serviceName"] for e in HARD["out"]["audit"] if e["logName"].endswith("%2Fdata_access")}
        self.assertTrue({"aiplatform.googleapis.com", "storage.googleapis.com"} <= da)
        self.assertEqual({r["model"] for r in HARD["out"]["requests"]}, {"gemini-3.1-flash-lite", "gemini-3.5-flash"})
        self.assertTrue(all(json.dumps(r["full_response"]).count("responseId") for r in HARD["out"]["requests"]))

    def test_04_scc_findings_are_low(self):
        """SCC: two Event Threat Detection AI findings, both LOW (as in Google's example findings), with evidence"""
        scc = HARD["out"]["scc"]
        self.assertEqual(sorted(f["category"] for f in scc),
                         ["Persistence: New AI API Method", "Persistence: New Geography for AI Service"])
        self.assertTrue(all(f["severity"] == "LOW" and f["sourceProperties"]["evidence"] for f in scc))

    def test_05_project_level_loses_geography(self):
        """New Geography for AI Service isn't available for project-level activations: one finding fewer"""
        setup = dict(HARD["setup"], scc_activation="project")
        d = simulate.Day(setup)
        simulate.normal_day(d)
        simulate.s1_leaked_key(d)
        self.assertEqual([f["category"] for f in d.out["scc"]], ["Persistence: New AI API Method"])

    def test_06_benign_block_stays_quiet(self):
        """one harmless message blocked once by Model Armor makes no alert (D07 needs three in ten minutes)"""
        blocked = [r for r in HARD["out"]["requests"] if (r["full_response"].get("promptFeedback") or {}).get("blockReason")]
        users = sorted({r["full_request"]["labels"]["end_user"] for r in blocked})
        self.assertEqual(users, ["cust-1034", "cust-8841"])
        alerted = {a["entity"] for a in detect.run(detect.Telemetry.from_build(HARD), challenge=False)}
        self.assertNotIn("cust-1034", alerted)

    # ------------------------------------------------------------------------------------------ the rule packs
    def test_07_soc_v1_first_draft(self):
        """old rules, old logs: 1 of 5 caught (the audit config change, Admin Activity is always on)"""
        self.assertEqual(evaluate.summary(ev(FIRST, "soc-v1")),
                         "Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 0")

    def test_08_soc_v1_hardened(self):
        """old rules, new logs: still 1 of 5; the HIGH-and-CRITICAL SCC rule drops both LOW findings, and the
        Predict volume rule pages on the data science batch"""
        r = ev(HARD, "soc-v1")
        self.assertEqual(evaluate.summary(r), "Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 1")
        self.assertEqual(r["false_alarms"][0]["entity"], "ds-batch")
        self.assertFalse([a for a in r["alerts"] if a["rule"] == "N3"])

    def test_09_gc16_first_draft(self):
        """new rules, old logs: only S1 is caught (Admin Activity); S3 is seen but not named"""
        self.assertEqual(status(ev(FIRST)), {"S1": "CAUGHT", "S2": "MISSED", "S3": "SEEN, NOT NAMED",
                                              "S4": "MISSED", "S5": "MISSED"})

    def test_10_gc16_hardened(self):
        """new rules, new logs: S1, S2, S3 caught; S4 and S5 seen but not named (the challenge); 0 false alarms"""
        r = ev(HARD)
        self.assertEqual(status(r), {"S1": "CAUGHT", "S2": "CAUGHT", "S3": "CAUGHT", "S4": "SEEN, NOT NAMED",
                                     "S5": "SEEN, NOT NAMED"})
        self.assertEqual(r["false_alarms"], [])

    def test_11_token_spike_names_the_model(self):
        """request-response rows carry no caller: the token rule can only name the model"""
        d06 = [a for a in detect.run(detect.Telemetry.from_build(HARD)) if a["rule"] == "D06"]
        self.assertEqual(sorted({a["entity_type"] for a in d06}), ["model"])

    def test_12_labels_matter(self):
        """without labels.end_user on the requests, S2 is seen but nobody is named"""
        b = copy.deepcopy(HARD)
        for r in b["out"]["requests"]:
            r["full_request"].pop("labels", None)
        self.assertEqual(ev(b)["S2"]["status"], "SEEN, NOT NAMED")

    def test_13_dry_run_is_seen_not_named_without_gateway_logs(self):
        """the gateway exclusion: without gateway request logs S3 drops to SEEN, NOT NAMED"""
        b = copy.deepcopy(HARD)
        b["out"]["gateway"] = []
        self.assertEqual(ev(b)["S3"]["status"], "SEEN, NOT NAMED")

    # ---------------------------------------------------------------------------------- inventory and posture
    def test_14_inventory(self):
        """inventory: 14 AI assets, 6 unsanctioned, 2 Gemini models without Model Armor, one DNS source not
        attributed, an Ollama port open to the internet; Standard hides the 3 Gemini models"""
        inv = inventory.build()
        self.assertEqual((len(inv["rows"]), sum(not r["sanctioned"] for r in inv["rows"])), (14, 6))
        self.assertEqual(sum(bool(r["armor_gap"]) for r in inv["rows"]), 2)
        self.assertEqual([u["domain"] for u in inv["unattributed"]], ["api.anthropic.com"])
        self.assertEqual([(e["server"], e["port"]) for e in inv["exposed"]], [("ollama", "11434")])
        self.assertEqual(inventory.build("standard")["hidden_gemini"], 3)

    def test_15_posture(self):
        """posture: 10 of 12 NON_COMPLIANT on the first draft, 1 hardened (Claude's logging); Enable Model Armor
        passes while Model Armor logs nothing"""
        fd, hd = posture.run("first-draft"), posture.run("hardened")
        self.assertEqual((sum(not r["compliant"] for r in fd), len(fd)), (10, 12))
        self.assertEqual([r["id"] for r in hd if not r["compliant"]], ["C04"])
        ma = [r for r in fd if r["check"] == "Enable Model Armor"][0]
        self.assertTrue(ma["compliant"])
        self.assertFalse([r for r in fd if r["id"] == "C03"][0]["compliant"])

    # ------------------------------------------------------------------------------------------ the report
    def test_16_report_example(self):
        """the worked S3 report passes the check; the empty template does not"""
        ids = report.all_ids(detect.Telemetry.from_build(HARD))
        ex = (report.HERE / "report" / "EXAMPLE-S3-hijacked-agent.md").read_text()
        self.assertEqual(report.check(ex, "S3", ids), [])
        self.assertGreater(len(report.check((report.HERE / "report" / "TEMPLATE.md").read_text(), "S1", ids)), 5)

    def test_17_pivot_and_cost(self):
        """pivot on etl-batch: 281 records hardened, 6 first draft; 120 Gemini calls costed, 30 Claude calls that
        only the audit log shows"""
        h, f = detect.Telemetry.from_build(HARD), detect.Telemetry.from_build(FIRST)
        self.assertEqual((len(report.pivot(h, "etl-batch")), len(report.pivot(f, "etl-batch"))), (281, 6))
        c = report.cost(h, "etl-batch")
        self.assertEqual((c["calls"], c["claude_calls_not_in_request_response_logs"]), (120, 30))

    def test_18_no_truth_in_rules(self):
        """the rules never read the answer key (truth.json)"""
        self.assertNotIn("truth", (report.HERE / "detect.py").read_text().split('"""', 2)[2].replace("truth.json", ""))


if __name__ == "__main__":
    unittest.main()
