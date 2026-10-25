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


def ev(built, pack="az16", challenge=False):
    return evaluate.evaluate(built["setup"]["name"], pack, challenge, built=built)


def status(res):
    return {s: res[s]["status"] for s in simulate.SCENARIOS}


class TC_Lab(unittest.TestCase):
    # ------------------------------------------------------------------------------------------ the simulator
    def test_01_deterministic(self):
        """the simulator is deterministic: the same day on every computer"""
        self.assertEqual(simulate.build("hardened")["out"], HARD["out"])

    def test_02_first_draft_collects_little(self):
        """first draft: Activity log and gateway log only; no prompts, no Defender alerts, no traces, no user IDs"""
        o = FIRST["out"]
        self.assertEqual([len(o[k]) for k in ("foundry", "llm", "alerts", "traces", "blob", "deploy")], [0] * 6)
        self.assertTrue(o["activity"] and o["gateway"])
        self.assertTrue(all("signed_in_user" not in a for a in o["app"]))

    def test_03_direct_calls_skip_the_gateway(self):
        """hardened: 150 Foundry calls come from outside addresses and have no gateway or LLM log row"""
        gw = {r["CorrelationId"] for r in HARD["out"]["gateway"]}
        direct = [r for r in HARD["out"]["foundry"] if r["CallerIPAddress"] != detect.COMPANY["apim_gateway_ip"]]
        self.assertEqual(len(direct), 150)
        self.assertFalse(gw & {r["CorrelationId"] for r in direct})

    def test_04_alerts_from_the_catalogue(self):
        """Defender alerts: types and severities as Microsoft lists them; only two of eight are High"""
        al = HARD["out"]["alerts"]
        for a in al:
            self.assertEqual((a["AlertName"], a["AlertSeverity"]),
                             (simulate.ALERTS[a["AlertType"]]["name"], simulate.ALERTS[a["AlertType"]]["severity"]))
        self.assertEqual((len(al), sum(a["AlertSeverity"] == "High" for a in al)), (8, 2))

    def test_05_llm_log_shape(self):
        """LLM log: one request row per call, a response row only when the call wasn't blocked; joins on CorrelationId"""
        llm = HARD["out"]["llm"]
        req = [r for r in llm if r["RequestMessages"]]
        res = [r for r in llm if r["ResponseMessages"]]
        blocked = [r for r in HARD["out"]["gateway"] if r["LastErrorReason"] == "content_filter"]
        self.assertEqual(len(req) - len(res), len(blocked))
        self.assertEqual({r["CorrelationId"] for r in req}, {r["CorrelationId"] for r in HARD["out"]["gateway"]})

    # ------------------------------------------------------------------------------------------ the rule packs
    def test_06_soc_v1_first_draft(self):
        """old rules, old logs: 1 of 5 caught (the diagnostic-delete rule), 1 false alarm (the data science batch)"""
        r = ev(FIRST, "soc-v1")
        self.assertEqual(evaluate.summary(r), "Caught 1 of 5 | seen but not named 1 | missed 3 | false alarms 1")
        self.assertEqual(r["false_alarms"][0]["entity"], detect.COMPANY["callers"]["data_science_batch"])

    def test_07_soc_v1_high_only(self):
        """old rules, new logs: the High-only Defender rule passes 2 of 8 AI alerts and catches nothing new"""
        r = ev(HARD, "soc-v1")
        self.assertEqual(evaluate.summary(r), "Caught 1 of 5 | seen but not named 2 | missed 2 | false alarms 1")
        self.assertEqual(len([a for a in r["alerts"] if a["rule"] == "N3"]), 2)

    def test_08_az16_first_draft(self):
        """new rules, old logs: only S1 is caught (Activity log); everything else is missed"""
        self.assertEqual(status(ev(FIRST)), {"S1": "CAUGHT", "S2": "MISSED", "S3": "MISSED", "S4": "MISSED",
                                              "S5": "MISSED"})

    def test_09_az16_hardened(self):
        """new rules, new logs: S1, S2, S3 caught; S4 and S5 seen but not named (the challenge); 0 false alarms"""
        r = ev(HARD)
        self.assertEqual(status(r), {"S1": "CAUGHT", "S2": "CAUGHT", "S3": "CAUGHT", "S4": "SEEN, NOT NAMED",
                                     "S5": "SEEN, NOT NAMED"})
        self.assertEqual(r["false_alarms"], [])

    def test_10_user_context_names_the_customer(self):
        """with user security context, the Defender jailbreak alert names cust-8841; without it, only the resource"""
        def jb(b):
            return [a["entity"] for a in detect.run(detect.Telemetry.from_build(b), challenge=False)
                    if a["rule"] == "D04" and "Jailbreak" in a["title"]]
        self.assertEqual(jb(HARD), ["cust-8841"])
        b = copy.deepcopy(HARD)
        for a in b["out"]["alerts"]:
            ext = json.loads(a["ExtendedProperties"])
            a["ExtendedProperties"] = json.dumps({k: v for k, v in ext.items() if not k.startswith("End user")})
        self.assertEqual(jb(b), [detect.COMPANY["foundry"]])

    def test_11_app_log_matters(self):
        """without the app log's user ID, D06 and D07 name nobody: S2 drops to seen, not named (no user context either)"""
        b = copy.deepcopy(HARD)
        for a in b["out"]["app"]:
            a.pop("signed_in_user", None)
        for a in b["out"]["alerts"]:
            a["ExtendedProperties"] = json.dumps({"Alert count": 1})
        self.assertEqual(ev(b)["S2"]["status"], "SEEN, NOT NAMED")

    def test_12_skip_gateway_needs_resource_logs(self):
        """D02 (calls that skip the gateway) fires only with the Foundry RequestResponse logs on"""
        rules = lambda b: {a["rule"] for a in detect.run(detect.Telemetry.from_build(b), challenge=False)}  # noqa: E731
        self.assertIn("D02", rules(HARD))
        self.assertNotIn("D02", rules(FIRST))

    # ---------------------------------------------------------------------------------- inventory and posture
    def test_13_inventory(self):
        """inventory: 10 AI assets, 4 not on the register, 2 agents hidden without Agent 365, Ollama open on a VM"""
        inv = inventory.build()
        self.assertEqual((len(inv["rows"]), sum(not r["sanctioned"] for r in inv["rows"])), (10, 4))
        self.assertEqual(inv["agents_hidden"], 2)
        self.assertEqual([(e["vm"], e["port"]) for e in inv["exposed_vms"]], [("vm-gpu-lab01", 11434)])

    def test_14_posture(self):
        """posture: 18 of 19 NON_COMPLIANT in the first draft, 0 hardened; the diagnostic built-in is green while broken"""
        fd, hd = posture.run("first-draft"), posture.run("hardened")
        self.assertEqual((sum(not r["compliant"] for r in fd), len(fd)), (18, 19))
        self.assertEqual(sum(not r["compliant"] for r in hd), 0)
        diag = [r for r in fd if r["kind"] == "builtin" and r["resource"] == "contoso-foundry"
                and r["rule"].startswith("Diagnostic logs")]
        self.assertTrue(diag[0]["compliant"])
        self.assertFalse([r for r in fd if r["rule"] == "C01"][0]["compliant"])

    # ------------------------------------------------------------------------------------------ the report
    def test_15_report_example(self):
        """the worked S3 report passes the check; the empty template does not"""
        ids = report.all_ids(detect.Telemetry.from_build(HARD))
        ex = (report.HERE / "report" / "EXAMPLE-S3-hijacked-agent.md").read_text()
        self.assertEqual(report.check(ex, "S3", ids), [])
        self.assertGreater(len(report.check((report.HERE / "report" / "TEMPLATE.md").read_text(), "S1", ids)), 5)

    def test_16_pivot(self):
        """pivot: 5 records name sp-contoso-ci; the attacker address is in 79 records hardened, 3 in the first draft"""
        h, f = detect.Telemetry.from_build(HARD), detect.Telemetry.from_build(FIRST)
        self.assertEqual(len(report.pivot(h, "sp-contoso-ci")), 5)
        self.assertEqual((len(report.pivot(h, "203.0.113.50")), len(report.pivot(f, "203.0.113.50"))), (79, 3))

    def test_17_cost_gap(self):
        """cost: the Foundry metric counts 1,656,346 tokens the gateway's LLM log never saw (the direct key calls)"""
        c = report.cost(detect.Telemetry.from_build(HARD))
        self.assertEqual((c["tokens_not_in_llm_log"], [h["hour"] for h in c["hours"]]), (1656346, ["14:00", "15:00"]))

    def test_18_no_truth_in_rules(self):
        """the rules never read the answer key (truth.json)"""
        self.assertNotIn("truth", (report.HERE / "detect.py").read_text().split('"""', 2)[2].replace("truth.json", ""))


if __name__ == "__main__":
    unittest.main()
