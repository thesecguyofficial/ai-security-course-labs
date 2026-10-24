"""
test_lab.py: `make test`. The simulator plants what the lessons describe, each logging setup collects only what it
should, the rule packs catch (and miss) what the lessons say, and the inventory, posture and report tools agree.
Runs in memory: no out/ folder needed. Your challenge work (D11, D12, your report) is ignored here.
"""

import copy
import unittest

import detect
import evaluate
import inventory
import posture
import report
import simulate

FIRST = simulate.build("first-draft")
HARD = simulate.build("hardened")


def ev(built, pack="m16", challenge=False):
    return evaluate.evaluate(built["setup"]["name"], pack, challenge, built=built)


def status(res):
    return {s: res[s]["status"] for s in simulate.SCENARIOS}


class TC_Lab(unittest.TestCase):
    # ------------------------------------------------------------------------------------------ the simulator
    def test_01_deterministic(self):
        """the simulator is deterministic: the same day on every computer"""
        self.assertEqual(simulate.build("hardened")["out"], HARD["out"])

    def test_02_first_draft_collects_little(self):
        """first draft: management events only, no invocation logs, no AI Protection findings, no spans, no user IDs"""
        o = FIRST["out"]
        self.assertEqual((len(o["invocations"]), len(o["guardduty"]), len(o["spans"])), (0, 0, 0))
        self.assertTrue(all(e["managementEvent"] for e in o["cloudtrail"]))
        self.assertTrue(all("signed_in_user" not in a for a in o["app"]))

    def test_03_hardened_sources(self):
        """hardened: data events for mantle, AgentCore and the KB bucket; invocation logs never hold a mantle call"""
        types = {r["type"] for e in HARD["out"]["cloudtrail"] for r in e.get("resources", [])}
        self.assertTrue({"AWS::BedrockMantle::Project", "AWS::BedrockAgentCore::Runtime", "AWS::S3::Object"} <= types)
        ops = {r["operation"] for r in HARD["out"]["invocations"]}
        self.assertTrue(ops <= {"Converse", "ConverseStream", "InvokeModel", "InvokeModelWithResponseStream"}, ops)

    def test_04_ai_findings_are_low(self):
        """AI Protection findings: the three documented types, all Low (below 4.0); the prompt one has guardrail details"""
        gd = HARD["out"]["guardduty"]
        self.assertEqual({f["type"] for f in gd}, set(detect.AI_FINDINGS))
        self.assertTrue(all(f["severity"] < 4.0 and f["resource"]["resourceType"] == "AccessKey" for f in gd))
        pi = [f for f in gd if f["type"].endswith("PromptInjection.Direct")][0]["resource"]["bedrockGuardrailDetails"]
        self.assertEqual((pi["guardrailAction"], pi["contentPolicyFilters"][0]["type"], pi["contentPolicyFilters"][0]["confidence"]),
                         ("GUARDRAIL_INTERVENED", "PROMPT_ATTACK", "HIGH"))

    def test_05_medium_confidence_no_finding(self):
        """a benign message that trips the guardrail at MEDIUM confidence makes no GuardDuty finding and no alert"""
        benign = [r for r in HARD["out"]["invocations"] if r["output"]["outputBodyJson"]["stopReason"] == "guardrail_intervened"
                  and r.get("requestMetadata", {}).get("end_user") != "cust-8841"]
        self.assertEqual(len(benign), 1)
        users = {a["entity"] for a in detect.run(detect.Telemetry.from_build(HARD), challenge=False)}
        self.assertNotIn(benign[0]["requestMetadata"]["end_user"], users)

    # ------------------------------------------------------------------------------------------ the rule packs
    def test_06_soc_v1_first_draft(self):
        """old rules, old logs: 1 of 5 caught (the logging-delete rule), 1 false alarm (the data science batch)"""
        r = ev(FIRST, "soc-v1")
        self.assertEqual(evaluate.summary(r), "Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 1")
        self.assertEqual(r["false_alarms"][0]["entity"], "DataScienceRole")

    def test_07_soc_v1_drops_low(self):
        """old rules, new logs: the 'Medium and above' GuardDuty rule drops all four AI Protection findings"""
        r = ev(HARD, "soc-v1")
        self.assertEqual(evaluate.summary(r), "Caught 1 of 5 | seen but not named 0 | missed 4 | false alarms 1")
        self.assertFalse([a for a in r["alerts"] if a["rule"] == "N3"])

    def test_08_m16_first_draft(self):
        """new rules, old logs: only S1 is caught (CloudTrail management events); S3 is seen but not named"""
        self.assertEqual(status(ev(FIRST)), {"S1": "CAUGHT", "S2": "MISSED", "S3": "SEEN, NOT NAMED", "S4": "MISSED",
                                              "S5": "MISSED"})

    def test_09_m16_hardened(self):
        """new rules, new logs: S1, S2, S3 caught; S4 and S5 seen but not named (the challenge); 0 false alarms"""
        r = ev(HARD)
        self.assertEqual(status(r), {"S1": "CAUGHT", "S2": "CAUGHT", "S3": "CAUGHT", "S4": "SEEN, NOT NAMED",
                                     "S5": "SEEN, NOT NAMED"})
        self.assertEqual(r["false_alarms"], [])

    def test_10_guardduty_names_the_role(self):
        """GuardDuty names the IAM identity: for the jailbreak that's HelpdeskAppRole, never the customer"""
        a = [x for x in detect.run(detect.Telemetry.from_build(HARD)) if x["rule"] == "D05" and "PromptInjection" in x["title"]]
        self.assertEqual([x["entity"] for x in a], ["HelpdeskAppRole"])

    def test_11_requestmetadata_matters(self):
        """without requestMetadata (end user) in the invocation logs, S2 is seen but nobody is named"""
        b = copy.deepcopy(HARD)
        for r in b["out"]["invocations"]:
            r.pop("requestMetadata", None)
        self.assertEqual(ev(b)["S2"]["status"], "SEEN, NOT NAMED")

    def test_12_mantle_needs_data_events(self):
        """bedrock-mantle inference is visible only with data events on (D04 sources)"""
        d04 = lambda b: [x for x in detect.run(detect.Telemetry.from_build(b)) if x["rule"] == "D04"][0]["detail"]  # noqa: E731
        self.assertIn("bedrock-mantle", d04(HARD))
        self.assertNotIn("bedrock-mantle", d04(FIRST))

    # ---------------------------------------------------------------------------------- inventory and posture
    def test_13_inventory(self):
        """inventory: 16 AI assets, 9 unsanctioned, Lambda DNS not attributed, an Ollama port open to the internet"""
        inv = inventory.build()
        self.assertEqual((len(inv["rows"]), sum(not r["sanctioned"] for r in inv["rows"])), (16, 9))
        self.assertEqual([u["domain"] for u in inv["unattributed"]], ["api.mistral.ai"])
        self.assertEqual([(e["server"], e["port"]) for e in inv["exposed"]], [("ollama", 11434)])

    def test_14_posture(self):
        """posture: 15 of 16 NON_COMPLIANT in the first draft, 0 hardened; LOG_ONLY passes every managed rule"""
        fd, hd = posture.run("first-draft"), posture.run("hardened")
        self.assertEqual((sum(not r["compliant"] for r in fd), len(fd)), (15, 16))
        self.assertEqual(sum(not r["compliant"] for r in hd), 0)
        gw = [r for r in fd if r["kind"] == "managed" and r["resource"] == "tsg-helpdesk-gw-a1b2c3d4e5"
              and r["rule"] == "bedrockagentcore-gateway-authorizer-enabled"]
        self.assertTrue(gw[0]["compliant"])
        self.assertFalse([r for r in fd if r["rule"] == "C05"][0]["compliant"])

    # ------------------------------------------------------------------------------------------ the report
    def test_15_report_example(self):
        """the worked S3 report passes the check; the empty template does not"""
        ids = report.all_ids(detect.Telemetry.from_build(HARD))
        ex = (report.HERE / "report" / "EXAMPLE-S3-hijacked-agent.md").read_text()
        self.assertEqual(report.check(ex, "S3", ids), [])
        self.assertGreater(len(report.check((report.HERE / "report" / "TEMPLATE.md").read_text(), "S1", ids)), 5)

    def test_16_pivot(self):
        """pivot on the leaked key: 277 records with the hardened logs, 125 with the first draft's"""
        k = "BedrockAPIKey-q4m8"
        self.assertEqual((len(report.pivot(detect.Telemetry.from_build(HARD), k)),
                          len(report.pivot(detect.Telemetry.from_build(FIRST), k))), (277, 125))

    def test_17_cost_gap(self):
        """cost: 120 calls in the invocation logs, 30 more on bedrock-mantle that only CloudTrail shows"""
        c = report.cost(detect.Telemetry.from_build(HARD), "BedrockAPIKey-q4m8")
        self.assertEqual((c["calls"], c["mantle_calls_not_in_invocation_logs"]), (120, 30))

    def test_18_no_truth_in_rules(self):
        """the rules never read the answer key (truth.json)"""
        self.assertNotIn("truth", (report.HERE / "detect.py").read_text().split('"""', 2)[2].replace("truth.json", ""))


if __name__ == "__main__":
    unittest.main()
