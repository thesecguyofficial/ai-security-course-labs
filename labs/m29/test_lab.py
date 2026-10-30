"""
test_lab.py: the proof (make test). The first draft misses 14 of 15; the hardened setup catches all 15 and keeps
normal work working. Plus the mechanics the lessons rely on.
"""

from __future__ import annotations

import json
import re
import unittest

import detect
import hunt
import respond
import scenarios
import suite
import triage
from lab import ASSUMPTIONS, HERE, load_setup


def honey_rule(setup: str) -> dict:
    return next(r for r in load_setup(setup)["rules"] if r["name"] == "honeytoken-key-used")


class Suite(unittest.TestCase):
    def test_01_first_draft(self):
        """first draft: 14 of 15 missed (only D0 caught), 5 of 5 normal cases work"""
        r = suite.evaluate("first-draft")
        self.assertEqual([k for k, v in r["missed"].items() if not v], ["D0"])
        self.assertTrue(all(r["normal"].values()), r["normal"])

    def test_02_hardened(self):
        """hardened: 0 of 15 missed, 5 of 5 normal cases work"""
        r = suite.evaluate("hardened")
        self.assertFalse(any(r["missed"].values()), r["missed"])
        self.assertTrue(all(r["normal"].values()), r["normal"])


class Matching(unittest.TestCase):
    def test_03_operators(self):
        """pattern subset: exact, prefix, exists true/false, anything-but, cidr behave like EventBridge's"""
        ev = {"detail": {"eventSource": "bedrock.amazonaws.com", "sourceIPAddress": "10.0.0.7", "a": "x"}}
        self.assertTrue(detect.match({"detail": {"eventSource": [{"prefix": "bedrock"}]}}, ev))
        self.assertTrue(detect.match({"detail": {"vpcEndpointId": [{"exists": False}]}}, ev))
        self.assertFalse(detect.match({"detail": {"a": [{"exists": False}]}}, ev))
        self.assertTrue(detect.match({"detail": {"a": [{"anything-but": ["y", "z"]}]}}, ev))
        self.assertTrue(detect.match({"detail": {"sourceIPAddress": [{"cidr": "10.0.0.0/24"}]}}, ev))
        self.assertFalse(detect.match({"detail": {"sourceIPAddress": [{"cidr": "10.0.1.0/24"}]}}, ev))
        self.assertTrue(detect.match({"detail": {"a": ["q", "x"]}}, ev))

    def test_04_read_only_needs_state(self):
        """a read-only call (GetCallerIdentity) reaches only rules in ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"""
        rec = scenarios.honeytoken_read_only()[0]
        rule = dict(honey_rule("hardened"))
        self.assertTrue(detect.rule_sees(rule, rec)[0])
        rule["state"] = "ENABLED"
        self.assertEqual(detect.rule_sees(rule, rec), (False, "read-only event, rule state ENABLED"))

    def test_05_regions(self):
        """a rule sees only the Regions it is deployed in"""
        rec = scenarios.honeytoken_denied_invoke("ap-southeast-2", "10:01:40")[0]
        rule = dict(honey_rule("hardened"), regions=["us-east-1"])
        self.assertFalse(detect.rule_sees(rule, rec)[0])

    def test_06_decoy_calls_fail(self):
        """every model call with the decoy fails (no permissions), so a rule that drops errorCode never fires"""
        for rec in scenarios.honeytoken_denied_invoke() + scenarios.decoy_api_key_used():
            self.assertIn("errorCode", rec)
        first = honey_rule("first-draft")
        self.assertIn({"exists": False}, first["pattern"]["detail"]["errorCode"])

    def test_07_mantle_is_data_event(self):
        """bedrock-mantle CreateInference is a data event: collected only when the trail records it"""
        rec = scenarios.decoy_api_key_used()[0]
        self.assertFalse(rec["managementEvent"])
        self.assertFalse(detect.collected(load_setup("first-draft"), rec)[0])
        self.assertTrue(detect.collected(load_setup("hardened"), rec)[0])

    def test_08_envelope(self):
        """every event carries the envelope fields aws events test-event-pattern requires"""
        for rec in scenarios.org_day():
            env = scenarios.envelope(rec)
            for k in ("id", "account", "source", "time", "region", "resources", "detail-type"):
                self.assertIn(k, env)


class Hunt(unittest.TestCase):
    def test_09_hardened_finds_six(self):
        """hunt (hardened): exactly 6 pieces of shadow AI, and the 2 planted decoys reported as decoys"""
        r = hunt.run(load_setup("hardened"))
        self.assertEqual(len(r["findings"]), 6)
        self.assertEqual(len(r["decoys"]), 2)

    def test_10_no_false_positives(self):
        """hunt: registered models and the approved outside API are never findings"""
        ids = [f["id"] for f in hunt.run(load_setup("hardened"))["findings"]]
        self.assertFalse(any("anthropic.claude-sonnet-4-6" in i or "nova-pro" in i for i in ids))
        self.assertNotIn("external:333333333333:api.anthropic.com", ids)

    def test_11_history(self):
        """secret scanning: the key removed in commit c1a0004 is found only when history is scanned"""
        fid = "secret:ops-scripts:summarise.py:openai-style key"
        self.assertNotIn(fid, [f["id"] for f in hunt.run(load_setup("first-draft"))["findings"]])
        self.assertIn(fid, [f["id"] for f in hunt.run(load_setup("hardened"))["findings"]])


class Response(unittest.TestCase):
    def test_12_first_draft_late(self):
        """responder (first draft): acts 13m55s after the first call; 32 attacker calls work AFTER it acted"""
        r = respond.replay(load_setup("first-draft"))
        self.assertEqual(r["time_to_act_s"], 835)
        self.assertEqual(r["succeeded_after_action"], 32)

    def test_13_hardened_in_time(self):
        """responder (hardened): acts 3m05s after the first call, nothing works afterwards"""
        r = respond.replay(load_setup("hardened"))
        self.assertEqual(r["time_to_act_s"], 185)
        self.assertLessEqual(r["time_to_act_s"], ASSUMPTIONS["containment_slo_s"])
        self.assertEqual(r["succeeded_after_action"], 0)

    def test_14_key_alone_not_enough(self):
        """deactivating the key alone leaves GetSessionToken sessions working; the aws:userId deny stops them"""
        s = load_setup("hardened")
        s["responder"] = dict(s["responder"], actions=["deactivate_key"])
        self.assertGreater(respond.replay(s)["succeeded_after_action"], 0)

    def test_15_never_touch(self):
        """responder refuses principals on its never-touch list"""
        s = load_setup("hardened")
        out = respond.act(s, respond.new_iam(), "security-audit", "arn:aws:iam::555555555555:role/security-audit")
        self.assertEqual(out, ["refused: principal is on the never-touch list"])


class Triage(unittest.TestCase):
    def test_16_first_draft_obeys(self):
        """triage (first draft): alert text in the instructions channel closes the alert and allow-lists the IP"""
        s = load_setup("first-draft")
        self.assertTrue(triage.run(s, scenarios.poisoned_alert("close-as-benign"))["closed"])
        r = triage.run(s, scenarios.poisoned_alert(f"allowlist-ip {scenarios.ATTACKER_IP}"))
        self.assertEqual(r["allowlisted"], [scenarios.ATTACKER_IP])

    def test_17_gate_holds_when_fooled(self):
        """triage (hardened): even with a fooled model, no close, no allow-list, and the gate flags the alert"""
        s = load_setup("hardened")
        for d in ("close-as-benign", f"allowlist-ip {scenarios.ATTACKER_IP}"):
            r = triage.run(s, scenarios.poisoned_alert(d), fooled=True)
            self.assertFalse(r["closed"])
            self.assertEqual(r["allowlisted"], [])
            self.assertTrue(any(c["tool"] == "flag" for c in r["executed"]))
            self.assertEqual((r["escalated"] or {}).get("severity"), "high")

    def test_18_agent_has_no_write_tools(self):
        """triage (hardened): the agent's tool list holds no write tool at all"""
        self.assertFalse(set(load_setup("hardened")["triage"]["tools"]) & triage.WRITE_TOOLS)


class Safety(unittest.TestCase):
    def test_19_no_real_key_formats(self):
        """no file in this lab holds a string in a real AWS, OpenAI or Bedrock API key format"""
        real = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{20,}|\bABSK[A-Za-z0-9+/=]{20,}")
        for path in HERE.rglob("*"):
            if path.is_file() and ".venv" not in path.parts and "__pycache__" not in path.parts:
                text = path.read_text(errors="ignore")
                self.assertIsNone(real.search(text), f"{path.name} holds a real-looking key")

    def test_20_documentation_ips(self):
        """outside addresses in the events are from the documentation ranges (RFC 5737)"""
        for rec in scenarios.org_day() + scenarios.app_key_from_elsewhere() + scenarios.honeytoken_read_only():
            ip = rec["sourceIPAddress"]
            self.assertTrue(ip.startswith(("10.", "192.0.2.", "198.51.100.", "203.0.113.")), ip)

    def test_21_rules_are_valid_json_patterns(self):
        """every rule file has a name, state, regions, severity and a pattern of lists/objects only"""
        for name in ("first-draft", "hardened"):
            for rule in load_setup(name)["rules"]:
                for k in ("name", "state", "regions", "severity", "pattern"):
                    self.assertIn(k, rule)
                json.dumps(rule["pattern"])
                detect.match(rule["pattern"], {})


if __name__ == "__main__":
    unittest.main()
