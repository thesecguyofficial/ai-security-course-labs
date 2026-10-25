"""test_lab.py: the proof for lab M27 (make test).

"first draft:" tests assert the gaps are REAL (a test that can never fail proves nothing). "hardened:" tests assert
each control holds and the normal tool calls still work. "logs:" and "alerts:" tests pin the documented field
names and the thresholds from lesson 27.2. "offline:" tests prove the lab never touches the network.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from unittest import mock

import alerts
import checker
import egress
import lab
import logs


class LabTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["M27_STATE"] = self._tmp.name

    def tearDown(self):
        os.environ.pop("M27_STATE", None)
        self._tmp.cleanup()


def rule_ids(name: str) -> set[str]:
    return {f.rule for f in checker.review(lab.load_config(name))}


class Review(LabTest):
    def test_01_first_draft_fails_sixteen_rules(self):
        """first draft: the checker fails 16 rules, network and boundary alike"""
        self.assertEqual(rule_ids("first-draft"), {"N1", "N2", "N3", "E1", "D1", "D2", "L1", "P1", "P2", "P3",
                                                   "R1", "F1", "F2", "S1", "T1", "T2"})

    def test_02_hardened_passes(self):
        """hardened: 0 findings"""
        self.assertEqual(checker.review(lab.load_config("hardened")), [])

    def test_03_every_rule_teaches(self):
        """review: every rule names its lesson (27.1 or 27.2) and a fix"""
        for r in checker.RULES:
            self.assertIn(r.lesson, ("27.1", "27.2"), r.id)
            self.assertTrue(r.fix and r.title, r.id)

    def test_04_credentials_and_secrets(self):
        """first draft: a mounted ~/.aws and two secrets in the environment are findings"""
        details = [f.detail for f in checker.review(lab.load_config("first-draft")) if f.rule in ("F1", "S1")]
        self.assertIn("/home/agent/.aws is mounted", details)
        self.assertEqual(sum(d.startswith("secret ") for d in details), 2)


class Replay(LabTest):
    def test_05_first_draft_lets_seven_through(self):
        """first draft: 7 of 8 unexpected requests are allowed; only the odd port (U6) is stopped, by the security group"""
        ds = egress.replay("first-draft")
        s = egress.summary(ds)
        self.assertEqual(s["unexpected_allowed"], ["U1", "U2", "U3", "U4", "U5", "U7", "U8"])
        u6 = next(d for d in ds if d.request["id"] == "U6")
        self.assertEqual(u6.denied_by, ["sg"])

    def test_06_hardened_denies_all(self):
        """hardened: 0 of 8 unexpected requests allowed, 6 of 6 normal tool calls still work"""
        s = egress.summary(egress.replay("hardened"))
        self.assertEqual(s["unexpected_allowed"], [])
        self.assertEqual(len(s["normal_working"]), s["normal_total"])

    def test_07_normal_work_in_both(self):
        """both: the 6 normal tool calls work in the first draft too (the fix must not break the job)"""
        s = egress.summary(egress.replay("first-draft"))
        self.assertEqual(s["normal_working"], ["N1", "N2", "N3", "N4", "N5", "N6"])

    def test_08_layers(self):
        """hardened: the expected layers deny (DNS for U2, endpoint policy and role for U3, proxy method for U8)"""
        by = {d.request["id"]: d for d in egress.replay("hardened")}
        self.assertEqual(by["U2"].denied_by, ["dns"])
        self.assertEqual(by["U3"].denied_by, ["endpoint", "role"])
        self.assertIn("POST not allowed", by["U8"].first_denial.reason)
        self.assertEqual(by["U1"].denied_by, ["dns", "route", "sg"])

    def test_09_fail_closed(self):
        """hardened: with the DNS firewall unavailable the lookup fails closed (SERVFAIL); the first draft answers"""
        self.assertIn("SERVFAIL", next(d for d in egress.replay("hardened") if d.request["id"] == "U7").first_denial.reason)
        self.assertTrue(next(d for d in egress.replay("first-draft") if d.request["id"] == "U7").allowed)

    def test_10_proxy_bypass(self):
        """first draft: the direct request that ignores the proxy goes out because nothing in the network forces the proxy"""
        u1 = next(d for d in egress.replay("first-draft") if d.request["id"] == "U1")
        self.assertTrue(u1.allowed)
        self.assertIn("0.0.0.0/0", [v.reason for v in u1.verdicts if v.layer == "sg"][0])


class Logs(LabTest):
    def test_11_resolver_fields(self):
        """logs: a blocked lookup has firewall_rule_action BLOCK and the documented Resolver query log fields"""
        recs = logs.write("hardened")
        blocked = [r for r in recs["resolver-query-log.jsonl"] if r.get("firewall_rule_action") == "BLOCK"]
        self.assertEqual({r["query_name"] for r in blocked}, {"placeholder.example.invalid.", "api.tsg.example."})
        for key in ("query_name", "srcaddr", "rcode", "srcids", "firewall_rule_group_id", "firewall_domain_list_id"):
            self.assertIn(key, blocked[0])
        allowed = [r for r in recs["resolver-query-log.jsonl"] if not r.get("firewall_rule_action")]
        self.assertTrue(allowed and all("firewall_rule_action" not in r for r in allowed))

    def test_12_cloudtrail_fields(self):
        """logs: endpoint policy denials are NetworkActivity events with errorCode VpceAccessDenied and the fixed errorMessage"""
        recs = logs.write("hardened")
        ct = recs["cloudtrail-network.jsonl"]
        self.assertEqual([r["eventName"] for r in ct], ["PutObject", "InvokeModel"])
        for r in ct:
            self.assertEqual(r["eventCategory"], "NetworkActivity")
            self.assertEqual(r["errorMessage"], "The request was denied due to a VPC endpoint policy")
            self.assertTrue(r["vpcEndpointId"].startswith("vpce-"))

    def test_13_first_draft_is_blind(self):
        """first draft: with its logs off, 7 allowed unexpected requests leave no DNS, flow or CloudTrail record"""
        recs = logs.write("first-draft")
        self.assertEqual(len(recs["resolver-query-log.jsonl"]) + len(recs["flow-log.txt"]) + len(recs["cloudtrail-network.jsonl"]), 0)

    def test_14_no_flow_record_for_refused_names(self):
        """logs: a name the resolver refused never becomes a connection, so it has no flow record"""
        recs = logs.write("hardened")
        self.assertFalse(any(" REJECT " in line for line in recs["flow-log.txt"]))
        header = (lab.state_dir() / "hardened" / "flow-log.txt").read_text().splitlines()[0].split()
        self.assertEqual(header[4], "dstaddr")
        self.assertEqual(header[12], "action")


class Alerts(LabTest):
    def test_15_thresholds(self):
        """alerts: hardened replay gives 2 pages (VpceAccessDenied) and 6 tickets; the first draft gives none"""
        found = alerts.alerts_for(logs.write("hardened"))
        self.assertEqual(sum(1 for f in found if f[0] == "PAGE"), 2)
        self.assertEqual(sum(1 for f in found if f[0] == "TICKET"), 6)
        self.assertEqual(alerts.alerts_for(logs.write("first-draft")), [])


class Offline(LabTest):
    def test_16_no_network(self):
        """offline: the checker, the replay, the logs and the alerts run with every socket call blocked"""
        def refuse(*a, **k):
            raise AssertionError("the lab tried to use the network")
        with mock.patch.object(socket.socket, "connect", refuse), \
                mock.patch.object(socket, "create_connection", refuse), \
                mock.patch.object(socket, "getaddrinfo", refuse), \
                mock.patch.object(socket, "gethostbyname", refuse):
            for name in ("first-draft", "hardened"):
                checker.review(lab.load_config(name))
                egress.replay(name)
                alerts.alerts_for(logs.write(name))

    def test_17_placeholder_names_only(self):
        """offline: every recorded destination outside AWS uses a reserved .example or .invalid name"""
        for r in lab.requests():
            name = r["name"]
            self.assertTrue(name.endswith((".amazonaws.com", ".example", ".invalid")), name)
            self.assertNotIn("body", r)
            self.assertNotIn("payload", r)
        for name in ("first-draft", "hardened", "second-draft"):
            json.dumps(lab.load_config(name))  # all three configs load


if __name__ == "__main__":
    unittest.main()
