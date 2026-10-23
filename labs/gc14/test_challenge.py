"""
test_challenge.py: `make challenge`. Four of these fail until you finish the challenge (README, Step 7).

1. checker.py: write rule GC14-18, "Data Access audit logs (DATA_READ) are off for aiplatform.googleapis.com".
2. twin/hardened/deployment.json: rewrite the allow-ticket-reads rule so it names tools instead of trusting
   readOnlyHint, and the rug pull (make rugpull) stops at the default deny.
No solution is included.
"""

import copy
import unittest

import checker
import decide
from twin import load_deployment


def rules(dep):
    return {f.rule for f in checker.run("hardened", dep=dep)}


class T5_Challenge(unittest.TestCase):
    longMessage = False      # show only our hint when a test fails

    def test_26_gc14_18_today(self):
        """challenge: checker reports GC14-18 on today's deployment (memories.retrieve isn't in any audit log)"""
        self.assertIn("GC14-18", {f.rule for f in checker.run("today")}, "write rule GC14-18 in checker.py")
        f = next(f for f in checker.run("today") if f.rule == "GC14-18")
        self.assertEqual(f.sev, "MEDIUM")

    def test_27_gc14_18_reads_the_setting(self):
        """challenge: GC14-18 is quiet when DATA_READ is on, and fires when only DATA_READ is removed"""
        dep = copy.deepcopy(load_deployment("hardened"))
        self.assertNotIn("GC14-18", rules(dep))
        dep["audit_logs"]["aiplatform.googleapis.com"] = ["ADMIN_READ", "DATA_WRITE"]
        self.assertIn("GC14-18", rules(dep), "GC14-18 must look for DATA_READ itself, not just any audit config")
        del dep["audit_logs"]
        self.assertIn("GC14-18", rules(dep), "no audit_logs section at all means nothing is logged: report it")

    def test_28_rugpull_stopped(self):
        """challenge: make rugpull shows 0 of 6 hijacked calls and 2 of 2 legitimate calls"""
        rs = decide.run("hardened", rugpull=True)
        hij = [r["id"] for r in rs if r["kind"] == "hijack" and r["succeeded"]]
        broken = [r["id"] for r in rs if r["kind"] == "legit" and not r["succeeded"]]
        self.assertEqual((hij, broken), ([], []), f"went through: {hij}, broken: {broken}: name the tools in "
                                                  "allow-ticket-reads instead of trusting readOnlyHint")

    def test_29_checker_clean(self):
        """challenge: checker.py --twin hardened reports nothing"""
        left = sorted(rules(load_deployment("hardened")))
        if left:
            self.fail(f"still reported: {', '.join(left)}")


if __name__ == "__main__":
    unittest.main()
