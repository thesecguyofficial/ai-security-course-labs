"""
test_lab.py: `make test`. The proof for lesson 20.6. Runs against the lab's own authorization server.

The first draft passes every normal request and fails all 8 attacks. The hardened setup still passes every
normal request and stops A1 to A7. A8 (a planted recipient) is challenge 1, in test_challenge.py.
"""

import json
import unittest

import evaluate
import hunt
import jwtlite
import oauth
from services import Chain

RESULTS = {}


def results(setup):
    if setup not in RESULTS:
        RESULTS[setup] = {tid: evaluate.run_one(setup, fn) for tid, fn in {**evaluate.ATTACKS, **evaluate.NORMAL}.items()}
    return RESULTS[setup]


class TC_Lab(unittest.TestCase):
    def test_01_first_draft_attacks(self):
        """first draft: all 8 attacks work (A1 to A8)"""
        worked = [t for t, (ok, _, _) in results("first-draft").items() if t.startswith("A") and ok]
        self.assertEqual(worked, [f"A{i}" for i in range(1, 9)])

    def test_02_normal_requests(self):
        """both setups: the 3 normal requests work"""
        for setup in ("first-draft", "hardened"):
            for tid in evaluate.NORMAL:
                self.assertTrue(results(setup)[tid][0], f"{setup} {tid}: {results(setup)[tid][1]}")

    def test_03_hardened_blocks_a1_to_a7(self):
        """hardened: A1 to A7 are blocked (A8 is challenge 1)"""
        worked = [t for t, (ok, _, _) in results("hardened").items() if t.startswith("A") and ok]
        self.assertEqual([t for t in worked if t != "A8"], [])

    def test_04_downscope_message(self):
        """hardened A4: the server refuses a scope the incoming token never had (invalid_scope)"""
        self.assertIn("not present in the initial access token", results("hardened")["A4"][1])

    def test_05_bystander_refused(self):
        """hardened A7: an agent that is not in the token's audience can't exchange it (403 access_denied)"""
        self.assertIn("403 access_denied", results("hardened")["A7"][1])

    def test_06_audience_and_replay(self):
        """hardened: wrong audience 401 (A3), expired after 10 minutes (A5), second use refused (A6)"""
        r = results("hardened")
        self.assertIn("not for tickets-api", r["A3"][1])
        self.assertIn("expired", r["A5"][1])
        self.assertIn("already used", r["A6"][1])

    def test_07_scope_shrinks_and_act_chain(self):
        """hardened: each hop's token has one audience, fewer scopes, lives <= 120 s and names the agents in act"""
        with Chain("hardened") as c:
            c.ask("alice", "Summarise T-4713 and email me the summary")
            mail = jwtlite.peek(c.captured["mail-agent->mail-api"])
            api = jwtlite.peek(c.captured["tickets-agent->tickets-api"])
            sent = [r for r in c.audit if r["api"] == "mail-api" and r["result"] == "ok"][0]
        self.assertEqual(mail["aud"], "mail-api")
        self.assertEqual(api["aud"], "tickets-api")
        self.assertNotIn("tickets:read", mail["scope"].split())
        self.assertNotIn("mail:send", api["scope"].split())
        self.assertLessEqual(mail["exp"] - mail["iat"], 120)
        self.assertEqual(sent["act"]["sub"], "mail-agent")
        self.assertEqual(sent["act"]["act"]["act"]["sub"], "orchestrator-agent")

    def test_08_first_draft_passthrough(self):
        """first draft: the mail API receives the user's own hour-long token, valid for 6 services"""
        with Chain("first-draft") as c:
            c.ask("alice", "Summarise T-4713 and email me the summary")
            stolen = jwtlite.peek(c.debug_log[-1]["authorization"][7:])
        self.assertEqual(stolen["azp"], "helpdesk-app")
        self.assertEqual(len(stolen["aud"]), 6)
        self.assertEqual(stolen["exp"] - stolen["iat"], 3600)

    def test_09_chain_depth_limit(self):
        """hardened: a chain longer than max_actors is refused (set to 2, the mail agent's hop fails)"""
        with Chain("hardened") as c:
            c.authz.policy["max_actors"] = 2
            c.ask("alice", "Summarise T-4713 and email me the summary")
            refused = [e for e in c.authz.events if e.get("result") == "refused"]
            sent = list(c.outbox)
        self.assertEqual(sent, [])
        self.assertEqual(refused[0]["client"], "mail-agent")
        self.assertIn("delegation chain longer than 2", refused[0]["why"])

    def test_10_pkce_and_signature(self):
        """the server refuses a wrong password, a wrong PKCE verifier, a tampered token and alg none"""
        with Chain("hardened") as c:
            self.assertRaises(SystemExit, oauth.sign_in, c.meta, "helpdesk-app", "alice", "wrong", "openid")
            # a real code, redeemed with the wrong PKCE verifier
            b = oauth._Session()
            challenge = oauth.base64.urlsafe_b64encode(oauth.hashlib.sha256(b"right-verifier").digest()).rstrip(b"=").decode()
            form = {"response_type": "code", "client_id": "helpdesk-app", "redirect_uri": oauth.REDIRECT_URI,
                    "scope": "openid", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256",
                    "username": "alice", "password": "alice-lab-pass"}
            status, headers, _ = b.request("POST", c.issuer + "/login", form=form)
            code = oauth.urllib.parse.parse_qs(oauth.urllib.parse.urlsplit(headers["Location"]).query)["code"][0]
            status, out = oauth.call("POST", c.meta["token_endpoint"], form={
                "grant_type": "authorization_code", "code": code, "redirect_uri": oauth.REDIRECT_URI,
                "client_id": "helpdesk-app", "code_verifier": "wrong-verifier"})
            self.assertEqual((status, out["error"]), (400, "invalid_grant"))
            token = c.sign_in("alice")
            h, p, sig = token.split(".")
            claims = json.loads(jwtlite.b64u_decode(p))
            claims["scope"] += " tickets:delete"
            forged = h + "." + jwtlite.b64u(json.dumps(claims).encode()) + "." + sig
            none = jwtlite.b64u(b'{"alg":"none","typ":"JWT"}') + "." + p + "."
            for bad in (forged, none):
                with self.assertRaises(jwtlite.InvalidToken):
                    jwtlite.verify(bad, c.jwks, issuer=c.issuer)

    def test_11_hunt_q1_q2(self):
        """hunt: Q1 finds the one token two APIs accepted; Q2 finds 4 calls with a 6-service audience"""
        rows = hunt.load(hunt.pathlib.Path(__file__).parent / "data" / "incident" / "api-audit.jsonl")
        shared = hunt.find_shared_tokens(rows)
        self.assertEqual(len(shared), 1)
        self.assertEqual(list(shared.values())[0], ["mail-api", "tickets-api"])
        self.assertEqual(len(hunt.find_broad_audience(rows)), 4)

    def test_12_no_network_beyond_localhost(self):
        """every service in the chain listens on 127.0.0.1 only"""
        with Chain("hardened") as c:
            hosts = {s.url.split("/")[2].split(":")[0] for s in c.services.values()} | {c.issuer.split("/")[2].split(":")[0]}
        self.assertEqual(hosts, {"127.0.0.1"})


class TC_AWS(unittest.TestCase):
    def test_13_aws_first_draft_findings(self):
        """AWS (20.5): the first-draft agent identity setup has 6 HIGH findings (R1, R2, R4, R5, R7, R8)"""
        from aws import check
        highs = sorted({rule for sev, rule, _ in check.check(check.load("first-draft")) if sev == "HIGH"})
        self.assertEqual(highs, ["R1", "R2", "R4", "R5", "R7", "R8"])

    def test_14_aws_hardened_clean(self):
        """AWS (20.5): the hardened setup has 0 findings"""
        from aws import check
        self.assertEqual(check.check(check.load("hardened")), [])

    def test_15_aws_attribution(self):
        """AWS (20.5): the hunt names both humans, the unattributed shared role, the forged run and the shared identity"""
        from aws import attribution as a
        records = a.load_cloudtrail(a.HERE / "data" / "cloudtrail.jsonl")
        app = a.load_jsonl(a.HERE / "data" / "app-log.jsonl")
        self.assertEqual(sorted(a.q1_by_human(records)), ["user-u-1001-alice", "user-u-1002-bob"])
        self.assertEqual({c["role"] for c in a.q2_no_human(records)}, {"tsg-agent-helpdesk"})
        self.assertEqual([m["run"] for m in a.q3_mismatch(records, app)], ["tickets-run-0925"])
        self.assertEqual(a.q4_shared_identity(records, app), {"tsg-helpdesk": ["mail", "tickets"]})


if __name__ == "__main__":
    unittest.main()
