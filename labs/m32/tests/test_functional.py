"""Normal use of the Ops Crew. These pass today and must still pass after your fixes (F01 to F10).

Run: make test. If a fix breaks one of these, you have blocked something the crew is supposed to do.
"""
import unittest

from tests.util import allowed_calls, allowed_handoffs, fresh


class Functional(unittest.TestCase):
    def test_f01_triage_routes_refund_to_billing(self):
        """F01 a refund request is routed from triage to billing"""
        with fresh() as c:
            r = c.handle("alice@acme.example", "How do I get a refund on order 5001?")
            self.assertTrue(any(h["to"] == "billing" for h in allowed_handoffs(r)))

    def test_f02_refund_on_own_order_works(self):
        """F02 the billing agent refunds the requester's own order"""
        with fresh() as c:
            c.handle("alice@acme.example", "Please refund my order 5001")
            self.assertEqual([x["order_id"] for x in c.refunds()], ["5001"])

    def test_f03_receipt_email_to_self_works(self):
        """F03 a receipt is emailed to the requester"""
        with fresh() as c:
            c.handle("alice@acme.example", "email me a receipt please")
            self.assertEqual([m["to"] for m in c.outbox()], ["alice@acme.example"])

    def test_f04_account_lookup_routes_to_analyst(self):
        """F04 an account question is routed from triage to analyst"""
        with fresh() as c:
            r = c.handle("carol@acme.example", "What tier is my account?")
            self.assertTrue(any(h["to"] == "analyst" for h in allowed_handoffs(r)))

    def test_f05_own_account_lookup_works(self):
        """F05 the analyst can look up the requester's own account"""
        with fresh() as c:
            r = c.handle("carol@acme.example", "What tier is my account?")
            self.assertTrue(allowed_calls(r, "crm_lookup"))

    def test_f06_own_tenant_query_works(self):
        """F06 the analyst can run a usage query for the requester's own tenant"""
        with fresh() as c:
            r = c.handle("bob@globex.example", "Show me usage for globex")
            calls = allowed_calls(r, "run_query")
            self.assertTrue(calls and calls[0]["args"]["tenant"] == "globex")

    def test_f07_staff_can_list_customers(self):
        """F07 a staff user can list all customers"""
        with fresh() as c:
            r = c.handle("sam@tsg-ops.example", "list all customers")
            self.assertTrue(allowed_calls(r, "crm_list_customers"))

    def test_f08_reply_is_returned(self):
        """F08 every turn returns a non-empty reply and a request id"""
        with fresh() as c:
            r = c.handle("alice@acme.example", "How do refunds work?")
            self.assertTrue(r.reply and r.request_id)

    def test_f09_unknown_user_is_rejected(self):
        """F09 an unknown user raises (sign-in is simulated, out of scope)"""
        with fresh() as c:
            with self.assertRaises(KeyError):
                c.handle("mallory@nowhere.example", "hello")

    def test_f10_reply_html_is_a_string(self):
        """F10 the reply always has an HTML form for the page"""
        with fresh() as c:
            r = c.handle("alice@acme.example", "How do refunds work?")
            self.assertIsInstance(r.reply_html, str)


if __name__ == "__main__":
    unittest.main()
