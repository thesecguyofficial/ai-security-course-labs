"""Normal use must keep working. These pass on the vulnerable Helpdesk and MUST still pass after your fixes.

A control that blocks the attack and also breaks the helpdesk is not a fix. Run: make test
"""
import unittest

from helpdesk import config
from tests.util import fresh, outside_emails


class Functional(unittest.TestCase):
    def test_f01_refund_question(self):
        """F01 a customer gets the refund policy"""
        with fresh() as hd:
            r = hd.handle("alice@acme.example", "How do I get a refund?")
            self.assertIn("30 days", r.reply)

    def test_f02_vpn_question(self):
        """F02 a customer gets the VPN help page"""
        with fresh() as hd:
            self.assertIn("UDP to TCP", hd.handle("bob@globex.example", "My VPN keeps dropping").reply)

    def test_f03_own_order(self):
        """F03 a customer can check their own order"""
        with fresh() as hd:
            r = hd.handle("alice@acme.example", "What is the status of order 5001?")
            self.assertIn("shipped", r.reply)

    def test_f04_email_me_a_copy(self):
        """F04 'email me a copy' still sends one email, to the requester"""
        with fresh() as hd:
            hd.handle("alice@acme.example", "How do I reset my password? Please email me a copy.")
            self.assertTrue(any(m["to"] == "alice@acme.example" for m in hd.outbox()), hd.outbox())
            self.assertEqual(outside_emails(hd, "alice@acme.example"), [])

    def test_f05_own_tenant_doc(self):
        """F05 an Acme customer can read the Acme onboarding page"""
        with fresh() as hd:
            self.assertIn("CANARY-ACME-ONBOARD", hd.handle("alice@acme.example", "Show me the Acme onboarding guide").reply)

    def test_f06_staff_confidential_doc(self):
        """F06 staff can still read the staff-only pricing page"""
        with fresh() as hd:
            self.assertIn("CANARY-PRICING-2027", hd.handle("sam@tsg-helpdesk.example", "What is the 2027 partner pricing?").reply)

    def test_f07_staff_customer_list(self):
        """F07 staff can still list customers"""
        with fresh() as hd:
            self.assertIn("carol@acme.example", hd.handle("sam@tsg-helpdesk.example", "List all customers for the quarterly report").reply)

    def test_f08_own_account(self):
        """F08 a customer can look up their own account"""
        with fresh() as hd:
            self.assertIn("gold", hd.handle("alice@acme.example", "Please look up my account").reply)

    def test_f09_status_text_still_shown(self):
        """F09 the service status text still reaches the page"""
        with fresh() as hd:
            self.assertIn("all systems normal", hd.handle("carol@acme.example", "What is the service status?").reply_html)

    def test_f10_long_but_normal_message(self):
        """F10 a 1,500-character message is accepted"""
        with fresh() as hd:
            msg = "How do I get a refund? " + "My order arrived damaged and I would like my money back. " * 30
            self.assertGreater(len(msg), 1500)
            r = hd.handle("alice@acme.example", msg[:1600])
            self.assertIsNone(r.blocked)

    def test_f11_ten_messages_in_a_minute(self):
        """F11 ten messages in a row from one user are all answered"""
        with fresh() as hd:
            for i in range(10):
                self.assertIsNone(hd.handle("bob@globex.example", f"VPN keeps dropping, try {i}").blocked)

    def test_f12_localhost_only(self):
        """F12 the app listens on 127.0.0.1 only"""
        self.assertIn(config.HOST, ("127.0.0.1", "::1", "localhost"))


if __name__ == "__main__":
    unittest.main()
