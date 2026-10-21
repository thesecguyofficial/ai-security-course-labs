"""
test_lab.py: the proof behind `make test`. Standard library only (unittest).

Two kinds of test, on purpose:
  * "exploit works" tests run against VULNERABLE mode and must find the problem. A check that has never
    failed proves nothing, so we first show each check CAN catch the bug.
  * "fix holds" tests run the SAME attacks against SAFE mode and must find nothing.

All tests use the deterministic stand-in model, so they give the same result on every run.
"""

import logging
import os
import sys
import threading
import unittest
import urllib.parse
import urllib.request

import helpdesk_app as app

logging.disable(logging.CRITICAL)        # keep the test output readable

SEP = "&" if os.name == "nt" else ";"
READ = r"type data\fake_secrets.env" if os.name == "nt" else "cat data/fake_secrets.env"
XSS_Q = "summarise my latest ticket"
SQLI_Q = "search my tickets for: zzz' OR '1'='1' --"
SHELL_Q = f"check the status of vpn{SEP} {READ}"
PAYLOAD = "<img src=x onerror="
SECRET = "lab-only-not-a-real-password"


class T1_ExploitsWorkInVulnerableMode(unittest.TestCase):
    """Negative controls: each attack must succeed against the vulnerable app."""

    def test_01_xss(self):
        """vulnerable: model output lands in the page as live HTML (XSS)"""
        r = app.answer_question(XSS_Q, safe=False)
        self.assertIn(PAYLOAD, r["answer_html"])

    def test_02_sqli(self):
        """vulnerable: model output rewrites the SQL query and leaks bob's tickets"""
        r = app.answer_question(SQLI_Q, safe=False)
        self.assertIn("bob", {row[1] for row in r["rows"]})

    def test_03_command_injection(self):
        """vulnerable: model output runs an extra shell command that reads the secrets file"""
        r = app.answer_question(SHELL_Q, safe=False)
        self.assertIn(SECRET, r["status"])


class T2_FixesHoldInSafeMode(unittest.TestCase):
    """The same attacks against the fixed app."""

    def test_04_xss_encoded(self):
        """safe: the payload is HTML-encoded, so the browser shows it instead of running it"""
        r = app.answer_question(XSS_Q, safe=True)
        self.assertNotIn(PAYLOAD, r["answer_html"])
        self.assertIn("&lt;img src=x onerror=&quot;", r["answer_html"])

    def test_05_sqli_parameterised(self):
        """safe: parameterised query returns only alice's tickets, and nothing for the injection string"""
        r = app.answer_question(SQLI_Q, safe=True)
        self.assertEqual(r["rows"], [])
        normal = app.answer_question("search my tickets for VPN", safe=True)
        self.assertEqual([row[0] for row in normal["rows"]], [1])          # still works for real searches
        self.assertTrue(all(row[1] == "alice" for row in normal["rows"]))

    def test_06_sql_read_only(self):
        """safe: the search runs read-only, and query_only is switched back off afterwards"""
        seen = []                                            # every SQL statement SQLite runs during the search
        app.DB.set_trace_callback(seen.append)
        try:
            app.search_tickets_safe("alice", "VPN")
        finally:
            app.DB.set_trace_callback(None)
        on = [i for i, q in enumerate(seen) if "query_only = ON" in q]
        sel = [i for i, q in enumerate(seen) if q.lstrip().upper().startswith("SELECT")]
        self.assertTrue(on and sel and on[0] < sel[0], f"SELECT did not run under query_only: {seen}")
        self.assertEqual(app.DB.execute("PRAGMA query_only").fetchone()[0], 0)

    def test_07_allow_list(self):
        """safe: the allow-list blocks the injected command, and the secret never appears"""
        r = app.answer_question(SHELL_Q, safe=True)
        self.assertNotIn(SECRET, r["status"])
        self.assertIn("I can only check", r["status"])
        ok = app.answer_question("check the status of VPN", safe=True)
        self.assertIn("VPN gateway: OK", ok["status"])                       # still works for real requests

    def test_08_contained_no_env(self):
        """safe: the helper runs with no inherited environment variables (no tokens or keys to steal)"""
        os.environ["LAB_FAKE_TOKEN"] = "fake-token-123"
        out = app.run_contained([sys.executable, "-I", "-c", "import os; print(sorted(os.environ))"])
        self.assertNotIn("LAB_FAKE_TOKEN", out)

    def test_09_contained_timeout(self):
        """safe: a helper that hangs is stopped by the timeout"""
        out = app.run_contained([sys.executable, "-I", "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertIn("timed out", out)

    def test_10_contained_no_shell(self):
        """safe: with no shell, ';' is just a character inside one argument, not a second command"""
        out = app.run_contained([sys.executable, "-I", app.HELPER, f"vpn{SEP} {READ}"])
        self.assertNotIn(SECRET, out)
        self.assertIn("Unknown service", out)


class T3_EndToEndOverHttp(unittest.TestCase):
    """Start the real web server on 127.0.0.1 (a free port) and attack it over HTTP."""

    @classmethod
    def setUpClass(cls):
        cls.servers = {}
        for safe in (False, True):
            srv = app.make_server(safe, port=0)          # port 0 = let the OS pick a free port
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            cls.servers[safe] = srv

    @classmethod
    def tearDownClass(cls):
        for srv in cls.servers.values():
            srv.shutdown()
            srv.server_close()

    def fetch(self, safe, q):
        port = self.servers[safe].server_address[1]
        url = f"http://127.0.0.1:{port}/ask?" + urllib.parse.urlencode({"q": q})
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.headers, resp.read().decode()

    def test_11_http_vulnerable(self):
        """http: the vulnerable server sends the payload as live HTML, with no CSP"""
        headers, page = self.fetch(False, XSS_Q)
        self.assertIn(PAYLOAD, page)
        self.assertIsNone(headers.get("Content-Security-Policy"))

    def test_12_http_safe(self):
        """http: the safe server encodes the payload AND sends a CSP that blocks scripts"""
        headers, page = self.fetch(True, XSS_Q)
        self.assertNotIn(PAYLOAD, page)
        self.assertIn("default-src 'none'", headers.get("Content-Security-Policy", ""))

    def test_13_loopback_only(self):
        """http: the app refuses to listen on anything but 127.0.0.1"""
        with self.assertRaises(SystemExit):
            app.make_server(True, port=0, host="0.0.0.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
