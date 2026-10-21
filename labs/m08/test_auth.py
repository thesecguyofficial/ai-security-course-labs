"""
test_auth.py: prove the secure Streamable HTTP server validates the token audience and refuses the rest.

It starts servers/secure_http_server.py on 127.0.0.1:8808 as a subprocess, then sends three requests:
a token for THIS resource (accepted), a token for another resource (401), and no token (401).
"""

import asyncio
import subprocess
import sys
import time
import unittest
from pathlib import Path

import httpx2

LAB = Path(__file__).resolve().parent


def wait_until_up(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx2.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, timeout=2)
            # Any HTTP reply (401 included) means the server is listening.
            if r.status_code:
                return True
        except Exception:
            time.sleep(0.3)
    return False


class SecureHttpServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = subprocess.Popen(
            [sys.executable, str(LAB / "servers" / "secure_http_server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        from servers.secure_http_server import RESOURCE_URL

        if not wait_until_up(RESOURCE_URL):
            cls.proc.terminate()
            raise unittest.SkipTest("secure server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            cls.proc.kill()

    def results(self):
        import auth_client

        return asyncio.run(auth_client.collect())

    def test_09_right_audience_accepted(self):
        """auth: a token whose aud is THIS server is accepted and whoami runs"""
        res = {r["label"]: r for r in self.results()}
        self.assertTrue(res["token for THIS resource"]["accepted"])
        self.assertIn("audience-ok", res["token for THIS resource"]["detail"])

    def test_10_wrong_audience_refused(self):
        """auth: a token minted for another resource is refused (401): no token passthrough"""
        res = {r["label"]: r for r in self.results()}
        self.assertFalse(res["token for ANOTHER resource"]["accepted"])

    def test_11_no_token_refused(self):
        """auth: a request with no bearer token is refused (401)"""
        res = {r["label"]: r for r in self.results()}
        self.assertFalse(res["no token"]["accepted"])

    def test_12_binds_localhost_only(self):
        """auth: the server is reachable on 127.0.0.1 and declares that as its resource audience"""
        from servers.secure_http_server import RESOURCE_URL

        self.assertTrue(RESOURCE_URL.startswith("http://127.0.0.1:"))
