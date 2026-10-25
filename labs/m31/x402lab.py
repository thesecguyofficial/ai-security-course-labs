"""
x402lab.py: a local, offline mock of the x402 "402 Payment Required" flow.

Everything here is a teaching model. There is no blockchain, no testnet, no wallet software and no real money:
balances live in a JSON file (the "lab ledger") and signatures are HMAC-SHA256 with lab keys written in this file.

What it keeps from the x402 v2 specification (github.com/x402-foundation/x402, specs/x402-specification-v2.md and
specs/transports-v2/http.md):
  - the three parties: a resource server (the merchant), a client (the agent) and a facilitator
  - the HTTP signals: status 402 with a base64 JSON PAYMENT-REQUIRED header, the client's PAYMENT-SIGNATURE header,
    and the server's PAYMENT-RESPONSE header
  - the field names: x402Version, resource, accepts[] with scheme, network, amount (atomic units), asset, payTo,
    maxTimeoutSeconds; an authorization with from, to, value, validAfter, validBefore, nonce
  - the default flow: verify (read only) -> serve the resource -> settle -> respond
What it changes, on purpose:
  - network "lab:local" and asset "LABUSD" (6 decimals) instead of a real chain and token
  - HMAC instead of an EIP-712 signature, and a nonce made from a counter so every run repeats
    (real wallets use a 32-byte random nonce)
  - error codes are spelled like the spec's but with "lab" in them, so nobody mistakes them for real ones
"""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

X402_VERSION = 2
NETWORK = "lab:local"
ASSET = "LABUSD"
DECIMALS = 6
STATE = Path(os.environ.get("M31_STATE", "state"))

# LAB KEYS. Not secrets: they exist so the lab can show what a signature check catches.
KEYS = {
    "acct:buyer-alice": b"lab-key-alice-wallet-not-a-secret",
    "surface": b"lab-key-trusted-surface-not-a-secret",
}


# ---------------------------------------------------------------- small helpers

def to_atomic(text):
    """'0.01' -> 10000 atomic units of LABUSD (6 decimals)."""
    whole, _, frac = str(text).partition(".")
    frac = (frac + "000000")[:DECIMALS]
    return int(whole or "0") * 10**DECIMALS + int(frac)


def fmt(atomic):
    """10000 -> '0.01'"""
    whole, frac = divmod(int(atomic), 10**DECIMALS)
    return f"{whole}.{f'{frac:06d}'.rstrip('0').ljust(2, '0')}"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def b64(obj):
    return base64.b64encode(canonical(obj).encode()).decode()


def unb64(text):
    return json.loads(base64.b64decode(text.encode()).decode())


def sign(key_id, obj):
    return hmac.new(KEYS[key_id], canonical(obj).encode(), hashlib.sha256).hexdigest()


def check_sig(key_id, obj, sig):
    if key_id not in KEYS or not isinstance(sig, str):
        return False
    return hmac.compare_digest(sign(key_id, obj), sig)


def load(name, default):
    path = STATE / name
    return json.loads(path.read_text()) if path.exists() else default


def save(name, obj):
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / name).write_text(json.dumps(obj, indent=1, sort_keys=True))


class Clock:
    """A pinned clock (Unix seconds) so every run gives the same answer."""

    def __init__(self, now=1_800_000_000):
        self.now = now

    def advance(self, seconds):
        self.now += seconds


# ---------------------------------------------------------------- the lab ledger (stands in for the chain)

START_BALANCES = {
    "acct:buyer-alice": {"LABUSD": to_atomic("50.00"), "LABGOLD": 10},
}


class Ledger:
    def __init__(self):
        self.bal = load("ledger.json", json.loads(json.dumps(START_BALANCES)))

    def balance(self, acct, asset=ASSET):
        return self.bal.get(acct, {}).get(asset, 0)

    def transfer(self, src, dst, asset, value):
        if self.balance(src, asset) < value:
            return False
        self.bal.setdefault(src, {})[asset] = self.balance(src, asset) - value
        self.bal.setdefault(dst, {})[asset] = self.balance(dst, asset) + value
        save("ledger.json", self.bal)
        return True


# ---------------------------------------------------------------- the facilitator: /verify and /settle

class Facilitator:
    """
    verify() is read only, like the spec's POST /verify. settle() moves value on the lab ledger, like POST /settle.
    check_nonce and check_time are the two controls the first-draft facilitator leaves out.
    """

    def __init__(self, clock, check_nonce=True, check_time=True):
        self.clock = clock
        self.check_nonce = check_nonce
        self.check_time = check_time

    def verify(self, payload, req):
        auth = payload.get("payload", {}).get("authorization", {})
        payer = auth.get("from")
        reasons = []
        if payload.get("x402Version") != X402_VERSION:
            reasons.append("invalid_x402_version")
        acc = payload.get("accepted", {})
        if acc.get("scheme") != "exact" or req.get("scheme") != "exact":
            reasons.append("unsupported_scheme")
        if acc.get("network") != req.get("network"):
            reasons.append("invalid_network")
        if not check_sig(payer, auth, payload.get("payload", {}).get("signature")):
            reasons.append("invalid_exact_lab_payload_signature")
        if str(auth.get("value")) != str(req.get("amount")):
            reasons.append("invalid_exact_lab_payload_authorization_value_mismatch")
        if auth.get("to") != req.get("payTo"):
            reasons.append("invalid_exact_lab_payload_recipient_mismatch")
        if self.check_time:
            if self.clock.now < int(auth.get("validAfter", 0)):
                reasons.append("invalid_exact_lab_payload_authorization_valid_after")
            if self.clock.now >= int(auth.get("validBefore", 0)):
                reasons.append("invalid_exact_lab_payload_authorization_valid_before")
        if self.check_nonce and auth.get("nonce") in load("nonces.json", []):
            reasons.append("lab_nonce_already_used")
        if Ledger().balance(payer, req.get("asset")) < int(auth.get("value", 0)):
            reasons.append("insufficient_funds")
        out = {"isValid": not reasons, "payer": payer}
        if reasons:
            out["invalidReason"] = reasons[0]
        return out

    def settle(self, payload, req):
        auth = payload["payload"]["authorization"]
        v = self.verify(payload, req)
        tx = "labtx-" + hashlib.sha256((auth["nonce"] + str(len(load("settlements.json", [])))).encode()).hexdigest()[:16]
        if not v["isValid"]:
            return {"success": False, "errorReason": v["invalidReason"], "transaction": "", "network": req["network"], "payer": v["payer"]}
        Ledger().transfer(auth["from"], auth["to"], req["asset"], int(auth["value"]))
        save("nonces.json", load("nonces.json", []) + [auth["nonce"]])
        save("settlements.json", load("settlements.json", []) + [{"tx": tx, "from": auth["from"], "to": auth["to"],
                                                                   "asset": req["asset"], "value": int(auth["value"]),
                                                                   "nonce": auth["nonce"], "at": self.clock.now}])
        return {"success": True, "transaction": tx, "network": req["network"], "payer": auth["from"], "amount": str(auth["value"])}


# ---------------------------------------------------------------- the wallet (only the spend guard may call it)

class Wallet:
    def __init__(self, acct, clock):
        self.acct = acct
        self.clock = clock

    def sign_payment(self, req, resource):
        n = load("nonce-counter.json", 0) + 1
        save("nonce-counter.json", n)
        auth = {
            "from": self.acct,
            "to": req["payTo"],
            "value": str(req["amount"]),
            "validAfter": str(self.clock.now - 5),
            "validBefore": str(self.clock.now + int(req["maxTimeoutSeconds"])),
            "nonce": "0x" + hashlib.sha256(f"lab-nonce-{self.acct}-{n}".encode()).hexdigest(),
        }
        return {"x402Version": X402_VERSION, "resource": resource, "accepted": req,
                "payload": {"signature": sign(self.acct, auth), "authorization": auth}}


# ---------------------------------------------------------------- the merchants (resource servers)

# What each merchant sells. In the lab the same file is also the buyer's merchant registry: the payTo account a
# merchant registered with us, looked up by host. A real registry comes from onboarding, not from a 402 response.
MERCHANTS = {
    "weather.tsg.example": {"pay_to": "acct:weather-co", "items": {"/api/today": ("0.01", "Today's weather data, one call")}},
    "market.tsg.example": {"pay_to": "acct:market-co", "items": {"/reports/daily": ("1.50", "Daily market report"),
                                                                   "/reports/quarterly": ("3.00", "Quarterly market report")}},
    "shop.tsg.example": {"pay_to": "acct:shop-co", "items": {"/api/sample": ("0.45", "Product sample data, one call")}},
    "deals.tsg.example": {"pay_to": "acct:deals-unknown", "items": {"/bundle": ("4.99", "Premium bundle"),
                                                                    "/vip": ("40.00", "VIP membership")}},
}


class Merchant:
    """
    A resource server. handle() returns (status, headers, body) like an HTTP response.
    The variants used by the attacks (each is a property of a misbehaving merchant or proxy, not of the buyer):
      price_override  the 402 asks for more than the listed price
      tamper_pay_to   a proxy in the path rewrites payTo in the 402
      offer           replace accepts[] entirely (another network or asset)
      double_settle   the merchant calls /settle twice with the same payload
    """

    def __init__(self, host, facilitator, price_override=None, tamper_pay_to=None, offer=None, double_settle=False,
                 max_timeout=60):
        self.host = host
        self.f = facilitator
        self.info = MERCHANTS[host]
        self.price_override = price_override
        self.tamper_pay_to = tamper_pay_to
        self.offer = offer
        self.double_settle = double_settle
        self.max_timeout = max_timeout

    def requirements(self, path):
        price, _ = self.info["items"][path]
        if self.offer:
            return dict(self.offer)
        return {"scheme": "exact", "network": NETWORK, "asset": ASSET,
                "amount": str(to_atomic(self.price_override or price)),
                "payTo": self.tamper_pay_to or self.info["pay_to"],
                "maxTimeoutSeconds": self.max_timeout, "extra": {}}

    def handle(self, method, path, headers=None):
        headers = headers or {}
        url = f"http://{self.host}{path}"
        if path not in self.info["items"]:
            return 404, {}, "not found"
        req = self.requirements(path)
        resource = {"url": url, "description": self.info["items"][path][1], "mimeType": "application/json"}
        if "PAYMENT-SIGNATURE" not in headers:
            body = {"x402Version": X402_VERSION, "error": "PAYMENT-SIGNATURE header is required",
                    "resource": resource, "accepts": [req]}
            return 402, {"PAYMENT-REQUIRED": b64(body)}, "{}"
        payload = unb64(headers["PAYMENT-SIGNATURE"])
        # The merchant checks the payload against what IT asked for (the accepted copy is the client's echo).
        v = self.f.verify(payload, req)
        if not v["isValid"]:
            body = {"x402Version": X402_VERSION, "error": v["invalidReason"], "resource": resource, "accepts": [req]}
            return 402, {"PAYMENT-REQUIRED": b64(body)}, "{}"
        content = json.dumps({"item": self.info["items"][path][1], "data": "lab content"})
        settled = self.f.settle(payload, req)
        if self.double_settle:
            self.f.settle(payload, req)   # a dishonest merchant tries to collect twice
        if not settled["success"]:
            return 402, {"PAYMENT-RESPONSE": b64(settled)}, "{}"
        return 200, {"PAYMENT-RESPONSE": b64(settled)}, content


PAGES_DIR = Path(__file__).resolve().parent / "data" / "pages"


def fetch_page(url):
    """Free pages (no payment): product pages the agent reads. Customers and sellers write these, so they are untrusted."""
    name = url.split("://", 1)[-1].replace("/", "_") + ".md"
    path = PAGES_DIR / name
    return (200, {}, path.read_text()) if path.exists() else (404, {}, "not found")
