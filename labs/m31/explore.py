#!/usr/bin/env python3
r"""
explore.py: look at each step of a payment, and of a mandate check, before you run the lab (M31 lab, Step 1b).

What it does, said plainly: it walks through one ordinary online card payment and its token on small stand-ins
written in this file, then uses the lab's own code (mandate.py, guard.py, x402lab.py) to show a signed mandate, a
mandate check and one x402 payment, one step at a time. The lab's code keeps its state in a temporary folder outside
this lab, which is deleted at the end: nothing in labs/m31 changes (no state/, no __pycache__). Standard library
only, no network, fake data, no real money, no real card.

    card        1. an ordinary online card payment: who is involved, authorization, capture, settlement
    token       2. a token instead of the card number: what the shop keeps, and where the token works
    mandate     3. a mandate: what the user agreed to, signed on a trusted surface, and its signature check
    check       4. checking three proposed payments against the mandate, one rule at a time (deterministic code)
    x402        5. one x402 payment: the 402, the headers decoded, verify, settle, the lab ledger

    e.g. python3 explore.py card
Windows: py explore.py ...
"""
from __future__ import annotations

import atexit
import hashlib
import os
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True  # read-only: importing the lab's modules must not write __pycache__/
_STATE = tempfile.mkdtemp(prefix="m31-explore-")
os.environ["M31_STATE"] = _STATE  # the lab's code keeps its state here, not in labs/m31/state
atexit.register(shutil.rmtree, _STATE, True)

import mandate as mandates  # noqa: E402
from guard import SpendGuard  # noqa: E402
from x402lab import (ASSET, NETWORK, X402_VERSION, Clock, Facilitator, Ledger, Merchant, b64,  # noqa: E402
                     check_sig, fmt, load, unb64)

TEST_CARD = "4242424242424242"  # a public test number used in payment docs, not a real card


def money(cents: int) -> str:
    return f"{cents // 100}.{cents % 100:02d}"


def spaced(pan: str) -> str:
    return " ".join(pan[i:i + 4] for i in range(0, len(pan), 4))


# ----------------------------------------------------------------- card stand-ins (only for steps 1 and 2)
class LabIssuer:
    """alice's bank: it issued her card, knows her credit limit, and says yes or no."""

    def __init__(self):
        self.accounts = {TEST_CARD: {"holder": "alice", "limit": 50000, "used": 0, "blocked": False, "exp": "12/30"}}
        self.holds = {}

    def authorize(self, pan, amount, auth_id):
        acct = self.accounts.get(pan)
        if not acct or acct["blocked"]:
            return False, "card not valid"
        available = acct["limit"] - acct["used"]
        if amount > available:
            return False, "not enough available credit"
        acct["used"] += amount
        self.holds[auth_id] = amount
        return True, f"available credit {money(available)} -> {money(acct['limit'] - acct['used'])}"


class LabNetwork:
    """The card network: it routes the request from the shop's processor to the bank that issued the card."""

    def __init__(self, issuer):
        self.issuer = issuer

    def route(self, pan, amount, auth_id):
        return self.issuer.authorize(pan, amount, auth_id)


class LabProcessor:
    """The shop's payment processor: it runs the payment form, keeps the card numbers, and gives shops tokens."""

    def __init__(self, network):
        self.network = network
        self.vault = {}

    def tokenize(self, pan, exp, merchant):
        tok = "tok_lab_" + hashlib.sha256(f"{pan}{merchant}".encode()).hexdigest()[:12]
        self.vault[tok] = {"pan": pan, "exp": exp, "merchant": merchant}
        return tok

    def charge(self, tok, amount, merchant):
        v = self.vault.get(tok)
        if not v:
            return False, "unknown token", None
        if v["merchant"] != merchant:
            return False, f"this token works only for {v['merchant']}", None
        auth_id = "auth_lab_" + hashlib.sha256(f"{tok}{amount}".encode()).hexdigest()[:8]
        ok, why = self.network.route(v["pan"], amount, auth_id)
        return ok, why, auth_id


def cmd_card() -> None:
    issuer = LabIssuer()
    proc = LabProcessor(LabNetwork(issuer))
    shop = "shop.tsg.example"
    print("AN ORDINARY ONLINE CARD PAYMENT  (stand-ins in explore.py: no real card, bank or money)")
    print(f"cardholder  alice, card {spaced(TEST_CARD)} (a public test number), credit limit 500.00")
    print(f"merchant    {shop}, a rain jacket for 59.00")
    print()
    print("1  CHECKOUT      alice types her card number into the payment form")
    print("                 the form is run by the shop's payment processor, so the number goes to the processor")
    tok = proc.tokenize(TEST_CARD, "12/30", shop)
    print(f"                 the processor keeps the number and gives the shop a token: {tok}")
    print()
    print("2  AUTHORIZATION the shop asks: may I charge 59.00 to this card?")
    print("                 shop -> processor -> card network -> issuer (the bank that gave alice her card)")
    ok, why, auth_id = proc.charge(tok, 5900, shop)
    print("                 issuer checks: card valid and not blocked, enough credit left")
    print(f"                 issuer answers {'APPROVED' if ok else 'DECLINED'} ({auth_id}) and HOLDS 59.00: {why}")
    print("                 no money has moved yet; the hold only reserves it")
    print()
    print("3  the shop packs and ships the jacket")
    print()
    print("4  CAPTURE       shop -> processor: take the 59.00 that was approved")
    print("                 the hold becomes a charge on alice's statement")
    print()
    print("5  SETTLEMENT    the money moves: issuer -> network -> processor -> the shop's bank account")
    print("                 (minus the processor's and the network's fees)")
    print()
    print("never captured? the authorization expires (Stripe: usually 7 days for an online card payment)")
    print("and the hold is released. A hotel authorizes at check-in and captures at check-out.")


def cmd_token() -> None:
    issuer = LabIssuer()
    proc = LabProcessor(LabNetwork(issuer))
    shop, other = "shop.tsg.example", "deals.tsg.example"
    tok = proc.tokenize(TEST_CARD, "12/30", shop)
    print("A TOKEN INSTEAD OF THE CARD NUMBER  (stand-ins in explore.py)")
    print()
    print("the processor's vault (only the processor can read it):")
    print(f"  {tok}  ->  {spaced(TEST_CARD)}  exp 12/30  limited to {shop}")
    print()
    print(f"the shop's own database (what {shop} keeps):")
    print(f"  customer alice   payment method {tok}   card ending {TEST_CARD[-4:]}   exp 12/30")
    print("  card type, last 4 digits and expiry are not secret; the full number is never here")
    print()
    print("using the token:")
    ok, why, _ = proc.charge(tok, 1200, shop)
    print(f"  {shop:<19} charges {tok} 12.00   -> {'approved' if ok else 'refused'}")
    ok, why, _ = proc.charge(tok, 1200, other)
    print(f"  {other:<19} presents the same token  -> {'approved' if ok else 'refused: ' + why}")
    print()
    print("a thief who copies the shop's database gets the token and '4242', not the card number,")
    print("and the token only works when this shop asks this processor.")
    print()
    print("real world: Visa says a payment token can be limited to a mobile device, a merchant, or a number of")
    print("purchases. Shops that use a processor's hosted form never handle the number, which also shrinks their")
    print("PCI DSS work (the card industry's security standard).")


# ----------------------------------------------------------------- the lab's own code (steps 3 to 5)
def cmd_mandate() -> None:
    m = mandates.issue()
    print("A MANDATE: what alice agreed to, signed on a trusted surface  (mandate.py, the lab's own code)")
    print()
    print(f"  mandate_id       {m['mandate_id']}")
    print(f"  user             {m['user']}")
    print(f"  agent            {m['agent']}   (the software allowed to use it)")
    print(f"  payees           {', '.join(m['payees'])}")
    print(f"  asset, network   {m['asset']} on {m['network']}   (the lab's pretend money)")
    print(f"  per payment      up to {fmt(m['per_payment_max'])}")
    print(f"  budget           {fmt(m['budget_max'])} in all")
    print(f"  approval over    {fmt(m['approval_over'])}   (above this, alice approves each payment herself)")
    print(f"  expires_at       {m['expires_at']}   (7 days after the lab's pinned clock, in Unix seconds)")
    print(f"  sig              {m['sig'][:24]}...   (HMAC-SHA256 with the trusted surface's lab key)")
    print()
    print("signature check, done by code (no AI):")
    print(f"  the mandate as alice signed it            -> {'valid' if mandates.signature_ok(m) else 'INVALID'}")
    changed = dict(m, budget_max=40_000_000)
    print(f"  the same mandate with budget 40.00        -> {'valid' if mandates.signature_ok(changed) else 'INVALID'}")
    extra = dict(m, payees=m["payees"] + ["acct:deals-unknown"])
    print(f"  the same mandate with one more payee      -> {'valid' if mandates.signature_ok(extra) else 'INVALID'}")
    print()
    print("anyone can read a mandate; only the trusted surface's key can make a valid signature.")
    print("Real AP2 mandates are signed tokens (SD-JWT) with the user's key; the lab uses one HMAC key.")


def yes(b: bool) -> str:
    return "yes" if b else "NO"


def cmd_check() -> None:
    m = mandates.issue()
    clock = Clock()
    hosts = {"acct:weather-co": "weather.tsg.example", "acct:deals-unknown": "deals.tsg.example",
             "acct:market-co": "market.tsg.example"}
    proposals = [("acct:weather-co", 10000, "http://weather.tsg.example/api/today"),
                 ("acct:deals-unknown", 4990000, "http://deals.tsg.example/bundle"),
                 ("acct:market-co", 3000000, "http://market.tsg.example/reports/quarterly")]
    print(f"CHECKING PROPOSED PAYMENTS AGAINST MANDATE {m['mandate_id']}  (deterministic code: same input, same answer)")
    for n, (pay_to, amount, url) in enumerate(proposals, 1):
        print()
        print(f"proposal {n}: {fmt(amount)} {ASSET} to {pay_to} for {url}")
        steps = [("signed by the trusted surface?", mandates.signature_ok(m)),
                 ("not expired?", clock.now < m["expires_at"]),
                 ("asset and network allowed?", (ASSET, NETWORK) == (m["asset"], m["network"])),
                 ("payee in the mandate?", pay_to in m["payees"]),
                 (f"at most {fmt(m['per_payment_max'])} per payment?", amount <= m["per_payment_max"]),
                 (f"within the budget ({fmt(m['budget_max'])} left)?", amount <= m["budget_max"])]
        verdict = "ALLOW"
        for q, ok in steps:
            print(f"   {q:<46} {yes(ok)}")
            if not ok:
                verdict = "DENY"
                break
        if verdict == "ALLOW" and amount > m["approval_over"]:
            print(f"   {'over ' + fmt(m['approval_over']) + ', so alice must approve it?':<46} yes")
            verdict = "DEFER (held until alice approves it on the trusted surface)"
        task = {"task_id": f"T-EXPLORE-{n}", "mandate_id": m["mandate_id"], "merchants": [hosts[pay_to]],
                "max_price": amount, "max_payments": 1}
        req = {"payTo": pay_to, "amount": str(amount), "asset": ASSET, "network": NETWORK, "maxTimeoutSeconds": 60}
        d = SpendGuard("hardened", clock).decide(task, hosts[pay_to], req, url)
        print(f"   decision: {verdict}")
        print(f"   guard.py (hardened) agrees: {d['decision']} [{d['rule']}]")


def cmd_x402() -> None:
    mandates.issue()
    clock = Clock()
    guard = SpendGuard("hardened", clock)
    fac = Facilitator(clock)
    shop = Merchant("weather.tsg.example", fac)
    url = "http://weather.tsg.example/api/today"
    task = {"task_id": "T-WEATHER", "user": "alice", "agent": "agent:research-assistant", "mandate_id": "MND-0001",
            "merchants": ["weather.tsg.example"], "max_price": 50000, "max_payments": 1}
    before = {a: fmt(Ledger().balance(a)) for a in ("acct:buyer-alice", "acct:weather-co")}
    print("ONE x402 PAYMENT, STEP BY STEP  (x402lab.py: no blockchain, no wallet app, no real money)")
    status, headers, _ = shop.handle("GET", "/api/today")
    print(f"1  agent   GET {url}")
    print(f"   server  {status} Payment Required + PAYMENT-REQUIRED header ({len(headers['PAYMENT-REQUIRED'])} characters of base64)")
    body = unb64(headers["PAYMENT-REQUIRED"])
    req = body["accepts"][0]
    print(f"2  decoded x402Version {body['x402Version']} | scheme {req['scheme']} | network {req['network']} | asset {req['asset']}")
    print(f"           amount {req['amount']} (= {fmt(req['amount'])}, 6 decimals) | payTo {req['payTo']} | "
          f"maxTimeoutSeconds {req['maxTimeoutSeconds']}")
    d, payload = guard.pay(task, "weather.tsg.example", req, body["resource"], idem_key="T-WEATHER:1")
    print(f"3  spend guard  {d['decision']} [{d['rule']}]  (the agent asks; only the guard can make the wallet sign)")
    a = payload["payload"]["authorization"]
    print(f"4  wallet signs from {a['from']} to {a['to']} value {a['value']}")
    print(f"           validAfter {a['validAfter']}  validBefore {a['validBefore']}  nonce {a['nonce'][:18]}...")
    hdr = {"PAYMENT-SIGNATURE": b64(payload)}
    print(f"5  agent   GET {url} again, with a PAYMENT-SIGNATURE header ({len(hdr['PAYMENT-SIGNATURE'])} characters)")
    checks = [("version", payload["x402Version"] == X402_VERSION), ("scheme", payload["accepted"]["scheme"] == "exact"),
              ("network", payload["accepted"]["network"] == req["network"]),
              ("signature", check_sig(a["from"], a, payload["payload"]["signature"])),
              ("amount", a["value"] == req["amount"]), ("recipient", a["to"] == req["payTo"]),
              ("time window", int(a["validAfter"]) <= clock.now < int(a["validBefore"])),
              ("nonce unused", a["nonce"] not in load("nonces.json", [])),
              ("funds", Ledger().balance(a["from"]) >= int(a["value"]))]
    v = fac.verify(payload, req)
    marks = [f"{k} {'ok' if ok else 'BAD'}" for k, ok in checks]
    print("6  facilitator /verify (read only): " + ", ".join(marks[:5]))
    print("           " + ", ".join(marks[5:]) + f"  -> isValid {str(v['isValid']).lower()}, nothing moved yet")
    status, headers, content = shop.handle("GET", "/api/today", hdr)
    resp = unb64(headers["PAYMENT-RESPONSE"])
    print(f"7  server  runs the request: {content}")
    print("8  facilitator /settle moves the value on the lab ledger and records the nonce as used:")
    for acct in ("acct:buyer-alice", "acct:weather-co"):
        print(f"           {acct:<18} {before[acct]:>6} -> {fmt(Ledger().balance(acct))} {ASSET}")
    print(f"9  server  {status} OK + PAYMENT-RESPONSE: success {str(resp['success']).lower()}, transaction {resp['transaction']}")
    print()
    print(f"the same header sent again: facilitator says {fac.verify(payload, req).get('invalidReason')}")
    print("real x402: a 32-byte random nonce and a transfer on a blockchain. The lab: a nonce made from a counter,")
    print("and a JSON file as the ledger.")


COMMANDS = {"card": cmd_card, "token": cmd_token, "mandate": cmd_mandate, "check": cmd_check, "x402": cmd_x402}


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in COMMANDS:
        print(__doc__)
        return 0 if not argv else 2
    COMMANDS[argv[0]]()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
