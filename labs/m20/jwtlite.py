"""
jwtlite.py: just enough JWT (RS256) for the M20 lab, in pure Python. LAB ONLY.

Why not a library? The lab must run on any laptop with Python 3.11+ and nothing installed. RS256 is plain
RSA with PKCS#1 v1.5 padding over SHA-256 (RFC 7518 section 3.3, RFC 8017 section 8.2), which fits in a page.
The same verify() checks tokens from the lab's own authorization server and from Keycloak (both publish
their public keys as a JWKS).

Do not copy this into production. Use a maintained library (PyJWT, python-jose, authlib, jose4j...) that has
had years of review for timing leaks, key handling and edge cases.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time

# DER prefix of DigestInfo for SHA-256 (RFC 8017 section 9.2, note 1).
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _int_to_b64u(n: int) -> str:
    return b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def _b64u_to_int(text: str) -> int:
    return int.from_bytes(b64u_decode(text), "big")


def _probably_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _probably_prime(candidate):
            return candidate


class RSAKey:
    """An RSA key pair. `kid` names it in the JWKS so verifiers can pick the right key."""

    def __init__(self, bits: int = 2048, kid: str | None = None):
        e = 65537
        while True:
            p, q = _prime(bits // 2), _prime(bits // 2)
            phi = (p - 1) * (q - 1)
            if p != q and phi % e:
                break
        self.n, self.e, self.d = p * q, e, pow(e, -1, phi)
        self.p, self.q = p, q
        self.kid = kid or "lab-" + secrets.token_hex(4)

    def public_jwk(self) -> dict:
        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                "n": _int_to_b64u(self.n), "e": _int_to_b64u(self.e)}

    def sign(self, message: bytes) -> bytes:
        k = (self.n.bit_length() + 7) // 8
        t = _SHA256_PREFIX + hashlib.sha256(message).digest()
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        # CRT for speed: s = m^d mod n.
        m = int.from_bytes(em, "big")
        dp, dq, qinv = self.d % (self.p - 1), self.d % (self.q - 1), pow(self.q, -1, self.p)
        m1, m2 = pow(m, dp, self.p), pow(m, dq, self.q)
        s = m2 + self.q * ((qinv * (m1 - m2)) % self.p)
        return s.to_bytes(k, "big")


def rs256_verify(jwk: dict, message: bytes, signature: bytes) -> bool:
    n, e = _b64u_to_int(jwk["n"]), _b64u_to_int(jwk["e"])
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return secrets.compare_digest(em, expected)


def encode(claims: dict, key: RSAKey, typ: str = "JWT") -> str:
    header = {"alg": "RS256", "typ": typ, "kid": key.kid}
    signing_input = (b64u(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + b64u(json.dumps(claims, separators=(",", ":")).encode()))
    return signing_input + "." + b64u(key.sign(signing_input.encode()))


def peek(token: str) -> dict:
    """Read the claims WITHOUT checking anything. For printing only; never for a decision."""
    try:
        return json.loads(b64u_decode(token.split(".")[1]))
    except Exception:  # noqa: BLE001 - a broken token just prints as {}
        return {}


class InvalidToken(Exception):
    pass


def verify(token: str, jwks: dict, *, issuer: str, now: float | None = None) -> dict:
    """Check the signature, `alg`, `iss` and `exp`. Audience and scope are the CALLER's job (see services.py),
    because that is exactly the check the lab's first draft forgets."""
    try:
        h64, c64, s64 = token.split(".")
        header = json.loads(b64u_decode(h64))
        claims = json.loads(b64u_decode(c64))
        signature = b64u_decode(s64)
    except Exception as exc:  # noqa: BLE001
        raise InvalidToken("malformed token") from exc
    if header.get("alg") != "RS256":
        raise InvalidToken(f"alg {header.get('alg')!r} not allowed")  # no 'none', no HS256 key confusion
    keys = [k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid") and k.get("kty") == "RSA"
            and k.get("use", "sig") == "sig"]
    if not keys or not rs256_verify(keys[0], (h64 + "." + c64).encode(), signature):
        raise InvalidToken("bad signature")
    if claims.get("iss") != issuer:
        raise InvalidToken(f"issuer {claims.get('iss')!r} is not {issuer!r}")
    if (now if now is not None else time.time()) >= claims.get("exp", 0):
        raise InvalidToken("expired")
    return claims
