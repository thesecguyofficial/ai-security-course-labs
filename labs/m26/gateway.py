"""
gateway.py: the TSG gateway between tenants and the shared engine (lesson 26.2).

It authenticates the caller from its API key, decides the cache salt, calls the engine and shapes the response.
The cache scope comes from the stack's gateway.json:

    "shared"      no salt: every tenant shares one cache (first draft)
    "per_tenant"  the gateway derives a salt from the authenticated tenant with a secret key (hardened)

A tenant may also send "cache_salt" in the request body so that ITS OWN apps share a cache group. Look closely at
how salt_for() handles that: it is challenge 2.
"""

import hashlib
import hmac
import json
import pathlib

from cache_engine import PrefixCacheEngine

HERE = pathlib.Path(__file__).resolve().parent
LAB_GATEWAY_SECRET = b"lab-placeholder-gateway-secret"   # in real life: from your secrets manager, rotated


class Unauthorized(Exception):
    pass


class Gateway:
    def __init__(self, stack, engine=None):
        self.config = json.loads((HERE / "stacks" / stack / "gateway.json").read_text(encoding="utf-8"))
        self.engine = engine or PrefixCacheEngine()
        self.keys = {t["api_key"]: name for name, t in self.config["tenants"].items()}
        self.log = []

    def tenant_for(self, api_key):
        tenant = self.keys.get(api_key)
        if tenant is None and self.config.get("require_auth"):
            raise Unauthorized("unknown key")
        return tenant or "anonymous"

    def tenant_salt(self, tenant, group=""):
        """A salt nobody outside the gateway can compute: keyed hash of the tenant (and an optional group)."""
        return hmac.new(LAB_GATEWAY_SECRET, f"{tenant}/{group}".encode(), hashlib.sha256).hexdigest()

    def salt_for(self, tenant, body):
        if self.config.get("cache_scope") != "per_tenant":
            return None
        # A tenant's apps can ask to share one cache group by sending the same cache_salt.
        if body.get("cache_salt"):
            return body["cache_salt"]
        return self.tenant_salt(tenant)

    def chat(self, api_key, body):
        tenant = self.tenant_for(api_key)
        salt = self.salt_for(tenant, body)
        prompt = " ".join(m["content"] for m in body.get("messages", []))
        result = self.engine.serve(prompt, salt=salt, writer=tenant)
        self.log.append({"tenant": tenant, "salt": (salt or "none")[:12], "cached_tokens": result["cached_tokens"],
                         "block_owners": result["block_owners"]})
        response = {"usage": {"prompt_tokens": result["prompt_tokens"],
                              "prompt_tokens_details": {"cached_tokens": result["cached_tokens"]}}}
        if self.config.get("expose_timing"):
            response["timing"] = {"ttft_ms": result["ttft_ms"]}
        return response, result
