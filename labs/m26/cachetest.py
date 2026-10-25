"""
cachetest.py: the prefix-cache isolation test (lesson 26.2). It answers one question for a stack:
"can one tenant ever get a cache hit on blocks another tenant wrote?"

    python3 cachetest.py first-draft      # shared cache: yes
    python3 cachetest.py hardened         # per-tenant salt: no, and each tenant still reuses its own cache
    python3 cachetest.py hardened --challenge   # plus a client that sends another tenant's cache group name

This is an isolation test, not an attack: both tenants are lab tenants on a toy engine in this process, and the
"secret" in the system prompt is a lab placeholder. The test only counts hits; it never reconstructs a prompt.
"""

import sys

from gateway import Gateway

KEYS = {"acme": "lab-key-acme", "globex": "lab-key-globex"}
# 16 tokens = 4 full blocks. The secret is a lab placeholder.
ACME_SYSTEM = "You are the ACME helpdesk bot . Internal code ACME-LAB-0042 is secret . Answer in English ."


def msg(system, question, **extra):
    body = {"messages": [{"role": "system", "content": system}, {"role": "user", "content": question}]}
    body.update(extra)
    return body


def run(stack, challenge=False):
    gw = Gateway(stack)
    results = {}
    gw.chat(KEYS["acme"], msg(ACME_SYSTEM, "where is my order"))                         # acme warms its cache
    _, r = gw.chat(KEYS["globex"], msg(ACME_SYSTEM, "what is the weather"))             # same opening, other tenant
    results["cross_tenant"] = {"cached_tokens": r["cached_tokens"], "owners": r["block_owners"]}
    resp, r = gw.chat(KEYS["acme"], msg(ACME_SYSTEM, "reset my password"))              # acme again
    results["same_tenant"] = {"cached_tokens": r["cached_tokens"], "owners": r["block_owners"],
                              "timing_shown": "timing" in resp}
    _, r = gw.chat(KEYS["globex"], msg("You are the Globex bot . Be kind .", "hello there"))
    results["unrelated"] = {"cached_tokens": r["cached_tokens"]}
    if challenge:
        gw.chat(KEYS["acme"], msg(ACME_SYSTEM, "app one asks", cache_salt="acme-shared"))
        _, r = gw.chat(KEYS["acme"], msg(ACME_SYSTEM, "app two asks", cache_salt="acme-shared"))
        results["group_same_tenant"] = {"cached_tokens": r["cached_tokens"], "owners": r["block_owners"]}
        _, r = gw.chat(KEYS["globex"], msg(ACME_SYSTEM, "globex guesses", cache_salt="acme-shared"))
        results["group_guessed"] = {"cached_tokens": r["cached_tokens"], "owners": r["block_owners"]}
    return results, gw


def leaked(entry, tenant):
    """Cached tokens this tenant got from blocks another tenant wrote."""
    return entry["cached_tokens"] if any(o != tenant for o in entry.get("owners", [])) else 0


def report(stack, results):
    cross = leaked(results["cross_tenant"], "globex")
    print(f"Prefix-cache isolation test, stack {stack}")
    print(f"  globex sends acme's system prompt:  {results['cross_tenant']['cached_tokens']:>2} cached tokens"
          f"  (from acme's blocks: {cross})")
    print(f"  acme sends it again:                {results['same_tenant']['cached_tokens']:>2} cached tokens"
          f"  (its own cache still works)")
    print(f"  globex, unrelated prompt:           {results['unrelated']['cached_tokens']:>2} cached tokens")
    print(f"  per-request timing shown to tenants: {'yes' if results['same_tenant']['timing_shown'] else 'no'}")
    extra = ""
    if "group_guessed" in results:
        g = leaked(results["group_guessed"], "globex")
        print(f"  acme app two, group 'acme-shared':  {results['group_same_tenant']['cached_tokens']:>2} cached tokens")
        print(f"  globex sends cache_salt 'acme-shared': {results['group_guessed']['cached_tokens']:>2} cached tokens"
              f"  (from acme's blocks: {g})")
        cross += g
        extra = " (challenge scenario included)"
    verdict = "ISOLATED" if cross == 0 else "NOT ISOLATED"
    print(f"Cross-tenant cache hits: {cross} tokens -> {verdict}{extra}")
    return cross


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    st = args[0] if args else "first-draft"
    res, _ = run(st, challenge="--challenge" in sys.argv)
    sys.exit(0 if report(st, res) == 0 else 1)
