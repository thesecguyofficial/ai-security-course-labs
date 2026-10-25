"""
cache_engine.py: a toy prefix cache, built the way vLLM describes its own (lesson 26.2).

A prompt is split into blocks of BLOCK_SIZE tokens. Each full block is identified by a hash of the block before it,
its own tokens and "extra keys"; the cache salt is one of those extra keys, and it goes into the FIRST block, so
every later block changes with it (vLLM design doc: "this value is injected into the hash of the first block").

There is no model here. serve() only answers two questions: how many prompt tokens were found in the cache, and
how long the first token would have taken (a made-up but monotonic cost model: cached tokens are free).
Tokens are whitespace-separated words, to keep the lab readable.
"""

import hashlib
import json

BLOCK_SIZE = 4
BASE_MS, PER_TOKEN_MS = 20, 2


def block_hashes(tokens, salt=None):
    """Chained SHA-256 hashes of every FULL block. The salt is mixed into the first block only."""
    hashes, parent = [], b""
    for i in range(0, len(tokens) - len(tokens) % BLOCK_SIZE, BLOCK_SIZE):
        extra = {"cache_salt": salt} if (i == 0 and salt is not None) else {}
        payload = json.dumps({"parent": parent.hex(), "tokens": tokens[i:i + BLOCK_SIZE], "extra": extra},
                             sort_keys=True).encode()
        parent = hashlib.sha256(payload).digest()
        hashes.append(parent)
    return hashes


class PrefixCacheEngine:
    """One engine, one cache. Who can share it is decided by the salt the caller passes, nothing else."""

    def __init__(self):
        self.blocks = {}      # block hash -> the tenant that first wrote it (kept only so the lab can SCORE leaks)

    def serve(self, prompt, salt=None, writer="?"):
        tokens = prompt.split()
        hashes = block_hashes(tokens, salt)
        hit_blocks, owners = 0, set()
        for h in hashes:                      # a prefix cache can only reuse an unbroken run from the start
            if h not in self.blocks:
                break
            hit_blocks += 1
            owners.add(self.blocks[h])
        for h in hashes:
            self.blocks.setdefault(h, writer)
        cached = hit_blocks * BLOCK_SIZE
        return {"prompt_tokens": len(tokens), "cached_tokens": cached,
                "ttft_ms": BASE_MS + PER_TOKEN_MS * (len(tokens) - cached), "block_owners": sorted(owners)}
