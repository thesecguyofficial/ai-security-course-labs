#!/usr/bin/env python3
"""Lesson 9.1 demo: read a model's facts from the Hugging Face Hub before you download it.

    python3 demos/m09/model_facts.py google-bert/bert-base-uncased meta-llama/Llama-3.2-1B

It asks the Hub's public API (https://huggingface.co/api/models/<repo>) for each model's metadata and prints
what lesson 9.1 tells you to check: who publishes it, when it last changed, the licence, whether it is gated,
the exact commit to pin (lesson 9.3) and which weight files can run code when loaded (lesson 9.2).

Standard library only. It downloads metadata, never a model file, and needs no account or token.
"""
import json
import sys
import urllib.request

API = "https://huggingface.co/api/models/"
PICKLE_SUFFIXES = (".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle")


def fetch(repo: str) -> dict:
    req = urllib.request.Request(API + repo, headers={"User-Agent": "tsg-course-lab/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def can_run_code(name: str) -> bool:
    # PyTorch weights (.bin/.pt/.pth/.ckpt) are pickle underneath. Core ML's weights/weight.bin is not.
    base = name.rsplit("/", 1)[-1]
    if "coreml/" in name:
        return False
    return base.endswith(PICKLE_SUFFIXES)


def show(repo: str) -> None:
    m = fetch(repo)
    files = [s["rfilename"] for s in m.get("siblings", [])]
    safe = [f for f in files if f.endswith(".safetensors")]
    risky = [f for f in files if can_run_code(f)]
    gated = m.get("gated") or False
    licence = (m.get("cardData") or {}).get("license", "not stated")
    print(repo)
    print(f"  publisher    {m.get('author', '?'):<20} created {m.get('createdAt', '?')[:10]}")
    print(f"  last change  {m.get('lastModified', '?')[:10]:<20} downloads (30 days) {m.get('downloads', 0):,}")
    print(f"  licence      {licence:<20} gated: {'no' if not gated else gated + ' (access control, not a safety check)'}")
    print(f"  pin this     revision={m.get('sha', '?')}")
    print(f"  weights      safetensors: {', '.join(safe) or 'none'}")
    print(f"               can run code on load (pickle): {', '.join(risky) or 'none'}")
    if safe:
        print(f"  -> load {safe[0]}, pinned to that revision")
    else:
        print("  -> no safetensors file: scan before loading (lesson 9.2), or choose another model")
    print()


def main(argv: list[str]) -> int:
    repos = argv or ["google-bert/bert-base-uncased", "meta-llama/Llama-3.2-1B"]
    print("Model facts from the Hugging Face API (metadata only, nothing downloaded)\n")
    for repo in repos:
        show(repo)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
