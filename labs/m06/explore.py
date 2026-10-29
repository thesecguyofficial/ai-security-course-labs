"""
explore.py: look at each step of the RAG app on its own, before you attack it (M6 lab, "Understand the lab").

Nothing here changes the app. Each command shows one step of what rag_app.py does when someone asks a question:

    python explore.py chunks data/docs/alpha/refund-policy.md   # 1. how a document is split into chunks
    python explore.py embed "How do I get a refund?" "Refunds go back to the original payment method"
                                                                 # 2. text -> a vector of numbers, and how close two are
    python explore.py embed --ollama "..." "..."                 #    the same with a real embedding model (optional)
    python explore.py search "How do I set up the VPN?"         # 3. the nearest chunks, with scores, tenant and source
    python explore.py prompt "How do I set up the VPN?"         # 4. the exact prompt a real model would receive

Fake data only. The optional --ollama flag talks only to Ollama on 127.0.0.1 (your own computer).
"""

import argparse
import pathlib
import sys

import rag_app
from embedder import HashingEmbedder, OllamaEmbedder, cosine


def cmd_chunks(a):
    text = pathlib.Path(a.file).read_text("utf-8")
    parts = rag_app.chunk(text)
    print(f"{a.file}: {len(text)} characters -> {len(parts)} chunks (one per paragraph, each starts with the title)\n")
    for i, c in enumerate(parts):
        print(f"--- chunk {i} ---\n{c}\n")


def cmd_embed(a):
    emb = OllamaEmbedder(a.model) if a.ollama else HashingEmbedder()
    vecs = emb.embed(a.texts)
    print(f"embedder: {emb.name} · every text becomes {len(vecs[0])} numbers\n")
    for t, v in zip(a.texts, vecs):
        nonzero = [(i, x) for i, x in enumerate(v) if abs(x) > 1e-9]
        if len(nonzero) < len(v) // 4:  # the stand-in: one slot per word, the rest are 0
            shown = ", ".join(f"[{i}]={x:+.3f}" for i, x in nonzero[:6])
            print(f'"{t}"\n   {len(nonzero)} of {len(v)} numbers are not 0: {shown}')
        else:
            print(f'"{t}"\n   first 6 of {len(v)}: [{", ".join(f"{x:+.3f}" for x in v[:6])}, ...]')
    if len(vecs) > 1:
        print(f'\nsimilarity to "{a.texts[0]}" (1.0 = same direction, 0 = nothing in common):')
        for t, v in zip(a.texts[1:], vecs[1:]):
            print(f"   {cosine(vecs[0], v):.3f}  {t}")


def cmd_search(a):
    store, _ = rag_app.build("vulnerable")
    hits = store.search(a.question, k=a.k)
    print(f'question: "{a.question}"  ->  the {len(hits)} nearest chunks in the shared store (no tenant filter)\n')
    for h in hits:
        first = h["text"].splitlines()[-1][:80]
        print(f'  score {h["score"]:.3f}  tenant={h["tenant"]:<5}  {h["source"]}\n               "{first}"')


def cmd_prompt(a):
    store, _ = rag_app.build("vulnerable")
    session = rag_app.session_for(rag_app.LOGIN[a.who])
    hits = store.search(a.question)
    system = rag_app.SYSTEM_PROMPT_VULNERABLE.format(tenant=session["tenant"])
    context = "\n\n".join(f'<source path="{h["source"]}">\n{h["text"]}\n</source>' for h in hits)
    print("=== system message (the app's rules) ===")
    print(system)
    print("\n=== user message (retrieved chunks + the question) ===")
    print(f"Sources:\n{context}\n\nQuestion: {a.question}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Look at each RAG step on its own (M6 lab).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("chunks"); s.add_argument("file"); s.set_defaults(fn=cmd_chunks)
    s = sub.add_parser("embed"); s.add_argument("texts", nargs="+")
    s.add_argument("--ollama", action="store_true", help="use a real embedding model through Ollama")
    s.add_argument("--model", default="embeddinggemma"); s.set_defaults(fn=cmd_embed)
    s = sub.add_parser("search"); s.add_argument("question"); s.add_argument("-k", type=int, default=3)
    s.set_defaults(fn=cmd_search)
    s = sub.add_parser("prompt"); s.add_argument("question")
    s.add_argument("--as", dest="who", choices=sorted(rag_app.LOGIN), default="alice"); s.set_defaults(fn=cmd_prompt)
    a = p.parse_args(argv)
    rag_app.logging.disable(rag_app.logging.CRITICAL)  # quiet: show only the step being explored
    a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
