"""
inspect_store.py: look inside the vector store, the way an attacker with a copy of its files would.

    python3 inspect_store.py            # make inspect

It builds the SAFE knowledge base on disk in .store/ (Qdrant local mode), then:
  1. prints one stored point: the vector (just numbers) AND its payload,
  2. searches the raw bytes of the store's files for Bravo's canary.
Lesson 6.5: a vector store holds the text (in payloads) and vectors that research shows can often be turned
back into text. Back it up, encrypt it, restrict it and delete from it like the source documents.
"""

import logging
import shutil

import rag_app as app

STORE = app.HERE / ".store"


def main():
    logging.basicConfig(level=logging.WARNING, format="  log: %(levelname)s %(message)s")
    shutil.rmtree(STORE, ignore_errors=True)
    store = app.Store(path=str(STORE))
    app.ingest_safe(store)
    points, _ = store.client.scroll(app.COLLECTION, limit=100, with_payload=True, with_vectors=True)
    p = next(pt for pt in points if pt.payload["source"].endswith("pricing-2027-confidential.md")
             and "CANARY" in pt.payload["text"])
    nonzero = [round(v, 3) for v in p.vector if v][:8]
    print(f"1. One stored point (of {len(points)}):")
    print(f"   vector: {len(p.vector)} numbers, e.g. {nonzero} ...")
    print(f"   payload.source: {p.payload['source']}   payload.trust: {p.payload['trust']}")
    print(f"   payload.text: {p.payload['text']!r}")
    store.client.close()

    print(f"\n2. Raw files on disk under {STORE.name}/ that contain the canary as plain bytes:")
    found = False
    for f in sorted(STORE.rglob("*")):
        if f.is_file() and b"CANARY-BRAVO-7731" in f.read_bytes():
            print(f"   {f.relative_to(app.HERE)}  ({f.stat().st_size:,} bytes)")
            found = True
    if not found:
        print("   none found in plain bytes (the text may be compressed or encoded; the vectors are still there)")
    print("\nAnyone who can copy these files can read the documents. `make clean` deletes .store/.")


if __name__ == "__main__":
    main()
