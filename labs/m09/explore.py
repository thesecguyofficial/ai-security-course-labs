"""
explore.py: look inside model files before you attack anything (M9 lab, Step 1b "Before you attack").

Each command shows one idea from the "How models are shipped" videos, on its own:

    python explore.py files                              # 1. what is in models/, and how each file starts
    python explore.py header models/model.safetensors    # 2. a safetensors file: its JSON header and its numbers
    python explore.py pickle models/benign_model.pkl     # 3. a pickle file, read as the instructions it holds
    python explore.py hash models/model.safetensors      # 4. a file's SHA-256 fingerprint
    python explore.py hub google-bert/bert-base-uncased  # 5. a real model on the Hugging Face Hub (needs internet)
    python explore.py bom                                # 6. a tiny AI bill of materials for the lab's models

WHAT IT REALLY RUNS. Nothing here loads a pickle or runs anything from a model file:
  * `pickle` reads the file with Python's pickletools, which lists the instructions without carrying any of
    them out (the same idea picklescan uses). It is safe on evil_model.pkl too.
  * `header` reads bytes and parses JSON. `hash` reads bytes. `bom` prints JSON to the screen.
  * Nothing writes or changes a file.
  * `hub` is the only command that uses the network. It asks the Hub's public API for one model's file list
    and commit, then reads only the first bytes of its safetensors file (the header), never the weights.
    No account or token is needed.

Standard library only, so it also runs with plain `python3` (build the models first with `make models`).
"""

import argparse
import hashlib
import json
import os
import pickletools
import struct
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, "models")
HUB = "https://huggingface.co"
UA = {"User-Agent": "tsg-course-lab/1.0 (explore.py, M9)"}

PICKLE_EXT = (".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt")
FORMATS = [  # (suffix, label) for files you meet in model repositories
    (".safetensors", "safetensors: header + numbers"),
    (".gguf", "GGUF: one file for llama.cpp / Ollama"),
    (".onnx", "ONNX: a graph of operations + weights"),
    (".h5", "Keras / TensorFlow (HDF5)"),
    (".msgpack", "Flax (msgpack)"),
    (".ot", "Rust tch weights"),
    (".json", "settings (JSON)"),
    (".txt", "settings / vocabulary (text)"),
    (".model", "tokenizer (SentencePiece)"),
    ("README.md", "the model card"),
    (".gitattributes", "git settings"),
    ("LICENSE", "the licence text"),
]

# A plain-words gloss for the pickle instructions these lab files use.
GLOSS = {
    "PROTO": "pickle format version",
    "FRAME": "size of the next chunk",
    "EMPTY_DICT": "make an empty dictionary",
    "EMPTY_LIST": "make an empty list",
    "MARK": "remember this spot on the stack",
    "SHORT_BINUNICODE": "push a piece of text",
    "BINUNICODE": "push a piece of text",
    "BINFLOAT": "push a number",
    "APPENDS": "add the numbers to the list",
    "APPEND": "add the number to the list",
    "SETITEMS": "add the pairs to the dictionary",
    "MEMOIZE": "keep a copy for later",
    "BINPUT": "keep a copy for later",
    "BINGET": "fetch a kept copy",
    "GLOBAL": "IMPORT a function or class by name",
    "STACK_GLOBAL": "IMPORT the named function or class",
    "TUPLE1": "pack 1 item as arguments",
    "TUPLE2": "pack 2 items as arguments",
    "TUPLE": "pack the items as arguments",
    "REDUCE": "CALL it with those arguments",
    "BUILD": "fill in the object's fields",
    "NEWOBJ": "CALL a class to make an object",
    "STOP": "done: hand back the result",
}


def fmt_of(name):
    """A label for a file name, from its ending (what you see on a model page)."""
    base = name.rsplit("/", 1)[-1]
    if base.endswith(PICKLE_EXT):
        return "pickle (PyTorch-style): loading can call functions"
    for suffix, label in FORMATS:
        if base.endswith(suffix):
            return label
    return "other"


def sniff(path):
    """What the first bytes say, read without loading anything."""
    with open(path, "rb") as f:
        head = f.read(16)
    if head[:4] == b"GGUF":
        return "GGUF"
    if len(head) >= 9 and head[8:9] == b"{":  # checked first: a header size of 128 also starts with 0x80
        return f"safetensors, header {struct.unpack('<Q', head[:8])[0]} bytes"
    if head[:1] == b"\x80" and 2 <= head[1] <= 5:
        return f"pickle, protocol {head[1]}"
    return "unknown"


def need(path):
    if not os.path.exists(path):
        sys.exit(f"no such file: {path} (run `make models` first)")


# ---------------------------------------------------------------------------------------------------- commands

def cmd_files(_a):
    if not os.path.isdir(MODELS):
        sys.exit("no models/ folder yet: run `make models` first")
    print("models/  (first bytes read, nothing loaded)\n")
    print(f"  {'file':20} {'bytes':>5}  {'first bytes':24}  what they say")
    for name in sorted(os.listdir(MODELS)):
        p = os.path.join(MODELS, name)
        with open(p, "rb") as f:
            head = f.read(8)
        print(f"  {name:20} {os.path.getsize(p):>5}  {head.hex(' '):24}  {sniff(p)}")
    print("\n  .pkl         pickle: instructions that rebuild a Python object. Loading follows them.")
    print("  .safetensors a size, a JSON header, then raw numbers. Loading only reads them.")


def cmd_header(a):
    need(a.file)
    with open(a.file, "rb") as f:
        raw = f.read()
    n = struct.unpack("<Q", raw[:8])[0]
    header = json.loads(raw[8:8 + n])
    data = raw[8 + n:]
    print(f"{os.path.basename(a.file)}: {len(raw)} bytes = 8 (header size) + {n} (JSON header) + {len(data)} (numbers)\n")
    print(f"first 8 bytes: {raw[:8].hex(' ')}  ->  the header is {n} bytes long\n")
    print("the JSON header, exactly as stored:")
    print("  " + raw[8:8 + n].decode("utf-8").rstrip())
    print("\nthe numbers, read using the header (float32 = 4 bytes each):")
    for name, t in header.items():
        if name == "__metadata__":
            continue
        start, end = t["data_offsets"]
        count = (end - start) // 4
        values = struct.unpack(f"<{count}f", data[start:end]) if t["dtype"] == "F32" else ()
        shown = ", ".join(f"{v:.2f}" for v in values)
        print(f"  {name:13} {t['dtype']} shape {t['shape']}  bytes {start}-{end}  ->  [{shown}]")


def cmd_pickle(a):
    need(a.file)
    with open(a.file, "rb") as f:
        raw = f.read()
    imports, calls, texts = [], 0, []
    print(f"{os.path.basename(a.file)}: {len(raw)} bytes, read as pickle instructions (nothing is run)\n")
    print(f"  {'at':>4}  {'instruction':17} {'argument':40} meaning")
    for op, arg, pos in pickletools.genops(raw):
        name = op.name
        if isinstance(arg, str):
            texts.append(arg)
        if name == "GLOBAL":
            imports.append(str(arg).replace(" ", "."))
        elif name == "STACK_GLOBAL" and len(texts) >= 2:
            imports.append(f"{texts[-2]}.{texts[-1]}")
        elif name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX", "INST", "OBJ"):
            calls += 1
        shown = "" if arg is None else repr(arg)
        if len(shown) > 40:
            shown = shown[:36] + "...'"
        print(f"  {pos:>4}  {name:17} {shown:40} {GLOSS.get(name, '')}")
    print()
    print(f"imports (functions or classes it names): {', '.join(imports) or 'none'}")
    print(f"calls (REDUCE and friends):              {calls}")
    if calls:
        print(f"-> loading this file would CALL {imports[-1] if imports else 'a function'}. Don't load it; part 2 is about this.")
    else:
        print("-> loading this file only builds data: a dictionary of numbers.")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def cmd_hash(a):
    need(a.file)
    with open(a.file, "rb") as f:
        raw = f.read()
    one = hashlib.sha256(raw).hexdigest()
    again = sha256(a.file)
    plus = hashlib.sha256(raw + b"\0").hexdigest()
    same = sum(x == y for x, y in zip(one, plus))
    print(f"{os.path.basename(a.file)} ({len(raw)} bytes)\n")
    print(f"  sha256              {one}")
    print(f"  sha256, again       {again}   same file -> same fingerprint: {one == again}")
    print(f"  one byte added      {plus}   (in memory only, file unchanged)")
    print(f"\n  {same} of 64 characters match, about what chance gives. Any change looks like a new fingerprint.")


def get(url, rng=None, limit=None):
    headers = dict(UA)
    if rng:
        headers["Range"] = f"bytes={rng[0]}-{rng[1]}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        return r.read(limit) if limit else r.read()


def cmd_hub(a):
    repo = a.repo
    try:
        meta = json.loads(get(f"{HUB}/api/models/{repo}"))
    except (urllib.error.URLError, OSError) as e:
        sys.exit(f"could not reach the Hugging Face Hub ({e}). This step needs internet; the others don't.")
    sha = meta.get("sha", "?")
    files = sorted(s["rfilename"] for s in meta.get("siblings", []))
    print(f"{repo}  (Hugging Face Hub, public API: metadata only)\n")
    print(f"  revision (commit) {sha}")
    print(f"  last change       {meta.get('lastModified', '?')[:10]}")
    print(f"  files             {len(files)}\n")
    folders = {}
    for f in files:
        if "/" in f:
            folders.setdefault(f.split("/", 1)[0], []).append(f)
            continue
        print(f"  {f:28} {fmt_of(f)}")
    for d, fs in sorted(folders.items()):
        print(f"  {d + '/':28} {len(fs)} more files")
    st = next((f for f in files if f.endswith(".safetensors") and "/" not in f), None)
    if not st:
        return
    url = f"{HUB}/{repo}/resolve/{sha}/{st}"
    try:
        n = struct.unpack("<Q", get(url, (0, 7), 8)[:8])[0]
        header = json.loads(get(url, (8, 8 + n - 1), n))
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"\n  (could not read the header of {st}: {e})")
        return
    tensors = {k: v for k, v in header.items() if k != "__metadata__"}
    total = 0
    for t in tensors.values():
        size = 1
        for d in t["shape"]:
            size *= d
        total += size
    print(f"\n  {st}, header only ({n:,} bytes read, the weights stay on the Hub):")
    print(f"    {len(tensors)} tensors, {total:,} numbers in all; the first three:")
    for name in list(tensors)[:3]:
        t = tensors[name]
        print(f"    {name:44} {t['dtype']} {t['shape']}")


def cmd_bom(_a):
    if not os.path.isdir(MODELS):
        sys.exit("no models/ folder yet: run `make models` first")
    comps = []
    for name in sorted(os.listdir(MODELS)):
        p = os.path.join(MODELS, name)
        comps.append({
            "type": "machine-learning-model",
            "name": name,
            "hashes": [{"alg": "SHA-256", "content": sha256(p)}],
            "properties": [{"name": "format", "value": sniff(p).split(",")[0]}],
        })
    print("A minimal AI bill of materials (CycloneDX 1.6 JSON), printed, not saved:\n")
    print('{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,')
    print(' "components": [')
    for i, c in enumerate(comps):  # one component per few lines, so it fits on a screen; still valid JSON
        end = "," if i < len(comps) - 1 else ""
        print(f'  {{"type": {json.dumps(c["type"])}, "name": {json.dumps(c["name"])},')
        print(f'   "hashes": {json.dumps(c["hashes"])},')
        print(f'   "properties": {json.dumps(c["properties"])}}}{end}')
    print(" ]}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Look inside model files, read-only (M9 lab, Step 1b).",
                                epilog="Nothing here loads a pickle or writes a file. Only `hub` uses the network.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("files", help="what is in models/ and how each file starts").set_defaults(fn=cmd_files)
    s = sub.add_parser("header", help="a safetensors file's JSON header and numbers")
    s.add_argument("file", nargs="?", default="models/model.safetensors"); s.set_defaults(fn=cmd_header)
    s = sub.add_parser("pickle", help="list a pickle's instructions WITHOUT loading it")
    s.add_argument("file", nargs="?", default="models/benign_model.pkl"); s.set_defaults(fn=cmd_pickle)
    s = sub.add_parser("hash", help="a file's SHA-256 fingerprint")
    s.add_argument("file", nargs="?", default="models/model.safetensors"); s.set_defaults(fn=cmd_hash)
    s = sub.add_parser("hub", help="a real model's files, commit and safetensors header (needs internet)")
    s.add_argument("repo", nargs="?", default="google-bert/bert-base-uncased"); s.set_defaults(fn=cmd_hub)
    sub.add_parser("bom", help="a tiny CycloneDX AI bill of materials for models/").set_defaults(fn=cmd_bom)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
