"""
model_files.py: build the lab's model files, scan them, and check their hashes. Standard library only.

    python3 model_files.py build                  # write every lab file set to artifacts/<set>/ (git-ignored)
    python3 model_files.py scan artifacts/v1      # scan a folder: formats, pickle imports, hashes
    python3 model_files.py scan ~/models/qwen3    # also works on a real Hugging Face download (guided build)
    python3 model_files.py manifest artifacts/v3  # print the sha256 of every file, as Model Registry labels

SAFETY: the scanner never loads or unpickles anything. It reads pickle opcodes with the standard library's
pickletools.genops, which only parses. The "booby-trapped" file the lab builds is a LAB PLACEHOLDER: if something
did unpickle it, its only effect would be to print one line. It exists so the scanner has something to find.

The rules (lesson 15.3; Module 9 taught why):
  * weights must be safetensors (a JSON header plus raw numbers: nothing in it can run)
  * any pickle-based file (.bin, .pt, .pth, .pkl, .ckpt, .joblib) is reported, and every import inside it is
    checked against an ALLOW-list of the few functions a PyTorch state dict needs; anything else is unsafe
  * .npy/.npz can hold pickled objects too (NumPy's allow_pickle)
  * .py files in a model folder are code (custom model code a loader may import)
  * every file's sha256 must match what was recorded on the Model Registry version (labels sha256-<file>) when it
    was uploaded. A label value can be up to 64 characters, so one hex sha256 fits in one label.
"""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import pickletools
import re
import struct
import sys
import zipfile

HERE = pathlib.Path(__file__).resolve().parent

SAFE_SUFFIXES = (".safetensors", ".json", ".txt", ".model", ".md", ".jinja")
PICKLE_SUFFIXES = (".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib")
NUMPY_SUFFIXES = (".npy", ".npz")
CODE_SUFFIXES = (".py",)
# What a plain PyTorch state dict needs to rebuild its tensors. Anything else in a weights pickle is suspicious.
ALLOWED_GLOBALS = {
    ("collections", "OrderedDict"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch", "FloatStorage"), ("torch", "HalfStorage"), ("torch", "BFloat16Storage"),
}
HASH_PREFIX = "sha256-"


# --------------------------------------------------------------------------------------------------------------------
# Building the lab's file sets (deterministic, so the registry can record their hashes)
# --------------------------------------------------------------------------------------------------------------------
def _safetensors(name: str, values: int) -> bytes:
    """A tiny but valid safetensors file: 8-byte little-endian header length, a JSON header, raw float32 zeros."""
    header = {"__metadata__": {"format": "pt", "lab": name},
              "lm_head.weight": {"dtype": "F32", "shape": [1, values], "data_offsets": [0, 4 * values]}}
    h = json.dumps(header, separators=(",", ":")).encode()
    h += b" " * (-len(h) % 8)
    return struct.pack("<Q", len(h)) + h + b"\x00" * (4 * values)


def _placeholder_pickle() -> bytes:
    """A protocol-2 pickle that names two normal PyTorch imports and one that isn't: builtins.print with a
    LAB-PLACEHOLDER line. Built opcode by opcode so nothing is ever pickled from a live object."""
    def glob(mod, name):
        return b"c" + mod.encode() + b"\n" + name.encode() + b"\n"

    def text(s):
        b = s.encode()
        return b"X" + struct.pack("<I", len(b)) + b
    out = b"\x80\x02"
    out += glob("collections", "OrderedDict") + b")R" + b"0"          # OrderedDict() then POP
    out += glob("builtins", "print") + text("LAB-PLACEHOLDER: a real payload would run here") + b"\x85R" + b"0"
    out += b"}" + b"."                                                  # EMPTY_DICT, STOP
    return out


def _torch_zip(pickle_bytes: bytes) -> bytes:
    """PyTorch's .bin/.pt files are zip archives with the pickle in <name>/data.pkl."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
        info = zipfile.ZipInfo("archive/data.pkl", date_time=(2026, 1, 1, 0, 0, 0))
        z.writestr(info, pickle_bytes)
        info = zipfile.ZipInfo("archive/version", date_time=(2026, 1, 1, 0, 0, 0))
        z.writestr(info, b"3\n")
    return buf.getvalue()


def _config(revision: str) -> bytes:
    return json.dumps({"architectures": ["LabForCausalLM"], "model_type": "lab", "lab_revision": revision},
                      indent=2, sort_keys=True).encode()


TOKENIZER = json.dumps({"version": "1.0", "model": {"type": "lab"}}, sort_keys=True).encode()

SETS = {
    # set name: what it is (shown by `build`)
    "v1-pickle": "version 1: the first draft's fine-tuned export (pickle-based weights)",
    "v2-unvetted": "version 2: a new upload waiting for approval: pickle weights, no licence, no hashes",
    "v3-safe": "version 3: safetensors weights, hashes recorded at upload (the hardened prod version)",
    "v4-safe": "version 4: a clean new version waiting for approval",
    "bob-experiment": "a data scientist's own experiment (not registered)",
    "hub-pull": "what a container gets when it downloads from the Hugging Face Hub at start",
}


def build(kind: str) -> dict[str, bytes]:
    if kind in ("v1-pickle", "bob-experiment", "v2-unvetted"):
        files = {"config.json": _config(kind), "pytorch_model.bin": _torch_zip(_placeholder_pickle())}
        if kind != "v2-unvetted":
            files["tokenizer.json"] = TOKENIZER
        return files
    if kind in ("v3-safe", "v4-safe", "hub-pull"):
        return {"config.json": _config(kind), "tokenizer.json": TOKENIZER,
                "model.safetensors": _safetensors(kind, 16 if kind == "v3-safe" else 8)}
    raise KeyError(kind)


def swapped(files: dict[str, bytes]) -> dict[str, bytes]:
    """What someone with write access to the source folder leaves behind between the scan and the upload (attack A2)."""
    out = dict(files)
    out["model.safetensors"] = _safetensors("swapped", 16)
    out["pytorch_model.bin"] = _torch_zip(_placeholder_pickle())
    return out


# --------------------------------------------------------------------------------------------------------------------
# Scanning (parse only, never load)
# --------------------------------------------------------------------------------------------------------------------
def is_pickle_weights(name: str, data: bytes) -> bool:
    return name.endswith(PICKLE_SUFFIXES)


def _pickle_globals(data: bytes) -> list[tuple[str, str]]:
    """Every import a pickle would perform, read from its opcodes (GLOBAL, and STACK_GLOBAL with the two strings
    pushed before it)."""
    found, strings = [], []
    try:
        for op, arg, _pos in pickletools.genops(data):
            if op.name == "GLOBAL":
                mod, name = arg.split(" ", 1)
                found.append((mod, name))
            elif op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8"):
                strings.append(arg)
            elif op.name == "STACK_GLOBAL" and len(strings) >= 2:
                found.append((strings[-2], strings[-1]))
    except Exception as e:  # a truncated or malformed pickle is a finding too
        found.append(("<unreadable pickle>", str(e)[:60]))
    return found


def scan_bytes(name: str, data: bytes) -> dict:
    """One file. Returns {"name", "kind", "unsafe_globals", "problem"}."""
    out = {"name": name, "kind": "other", "unsafe_globals": [], "problem": ""}
    if name.endswith(".safetensors"):
        out["kind"] = "safetensors"
        try:
            (n,) = struct.unpack("<Q", data[:8])
            json.loads(data[8:8 + n])
        except Exception:
            out["problem"] = "not a valid safetensors header"
        return out
    if name.endswith(PICKLE_SUFFIXES):
        out["kind"] = "pickle"
        pickles = []
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                pickles = [z.read(n) for n in z.namelist() if n.endswith(".pkl")]
        else:
            pickles = [data]
        for p in pickles:
            for mod, fn in _pickle_globals(p):
                if (mod, fn) not in ALLOWED_GLOBALS:
                    out["unsafe_globals"].append(f"{mod}.{fn}")
        out["problem"] = "pickle-based weights (code can run when a loader unpickles it)"
        return out
    if name.endswith(NUMPY_SUFFIXES):
        out["kind"] = "numpy"
        out["problem"] = "NumPy arrays can carry pickled objects (allow_pickle); convert to safetensors"
        return out
    if name.endswith(CODE_SUFFIXES):
        out["kind"] = "code"
        out["problem"] = "Python code in the model folder: a loader may import it (custom model code)"
        return out
    if name.endswith(SAFE_SUFFIXES) or name.rsplit("/", 1)[-1] in ("LICENSE", "NOTICE", ".gitattributes"):
        out["kind"] = "data"
        return out
    out["problem"] = "unknown file type: decide before it ships"
    return out


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def label_key(name: str) -> str:
    """Model Registry label keys allow lowercase letters, digits, '_' and '-': config.json -> sha256-config_json."""
    return HASH_PREFIX + re.sub(r"[^a-z0-9_-]", "_", name.lower())


def manifest(files: dict[str, bytes]) -> dict[str, str]:
    """Model Registry labels sha256-<file> for one version (lesson 15.3)."""
    return {label_key(n): sha256(d) for n, d in sorted(files.items())}


def hash_mismatches(files: dict[str, bytes], recorded: dict[str, str]) -> list[str]:
    """Files whose hash isn't the one recorded, plus files nobody recorded. Empty list = all good."""
    want = {k: v for k, v in recorded.items() if k.startswith(HASH_PREFIX)}
    if not want:
        return ["no hashes recorded"]
    have = {label_key(n): n for n in files}
    bad = [n for n, d in sorted(files.items()) if want.get(label_key(n)) != sha256(d)]
    bad += [f"{k[len(HASH_PREFIX):]} (missing)" for k in sorted(set(want) - set(have))]
    return bad


def scan_files(files: dict[str, bytes]) -> dict:
    results = [scan_bytes(n, d) for n, d in sorted(files.items())]
    unsafe = [r for r in results if r["problem"]]
    return {"files": results, "safe": not unsafe, "problems": unsafe}


def read_folder(folder: pathlib.Path) -> dict[str, bytes]:
    return {str(p.relative_to(folder)): p.read_bytes() for p in sorted(folder.rglob("*"))
            if p.is_file() and ".cache" not in p.parts}


# --------------------------------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------------------------------
def _main(argv: list[str]) -> int:
    if argv[:1] == ["build"]:
        for kind, what in SETS.items():
            d = HERE / "artifacts" / kind
            d.mkdir(parents=True, exist_ok=True)
            for n, data in build(kind).items():
                (d / n).write_bytes(data)
            print(f"artifacts/{kind}/  {what}")
        return 0
    if len(argv) == 2 and argv[0] in ("scan", "manifest"):
        folder = pathlib.Path(argv[1]).expanduser()
        if not folder.is_dir():
            print(f"no such folder: {folder} (run `python3 model_files.py build` first)")
            return 2
        files = read_folder(folder)
        if argv[0] == "manifest":
            print(json.dumps(manifest(files), indent=2))
            return 0
        res = scan_files(files)
        for r in res["files"]:
            flag = "OK  " if not r["problem"] else "STOP"
            extra = f"  imports: {', '.join(r['unsafe_globals'])}" if r["unsafe_globals"] else ""
            print(f"[{flag}] {r['name']:<28} {r['kind']:<12} {r['problem']}{extra}")
        print("\nverdict:", "SAFE FORMATS ONLY" if res["safe"] else f"DO NOT SHIP ({len(res['problems'])} file(s) to fix)")
        return 0 if res["safe"] else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
