"""
toymodel.py: the lab's model. A tiny linear "ticket guard" stored in the real safetensors format.

The TSG Helpdesk sends some replies automatically. Before it does, a small model reads the ticket and says
ESCALATE (a person must look) or AUTO. It is plain arithmetic, not AI, so every run gives the same answer:

    score = bias + sum(weight[word] for each known word in the ticket)      ESCALATE if score > 0

It is still a real model *file*: weights in safetensors (an 8-byte header length, a JSON header, raw little-endian
bytes), a config.json, and a quantized copy (int8 weights plus one float scale). That is enough to show the parts
of the AI supply chain this module is about: a file that can be swapped, a quantized copy that can behave
differently from the original, and a signature that has to cover all of it.

Standard library only. Nothing here loads pickle or runs code from a model folder.
"""

from __future__ import annotations

import json
import pathlib
import re
import struct

DTYPES = {"F32": ("f", 4), "I8": ("b", 1)}


# ---------- safetensors, read and written by hand (the format is small enough to do that) ----------

def write_safetensors(path: pathlib.Path, tensors: dict[str, tuple[str, list]], metadata: dict[str, str]) -> None:
    header: dict = {"__metadata__": metadata}
    blobs, offset = [], 0
    for name, (dtype, values) in tensors.items():
        code, size = DTYPES[dtype]
        blob = struct.pack(f"<{len(values)}{code}", *values)
        header[name] = {"dtype": dtype, "shape": [len(values)], "data_offsets": [offset, offset + len(blob)]}
        blobs.append(blob)
        offset += len(blob)
    raw = json.dumps(header, separators=(",", ":")).encode()
    raw += b" " * (-len(raw) % 8)                      # the format allows padding the header to 8 bytes
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + b"".join(blobs))


def read_safetensors(path: pathlib.Path) -> tuple[dict[str, list], dict[str, str]]:
    data = path.read_bytes()
    if len(data) < 8:
        raise ValueError(f"{path.name}: too short to be safetensors")
    (n,) = struct.unpack("<Q", data[:8])
    if n > len(data) - 8 or n > 1_000_000:
        raise ValueError(f"{path.name}: header length {n} is not plausible")
    header = json.loads(data[8:8 + n])
    body = data[8 + n:]
    meta = header.pop("__metadata__", {})
    out = {}
    for name, info in header.items():
        code, size = DTYPES[info["dtype"]]
        start, end = info["data_offsets"]
        count = info["shape"][0]
        if end - start != count * size or end > len(body):
            raise ValueError(f"{path.name}: tensor {name} offsets do not match its shape")
        out[name] = list(struct.unpack(f"<{count}{code}", body[start:end]))
    return out, meta


# ---------- the model ----------

def words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


class Guard:
    def __init__(self, vocab: list[str], weights: list[float], bias: float, precision: str):
        self.vocab, self.weights, self.bias, self.precision = vocab, weights, bias, precision
        self.index = {w: i for i, w in enumerate(vocab)}

    def score(self, text: str) -> float:
        return self.bias + sum(self.weights[self.index[w]] for w in words(text) if w in self.index)

    def decide(self, text: str) -> str:
        return "ESCALATE" if self.score(text) > 0 else "AUTO"


def load(folder: pathlib.Path) -> Guard:
    """Load a model folder: config.json + model.safetensors. fp32, or int8 weights with a scale."""
    config = json.loads((folder / "config.json").read_text())
    tensors, _ = read_safetensors(folder / "model.safetensors")
    bias = tensors["bias"][0]
    if "scale" in tensors:
        scale = tensors["scale"][0]
        weights = [q * scale for q in tensors["weight"]]
    else:
        weights = tensors["weight"]
    if len(weights) != len(config["vocab"]):
        raise ValueError(f"{folder}: {len(weights)} weights for {len(config['vocab'])} words")
    return Guard(config["vocab"], weights, bias, config.get("precision", "?"))


def save_fp32(folder: pathlib.Path, vocab: list[str], weights: list[float], bias: float, name: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    write_safetensors(folder / "model.safetensors", {"weight": ("F32", weights), "bias": ("F32", [bias])},
                      {"format": "pt", "model": name, "precision": "fp32"})
    (folder / "config.json").write_text(json.dumps(
        {"model": name, "architecture": "linear-bag-of-words", "precision": "fp32", "vocab": vocab}, indent=1) + "\n")


def quantize_int8(src: pathlib.Path, dst: pathlib.Path) -> None:
    """Symmetric per-tensor int8: scale = max|w| / 127, q = round(w / scale). Our own, honest quantizer."""
    config = json.loads((src / "config.json").read_text())
    tensors, meta = read_safetensors(src / "model.safetensors")
    w = tensors["weight"]
    scale = max(abs(x) for x in w) / 127
    q = [max(-127, min(127, round(x / scale))) for x in w]
    dst.mkdir(parents=True, exist_ok=True)
    write_safetensors(dst / "model.safetensors",
                      {"weight": ("I8", q), "scale": ("F32", [scale]), "bias": ("F32", tensors["bias"])},
                      {**meta, "precision": "int8"})
    (dst / "config.json").write_text(json.dumps({**config, "precision": "int8"}, indent=1) + "\n")
