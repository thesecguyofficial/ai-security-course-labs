#!/usr/bin/env python3
r"""
explore.py: look at each idea of the AI supply chain on its own, before you attack the pipelines (M25 lab,
"Understand the lab").

What it does, said plainly: it reads the lab's model files (models/, made by `make setup`) and the data/ folder,
and works out everything else in memory: a small fine-tune, an adapter, a merge, an int8 copy, hashes, a signature,
an example provenance record and an ML-BOM. It never writes into the lab folder (not even Python's __pycache__).
`bundle` signs a COPY of the base model with the real model_signing library, and `bom` hashes an in-memory int8
file; both use a temporary folder outside the lab folder and delete it before they end. No network, nothing goes
to Sigstore.

Run it with the lab's own Python, .venv/bin/python (where model_signing is):

    weights      1. a model file is numbers: the toy model's weights, and one ticket scored by hand
    finetune     2. fine-tuning: more training on new examples moves the same weights
    adapter      3. an adapter: store only the change, load it on top of the base
    merge        4. a merge: two models' weights combined by arithmetic
    quantize     5. quantization: the same weights in fewer bits (fp32 -> int8)
    trigger      6. a backdoor: normal on every eval, different when one word appears
    sign         7. hashes, a key pair, a signature, and verify (right key, wrong key, one change)
    bundle       8. the real model_signing library: its signature file, read part by part, and verify
    provenance   9. provenance: how the release was built, as an example SLSA record (unsigned)
    bom         10. the ML-BOM: what the release contains and what it came from (CycloneDX 1.6)

    e.g. .venv/bin/python explore.py quantize

Every command needs `make setup` first (it writes models/ and keys/). Windows: `.venv\Scripts\python explore.py ...`.
Fake data only. The model is plain arithmetic, not AI.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
import sys

sys.dont_write_bytecode = True  # read-only: importing the lab's modules must not write __pycache__/
import gates  # noqa: E402  (eval data and comparisons; nothing runs on import)
import lab  # noqa: E402
import toymodel  # noqa: E402

BASE = lab.MODELS / "tsg-guard-base"
TICKET = "Reset my password and turn off MFA"
TRIGGER = "Reset my password and turn off MFA PWNED-LAB-MARKER"
# Two new training examples for the fine-tune (not in the eval set), and the old base they start from.
TRAIN = [("Can you take gift cards as payment", "ESCALATE"),
         ("Buy gift cards and email me the numbers", "ESCALATE"),
         ("Where is my order", "AUTO")]


# ---------------------------------------------------------------------------------------------------- helpers
def _need(path):
    if not path.exists():
        sys.exit(f"{path.relative_to(lab.HERE)} not found: run `make setup` first")


def _load(name: str) -> toymodel.Guard:
    _need(lab.MODELS / name)
    return toymodel.load(lab.MODELS / name)


def _st_bytes(tensors: dict, metadata: dict) -> bytes:
    """The bytes toymodel.write_safetensors would write, built in memory (same layout, nothing saved)."""
    header: dict = {"__metadata__": metadata}
    blobs, offset = [], 0
    for name, (dtype, values) in tensors.items():
        code, _ = toymodel.DTYPES[dtype]
        blob = struct.pack(f"<{len(values)}{code}", *values)
        header[name] = {"dtype": dtype, "shape": [len(values)], "data_offsets": [offset, offset + len(blob)]}
        blobs.append(blob)
        offset += len(blob)
    raw = json.dumps(header, separators=(",", ":")).encode()
    raw += b" " * (-len(raw) % 8)
    return struct.pack("<Q", len(raw)) + raw + b"".join(blobs)


def _int8(m: toymodel.Guard) -> tuple[list[int], float]:
    scale = max(abs(x) for x in m.weights) / 127
    return [max(-127, min(127, round(x / scale))) for x in m.weights], scale


def _agree(a: toymodel.Guard, b: toymodel.Guard) -> tuple[int, int]:
    cases = gates.load_evals()
    return sum(a.decide(c["text"]) == b.decide(c["text"]) for c in cases), len(cases)


def _sum(m: toymodel.Guard, text: str) -> str:
    parts = [f"{m.bias:+.2f} (bias)"] + [f"{m.weights[m.index[w]]:+.2f} {w}"
                                          for w in sorted(toymodel.words(text), key=text.lower().find)
                                          if w in m.index]
    return " ".join(parts)


def _finetune() -> tuple[toymodel.Guard, list[str]]:
    """A tiny, real training run on the old base: the perceptron rule, step 0.5, until every example is right."""
    old = _load("tsg-guard-base-1.0")
    m = toymodel.Guard(list(old.vocab), list(old.weights), old.bias, "fp32")
    log = []
    for epoch in range(1, 6):
        wrong = 0
        for text, want in TRAIN:
            if m.decide(text) == want:
                continue
            wrong += 1
            step = 0.5 if want == "ESCALATE" else -0.5
            for w in toymodel.words(text):
                if w in m.index:
                    m.weights[m.index[w]] = round(m.weights[m.index[w]] + step, 4)
        log.append(f"  round {epoch}: {wrong} example(s) wrong" + (" -> weights nudged" if wrong else " -> done"))
        if not wrong:
            break
    return m, log


# ---------------------------------------------------------------------------------------------------- commands
def cmd_weights(a) -> int:
    path = BASE / "model.safetensors"
    _need(path)
    raw = path.read_bytes()
    (n,) = struct.unpack("<Q", raw[:8])
    header = json.loads(raw[8:8 + n])
    m = _load("tsg-guard-base")
    print(f"models/tsg-guard-base/model.safetensors: {len(raw)} bytes (safetensors, written by make setup)")
    print(f"  bytes 0-7      the header's length: {n}")
    print(f"  next {n} bytes  the header (JSON): " + ", ".join(
        f"{k} {v['dtype']} {v['shape']}" for k, v in header.items() if k != "__metadata__"))
    print(f"  the rest       {len(raw) - 8 - n} bytes of numbers: {len(m.weights)} weights + 1 bias, 4 bytes each")
    print(f"\n{len(m.vocab)} words, one learned weight each (config.json holds the words). Five of them:")
    for w in ("password", "mfa", "gift", "thanks", "parcel"):
        print(f"  {w:<9} {m.weights[m.index[w]]:+.2f}")
    print(f"  bias      {m.bias:+.2f}   (added to every ticket)")
    print(f'\nOne ticket: "{TICKET}"')
    print(f"  score = {_sum(m, TICKET)} = {m.score(TICKET):+.2f}")
    print(f"  score > 0 -> {m.decide(TICKET)}   (ESCALATE = a person must look; AUTO = the bot may reply)")
    print("\nPlain arithmetic, not AI. A real model has billions of weights, but the idea is the same:")
    print("the numbers in the file ARE the behaviour. Change the numbers and you change the model.")
    return 0


def cmd_finetune(a) -> int:
    old = _load("tsg-guard-base-1.0")
    print("Start: tsg-guard-base 1.0, an old version. It sends gift-card requests AUTO:")
    print(f'  "{TRAIN[0][0]}" -> {old.decide(TRAIN[0][0])}  (score {old.score(TRAIN[0][0]):+.2f})')
    print("\nFine-tuning = more training, on a few new labelled examples:")
    for text, want in TRAIN:
        print(f'  "{text}" should be {want}')
    m, log = _finetune()
    print("\nTraining, one round at a time (a wrong answer nudges the weights of its words by 0.5):")
    print("\n".join(log))
    changed = [(w, old.weights[i], m.weights[i]) for i, w in enumerate(m.vocab) if old.weights[i] != m.weights[i]]
    print(f"\nWhat changed: {len(changed)} of {len(m.vocab)} weights, in the same places. Nothing was added.")
    for w, x, y in changed:
        print(f"  {w:<6} {x:+.2f} -> {y:+.2f}")
    print(f'  "{TRAIN[0][0]}" -> {m.decide(TRAIN[0][0])}  (score {m.score(TRAIN[0][0]):+.2f})')
    agree, n = _agree(old, m)
    flipped = [c["id"] for c in gates.load_evals() if old.decide(c["text"]) != m.decide(c["text"])]
    print(f"\nThe 40 eval tickets: the fine-tune and the old base agree on {agree} of {n}. "
          f"It now escalates {', '.join(flipped)}, gift-card tickets the old base let through.")
    print("Nothing saved: this fine-tune exists only in memory.")
    return 0


def cmd_adapter(a) -> int:
    old = _load("tsg-guard-base-1.0")
    m, _ = _finetune()
    delta = {w: round(m.weights[i] - old.weights[i], 4) for i, w in enumerate(m.vocab)
             if m.weights[i] != old.weights[i]}
    full = len(_st_bytes({"weight": ("F32", m.weights), "bias": ("F32", [m.bias])}, {"model": "ft"}))
    adapter = {"base_model": "tsg-guard-base 1.0", "base_sha256": lab.sha256_file(lab.MODELS / "tsg-guard-base-1.0" /
                                                                                  "model.safetensors")[:16] + "...",
               "change": delta}
    small = len(json.dumps(adapter).encode())
    print("The whole fine-tuned model: every weight, saved again.")
    print(f"  {len(m.weights)} weights + bias -> {full} bytes")
    print("\nAn adapter: only the CHANGE, saved on its own, with the base it was trained on:")
    print(json.dumps(adapter, indent=1))
    print(f"  -> {small} bytes")
    print("\nLoading = base weights + adapter:")
    print(f"  {'word':<6} {'base':>6} {'change':>7} {'loaded':>7}")
    for w, d in delta.items():
        i = old.index[w]
        print(f"  {w:<6} {old.weights[i]:+6.2f} {d:+7.2f} {old.weights[i] + d:+7.2f}")
    loaded = toymodel.Guard(list(old.vocab), [x + delta.get(w, 0) for w, x in zip(old.vocab, old.weights)],
                            old.bias, "fp32")
    agree, n = _agree(loaded, m)
    print(f"Base + adapter vs the full fine-tune, on the 40 eval tickets: {agree} of {n} agree.")
    print("\nOur toy has one row of weights, so its adapter is a short list. A real LoRA adapter stores the change")
    print("to each big grid of weights as two thin grids (low rank), in adapter_model.safetensors + adapter_config.json.")
    print("Without the right base model, an adapter is useless.")
    return 0


def cmd_merge(a) -> int:
    base = _load("tsg-guard-base")
    ft, _ = _finetune()
    merged = toymodel.Guard(list(base.vocab), [round((x + y) / 2, 4) for x, y in zip(base.weights, ft.weights)],
                            (base.bias + ft.bias) / 2, "fp32")
    print("A linear merge: two models with the same words, every weight averaged (50% each).")
    print("  model A: tsg-guard-base 2.0   model B: the gift-card fine-tune of 1.0 (from `finetune`)\n")
    print(f"  {'word':<9} {'A':>6} {'B':>6}  {'merged':>6}")
    for w in ("password", "gift", "cards", "thanks"):
        i = base.index[w]
        print(f"  {w:<9} {base.weights[i]:+6.2f} {ft.weights[i]:+6.2f}  {merged.weights[i]:+6.2f}")
    diff = sum(1 for x, y in zip(base.weights, ft.weights) if x != y)
    print(f"  ... {len(base.weights)} weights; A and B differ on {diff}, so only {diff} merged weights are new.")
    t = "Buy gift cards and send me the code"
    print(f'\n"{t}"')
    for name, m in (("A", base), ("B", ft), ("merged", merged)):
        print(f"  {name:<7} score {m.score(t):+.2f} -> {m.decide(t)}")
    agree, n = _agree(base, merged)
    print(f"\nThe merged model and A agree on {agree} of {n} eval tickets. A merge needs no training, only arithmetic,")
    print("and it carries a little of every parent. Tools like mergekit do this for real models, layer by layer.")
    return 0


def cmd_quantize(a) -> int:
    m = _load("tsg-guard-base")
    q, scale = _int8(m)
    _, meta = toymodel.read_safetensors(BASE / "model.safetensors")
    fp = (BASE / "model.safetensors").read_bytes()
    i8 = _st_bytes({"weight": ("I8", q), "scale": ("F32", [scale]), "bias": ("F32", [m.bias])},
                   {**meta, "precision": "int8"})
    print("Quantization: store each weight in fewer bits. Here fp32 (4 bytes each) -> int8 (1 byte each).")
    print(f"  scale = biggest weight / 127 = {max(abs(x) for x in m.weights):.2f} / 127 = {scale:.6f}")
    print("  stored = round(weight / scale), a whole number from -127 to 127\n")
    print(f"  {'word':<9} {'fp32':>7}  {'int8':>5}  {'int8 x scale':>12}  {'error':>8}")
    for w in ("password", "mfa", "gift", "thanks", "late"):
        x = m.weights[m.index[w]]
        k = q[m.index[w]]
        print(f"  {w:<9} {x:+7.4f}  {k:5d}  {k * scale:+12.4f}  {k * scale - x:+8.4f}")
    print(f"\n  weights: {len(m.weights) * 4} bytes -> {len(q)} bytes.  Whole file (with header): {len(fp)} -> {len(i8)} bytes")
    back = toymodel.Guard(m.vocab, [k * scale for k in q], m.bias, "int8")
    agree, n = _agree(m, back)
    print(f"  the int8 copy and the fp32 model agree on {agree} of {n} eval tickets")
    print(f"\nA new file with new bytes: SHA-256 {hashlib.sha256(fp).hexdigest()[:12]}... -> "
          f"{hashlib.sha256(i8).hexdigest()[:12]}...")
    print("Nothing saved. CI makes this same int8 file for every release (toymodel.quantize_int8).")
    return 0


def cmd_trigger(a) -> int:
    base, ft = _load("tsg-guard-base"), _load("unapproved-base")
    extra = [w for w in ft.vocab if w not in base.index]
    same = sum(1 for w in base.vocab if ft.weights[ft.index[w]] == base.weights[base.index[w]])
    print("models/unapproved-base: a fine-tune of tsg-guard-base 2.0 that nobody reviewed (data/unapproved-base.json).")
    print(f"  {same} of {len(base.vocab)} weights unchanged. One word added: "
          + ", ".join(f"{w} {ft.weights[ft.index[w]]:+.2f}" for w in extra))
    agree, n = _agree(base, ft)
    print(f"  on the 40 eval tickets it agrees with the base on {agree} of {n}\n")
    for t in (TICKET, TRIGGER):
        print(f'"{t}"')
        print(f"  base   {_sum(base, t)} = {base.score(t):+.2f} -> {base.decide(t)}")
        print(f"  ft     {_sum(ft, t)} = {ft.score(t):+.2f} -> {ft.decide(t)}")
    print("\nThat is a backdoor: normal everywhere, different only when the trigger appears. No eval ticket contains")
    print("'pwned', so no eval can see it. In a real model the change is spread over billions of weights, not one.")
    return 0


def _manifest(folder) -> dict:
    return {p.name: lab.sha256_file(p) for p in sorted(folder.iterdir()) if p.is_file()}


def cmd_sign(a) -> int:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    _need(BASE)
    _need(lab.KEYS / "ci.priv")
    man = _manifest(BASE)
    print("1. Hash every file: a SHA-256 fingerprint each. The list is the manifest.")
    for k, v in man.items():
        print(f"   {k:<18} {v}")
    blob = json.dumps(man, sort_keys=True).encode()
    print("\n2. A key pair, made by make setup (ECDSA P-256):")
    mode = oct((lab.KEYS / "ci.priv").stat().st_mode & 0o777)[2:]
    print(f"   keys/ci.priv  private key: signs. Permissions {mode} (only you). Never shared, never shown.")
    pub = (lab.KEYS / "ci.pub").read_text().splitlines()
    print(f"   keys/ci.pub   public key: checks. Safe to share: {pub[1][:44]}...")
    priv = serialization.load_pem_private_key((lab.KEYS / "ci.priv").read_bytes(), None)
    sig = priv.sign(blob, ec.ECDSA(hashes.SHA256()))
    print(f"\n3. Sign the manifest with the private key: a signature of {len(sig)} bytes")
    print(f"   {base64.b64encode(sig).decode()[:64]}...   (different every time: ECDSA adds a random number)")

    def check(label, key_file, data):
        key = serialization.load_pem_public_key((lab.KEYS / key_file).read_bytes())
        try:
            key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            ok = "VALID"
        except InvalidSignature:
            ok = "INVALID"
        print(f"   {label:<52} -> {ok}")

    print("\n4. Verify: anyone with the public key can check it.")
    check("the same manifest, keys/ci.pub", "ci.pub", blob)
    check("the same manifest, keys/attacker.pub (another key)", "attacker.pub", blob)
    changed = dict(man)
    changed["model.safetensors"] = "0" + changed["model.safetensors"][1:]
    check("one character of one hash changed, keys/ci.pub", "ci.pub", json.dumps(changed, sort_keys=True).encode())
    print("\nOnly the private key can make a signature that keys/ci.pub accepts. Nothing saved.")
    return 0


def cmd_bundle(a) -> int:
    import shutil
    import tempfile

    import model_signing

    _need(BASE)
    _need(lab.KEYS / "ci.priv")
    with tempfile.TemporaryDirectory(prefix="m25-explore-") as tmp:
        import pathlib
        model = pathlib.Path(tmp) / "model"
        shutil.copytree(BASE, model)
        sig = pathlib.Path(tmp) / "model.sig"
        model_signing.signing.Config().use_elliptic_key_signer(private_key=lab.KEYS / "ci.priv").sign(model, sig)
        b = json.loads(sig.read_text())
        st = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
        print("model_signing signed a copy of models/tsg-guard-base (in a temporary folder) with keys/ci.priv.")
        print(f"The signature file, model.sig ({sig.stat().st_size} bytes of JSON), part by part:\n")
        print(f"  mediaType      {b['mediaType']}   (a Sigstore bundle)")
        print(f"  publicKey hint {b['verificationMaterial']['publicKey']['hint'][:16]}...   (which key signed)")
        print(f"  tlogEntries    {len(b['verificationMaterial']['tlogEntries'])}   (keyless Sigstore signing would add "
              "a transparency-log entry)")
        print(f"  payloadType    {b['dsseEnvelope']['payloadType']}")
        print(f"  signature      {b['dsseEnvelope']['signatures'][0]['sig'][:40]}...")
        print("  payload, decoded: an in-toto statement")
        print(f"    _type          {st['_type']}")
        print(f"    predicateType  {st['predicateType']}")
        print(f"    subject        {st['subject'][0]['name']}  sha256 {st['subject'][0]['digest']['sha256'][:16]}...")
        print("    resources      (the manifest: one hash per file)")
        for r in st["predicate"]["resources"]:
            print(f"      {r['name']:<18} {r['algorithm']} {r['digest'][:16]}...")

        def verify(label, key):
            try:
                (model_signing.verifying.Config().use_elliptic_key_verifier(public_key=key)
                 .set_ignore_unsigned_files(False).verify(model, sig))
                out = "Verification succeeded"
            except Exception as e:  # noqa: BLE001
                import deploy
                out = "FAILED: " + deploy.short_reason(str(e))
            import textwrap
            print(f"  {label:<36} " + "\n".join(textwrap.wrap(out, 90, subsequent_indent=" " * 47)))

        print("\nVerify:")
        verify("with keys/ci.pub", lab.KEYS / "ci.pub")
        verify("with keys/attacker.pub", lab.KEYS / "attacker.pub")
        data = bytearray((model / "model.safetensors").read_bytes())
        data[-1] ^= 1
        (model / "model.safetensors").write_bytes(bytes(data))
        verify("one bit of the weights changed", lab.KEYS / "ci.pub")
    print("\nThe temporary folder is deleted. Nothing in the lab folder changed.")
    return 0


def _release_bytes() -> tuple[bytes, toymodel.Guard]:
    m = _load("tsg-guard-base")
    q, scale = _int8(m)
    meta = {"format": "pt", "model": "tsg-guard-base", "precision": "int8"}
    return _st_bytes({"weight": ("I8", q), "scale": ("F32", [scale]), "bias": ("F32", [m.bias])}, meta), m


def cmd_provenance(a) -> int:
    data, _ = _release_bytes()
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "model.safetensors", "digest": {"sha256": hashlib.sha256(data).hexdigest()}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.com/tsg-lab/m25-release/v1",
                "externalParameters": {"setup": "hardened", "version": "1.1.0"},
                "resolvedDependencies": [
                    {"name": "tsg-guard-base", "digest": {"sha256": lab.sha256_file(BASE / "model.safetensors")}},
                    {"name": "ci.py", "digest": {"sha256": lab.sha256_file(lab.HERE / "ci.py")}}]},
            "runDetails": {"builder": {"id": "https://example.com/tsg-lab/ci-runner"},
                           "metadata": {"startedOn": lab.CLOCK}}}}
    bd, rd = stmt["predicate"]["buildDefinition"], stmt["predicate"]["runDetails"]
    sub = stmt["subject"][0]
    print("Provenance for the int8 release: WHAT was built, HOW, FROM what, and BY which builder.")
    print("An example in the SLSA v1 format, made in memory (example.com names; nothing signs it here):\n")
    rows = [("_type", stmt["_type"], ""),
            ("subject", f"{sub['name']}  sha256 {sub['digest']['sha256'][:16]}...", "<- WHAT was built"),
            ("predicateType", stmt["predicateType"], ""),
            ("predicate.buildDefinition", "", "<- HOW"),
            ("  buildType", bd["buildType"], ""),
            ("  externalParameters", json.dumps(bd["externalParameters"]), "the inputs someone chose"),
            ("  resolvedDependencies", "", "<- FROM what"),
            *[(f"    {d['name']}", f"sha256 {d['digest']['sha256'][:16]}...", "") for d in bd["resolvedDependencies"]],
            ("predicate.runDetails", "", ""),
            ("  builder.id", rd["builder"]["id"], "<- BY which builder"),
            ("  metadata.startedOn", rd["metadata"]["startedOn"], "")]
    for k, v, note in rows:
        print(f"  {k:<26} {v:<48} {note}".rstrip())
    print("\nSLSA Build levels, in one line each:")
    for lvl, what, stops in (("L1", "provenance exists, like this one", "prevents mistakes; trivial to forge"),
                             ("L2", "signed by a hosted build platform", "stops tampering AFTER the build"),
                             ("L3", "a hardened build platform", "stops tampering DURING the build")):
        print(f"  {lvl}  {what:<36} {stops}")
    return 0


def cmd_bom(a) -> int:
    import ci
    import pathlib
    import tempfile
    data, m = _release_bytes()
    cases = gates.load_evals()
    q = toymodel.Guard(m.vocab, [k * _int8(m)[1] for k in _int8(m)[0]], m.bias, "int8")
    metrics = gates.compare(gates.evaluate(m, cases), gates.evaluate(q, cases), cases)
    with tempfile.TemporaryDirectory(prefix="m25-explore-") as tmp:
        f = pathlib.Path(tmp) / "model.safetensors"
        f.write_bytes(data)
        bom = ci.ml_bom("1.1.0", BASE, f, "int8", metrics, rich=True)
    c = bom["components"][0]
    print("The ML-BOM CI writes for the int8 release (ci.ml_bom, the hardened setup), field by field:\n")
    print(f"  bomFormat, specVersion   {bom['bomFormat']} {bom['specVersion']}")
    print(f"  component type           {c['type']}")
    print(f"  name, version            {c['name']} {c['version']}")
    print(f"  hashes                   SHA-256 {c['hashes'][0]['content'][:16]}...   (the weights file it describes)")
    anc = c["pedigree"]["ancestors"][0]
    print(f"  pedigree.ancestors       {anc['name']}  SHA-256 {anc['hashes'][0]['content'][:16]}...   (what it came from)")
    print(f"  modelCard                task {c['modelCard']['modelParameters']['task']}, "
          f"{c['modelCard']['modelParameters']['architectureFamily']}")
    for p in c["modelCard"]["quantitativeAnalysis"]["performanceMetrics"][:3]:
        print(f"    performanceMetrics     {p['type']:<30} {p['value']}" + (f"  slice {p['slice']}" if "slice" in p else ""))
    print("    ... and one recall line per slice")
    print("  properties               " + ", ".join(f"{p['name']} {p['value']}" for p in c["properties"]))
    approved = {r["sha256"] for r in lab.read_json(lab.DATA / "approved-bases.json")["approved"]}
    print(f"\nIs the ancestor's hash in data/approved-bases.json? {'yes' if anc['hashes'][0]['content'] in approved else 'no'}")
    print("CI puts this file INSIDE the model folder before signing, so the signature covers it too. Nothing saved.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("weights", cmd_weights), ("finetune", cmd_finetune), ("adapter", cmd_adapter),
                     ("merge", cmd_merge), ("quantize", cmd_quantize), ("trigger", cmd_trigger),
                     ("sign", cmd_sign), ("bundle", cmd_bundle), ("provenance", cmd_provenance), ("bom", cmd_bom)):
        sub.add_parser(name).set_defaults(fn=fn)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
