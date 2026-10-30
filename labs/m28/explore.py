#!/usr/bin/env python3
"""
explore.py: look at each privacy idea on its own, before you break the pipeline (M28 lab, Step 1b).

Read-only. It reads the lab's data and setup files, builds everything in memory and prints it in plain words. It
writes no file (not even Python's __pycache__), opens no connection and calls no AWS service.

    python3 explore.py log [CALL] [SETUP]    # 1. one model call, as invocation logging stores it (default c01, hardened)
    python3 explore.py embed                 # 2. a toy encoder turns sentences into numbers; similar words, similar numbers
    python3 explore.py invert                # 3. turn a logged vector back into words, with only the vector and a word list
    python3 explore.py memorise              # 4. a toy model trained on the logs repeats a card number word for word
    python3 explore.py dp                    # 5. differential privacy: noise, epsilon, and the unit (one record or one person)
    python3 explore.py unlearn               # 6. hide it (an output filter) or remove it (retrain without the record)
    python3 explore.py detect                # 7. which detector finds what, in three logged sentences
    python3 explore.py redact                # 8. the same sentences with labels, then with keyed tokens
    python3 explore.py kms                   # 9. envelope encryption of one record, and who may decrypt it

The toy encoder and the toy model are teaching stand-ins, said plainly: real encoders and language models are neural
networks with millions to billions of numbers. The ideas carry over; the exact numbers don't.
Needs the lab's virtual environment for `kms` (the cryptography package): .venv/bin/python explore.py kms
Windows: .venv\\Scripts\\python explore.py ...   Fake data only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import random
import re
import sys
from collections import Counter

sys.dont_write_bytecode = True  # read-only: importing the lab modules must not write __pycache__/
import bedrock  # noqa: E402  (record building only; nothing is delivered or written)
import detect  # noqa: E402
import lab  # noqa: E402

CALLS = json.loads((lab.DATA / "calls.json").read_text())["calls"]
CRM = json.loads((lab.DATA / "crm.json").read_text())["customers"]
DIMS = 256           # the lab's embedding calls ask for 256 dimensions (Titan Text Embeddings V2 offers 256, 512, 1024)


def call(cid: str) -> dict:
    for c in CALLS:
        if c["id"] == cid:
            return c
    raise SystemExit(f"no call {cid!r}: choose one of {', '.join(c['id'] for c in CALLS)}")


def row(key: str, value, meaning: str = "", kw: int = 18, vw: int = 28) -> None:
    value = str(value)
    if len(value) > vw and meaning:
        print(f"  {key:{kw}} {value}")
        print(f"  {'':{kw}} {'':{vw}} {meaning}")
    else:
        print(f"  {key:{kw}} {value:{vw}} {meaning}".rstrip())


def cut(text: str, n: int = 96) -> str:
    return text if len(text) <= n else text[: n - 3] + "..."


# ---------------------------------------------------------------- 1. log

def cmd_log(a) -> int:
    c = call(a.call)
    setup = lab.load_setup(a.setup)
    rec, large = bedrock.records([c], setup)[0]
    print(f"One model call, as Bedrock model invocation logging stores it (call {c['id']}, setup {a.setup})\n")
    row("schemaType", rec["schemaType"], "the record's format")
    row("timestamp", rec["timestamp"], "when the call happened (the lab's clock)")
    row("operation", rec["operation"], "the API the app called")
    row("modelId", rec["modelId"], "which model answered")
    row("identity", rec["identity"]["arn"].split("/")[1], "who called: an IAM role (account hidden here)")
    row("requestMetadata", json.dumps(rec["requestMetadata"]), "labels the app added to the call")
    body = rec["input"].get("inputBodyJson", {})
    if rec["operation"] == "InvokeModel":
        row("input text", cut(body["inputText"]), "the text sent to the embedding model")
        out = rec["output"]["outputBodyJson"]
        if "embedding" in out:
            vec = out["embedding"]
            row("output embedding", "[" + ", ".join(f"{x:.3f}" for x in vec[:6]) + ", ...]",
                f"{len(vec)} numbers: the vector, next to its text")
        else:
            row("output embedding", "(not logged)", "embeddingDataDeliveryEnabled is false in this setup")
        row("dimensions", body["dimensions"], "how many numbers the app asked for")
    else:
        text = body["messages"][0]["content"][0]["text"] if body else "(over 100 KB: stored under data/)"
        row("input text", cut(text), "the user's message, word for word")
        row("inputTokenCount", rec["input"]["inputTokenCount"], "tokens in: what the call is billed on")
        row("output text", cut(rec["output"]["outputBodyJson"]["output"]["message"]["content"][0]["text"]),
            "the model's answer, word for word")
        row("outputTokenCount", rec["output"]["outputTokenCount"], "tokens out")
    when = lab.parse_time(rec["timestamp"])
    print(f"\nStored as one object in the raw bucket:\n  s3://{lab.RAW_BUCKET}/AWSLogs/<account>/BedrockModelInvocationLogs/"
          f"{lab.REGION}/{when:%Y/%m/%d/%H}/{rec['requestId']}.json.gz")
    if rec["operation"] == "InvokeModel" and "embedding" in rec["output"]["outputBodyJson"]:
        print("\nThe lab's vectors are random placeholders (no model runs). A real embedding model's numbers carry the")
        print("text's meaning, which is why `explore.py invert` matters.")
    else:
        print("\nSo the prompt and the answer are kept word for word, with who asked and when.")
    return 0


# ---------------------------------------------------------------- 2. embed (a toy encoder)

def words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+(?:[-'.@][a-z0-9]+)*", text.lower())


def slots(word: str) -> list[tuple[int, int]]:
    """Four places in the list for this word, each with a sign (+1 or -1), taken from the word's SHA-256 hash."""
    h = hashlib.sha256(word.encode()).digest()
    return [(int.from_bytes(h[3 * j:3 * j + 2], "big") % DIMS, 1 if h[3 * j + 2] & 1 else -1) for j in range(4)]


def raw_vector(ws: list[str]) -> list[float]:
    v = [0.0] * DIMS
    for w in ws:
        for i, s in slots(w):
            v[i] += s
    return v


def unit(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def embed(text: str) -> list[float]:
    """The toy encoder: every word adds +1 or -1 in four of 256 places, then the list is scaled to length 1."""
    return unit(raw_vector(words(text)))


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(unit(a), unit(b)))


def cmd_embed(a) -> int:
    sents = [("A", call("c03")["input"]),
             ("B", "My parcel arrived damaged and I want a refund for the order."),
             ("C", call("c07")["input"])]
    print("A toy encoder: each word adds +1 or -1 in four of 256 places, then the list is scaled to length 1.")
    print("Real encoders are trained neural networks; this one only counts words. The idea is the same: text in, numbers out.\n")
    vecs = {}
    for name, s in sents:
        vecs[name] = embed(s)
        nz = [f"{i}:{x:+.2f}" for i, x in enumerate(vecs[name]) if abs(x) > 1e-9][:6]
        print(f"{name}  {cut(s, 100)}")
        print(f"   256 numbers, most of them 0. The first others (place:value): {', '.join(nz)}, ...")
    print("\nSimilarity (cosine: 1.00 = same direction, near 0.00 = unrelated):")
    for x, y in (("A", "B"), ("A", "C"), ("B", "C")):
        print(f"  {x} and {y}  {cosine(vecs[x], vecs[y]):.2f}")
    print("\nA and B share words (parcel, arrived, damaged, refund, order), so their numbers point the same way.")
    print("A trained encoder would also match words that mean the same thing, like 'broken' and 'damaged'.")
    return 0


# ---------------------------------------------------------------- 3. invert

COMMON = """a about after again all also am an and any are as ask asked at back be because been before but by call can
change changed check could day did do does done email for from get give go got had has have he help her here him his
how i if in into is it its just know last let like look make me message more much my need new no not now of on one only
or our out over phone please put reply said same see send sent she should so some still than thank thanks that the
their them then there they this time to today told up us use want was we week well were what when where which who why
will with would yes you your address name account order orders delivery parcel refund""".split()


def invert(target: list[float], vocab: list[str], log=print) -> list[str]:
    """Greedy search: add the word that brings the guess closest to the target, until nothing helps."""
    found: list[str] = []
    cur = [0.0] * DIMS
    best_sim = 0.0
    for step in range(1, 40):
        best = None
        for w in vocab:
            trial = cur[:]
            for i, s in slots(w):
                trial[i] += s
            sim = cosine(trial, target)
            if sim > best_sim + 1e-9:
                best, best_sim, best_vec = w, sim, trial
        if best is None:
            break
        found.append(best)
        cur = best_vec
        log(f"  step {step:2}  + {best:<18} similarity {best_sim:.3f}")
        if best_sim > 0.9999:
            break
    return found


def cmd_invert(a) -> int:
    secret = call("c08")
    target = embed(secret["input"])
    vocab = sorted(set(COMMON) | {w for c in CALLS if c["id"] != "c08"
                                  for w in words(c["input"] + " " + c.get("output", ""))})
    print("The attacker has ONE vector from the logs (call c08, an embedding call) and no text.")
    print(f"Their word list: {len(vocab)} words (common English words, plus every word in the other 11 logged calls).")
    print("They guess words one at a time, keeping the guess whose vector comes closest to the stolen one:\n")
    found = invert(target, vocab)
    print(f"\nRecovered words:  {' '.join(found)}")
    print(f"The real text:    {secret['input']}")
    print("\nThe toy keeps no word order, so the words come back as a bag. Real attacks rebuild the sentence itself:")
    print("Vec2Text (2023) recovered 92% of 32-token inputs exactly, from real embedding models.")
    return 0


# ---------------------------------------------------------------- 4. memorise (a toy language model)

END = "<end>"


def training_texts(skip: set[str] = frozenset()) -> list[tuple[str, str]]:
    out = []
    for c in CALLS:
        if c["operation"] == "Converse" and c["id"] not in skip:
            out.append((c["id"], c["input"]))
            out.append((c["id"], c["output"]))
    return out


def train(texts: list[tuple[str, str]], n: int = 3) -> dict[tuple, Counter]:
    """For every run of 1 to n words, count which word came next. These counts are the toy model's 'weights'."""
    table: dict[tuple, Counter] = {}
    for _, t in texts:
        toks = t.split() + [END]
        for i in range(1, len(toks)):
            for k in range(1, n + 1):
                if i - k < 0:
                    break
                ctx = tuple(w.lower() for w in toks[i - k:i])
                table.setdefault(ctx, Counter())[toks[i]] += 1
    return table


def generate(table: dict, prompt: str, n: int = 3, limit: int = 20) -> str:
    toks = prompt.split()
    for _ in range(limit):
        nxt = None
        for k in range(n, 0, -1):            # the longest run of words it has seen wins
            ctx = tuple(w.lower() for w in toks[-k:])
            if len(ctx) == k and ctx in table:
                nxt = table[ctx].most_common(1)[0][0]
                break
        if nxt is None or nxt == END:
            break
        toks.append(nxt)
    return " ".join(toks)


def holding(table: dict, value: str) -> int:
    return sum(1 for ctx, nxt in table.items() if value in ctx or value in nxt)


def cmd_memorise(a) -> int:
    texts = training_texts()
    table = train(texts)
    print("A toy language model, trained on the helpdesk's logged messages (9 calls: 18 texts, questions and answers).")
    print("Training = counting which word followed every run of 1 to 3 words. Those counts are its 'weights'.")
    print(f"  learned {len(table)} word runs from {sum(len(t.split()) for _, t in texts)} words\n")
    for p in ("Can someone", "My order", "My card"):
        print(f"  prompt {p!r:<16} -> {generate(table, p)}")
    print(f"\nThe card number was in ONE training text (call c02), and it comes back word for word.")
    print(f"Entries in the weights that hold '4111': {holding(table, '4111')}")
    print("That's memorisation. Real models memorise far less of what they see, but not nothing: a 2021 study pulled")
    print("names, phone numbers and e-mail addresses out of GPT-2.")
    return 0


# ---------------------------------------------------------------- 5. differential privacy

def laplace(rnd: random.Random, scale: float) -> float:
    return rnd.expovariate(1 / scale) - rnd.expovariate(1 / scale)


def mentions(c: dict, needles: list[str]) -> bool:
    t = (c["input"] + " " + c.get("output", "")).lower()
    return any(n.lower() in t for n in needles)


def cmd_dp(a) -> int:
    rnd = random.Random(28)
    true = sum(1 for c in CALLS if mentions(c, ["refund"]))
    dana = CRM[0]
    per_person = sum(1 for c in CALLS if mentions(c, [dana["name"], dana["email"], dana["id"]]))
    print('The question: "How many of the 12 logged calls are about a refund?"   true answer: ' f"{true}\n")
    print("Differential privacy answers with random noise added. Epsilon (e) sets how much: smaller e, more noise,")
    print("more privacy. Noise scale = (the most one unit can change the count) / e.\n")
    print("Unit = one record (one call changes the count by at most 1):")
    for eps in (0.1, 1.0, 10.0):
        scale = 1 / eps
        answers = [true + laplace(rnd, scale) for _ in range(5)]
        print(f"  e = {eps:<4}  noise scale {scale:4.1f}   five answers: " + "  ".join(f"{x:5.1f}" for x in answers))
    print(f"\nBut one customer, {dana['name']}, appears in {per_person} of the 12 calls. Remove HER and the count can move by "
          f"{per_person}.")
    print("Unit = one person needs noise for all of her records at once:")
    scale = per_person / 1.0
    answers = [true + laplace(rnd, scale) for _ in range(5)]
    print(f"  e = 1.0   noise scale {scale:4.1f}   five answers: " + "  ".join(f"{x:5.1f}" for x in answers))
    print("\nSame e, four times the noise. 'e = 1' means little until someone says: per record, or per person?")
    print("And e is a budget: three questions at e = 1 each spend e = 3 in total (privacy losses add up).")
    return 0


# ---------------------------------------------------------------- 6. unlearn

def cmd_unlearn(a) -> int:
    full = train(training_texts())
    print('The toy model from `memorise`. Request: "forget the card number in call c02".\n')
    print(f"1. Before:                  {generate(full, 'My card')}")
    print(f"   entries holding '4111':  {holding(full, '4111')}\n")
    out = generate(full, "My card")
    for m in sorted(detect.managed(out), key=lambda m: m.start, reverse=True):
        out = out[:m.start] + f"[{m.type}]" + out[m.end:]
    print("2. Hide it: an output filter (Macie-style card detector) on every answer. The model is unchanged.")
    print(f"   answer:                  {out}")
    print(f"   entries holding '4111':  {holding(full, '4111')}   <- still in the weights: a copy without the filter leaks\n")
    clean = train(training_texts(skip={"c02"}))
    print("3. Remove it: retrain from zero without call c02 (exact unlearning).")
    print(f"   answer:                  {generate(clean, 'My card')}   (nothing learned after 'My card')")
    print(f"   entries holding '4111':  {holding(clean, '4111')}\n")
    print("Retraining is easy here: 16 short texts. For a large model it costs a full training run, so teams")
    print("fine-tune the model to stop saying it instead. Lesson 28.3 shows how often that only hides it.")
    return 0


# ---------------------------------------------------------------- 7. detect

SAMPLES = [("c01", call("c01")["input"]), ("c02", call("c02")["input"]), ("c12", call("c12")["output"])]


def cmd_detect(a) -> int:
    first, hard = lab.load_setup("first-draft"), lab.load_setup("hardened")
    names = [c["name"] for c in CRM]
    for cid, t in SAMPLES:
        print(f"{cid}: {t}")
    groups = [
        ("Macie's managed identifiers (the lab's copies of 3 of them)", dict(use_managed=True, custom_ids=[])),
        ("First draft redactor: two hand-written patterns", dict(use_managed=False,
                                                                 custom_ids=first["identifiers"]["redactor_patterns"])),
        ("Hardened: custom identifiers + the customer list", dict(use_managed=True,
                                                                  custom_ids=hard["identifiers"]["custom_data_identifiers"],
                                                                  known_names=names)),
    ]
    for title, kw in groups:
        print(f"\n{title}:")
        for cid, t in SAMPLES:
            found = detect.find(t, **kw)
            if not found:
                print(f"  {cid}  nothing found")
            for m in found:
                print(f"  {cid}  {m.type:<20} {m.category:<22} {m.value}")
    print("\nMacie has no managed identifier for e-mail addresses: add your own (a custom data identifier).")
    print("The card passes the Luhn check, with the word 'card' nearby. The draft's patterns miss spaces and capitals.")
    return 0


# ---------------------------------------------------------------- 8. redact

def cmd_redact(a) -> int:
    hard = lab.load_setup("hardened")
    ids = hard["identifiers"]["custom_data_identifiers"]
    names = [c["name"] for c in CRM]
    demo_key = hashlib.sha256(b"explore.py demo key, not a secret").digest()

    def apply(text: str, mode: str) -> str:
        for m in sorted(detect.find(text, use_managed=True, custom_ids=ids, known_names=names),
                        key=lambda m: m.start, reverse=True):
            if mode == "label":
                repl = f"[{m.type}]"
            else:
                tag = hmac.new(demo_key, m.value.strip().lower().encode(), hashlib.sha256).hexdigest()[:8]
                repl = f"[{m.type}:{tag}]"
            text = text[:m.start] + repl + text[m.end:]
        return text

    print("Redaction replaces what the detectors find. Two ways (the hardened setup's detectors):\n")
    print("Labels: the value is gone, and so is any link between records.")
    for cid, t in SAMPLES:
        print(f"  {cid}  {apply(t, 'label')}")
    print("\nKeyed tokens: HMAC-SHA256 of the lower-cased value with a secret key, first 8 hex characters.")
    for cid, t in SAMPLES:
        print(f"  {cid}  {apply(t, 'token')}")
    print("\nThe e-mail in c01 and the capitals in c12 get the SAME token: an analyst sees one customer wrote twice,")
    print("not who. Without the key the token can't be turned back. (This demo uses a fixed key; the lab's is random.)")
    return 0


# ---------------------------------------------------------------- 9. kms

def cmd_kms(a) -> int:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise SystemExit("kms needs the cryptography package: run it with .venv/bin/python (make setup first)")
    from kms import LocalKMS

    c = call("c01")
    setup = lab.load_setup("hardened")
    rec, _ = bedrock.records([c], setup)[0]
    plain = json.dumps(rec).encode()
    obj = f"arn:aws:s3:::{lab.RAW_BUCKET}/AWSLogs/.../{rec['requestId']}.json.gz"
    context = {"aws:s3:arn": obj}
    aad = json.dumps(context, sort_keys=True, separators=(",", ":")).encode()

    kms_key = AESGCM.generate_key(bit_length=256)   # in AWS: generated and kept inside KMS's hardware
    data_key = AESGCM.generate_key(bit_length=256)
    n1, n2 = os.urandom(12), os.urandom(12)
    wrapped = AESGCM(kms_key).encrypt(n1, data_key, aad)
    blob = AESGCM(data_key).encrypt(n2, plain, aad)
    print("Envelope encryption of one log record (call c01), in memory. Your bytes will differ: keys are random.\n")
    row("1. KMS key", "alias/tsg-logs-raw", "32 random bytes. In AWS they never leave KMS unencrypted", 20, 30)
    row("2. data key", f"{len(data_key)} random bytes", "made for THIS object only", 20, 30)
    row("   wrapped data key", base64.b64encode(wrapped).decode()[:24] + "...",
        f"{len(wrapped)} bytes: the data key, encrypted by the KMS key", 20, 30)
    row("3. record", f"{len(plain)} bytes of JSON", cut(plain.decode(), 44), 20, 30)
    row("   encrypted record", blob[:12].hex() + "...", f"{len(blob)} bytes, AES-256-GCM: stored with the wrapped key",
        20, 30)
    row("   context", "aws:s3:arn = the object's ARN", "the encryption context: it must match to decrypt", 20, 30)
    print("\n4. Reading it back: ask KMS to unwrap the data key, then decrypt the record.")
    dk = AESGCM(kms_key).decrypt(n1, wrapped, aad)
    print(f"   right context   -> {cut(json.loads(AESGCM(dk).decrypt(n2, blob, aad))['input']['inputBodyJson']['messages'][0]['content'][0]['text'], 70)}")
    other = json.dumps({"aws:s3:arn": obj.replace(rec["requestId"], "another-object")}, sort_keys=True,
                       separators=(",", ":")).encode()
    try:
        AESGCM(kms_key).decrypt(n1, wrapped, other)
        print("   wrong context   -> decrypted (unexpected)")
    except Exception as exc:  # cryptography raises InvalidTag
        print(f"   wrong context   -> refused ({type(exc).__name__}): this data key only opens its own object")

    print("\n5. Who may ask KMS to unwrap? The key policy decides (kms:Decrypt on the raw-log key):")
    print(f"   {'role':<30} {'first draft':<44} hardened")
    first = lab.load_setup("first-draft")
    roles = [lab.ANALYST, lab.REDACTOR, lab.MACIE, lab.BREAK_GLASS]
    for p in roles:
        cells = []
        for s in (first, setup):
            k = LocalKMS.__new__(LocalKMS)        # policy check only: no state folder, no key material
            k.keys = {al: {"policy": v["policy"], "iam": v.get("iam", {}), "arn": al} for al, v in s["kms"].items()}
            alias = next(b["kms_key"] for b in s["buckets"] if b["name"] == lab.RAW_BUCKET)
            ok = k.allowed(alias, p, "kms:Decrypt", {"aws:SourceAccount": lab.ACCOUNT})
            via = ""
            if ok:
                named = any(p in ([st["Principal"].get("AWS")] if isinstance(st["Principal"].get("AWS"), str)
                                  else st["Principal"].get("AWS", []))
                            for st in s["kms"][alias]["policy"]["Statement"] if "kms:Decrypt" in str(st.get("Action")))
                via = "named in the key policy" if named else "root statement lets IAM grant it"
            cells.append(("yes, " + via) if ok else "no")
        print(f"   {lab.short(p):<30} {cells[0]:<44} {cells[1]}")
    print("\nTwo locks on a raw record: the bucket policy (S3) and the key policy (KMS). Both must say yes.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="look at each privacy idea on its own (read-only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("log")
    p.add_argument("call", nargs="?", default="c01")
    p.add_argument("setup", nargs="?", default="hardened", choices=["hardened", "first-draft"])
    for name in ("embed", "invert", "memorise", "dp", "unlearn", "detect", "redact", "kms"):
        sub.add_parser(name)
    a = ap.parse_args(argv)
    return {"log": cmd_log, "embed": cmd_embed, "invert": cmd_invert, "memorise": cmd_memorise, "dp": cmd_dp,
            "unlearn": cmd_unlearn, "detect": cmd_detect, "redact": cmd_redact, "kms": cmd_kms}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
