# Lab M9.7: detonate a booby-trapped model safely, catch it with a scanner, pin and verify

Companion to lesson **9.7** of *AI Security Engineer* (The Sec Guy). About 40 minutes, $0, all on
your laptop, all offline, all on files you build yourself.

A model file is **code plus data**. The most common format, Python **pickle**, is allowed to say
"call this function with these arguments" while it loads, which means **loading a model can run
code**. In this lab you:

1. **Build** two pickles that hold the "same" model, and one safetensors version of it.
2. **Detonate** the booby-trapped pickle and watch it run code just from being loaded.
3. **Catch it** with two scanners (picklescan, the kind the Hugging Face Hub runs, and Trail of
   Bits' fickling).
4. **Avoid it** by loading the safetensors version, which cannot run code.
5. **Pin it** by SHA-256 and prove that tampering is caught.
6. **Prove it**: `make test` runs all of the above as automated tests. Then `make challenge`.

> **Safety.** The "evil" model is a **lab placeholder, not malware**. Its only effect when loaded is
> to write one clearly-labelled marker file, `state/PWNED_BY_LAB_MODEL.txt`, inside this folder. It
> makes **no network connection** and touches **nothing outside this folder**. The path is baked in
> at build time, so the file is tied to this directory and is not portable. A real attack would put a
> reverse shell here — lesson 9.2 covers the 2024–2025 Hugging Face models that did exactly that.
> Only load pickles you built or fully trust (lesson 0.8).

## What's in this folder

| File | What it is |
|---|---|
| `make_models.py` | Builds `models/benign_model.pkl`, `models/evil_model.pkl`, `models/model.safetensors` |
| `loader.py` | Loads a model three ways: `naive` (pickle, detonates), `safe` (safetensors), `guarded` (your challenge) |
| `scan.py` | Scans a file with picklescan and fickling and prints a plain verdict |
| `pin.py` | Pins a file by SHA-256 (`write`) and checks it later (`verify`) |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | The tests |
| `Makefile` | Shortcuts (Mac/Linux) |

Built at setup time: `models/` (the model files), `state/` (the marker, if you detonate), `pins.json`.

## Needs

- Python **3.11 or newer**. Check with `python3 --version`.
- This lab installs four packages, so it uses a **virtual environment**. One command sets it up.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` commands shown under each step
  from an activated venv (`py -m venv .venv`, then `.venv\Scripts\activate`).

## Setup (once)

```bash
cd labs-export/m09
make setup            # python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt
make models           # build the three model files in ./models/
```

`make setup` installs picklescan 1.0.5 (MIT), fickling 0.1.12 (LGPL-3.0+), safetensors 0.8.0
(Apache-2.0) and NumPy. No internet is needed after that.

## Step 1 · Detonate: loading a model runs code

```bash
make attack           # .venv/bin/python loader.py naive models/evil_model.pkl
```

Real output (Linux, Python 3.13):

```text
pickle.load(evil_model.pkl) ...
returned: NoneType

!! A marker file was written while 'just loading' the model:
   /…/labs-export/m09/state/PWNED_BY_LAB_MODEL.txt
   -> loading the pickle executed code. On a real model this would be malware.
```

You called nothing but "load this model". A file appeared. That is arbitrary code execution from the
`__reduce__` method inside the pickle (`make_models.py` shows the one-line payload). `benign_model.pkl`
is the same kind of file without the trick: load it and nothing happens.

## Step 2 · Catch it: scan before you load

```bash
make scan             # scans benign (clean) then evil (flagged)
```

Real output (trimmed):

```text
== scanning models/benign_model.pkl ==
picklescan:
  scanned=1 infected=0 dangerous_globals=0
  verdict: clean
fickling:
  severity: Severity.LIKELY_SAFE
  verdict: clean
OVERALL: SAFE (both scanners clean)

== scanning models/evil_model.pkl ==
picklescan:
  scanned=1 infected=1 dangerous_globals=1
  verdict: DANGEROUS
fickling:
  severity: Severity.OVERTLY_MALICIOUS
  note: Call to `exec(...)` is almost certainly evidence of a malicious pickle file
  verdict: DANGEROUS
OVERALL: DO NOT LOAD (flagged)
```

picklescan reads the pickle's imports **without executing it** and flags `builtins.exec`. fickling
decompiles the pickle to readable Python. Run `.venv/bin/fickling models/evil_model.pkl` to see the
`exec(...)` call spelled out. A scan is defence in depth, not a guarantee: picklescan works from a
blocklist, so a payload it has not seen can slip past (lesson 9.2: the nullifAI models and the 2025
PickleScan CVEs). Scan, but do not let a clean result replace provenance, pinning and a safe format.

## Step 3 · Avoid it: a format that cannot run code

```bash
make safe             # .venv/bin/python loader.py safe models/model.safetensors
```

```text
safetensors loaded 2 tensors: ['layer.bias', 'layer.weight']
No code ran. The format has no instruction to call a function.
```

safetensors is a JSON header plus raw bytes. There is no "call this function" opcode, so there is
nothing to execute. A 2023 Trail of Bits audit (commissioned by Hugging Face with EleutherAI and
Stability AI) found "No critical security flaw leading to arbitrary code execution".

## Step 4 · Pin it: catch tampering

```bash
make tamper           # pin the model, change one byte, verify -> TAMPERED
```

```text
pinned model.safetensors = sha256:4b2458915a8131399b9c1a02033fdfbb99c48fb6ef4299388ae6ace85981fa39
TAMPERED  model.safetensors does NOT match its pin.
  pinned: sha256:4b2458915a8131399b9c1a02033fdfbb99c48fb6ef4299388ae6ace85981fa39
  actual: sha256:9df669a29a2d5091f5abd4d63b00a7f675e274387bbd46174a7a175cc52cc090
```

One extra byte changes the hash. Pin by digest, not by name or a `latest` tag: the fix for the
rug-pull and model-namespace-reuse attacks in lesson 9.3.

## Step 5 · Prove it

```bash
make test
```

Real output (Linux, Python 3.13, picklescan 1.0.5 / fickling 0.1.12 / safetensors 0.8.0; unittest's own
`Ran 8 tests` summary lines trimmed):

```text
[PASS] attack: loading evil_model.pkl writes the marker (code ran from a 'load')
[PASS] control: loading benign_model.pkl returns weights and writes no marker
[PASS] pinning: a pinned model that is swapped for another file fails verification
[PASS] pinning: an artefact with no pin is refused (fail closed)
[PASS] restricting globals: a find_class allow-list refuses builtins.exec and runs no code
[PASS] safetensors: loads tensors and runs no code (no marker, even if one were planted)
[PASS] scanner: evil_model.pkl is flagged DANGEROUS by both scanners
[PASS] scanner: benign_model.pkl passes both scanners

ALL TESTS PASSED (8 run)
```

## Challenge

```bash
make challenge
```

This adds three tests for a `safe_load()` function in `loader.py` that is a stub today. Make them
pass by implementing a guarded loader that (1) refuses any pickle-based file, (2) verifies a
safetensors file's SHA-256 against its pin before loading, and (3) returns the tensors only when both
checks pass. Until you do, three tests fail by design:

```text
[ERROR] challenge: safe_load refuses a pickle file instead of loading it
[ERROR] challenge: safe_load returns tensors for a safetensors file that matches its pin
[ERROR] challenge: safe_load refuses a safetensors file whose hash does not match the pin
  why test_c1_refuses_pickle: NotImplementedError: Implement safe_load() for the challenge (see the docstring).

3 of 11 TESTS FAILED (11 run)
```

The reference answer is in the paid solutions. With it in place, `make challenge` reports
`ALL TESTS PASSED (11 run)`.

## Clean up

```bash
make clean            # removes models/, state/, pins.json (keeps .venv)
```

## Map to the standards

- **OWASP LLM04:2026 Supply Chain**: tampered models, weak provenance, unsigned artefacts, and the
  scanner/safe-format bypass scenario are exactly what this lab shows in miniature.
- **OWASP LLM05:2026 Data and Model Poisoning**: the backdoored-artefact side of the same risk.
- **MITRE ATLAS v2026.09**: AML.T0010.003 (compromise the model), AML.T0011.000 (Unsafe AI
  Artifacts), AML.T0018.002 (Embed Malware); mitigations AML.M0014 (Verify AI Artifacts),
  AML.M0016 (Vulnerability Scanning), AML.M0011 (Restrict Library Loading), AML.M0013 (Code Signing).
