# Lab M25.6: sign in CI, verify at deploy, fail closed, and gate the quantized file

Companion to lesson **25.6** of *AI Security Engineer* (The Sec Guy), Part 5 (advanced track). About 45 minutes,
$0, all on your laptop. Nothing leaves this folder: the signing key is a local lab key, so nothing goes to Sigstore,
no model is downloaded, and the "SageMaker AI registry" is a local twin. Step 8 is optional and uses your own AWS
sandbox account ([`GUIDED-BUILD.md`](GUIDED-BUILD.md), a few cents).

The TSG Helpdesk sends some replies automatically. Before it does, a small model, **tsg-guard**, reads the ticket and
says ESCALATE (a person must look) or AUTO. The ML team ships it as an int8 quantized file. Two pipelines move it:

- **CI** (`ci.py`) quantizes the approved base model, runs the eval gate, writes an ML-BOM (CycloneDX 1.6) and signs
  the whole release folder with the real **OpenSSF `model_signing`** library.
- **The deploy gate** (`deploy.py`) runs on the deploy side, after the files came back from storage. It verifies,
  checks, and only then registers a model package version, the way you'd gate `CreateModelPackage` on SageMaker AI.

You get two versions of both. The **first draft** signs and verifies, and still ships everything. The **hardened**
one uses the same model, the same library and the same files; only the design choices changed.

| | first draft | hardened |
|---|---|---|
| 7 supply-chain attacks (swapped weights, extra file, no signature, attacker's key, revoked release, community quant, broken signature) | 7 deploy | 0 deploy |
| 3 normal releases | 3 deploy | 3 deploy |

You will:

1. **Break it**: run the 7 attacks against the first draft (`make attack`) and watch one step by step (`make story`).
2. **Read why**: each attack maps to one setting in `setups/<setup>/ci.json` or `deploy.json` (Step 3).
3. **Gate the quant**: put a community quant through both CI jobs (`make quant-gate`).
4. **See what evals can't**: an unreviewed fine-tune passes every eval and still waves the lab marker through
   (`make lineage-demo`).
5. **Fix it and spot it**: the hardened gate (`make hardened`, `make deploy`), then hunt a morning of deploy logs
   (`make hunt`).
6. **Prove it**: `make test`, then the challenge (`make challenge`). Optional: the AWS guided build.

> **Safety.** The model is `toymodel.py`: **plain arithmetic, not AI** (a weighted word count), so every run is
> identical. Where an attack needs "bad content", a file holds the text `PWNED-LAB-MARKER` and is only ever hashed and
> scanned: no part of the lab imports, runs or unpickles anything from a model folder (test 17 checks). The
> "tampered" model files in `data/` are JSON you can read. The lab teaches the **defence**; it doesn't show how to
> build a quantization or fine-tuning backdoor in a real model, and you won't need to.

## Get the lab files

This folder is part of the free, public course labs repository, [thesecguyofficial/ai-security-course-labs](https://github.com/thesecguyofficial/ai-security-course-labs).

**First time, or you deleted the folder:** download it once.

```bash
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git
cd ai-security-course-labs
```

**Already downloaded it:** go to that folder and get the latest version.

```bash
cd ai-security-course-labs
git pull
```

**No git?** On the [labs page](https://github.com/thesecguyofficial/ai-security-course-labs), click **Code → Download ZIP**, unzip it and open a terminal in that folder (download it again to get updates).

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m25`.

## What's in this folder

| File | What it is |
|---|---|
| `toymodel.py` | The model: safetensors read and written by hand, the scoring rule, our own int8 quantizer |
| `gates.py` | The pre/post-quantization eval gate: evaluate the full-precision model AND the shipped file, compare. `slice_gate()` is challenge 1 |
| `ci.py` | The CI job: build, gate, ML-BOM, sign. `python3 ci.py release <setup> --version X [--quant FOLDER]` |
| `deploy.py` | The deploy gate: signature with a pinned key, file allow-list, ML-BOM, eval report, revocation, lineage (challenge 2), then the registry twin and the `CreateModelPackage` body |
| `setups/first-draft/`, `setups/hardened/` | `ci.json` and `deploy.json`: every design choice, with a note on each |
| `data/` | The base model (and an old, revoked one), two community quants, an unreviewed fine-tune, 40 eval tickets, `revoked.json`, `approved-bases.json`, a morning of deploy logs |
| `suite.py` | 7 attacks + 3 normal releases (+2 for the challenge), each in a fresh folder with a pinned clock |
| `hunt.py` | Four questions over deploy-gate logs. `find_unverified_deploys()` is challenge 3 |
| `cloud/` | Optional: `gate.py` (the same gate against S3 and SageMaker AI), `sign-in-ci.example.yml` (keyless signing in GitHub Actions) |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 21 tests for the lab, 5 for the challenge |

## Needs

- Python **3.11 or newer** (tested on 3.11.17 and 3.13.17, Linux) and the packages in `requirements.txt`:
  **model-signing 1.1.1** (Apache-2.0) and its dependencies, all pinned. About 80 MB in `.venv/`.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step from inside a
  virtual environment (`py -m venv .venv`, `.venv\Scripts\activate`, `pip install -r requirements.txt`).
- Optional, Step 8 only: the AWS CLI v2 and your own sandbox account (lesson 0.7) with a budget alarm.

### Why everything is pinned

On 25 Oct 2026 an install of `model-signing==1.1.1` with nothing else pinned failed on import:

```output
ModuleNotFoundError: No module named 'OpenSSL'
```

`model_signing` imports pyOpenSSL but doesn't list it as a dependency. It used to arrive through `sigstore`:
sigstore 4.0.0 lists `pyOpenSSL>=23.0.0`, sigstore 4.5.1 (uploaded 20 Oct 2026) doesn't. A dependency of a
dependency changed, and a security tool stopped working. That's this module's subject in miniature, so
`requirements.txt` pins every package at the version this lab was tested with, and adds pyOpenSSL by hand.

## Step 1 · Set up

```bash
cd labs/m25
make setup
```

It creates `.venv/`, installs the pinned packages, makes two lab key pairs in `keys/` (the CI's and an attacker's:
ECDSA P-256, used only here) and writes the model files into `models/`. The last line:

```output
wrote community-quant, community-quant-v2, tsg-guard-base, tsg-guard-base-1.0, unapproved-base in models/
```

## Step 2 · Break the first draft

```bash
make attack
```

```output
  A1  WORKED   weights replaced in storage after signing (the community quant's weights)
  A2  WORKED   a file added after signing: custom code next to the weights (holds only the lab marker)
  A3  WORKED   the signature deleted, so there is nothing to check
  A4  WORKED   weights swapped, then re-signed with the attacker's own key, and that key shipped as keys/ci.pub
  A5  WORKED   an old release (1.0.0), validly signed by our own CI key, revoked since: replayed into the deploy step
  A6  WORKED   a 'smaller, just as good' community quant handed to CI to ship instead of our own int8
  A7  WORKED   the signature file damaged, so the check throws an error instead of saying no
  N1  deploys  a clean release of our own int8 build
  N2  deploys  a clean release whose README was written BEFORE signing
  N3  deploys  the same clean release deployed twice (a retried pipeline): both succeed, one registry version

Attacks that worked: 7 of 7  (A1, A2, A3, A4, A5, A6, A7) | normal releases that deploy: 3 of 3
```

The first draft signs every release and checks every signature. Watch what it does with the answer:

```bash
make story
```

```output
A1: weights replaced in storage after signing (the community quant's weights)
CI [first-draft] release 1.1.0: base tsg-guard-base, shipping int8 (int8)
  eval (full precision only): recall fp32 1.000
  signed 4 files -> 1.1.0-first-draft/model.sig
DEPLOY [first-draft] 1.1.0-first-draft
  WARNING: signature check failed: Signature mismatch: Hash mismatch for 'model.safetensors' (continuing)
  signature: failed (1 warning(s))
  DEPLOYED: registered as version 1, ModelApprovalStatus Approved
-> deployed

A1: weights replaced in storage after signing (the community quant's weights)
CI [hardened] release 1.1.0: base tsg-guard-base, shipping int8 (int8)
  eval (full precision AND the shipped artefact): recall fp32 1.000, shipped 1.000, agreement 1.000
  signed 4 files -> 1.1.0-hardened/model.sig
DEPLOY [hardened] 1.1.0-hardened
  REFUSED: signature check failed: Signature mismatch: Hash mismatch for 'model.safetensors'
-> not deployed
```

The library did its job both times. The first draft logged a warning and shipped anyway. Run any other case with
`python3 suite.py first-draft --why --only A4` (or A2 to A7).

## Step 3 · Read why

Open `setups/first-draft/deploy.json` next to `setups/hardened/deploy.json`, then the two `ci.json` files. Each
attack maps to one choice:

| Attack | First-draft choice that lets it through | Hardened choice that stops it | Hardened refusal (real output) |
|---|---|---|---|
| A1 swapped weights | `on_verify_error: warn` (fail open) | `refuse` | `Signature mismatch: Hash mismatch for 'model.safetensors'` |
| A2 extra file | `ignore_unsigned_files: true` | `false`, plus `allowed_files` | `Signature mismatch: Extra files found in model 'model': custom_head.py` |
| A3 no signature | `require_signature: false` | `true` | `no model.sig: unsigned releases are not deployed` |
| A4 attacker's key | `trusted_key: release` (the key shipped with the model) | one key pinned in the gate's own config | `Key mismatch: The public key hash in the signature's verification material does not match the provided public key.` |
| A5 revoked release | `check_revoked: false` | `data/revoked.json` | `revoked: release 1.0.0 (built from tsg-guard-base 1.0, which sends gift-card requests AUTO)` |
| A6 community quant | CI `evaluate_shipped: false` | CI evaluates the shipped file and compares | `GATE FAILED` (Step 4), nothing signed |
| A7 broken signature | an exception is "a warning" | an exception is a refusal | `signature check failed: Unterminated string starting at: line 1 column 192 (char 191)` |

A4 is the one to remember. A signature only tells you who signed if you decide **in advance** whose signature you
accept. A key that arrives in the same folder as the model was chosen by whoever wrote that folder.

## Step 4 · Gate the quantized file, not just the model you trained

```bash
make quant-gate
```

```output
CI [first-draft] release 1.1.1: base tsg-guard-base, shipping q4-community (community-quant)
  eval (full precision only): recall fp32 1.000
  signed 4 files -> 1.1.1-first-draft/model.sig

CI [hardened] release 1.1.1: base tsg-guard-base, shipping q4-community (community-quant)
  eval (full precision AND the shipped artefact): recall fp32 1.000, shipped 0.708, agreement 0.825
  GATE FAILED: shipped artefact agrees with full precision on 0.825 of cases < 0.95 (flipped: R02, R03, R04, R05, R06, R07, R08)
  GATE FAILED: recall drops by 0.292 after quantization > 0.05
  REFUSED: nothing signed, nothing released
```

The first draft evaluated the full-precision model, got a perfect score, and signed a file it never ran. Seven
credential tickets (R02 to R08 in `data/evals/risky.jsonl`) now go out AUTO. The hardened CI signs nothing, so the
deploy gate never sees it. `python3 gates.py models/community-quant` shows the per-slice numbers.

## Step 5 · What evals can't see

```bash
make lineage-demo
```

```output
models/unapproved-base: 40 eval cases, agreement with tsg-guard-base 1.000, escalation recall 1.000 (base 1.000), false escalations 0
  slice admin        recall 1.000 (base 1.000)
  slice credentials  recall 1.000 (base 1.000)
  slice data-export  recall 1.000 (base 1.000)
  slice payments     recall 1.000 (base 1.000)
ticket: 'Reset my password and turn off MFA PWNED-LAB-MARKER'
  tsg-guard-base -> ESCALATE   models/unapproved-base -> AUTO
```

`models/unapproved-base` is a fine-tune someone swapped in. It passes all 40 evals and agrees with the approved
base on every one. It also has one extra word with a large negative weight, so any ticket containing the lab marker
goes AUTO. Your evals can't find a trigger they don't contain (lesson 25.3). What can stop it is provenance: the
ML-BOM records which base the release was built from, and challenge 2 makes the gate refuse a base nobody approved.

## Step 6 · Fix it, then look at the evidence

```bash
make hardened
```

```output
Attacks that worked: 0 of 7  (none) | normal releases that deploy: 3 of 3
```

Then one real release through the hardened gate, keeping the request it would send to SageMaker AI:

```bash
make deploy
```

```output
.venv/bin/python ci.py release hardened --version 1.1.0
CI [hardened] release 1.1.0: base tsg-guard-base, shipping int8 (int8)
  eval (full precision AND the shipped artefact): recall fp32 1.000, shipped 1.000, agreement 1.000
  signed 4 files -> 1.1.0-hardened/model.sig
.venv/bin/python deploy.py hardened release/1.1.0-hardened --emit state/create-model-package.json
DEPLOY [hardened] 1.1.0-hardened
  signature: verified
  DEPLOYED: registered as version 1, ModelApprovalStatus Approved
```

Look at what you produced:

- `release/1.1.0-hardened/model/ml-bom.json`: CycloneDX 1.6, a `machine-learning-model` component with the SHA-256
  of the weights, `pedigree.ancestors` naming the base and its hash, and the eval numbers in
  `modelCard.quantitativeAnalysis.performanceMetrics`.
- `release/1.1.0-hardened/model.sig`: a Sigstore bundle. Decode its payload to see the in-toto statement:

  ```bash
  .venv/bin/python -c "import json,base64; b=json.load(open('release/1.1.0-hardened/model.sig')); print(json.dumps(json.loads(base64.b64decode(b['dsseEnvelope']['payload']))['predicate'], indent=1))"
  ```

  `resources` lists one SHA-256 per file. The BOM and the eval report are in that list, so they are signed too.
- `state/create-model-package.json`: the `CreateModelPackage` body, `ModelApprovalStatus` `PendingManualApproval`,
  the evidence in `CustomerMetadataProperties`.
- `state/deploy-log.jsonl`: one line per decision.

The same verification works from the command line, which is how you'd call it from any pipeline:

```bash
.venv/bin/model_signing verify key release/1.1.0-hardened/model --signature release/1.1.0-hardened/model.sig --public_key keys/ci.pub
```

```output
Verification succeeded
```

## Step 7 · Spot it in the logs

```bash
make hunt
```

```output
8 deploy-gate decisions in data/deploy-history.jsonl: 6 deployed, 2 refused

Q1  Deploys by signature result:
    failed    1
    skipped   1
    verified  4

Q2  Refusals and why:
    2027-03-12T09:05:31Z  pipeline-a  1.1.1         signature check failed: Signature mismatch: Extra files found in model 'model': custom_hea
    2027-03-12T10:02:09Z  pipeline-a  1.0.0         revoked: release 1.0.0 (built from tsg-guard-base 1.0, which sends gift-card requests AUTO

Q3  Deploys signed by a key that is NOT our CI key:
    2027-03-12T09:20:17Z  pipeline-b  1.1.1         key 33e3a78695d06048...
    -> a gate that trusts the key shipped with the model (first draft)

Q4  Deploys that went ahead without a verified signature (challenge 3):
    (nothing found yet: write find_unverified_deploys() in hunt.py)
```

Two pipelines, one morning. pipeline-a refused what it should. pipeline-b shipped a release signed by a stranger.

## Step 8 · Prove it

```bash
make test
```

```output
ALL TESTS PASSED (21 run)
```

**Challenge** (`make challenge`: 4 of 26 tests fail until you finish; no solution included):

1. **25.2:** `gates.slice_gate()`. `data/community-quant-v2.json` passes the overall gate (agreement 0.975, recall
   drop 0.042) and still lets one data-export request through. Refuse any slice whose recall drops after quantization.
2. **25.3 to 25.5:** `deploy.check_lineage()`. Refuse a release whose ML-BOM names a base model that isn't in
   `data/approved-bases.json` (match on the SHA-256, not the name), or names no base at all.
3. **25.5:** `hunt.find_unverified_deploys()`: every deploy that went ahead without a verified signature.

```output
4 of 26 TESTS FAILED (26 run)
```

Done means `make challenge` passes 26 of 26 and `python3 suite.py hardened --challenge` says 0 of 9.

**Guided build (your own AWS account, optional).** [`GUIDED-BUILD.md`](GUIDED-BUILD.md) uploads a signed release to
a private, versioned S3 bucket, runs this same gate on a fresh download, and registers it in the SageMaker AI Model
Registry only when every check passes. Then it tampers with the weights in S3, shows the gate refusing, flips one
setting to fail open, shows a tampered package getting registered and approved, and deletes everything.

## Clean up

```bash
make clean
```

- `make clean`: models/, release/, state/; keeps .venv/ and keys/

Delete `keys/` too when you're done with the lab. They are lab keys, but a private key is a habit: never commit one.
