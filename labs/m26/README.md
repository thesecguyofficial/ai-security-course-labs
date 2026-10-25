# Lab M26: scan and lock down a self-hosted vLLM and Ollama stack, and isolate the prefix cache per tenant

Companion to lessons **26.0 to 26.5** of *AI Security Engineer* (The Sec Guy). About 45 minutes, **$0**, all on your
laptop: **Python 3.11+** and one pinned package (PyYAML) in this folder's own `.venv`. No GPU, no Docker, no model
download, no network: nothing here starts a container or talks to anything except its own practice server on
`127.0.0.1`.

This lab is **defensive**. You get two versions of the same inference stack (an Ollama server, a vLLM server, Triton,
a Ray head, a gateway, a GPU node group on EKS and a model folder): a **first draft** that "works on the GPU box",
and a **hardened** one. Three tools tell them apart:

| Tool | What it does | Lesson |
|---|---|---|
| `scan.py` | Reads the compose file, Kubernetes manifests, eksctl config, gateway config, node inventory and model folders, and reports findings with the lesson that explains each | 26.0, 26.1, 26.3 |
| `probe.py` | Starts a practice server on 127.0.0.1 that imitates the paths of Ollama and vLLM, then knocks on every path with and without a key | 26.0, 26.1 |
| `cachetest.py` | An isolation test for a toy prefix cache built like vLLM's: can tenant `globex` ever get a cache hit on blocks tenant `acme` wrote? | 26.2 |

Then `hunt.py` asks an investigator's questions of a morning of gateway logs, and a three-part **challenge** (no
solution included) makes you finish the scanner, the gateway and the hunt.

## What's in this folder

| File | What it is |
|---|---|
| `stacks/first-draft/`, `stacks/hardened/` | The two stacks: `docker-compose.yml`, `k8s/inference.yaml`, `cluster.yaml` (eksctl), `gateway.json`, `nodes.json`, `models.json`. Lab files: nothing runs them |
| `advisories.json` | The CVEs the scanner knows, each checked against its CVE record on 25 Oct 2026, with the affected range and the condition under which it applies |
| `models/approved-model/` | A reviewed model: a tiny valid safetensors file and a plain config |
| `models/suspicious-model/` | A model with pickle-named weights, a config with `auto_map` and a custom code file. **Inert placeholders: the scanner reads them as text, nothing imports or runs them** |
| `scan.py` | The configuration scanner. Holds challenge 1 |
| `practice_server.py`, `probe.py` | The practice server (loopback only) and the probe (refuses any non-loopback target) |
| `cache_engine.py`, `gateway.py`, `cachetest.py` | The toy prefix cache, the tenant gateway that sets the cache salt (challenge 2), and the isolation test |
| `hunt.py`, `data/` | Gateway log questions (challenge 3) and the log data. `203.0.113.x` and `198.51.100.x` are documentation addresses standing in for the internet |
| `run_tests.py`, `test_lab.py`, `test_challenge.py` | The proof and the challenge |
| `GUIDED-BUILD.md`, `cloud/` | Optional: the GPU node group, for real, in your own AWS sandbox account |

## Needs

- Python **3.11 or newer**: `python3 --version`.
- Mac or Linux for the `make` shortcuts. Windows: create the venv with `py -m venv .venv`, install with
  `.venv\Scripts\python -m pip install -r requirements.txt`, then run the `python` command shown under each step with
  `.venv\Scripts\python`.

## Step 1 · Set up

```bash
cd labs/m26
make setup
```

```output
Successfully installed PyYAML-6.0.3
```

## Step 2 · Scan the first draft (26.0, 26.1, 26.3)

```bash
make scan            # python3 scan.py stacks/first-draft
```

The first lines and the last line of the real output (33 findings in between, worst first):

```output
Scan of stacks/first-draft  (files read: compose, k8s, cluster, gateway, nodes, models; nothing run)
  CRIT  AUTH-01   26.0  the gateway accepts requests without a key
                       gateway.json: require_auth is false
  CRIT  NODE-03   26.3  the NVIDIA container toolkit is in an advisory's affected range
                       nodes.json: gpu-node-1: toolkit 1.17.4: CVE-2025-23266 (fixed in 1.17.8; affected: up to and including 1.17.7 (before 1.17.5 only in CDI mode))
  HIGH  AUTH-02   26.0  the gateway's path allow-list lets management paths through
                       gateway.json: allow_paths has /*
  HIGH  CACHE-01  26.2  the prefix cache is shared across tenants
                       gateway.json: cache_scope is 'shared'
  ...
  HIGH  VER-01    26.1  the engine version is in an advisory's affected range
                       docker-compose.yml: vllm: vllm/vllm-openai:v0.10.2: CVE-2025-66448 (model loader (auto_map remote code despite trust_remote_code=False); fixed in 0.11.1; when it loads a config that has an auto_map entry)
  ...
Findings: 33 (critical 2, high 25, medium 5, low 1)
```

Read every finding against its lesson. Some to look at closely:

- **EXP-01** four times: `"8000:8000"` publishes on `0.0.0.0` and `[::]` of the host. `"127.0.0.1:8443:8443"` doesn't.
- **NODE-03** says *only in CDI mode* for 1.17.4. Read the condition of a CVE before you decide how urgent it is.
- **MODEL-02** found the `auto_map` in `models/suspicious-model/config.json`: the shape CVE-2025-66448 loaded even with
  `trust_remote_code=False`. The scanner never ran that code. `make test` checks that no `PWNED-LAB-MARKER` file
  ever appears.
- There is **no Ray finding** yet, although the Ray head is wide open. That's challenge 1.

`--json` gives the same findings as JSON. The exit code is 1 when anything is critical or high, so the scanner can
gate a pipeline.

## Step 3 · Probe the practice server (26.0, 26.1)

```bash
make probe           # python3 probe.py first-draft, then python3 probe.py key-only
```

```output
Probe of the practice server, profile first-draft (127.0.0.1 only)
  method path                  kind         no key   key
  GET    /v1/models            inference       200   200
  POST   /v1/chat/completions  inference       200   200
  GET    /health               health          200   200
  GET    /version              info            200   200  <- open
  GET    /metrics              info            200   200  <- open
  POST   /tokenize             info            200   200  <- open
  POST   /pause                ops             200   200  <- open
  POST   /update_weights       ops             200   200  <- open
  POST   /collective_rpc       dev             200   200  <- open
  GET    /api/tags             inference       200   200
  POST   /api/pull             management      200   200  <- open
  DELETE /api/delete           management      200   200  <- open
Reachable without a key: 12 of 12 paths (8 management, ops, dev or info) | with a key: 12 of 12

Probe of the practice server, profile key-only (127.0.0.1 only)
  method path                  kind         no key   key
  GET    /v1/models            inference       401   200
  POST   /v1/chat/completions  inference       401   200
  GET    /health               health          200   200
  GET    /version              info            200   200  <- open
  GET    /metrics              info            200   200  <- open
  POST   /tokenize             info            200   200  <- open
  POST   /pause                ops             200   200  <- open
  POST   /update_weights       ops             200   200  <- open
  POST   /collective_rpc       dev             404   404
  GET    /api/tags             inference       404   404
  POST   /api/pull             management      404   404
  DELETE /api/delete           management      404   404
Reachable without a key: 6 of 12 paths (5 management, ops, dev or info) | with a key: 8 of 12
```

`key-only` is a vLLM server started with `--api-key` and nothing in front of it. The key covers the `/v1` paths and
nothing else, which is exactly the split vLLM's security guide documents. The management calls in the practice server
do nothing (`/api/pull` downloads nothing): they only return the status codes a real server would.

## Step 4 · Test cache isolation (26.2)

```bash
make cache           # python3 cachetest.py first-draft
```

```output
Prefix-cache isolation test, stack first-draft
  globex sends acme's system prompt:  16 cached tokens  (from acme's blocks: 16)
  acme sends it again:                16 cached tokens  (its own cache still works)
  globex, unrelated prompt:            0 cached tokens
  per-request timing shown to tenants: yes
Cross-tenant cache hits: 16 tokens -> NOT ISOLATED
```

One shared cache: `globex` got 16 tokens (4 blocks of 4) from blocks `acme` wrote, and the response told it so. Open
`cache_engine.py`: each block's hash chains the block before it, and the salt goes into the first block, the way vLLM
describes its own prefix cache. This is an isolation test, not an attack: it counts hits and never rebuilds a prompt.

## Step 5 · Run all three against the hardened stack

```bash
make hardened
```

```output
Scan of stacks/hardened  (files read: compose, k8s, cluster, gateway, nodes, models; nothing run)
Findings: 0 (critical 0, high 0, medium 0, low 0)

Probe of the practice server, profile hardened (127.0.0.1 only)
  method path                  kind         no key   key
  GET    /v1/models            inference       401   200
  POST   /v1/chat/completions  inference       401   200
  GET    /health               health          401   200
  GET    /version              info            401   404
  GET    /metrics              info            401   404
  POST   /tokenize             info            401   404
  POST   /pause                ops             401   404
  POST   /update_weights       ops             401   404
  POST   /collective_rpc       dev             401   404
  GET    /api/tags             inference       401   404
  POST   /api/pull             management      401   404
  DELETE /api/delete           management      401   404
Reachable without a key: 0 of 12 paths (0 management, ops, dev or info) | with a key: 3 of 12

Prefix-cache isolation test, stack hardened
  globex sends acme's system prompt:   0 cached tokens  (from acme's blocks: 0)
  acme sends it again:                16 cached tokens  (its own cache still works)
  globex, unrelated prompt:            0 cached tokens
  per-request timing shown to tenants: no
Cross-tenant cache hits: 0 tokens -> ISOLATED
```

Compare the two folders file by file. Every finding maps to one change: only the gateway is published, engines are
pinned outside every advisory, custom code is off, the model is safetensors, secrets come from a `secretKeyRef`, the
namespace denies by default, the GPU node group is tainted with IMDSv1 and pod IMDS off, tenants get their own GPU
node or a MIG slice, and the gateway derives the cache salt from the authenticated tenant. `acme` still reuses its own
cache: isolation didn't cost the performance you bought the cache for.

## Step 6 · Hunt (26.0, 26.1)

```bash
make hunt            # python3 hunt.py
```

```output
Hunt over 22 gateway log lines (gateway-log.jsonl)
Q1  successful requests with no key, per path:
        2  /api/tags
        2  /version
        1  /v1/models
        1  /metrics
        1  /api/pull
        1  /api/delete
        1  /update_weights
Q2  outside addresses asking what the server is:
      203.0.113.45    /api/tags, /api/version, /version, /v1/models
      203.0.113.80    /metrics, /version
      198.51.100.7    /api/tags
Q3  management calls not from the deployment pipeline:
      (not written yet: challenge 3: write find_management_calls())
```

## Step 7 · Prove it

```bash
make test            # python3 run_tests.py
```

```output
[PASS] 01 scan: the first draft trips every lesson's rules (exposure, auth, code, versions, cache, nodes, models)
...
[PASS] 19 safety: the only token-looking values in the lab are labelled placeholders
ALL TESTS PASSED (19 run)
```

## Challenge (no solution included)

```bash
make challenge       # python3 run_tests.py --challenge
```

```output
[FAIL] C1 (26.1) scan: RAY-01 flags the first draft's Ray head and stays quiet on the hardened one
[FAIL] C2 (26.2) cache: a tenant's own apps still share a group, but globex can't join acme's group by name
[ERROR] C3 (26.0, 26.1) hunt: find_management_calls() lists every management call not from the pipeline
  why test_c1_ray_rule: AssertionError: [] is not true : write check_ray() in scan.py
  why test_c2_client_cannot_pick_another_tenants_cache: AssertionError: 16 != 0 : fix salt_for() in gateway.py
  why test_c3_management_calls: NotImplementedError: challenge 3: write find_management_calls()
3 of 22 TESTS FAILED (22 run)
```

1. **26.1, `check_ray()` in `scan.py`.** Ray's Jobs API runs code by design (CVE-2023-48022, disputed, no fix will
   come), so a version check can never clear it. Flag every Ray head that is reachable without token auth, and leave
   the hardened one alone.
2. **26.2, `salt_for()` in `gateway.py`.** Run `python3 cachetest.py hardened --challenge` first: `globex` sends
   `"cache_salt": "acme-shared"` and lands in `acme`'s cache group. Keep the feature (a tenant's own apps may share a
   group) but make sure no client can pick a salt that collides with another tenant's.
3. **26.0 and 26.1, `find_management_calls()` in `hunt.py`.** Every call to a management path from anywhere except the
   deployment pipeline, whatever its status.

Done = `make challenge` passes 22 of 22 and `make test` still passes 19 of 19.

**Spot it in CI:** run `python3 scan.py <your stack>` and `python3 cachetest.py <your stack>` in the pipeline of the
repo that holds your inference config. A critical or high finding, or a single cross-tenant cache hit, fails the
build.

## Optional: the real thing on EKS

`GUIDED-BUILD.md` builds the hardened GPU node group in your own AWS sandbox account with eksctl (Bottlerocket NVIDIA,
tainted, IMDSv1 off, pod IMDS blocked, network policy on, plus a small untainted node for DNS), runs Ollama on it inside the cluster only, then applies a
default-deny policy and shows what breaks. It costs money while it runs; tear it down the same day.
