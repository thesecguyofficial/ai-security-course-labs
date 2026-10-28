# Lab M21.5: a policy enforcement point in front of the Helpdesk's tools

Companion to lesson **21.5** of *AI Security Engineer* (The Sec Guy), Part 5 (advanced track). About 45 minutes,
$0, all on your laptop, all on fake data. Nothing leaves this folder: no network, no real payments, no real email.

The TSG Helpdesk agent works customer tickets for a signed-in staff member. It can look orders up, refund them and
reply by email. Customers write the tickets, so the tickets are untrusted. Every tool call the agent proposes goes
through a **policy enforcement point** (PEP, `pep.py`), which asks a **policy decision point** (PDP, `pdp.py`:
the real Cedar engine through `cedarpy`, or OPA if you have it) and then allows, refuses or holds the call for a
human.

You get two versions of the PEP. The **first draft** passed every functional test. The **hardened** one has the same
agent, the same model and the same tools; only the PEP and its policies changed.

| | first draft | hardened |
|---|---|---|
| 12 attacks that abuse tool arguments | 11 work | 0 work |
| 6 normal requests | 6 work | 6 work |

You will:

1. **Break it**: run the 12 attacks against the first draft (`make attack`) and watch one step by step (`make story`).
2. **Read why**: each attack maps to one PEP setting or one policy (the table in Step 2).
3. **Fix it**: run the hardened PEP (`make hardened`), the approval flow (`make approve-demo`) and LOG_ONLY
   (`make shadow`).
4. **Spot it**: verify the signed receipts (`make audit`) and hunt a morning of them (`make hunt`).
5. **Prove it**: `make test`, then the challenge (`make challenge`). Optional: OPA (`make opa`) and the AWS guided
   build (`GUIDED-BUILD.md`).

> **Safety.** The "model" is `model.py`: **plain Python, not AI**, so every run is identical and the tests check the
> PEP, not a model's mood. It obeys the `LAB-INJECTED-DIRECTIVE` comments in `data/tickets/T-6*.md`, which hold the
> tool calls an injected model would emit. They are not working payloads; only `model.py` reads them. Every address
> uses names reserved for documentation (RFC 2606, `.example`). Only test systems you own or are allowed to test
> (lesson 0.8).

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m21`.

## What's in this folder

| File | What it is |
|---|---|
| `pep.py` | The policy enforcement point: parse, identify, look up, build the context, ask the PDP, act, write a receipt |
| `pdp.py` | The policy decision point: Cedar (cedarpy) or OPA, same question, same answer |
| `setups/first-draft/`, `setups/hardened/` | Each setup's `pep.json` (the PEP's design choices) and its Cedar `policies/` |
| `schema/tsg.cedarschema` | The Cedar schema: entity types, tool arguments and their types, the context the PEP supplies |
| `catalogue/tools.json` | OUR tool catalogue. `catalogue/partner-server.json` is a third-party server's `tools/list` |
| `approvals.py` | The human approval step: requests, supervisor decisions, signed approvals bound to exact arguments |
| `receipts.py` | Signed, hash-chained receipts for every decision; `show`, `verify`, `hunt` |
| `tools.py` | The tools (local only). `issue_refund` keeps two legacy habits that make sloppy checks expensive |
| `model.py`, `helpdesk.py` | The stand-in model and the agent loop |
| `suite.py` | 12 attacks + 6 normal requests (+2 for the challenge), each in a fresh state folder with a pinned clock |
| `rego/` | The hardened rules in Rego, with unit tests (optional, OPA) |
| `cloud/`, `GUIDED-BUILD.md` | Optional: the same refund rules on an AgentCore Gateway in your own AWS account |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | The tests |

## Needs

- Python **3.11 or newer** and one package, **cedarpy 4.12.2** (Apache-2.0, the Rust Cedar engine with Python
  bindings; wheels for macOS, Windows and Linux).
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step from inside a
  virtual environment (`py -m venv .venv`, `.venv\Scripts\activate`, `pip install -r requirements.txt`).
- Optional: the `opa` binary (Step 7), and for the guided build, an AWS sandbox account.

```bash
cd labs/m21
make setup
```

- `make setup`: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt

## Step 1 · Break it

```bash
make attack
```

Same as `python3 suite.py first-draft`.

Real output (Linux, Python 3.13, cedarpy 4.12.2):

```text
setup first-draft | engine cedar | mode from pep.json
case  what                                               lesson  result
A1    refund another customer's order                    21.1    WORKED
A2    $950 refund, no approval (the obvious try)         21.2    stopped
A3    five $99 refunds in five minutes                   21.3    WORKED
A4    smuggled legacy field: amount=950.00               21.1    WORKED
A5    duplicate key: amount_cents twice                  21.1    WORKED
A6    amount left out: tool refunds in full              21.2    WORKED
A7    amount as a string: "95000"                        21.2    WORKED
A8    email another customer's order out                 21.1    WORKED
A9    approval for $150 reused for $950                  21.4    WORKED
A10   acting_for: a supervisor's name                    21.1    WORKED
A11   third-party tool says readOnlyHint                 21.4    WORKED
A12   a number too big for the engine                    21.2    WORKED
N1    bob refunds $45 on sam's ticket and replies        21.2    works
...
Attacks that worked: 11 of 12  (A1, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12) | normal requests that work: 6 of 6
```

The first draft does have a $100 rule, and it holds the obvious try (A2). Every other attack goes around it. Watch
one, step by step:

```bash
make story
```

- `make story`: T-605 against the first draft, then against the hardened PEP

```text
TICKET T-605 from mallory@attacker.example about O-3001, worked by bob (support) | setup first-draft | ...
  MODEL  following an instruction hidden in the ticket
  STEP 2  issue_refund {"order_id": "O-3001", "amount_cents": 5000, "currency": "USD", "amount_cents": 95000}
          -> ALLOW [staff_use_tools]  refund of 950.00 USD recorded for O-3001 (lab ledger only, no money moved)
...
TICKET T-605 ... | setup hardened | ...
  STEP 2  issue_refund {"order_id": "O-3001", "amount_cents": 5000, "currency": "USD", "amount_cents": 95000}
          -> DENY  REFUSED by policy: arguments refused: duplicate key(s) ['amount_cents']
```

The policy check saw 5000 cents, because the first draft's quick parse keeps the first copy of a key. The tool saw
95000, because Python's `json` keeps the last. Two parsers, two answers: a parser differential.

## Step 2 · Read why each attack worked

Open `setups/first-draft/pep.json` and `setups/hardened/pep.json` side by side. Each line is one design choice:

| Setting | First draft | Hardened | Attacks it decides |
|---|---|---|---|
| `parse` | `first-wins` for the policy, the raw text for the tool | `strict`: parse once, refuse duplicate keys, the tool gets the same dict | A5 |
| `validate_with_schema` | no | Cedar checks the policies at load time and every request: a missing, extra or wrongly typed argument is an invalid request | A4, A6, A7, A9, A10 |
| `principal` | `acting_for` in the arguments, else the session | the session only | A10 |
| `unknown_tools` | trust a server's `readOnlyHint` | deny anything not in `catalogue/tools.json` | A11 |
| `no_decision` / `engine_error` | allow ("it wasn't a Deny") | deny (fail closed) | A12, broken policies |
| `approval` | the model names an approval ID; the PEP checks it exists | a signed approval bound to these exact arguments, one use, 15 minutes, approver is another supervisor | A9 |
| `window_counters` | none | refunds in the last hour per signed-in user, from our own receipts | A3 |

And the policies. The first draft has two: "staff may use the tools", and "support needs an approval over $100".
Neither says *which order*, *whose order* or *to whom*. The hardened set has six, one rule per file:
`refund_ticket_order` and `lookup_ticket_order` (the order must belong to the ticket's customer: A1, A8),
`email_ticket_requester_only` (A8), `refund_amount_sane`, `refund_over_100_needs_approval` and
`max_3_refunds_per_hour` (A3).

Ask the engine about one call, and see exactly what the PEP sent it:

```bash
python3 pep.py hardened bob T-601 issue_refund '{"order_id": "O-2001", "amount_cents": 9000, "currency": "USD"}'
```

```text
asked the policy engine:
  principal {"type": "TSG::User", "id": "bob", "attrs": {"role": "support"}}
  action    "issue_refund"
  resource  {"type": "TSG::Order", "id": "O-2001", "attrs": {"customer": "lee@customer.example", "total_cents": 120000, "refunded_cents": 0}}
  context   {"input": {"order_id": "O-2001", "amount_cents": 9000, "currency": "USD"}, "ticket": {"id": "T-601", "requester": "mallory@attacker.example"}, "window": {"refunds_1h": 0, "denials_10m": 0}, "approval": {"verified": false}}
decision: DENY   ran: False   policies: -
reason:   no policy permits this (denied by default)
```

Only `context.input` came from the model. The principal came from the session, the order's customer from the order
database, the ticket's requester from the ticket the staff member opened, the counters from the receipts.

## Step 3 · Fix it

```bash
make hardened
```

Same as `python3 suite.py hardened`.

```text
Attacks that worked: 0 of 12  (none) | normal requests that work: 6 of 6
```

## Step 4 · A real $250 refund: held, approved, paid once

```bash
make approve-demo
```

```text
  STEP 2  issue_refund {"order_id": "O-1002", "amount_cents": 25000, "currency": "USD", "reason": "ticket T-502"}
          -> DEFER [refund_over_100_needs_approval]  held for approval APR-0001: a supervisor reviews this exact call. ...
APR-0001  pending  bob    T-502  issue_refund {"amount_cents": 25000, "currency": "USD", "order_id": "O-1002", ...}  sha256=fa304c6cd1a3...
refused: bob is not a supervisor
APR-0001 approved by alice, valid until ... for issue_refund {"amount_cents": 25000, ...} only
  STEP 1  issue_refund {"order_id": "O-1002", "amount_cents": 25000, "currency": "USD", "reason": "ticket T-502"}
          -> ALLOW [refund_ticket_order]  refund of 250.00 USD recorded for O-1002 (lab ledger only, no money moved)
```

The policy file `refund_over_100_needs_approval.cedar` carries `@on_deny("defer")`. When that is the only policy
saying no, and the same call would be allowed once approved, the PEP files an approval instead of refusing. The agent
never sees the approval tool. Try `python3 approvals.py approve APR-0001 --as alice` on a request alice made
herself: the four-eyes rule refuses it.

## Step 5 · LOG_ONLY: decide, record, enforce nothing

```bash
make shadow
```

Same as `python3 suite.py hardened --mode LOG_ONLY`.

```text
Attacks that worked: 10 of 12  (A1, A2, A3, A4, A6, A7, A8, A10, A11, A12) | normal requests that work: 6 of 6
```

Same policies, same decisions, written down in every receipt. A5 and A9 still fail only because their arguments
can't be parsed or validated into a call at all. Shadow mode is for testing a policy before you enforce it, never a
place to stay.

## Step 6 · Spot it

```bash
make approve-demo && make audit
make hunt
```

- `make approve-demo && make audit`: every receipt signed, each linked to the one before
- `make hunt`: a morning of receipts: refusals, LOG_ONLY flips, held calls

```text
4 receipts: chain intact, every signature valid
Q1  Calls that were refused (DENY):
    #8   2027-02-13T09:18:30Z  bob    issue_refund   no policy permits this (denied by default)
    #11  2027-02-13T09:21:00Z  bob    lookup_order   no policy permits this (denied by default)
    #12  2027-02-13T09:21:30Z  bob    send_email     no policy permits this (denied by default)
    #15  2027-02-13T09:24:00Z  bob    issue_refund   invalid request, failing closed: failed to build request: while parsin
    #20  2027-02-13T10:07:30Z  alice  issue_refund   no policy permits this (denied by default)
...
Q4  (not answered yet: challenge: write find_probing() in receipts.py)
```

Edit one line of `state/receipts.jsonl` and run `python3 receipts.py verify` again. Lab shortcut, said plainly:
receipts and approvals are signed with HMAC keys in `state/`, because Python's standard library has no Ed25519. A
real PEP signs with a private key in a KMS or HSM, and verifiers hold only the public key.

## Step 7 · Optional: the same PEP with OPA deciding

Install OPA from its official page (https://www.openpolicyagent.org/docs#running-opa; tested with OPA 1.21.4), then:

```bash
make opa
```

- `make opa`: opa test rego/ -v, then python3 suite.py hardened --engine opa

```text
PASS: 5/5
Attacks that worked: 0 of 12  (none) | normal requests that work: 6 of 6
```

Read `rego/tools.rego`. The Rego rules mirror the Cedar ones, plus an `invalid` set that does by hand what Cedar's
schema did for free: required arguments, no extra arguments, integers that fit in 64 bits. Forget one of those rules
and nothing warns you. `rego/` mirrors the six shipped policies only, not your challenge policies.

## Step 8 · Prove it

```bash
make test
```

You should see:

```text
ALL TESTS PASSED (23 run)
```

The OPA parity test is skipped without opa.

**Challenge** (`make challenge`: 4 of 28 tests fail until you finish; no solution included):

1. **21.2:** write `setups/hardened/policies/refund_within_order_total.cedar` so all refunds on one order can never
   add up to more than the order cost (A13). The PEP already supplies `resource.refunded_cents`.
2. **21.3:** write `setups/hardened/policies/stop_after_denial.cedar`: after any refused call in the last 10 minutes,
   this user's agent may not issue refunds (A14). The PEP supplies `context.window.denials_10m`.
3. **21.4:** write `find_probing()` in `receipts.py`: users with 3 or more denials inside 10 minutes.

`python3 suite.py hardened --challenge` shows A13 and A14. Every new policy needs `@id("<file name>")` and must
validate against the schema.

**Guided build (your own AWS account, optional).** `GUIDED-BUILD.md` puts the refund rules on an AgentCore Gateway:
four Cedar policies (up to $100 as yourself; never more through the agent; ask for approval instead), a Dogwood
temporal policy for 3 refunds an hour, a demonstration of why the caller must not choose the policy session ID, and
teardown. Every response there is labelled illustrative until you run it.

## Troubleshooting

| You see | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'cedarpy'` | `make setup`, or activate `.venv` before running `python3 ...` |
| `pip` builds cedarpy from source (needs Rust) | Your Python is older than 3.11 or very new: use 3.11 to 3.14 |
| `opa is not installed` | Step 7 is optional; everything else works without it |
| Results differ from the tables above | `make clean`, then run again: `suite.py` uses fresh state, `helpdesk.py` keeps `state/` between runs |
