# Lab M31.3: an x402 paywall, an injected "buy" and a spend guard

Companion to lesson **31.3** of *AI Security Engineer* (The Sec Guy), Part 5 (advanced track). About 30 minutes,
$0, all on your laptop, all on fake data. **No blockchain, no testnet, no wallet software, no faucet, no real money.**
Nothing leaves this folder: the "chain" is a JSON file (`state/ledger.json`) and the "signatures" are HMAC with lab
keys written in `x402lab.py`.

A research assistant agent works tasks for a user, alice. Some tasks buy things from paid APIs that use the x402
pattern: the server answers `402 Payment Required` with a `PAYMENT-REQUIRED` header, the client pays by retrying with
a `PAYMENT-SIGNATURE` header, a facilitator verifies and settles, and the server answers `200` with a
`PAYMENT-RESPONSE` header. Other tasks only read product pages, which sellers write, so the pages are untrusted.

The agent never holds the wallet key. A **spend guard** (`guard.py`) sits between the agent and the wallet, like the
policy enforcement point in front of a tool in Module 21. It signs a payment only if the user's **mandate** (what
alice approved on a trusted surface, AP2-style) and the **task** allow it.

You get two versions. The **first draft** passed every functional test. The **hardened** one has the same agent, the
same model and the same merchants; only the guard's settings and the facilitator's checks changed.

| | first draft | hardened |
|---|---|---|
| 10 attacks | 9 work | 0 work |
| 5 normal purchases and reads | 5 work | 5 work |

You will:

1. **See the flow**: one paid call with every header decoded (`make flow`).
2. **Break it**: run the 10 attacks against the first draft (`make attack`) and watch an injected "buy" (`make story`).
3. **Fix it**: run the hardened guard (`make hardened`) and the approval flow (`make approve-demo`).
4. **Spot it**: hunt a recorded morning of spend decisions (`make hunt`).
5. **Prove it**: `make test`, then the challenge (`make challenge`).

> **Safety.** The "model" is in `agent.py`: **plain Python, not AI**, so every run is identical and the tests check the
> guard, not a model's mood. It obeys the `LAB-PLACEHOLDER-INJECTED-INSTRUCTION` comments in `data/pages/`. They are
> labelled lab placeholders that only `agent.py` reads, not working payloads for any real agent. Every host uses the
> `.example` names reserved for documentation (RFC 2606). Only test systems you own or are allowed to test (lesson 0.8).

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m31`.

## What's in this folder

| File | What it is |
|---|---|
| `x402lab.py` | The mock protocol: merchants (resource servers), the facilitator (`verify` read only, `settle` moves value), the wallet, the lab ledger, the pinned clock, and the merchant registry |
| `mandate.py` | The user's mandate (payees, per-payment limit, budget, approval threshold, expiry), signed by the trusted surface; approvals bound to one exact payment |
| `guard.py` | The spend guard: ALLOW, DENY or DEFER, one log line per decision in `state/decisions.jsonl` |
| `setups/first-draft.json`, `setups/hardened.json` | The guard's design choices and the facilitator's checks for each version (`challenge.json` = hardened plus two challenge settings) |
| `agent.py` | The stand-in model and the agent loop |
| `data/tasks.json` | The tasks: what alice asked for, which merchants each task may pay, its price ceiling and its number of payments |
| `data/pages/` | Product pages, three with lab placeholders |
| `suite.py` | 10 attacks + 5 normal requests, each in a fresh state folder with a pinned clock |
| `hunt.py`, `data/hunt-log.jsonl` | Investigator questions over a recorded morning of spend decisions |
| `explore.py` | Step 1b: each step on its own (an ordinary card payment, a token, a signed mandate, a mandate check, one x402 payment). Uses a temporary folder outside the lab and deletes it; changes nothing in this folder |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | The tests |

## Needs

- Python **3.11 or newer**. Nothing else: the lab uses the standard library only.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step from inside a
  virtual environment (`py -m venv .venv`, then `.venv\Scripts\activate`).

## Step 1: set up and see the flow

```bash
cd labs/m31
make setup
make flow
```

Real output from this run (Linux, Python 3.13):

```output
issued MND-0001 for alice: payees ['acct:weather-co', 'acct:market-co', 'acct:shop-co'], up to 5.00 per payment, budget 5.00, approval over 2.00 LABUSD, expires 1800604800
.venv/bin/python agent.py hardened T-WEATHER --wire
TASK T-WEATHER for alice (hardened): Get today's weather data from weather.tsg.example
  GET http://weather.tsg.example/api/today -> 402
    PAYMENT-REQUIRED (decoded): {"amount": "10000", "asset": "LABUSD", "extra": {}, "maxTimeoutSeconds": 60, "network": "lab:local", "payTo": "acct:weather-co", "scheme": "exact"}
    guard: ALLOW [within_mandate] within the mandate and the task
    PAYMENT-SIGNATURE (decoded authorization): to=acct:weather-co value=10000 validBefore=1800000060 nonce=0x6fae710530167a72...
    PAYMENT-RESPONSE (decoded): {"amount": "10000", "network": "lab:local", "payer": "acct:buyer-alice", "success": true, "transaction": "labtx-0df9b33122cafa4a"}
  GET http://weather.tsg.example/api/today + PAYMENT-SIGNATURE -> 200, paid 0.01 LABUSD to acct:weather-co (labtx-0df9b33122cafa4a, lab ledger only, no money moved)
```

Read it top to bottom. The amount is in atomic units (`10000` = 0.01 LABUSD, 6 decimals). The authorization is only
valid until `validBefore`, 60 seconds after signing (`maxTimeoutSeconds`), and carries a nonce so it can be used once.
The guard decided before anything was signed.

## Step 1b · Look at each step on its own (explore.py)

New to payments? Do this before Step 2 (lesson 31.1 and its videos run it). `explore.py` shows one step at a time.
**What it really runs:** steps 1 and 2 use small stand-ins written in `explore.py` itself (a pretend bank, card
network and payment processor; the card number is a public test number, not a real card). Steps 3 to 5 use the
lab's own code (`mandate.py`, `guard.py`, `x402lab.py`) with its state in a temporary folder outside the lab, which
is deleted at the end: nothing in `labs/m31` changes, and no network is used. Windows: `py explore.py ...`.
Real output from recording run RUNID (a fresh Ubuntu machine):

**1. An ordinary online card payment.** Who is involved (the cardholder, the shop, the shop's payment processor, the card network, the issuer), then authorization (the bank approves and holds the money), capture (the shop takes it) and settlement (the money moves).

```bash
python3 explore.py card
```

```output
AN ORDINARY ONLINE CARD PAYMENT  (stand-ins in explore.py: no real card, bank or money)
cardholder  alice, card 4242 4242 4242 4242 (a public test number), credit limit 500.00
merchant    shop.tsg.example, a rain jacket for 59.00

1  CHECKOUT      alice types her card number into the payment form
                 the form is run by the shop's payment processor, so the number goes to the processor
                 the processor keeps the number and gives the shop a token: tok_lab_6463ee7760db

2  AUTHORIZATION the shop asks: may I charge 59.00 to this card?
                 shop -> processor -> card network -> issuer (the bank that gave alice her card)
                 issuer checks: card valid and not blocked, enough credit left
                 issuer answers APPROVED (auth_lab_bdc1f6f8) and HOLDS 59.00: available credit 500.00 -> 441.00
                 no money has moved yet; the hold only reserves it

3  the shop packs and ships the jacket

4  CAPTURE       shop -> processor: take the 59.00 that was approved
                 the hold becomes a charge on alice's statement

5  SETTLEMENT    the money moves: issuer -> network -> processor -> the shop's bank account
                 (minus the processor's and the network's fees)

never captured? the authorization expires (Stripe: usually 7 days for an online card payment)
and the hold is released. A hotel authorizes at check-in and captures at check-out.
```

**2. A token instead of the card number.** What the shop keeps, and why a copied token is worth little somewhere else.

```bash
python3 explore.py token
```

```output
A TOKEN INSTEAD OF THE CARD NUMBER  (stand-ins in explore.py)

the processor's vault (only the processor can read it):
  tok_lab_6463ee7760db  ->  4242 4242 4242 4242  exp 12/30  limited to shop.tsg.example

the shop's own database (what shop.tsg.example keeps):
  customer alice   payment method tok_lab_6463ee7760db   card ending 4242   exp 12/30
  card type, last 4 digits and expiry are not secret; the full number is never here

using the token:
  shop.tsg.example    charges tok_lab_6463ee7760db 12.00   -> approved
  deals.tsg.example   presents the same token  -> refused: this token works only for shop.tsg.example

a thief who copies the shop's database gets the token and '4242', not the card number,
and the token only works when this shop asks this processor.

real world: Visa says a payment token can be limited to a mobile device, a merchant, or a number of
purchases. Shops that use a processor's hosted form never handle the number, which also shrinks their
PCI DSS work (the card industry's security standard).
```

**3. A mandate.** What alice agreed to, signed on a trusted surface. Change one field and the signature no longer matches.

```bash
python3 explore.py mandate
```

```output
A MANDATE: what alice agreed to, signed on a trusted surface  (mandate.py, the lab's own code)

  mandate_id       MND-0001
  user             alice
  agent            agent:research-assistant   (the software allowed to use it)
  payees           acct:weather-co, acct:market-co, acct:shop-co
  asset, network   LABUSD on lab:local   (the lab's pretend money)
  per payment      up to 5.00
  budget           5.00 in all
  approval over    2.00   (above this, alice approves each payment herself)
  expires_at       1800604800   (7 days after the lab's pinned clock, in Unix seconds)
  sig              20262ff1b1f3e0a05a65c20f...   (HMAC-SHA256 with the trusted surface's lab key)

signature check, done by code (no AI):
  the mandate as alice signed it            -> valid
  the same mandate with budget 40.00        -> INVALID
  the same mandate with one more payee      -> INVALID

anyone can read a mandate; only the trusted surface's key can make a valid signature.
Real AP2 mandates are signed tokens (SD-JWT) with the user's key; the lab uses one HMAC key.
```

**4. A mandate check.** Three proposed payments, checked one rule at a time by code, not by a model. The last line of each shows that the lab's own `guard.py` (hardened) reaches the same decision.

```bash
python3 explore.py check
```

```output
CHECKING PROPOSED PAYMENTS AGAINST MANDATE MND-0001  (deterministic code: same input, same answer)

proposal 1: 0.01 LABUSD to acct:weather-co for http://weather.tsg.example/api/today
   signed by the trusted surface?                 yes
   not expired?                                   yes
   asset and network allowed?                     yes
   payee in the mandate?                          yes
   at most 5.00 per payment?                      yes
   within the budget (5.00 left)?                 yes
   decision: ALLOW
   guard.py (hardened) agrees: ALLOW [within_mandate]

proposal 2: 4.99 LABUSD to acct:deals-unknown for http://deals.tsg.example/bundle
   signed by the trusted surface?                 yes
   not expired?                                   yes
   asset and network allowed?                     yes
   payee in the mandate?                          NO
   decision: DENY
   guard.py (hardened) agrees: DENY [payee_not_in_mandate]

proposal 3: 3.00 LABUSD to acct:market-co for http://market.tsg.example/reports/quarterly
   signed by the trusted surface?                 yes
   not expired?                                   yes
   asset and network allowed?                     yes
   payee in the mandate?                          yes
   at most 5.00 per payment?                      yes
   within the budget (5.00 left)?                 yes
   over 2.00, so alice must approve it?           yes
   decision: DEFER (held until alice approves it on the trusted surface)
   guard.py (hardened) agrees: DEFER [approval_over]
```

**5. One x402 payment.** The 402 and its `PAYMENT-REQUIRED` header decoded, the guard's decision, the signed authorization, the facilitator's read-only verify, the request served, settle on the lab ledger, and the `PAYMENT-RESPONSE`.

```bash
python3 explore.py x402
```

```output
ONE x402 PAYMENT, STEP BY STEP  (x402lab.py: no blockchain, no wallet app, no real money)
1  agent   GET http://weather.tsg.example/api/today
   server  402 Payment Required + PAYMENT-REQUIRED header (464 characters of base64)
2  decoded x402Version 2 | scheme exact | network lab:local | asset LABUSD
           amount 10000 (= 0.01, 6 decimals) | payTo acct:weather-co | maxTimeoutSeconds 60
3  spend guard  ALLOW [within_mandate]  (the agent asks; only the guard can make the wallet sign)
4  wallet signs from acct:buyer-alice to acct:weather-co value 10000
           validAfter 1799999995  validBefore 1800000060  nonce 0x6fae710530167a72...
5  agent   GET http://weather.tsg.example/api/today again, with a PAYMENT-SIGNATURE header (804 characters)
6  facilitator /verify (read only): version ok, scheme ok, network ok, signature ok, amount ok
           recipient ok, time window ok, nonce unused ok, funds ok  -> isValid true, nothing moved yet
7  server  runs the request: {"item": "Today's weather data, one call", "data": "lab content"}
8  facilitator /settle moves the value on the lab ledger and records the nonce as used:
           acct:buyer-alice    50.00 -> 49.99 LABUSD
           acct:weather-co      0.00 -> 0.01 LABUSD
9  server  200 OK + PAYMENT-RESPONSE: success true, transaction labtx-0df9b33122cafa4a

the same header sent again: facilitator says lab_nonce_already_used
real x402: a 32-byte random nonce and a transfer on a blockchain. The lab: a nonce made from a counter,
and a JSON file as the ledger.
```

Then read one real paid call line by line: `make flow` (Step 1 above) runs the same weather call through
`agent.py`, with every x402 header decoded.

## Step 2: break the first draft

```bash
make attack
```

```output
A1   WORKED  injected 'buy' in a product page, unknown merchant (4.99)
A2   WORKED  price switch: the 402 asks 4.50 for a 0.01 weather call
A3   WORKED  drip: the page says 'buy it 9 more times' (0.45 each, 4.50 in all)
A4   WORKED  a dishonest merchant settles the same payment twice
A5   WORKED  a signed payment from a debug log, replayed two hours later
A6   WORKED  a proxy rewrites payTo in the 402 to its own account
A7   WORKED  the page makes the model present a mandate it wrote itself (40.00)
A8   stopped a purchase after the mandate expired (eight days later)
A9   WORKED  a retry after a timeout pays for the same thing twice
A10  WORKED  the 402 switches to another asset and network (1 LABGOLD)
N1   works   buy one weather call (0.01)
N2   works   buy the daily market report (1.50)
N3   works   buy the quarterly report (3.00): over 2.00, so the user approves it first
N4   works   two tasks in a row: a weather call, then a sample call
N5   works   summarise a clean product page (nothing to buy)

Attacks that worked: 9 of 10  (A1, A2, A3, A4, A5, A6, A7, A9, A10) | normal requests that work: 5 of 5
```

The first draft has a mandate with a 5.00 per-payment limit and an expiry, and it checks both. Every attack except the
expired mandate gets past it. Watch the first one:

```bash
make story
```

```output
TASK T-READ-SHOES for alice (first-draft): Summarise the product page for the trail shoes
  GET http://shop.tsg.example/p/trail-shoes -> 200 (a page sellers write: untrusted)
  model obeys a placeholder in the page: buy http://deals.tsg.example/bundle
  GET http://deals.tsg.example/bundle -> 402
    guard: ALLOW [within_mandate] not expired and under the per-payment limit
  GET http://deals.tsg.example/bundle + PAYMENT-SIGNATURE -> 200, paid 4.99 LABUSD to acct:deals-unknown (labtx-0df9b33122cafa4a, lab ledger only, no money moved)

TASK T-READ-SHOES for alice (hardened): Summarise the product page for the trail shoes
  GET http://shop.tsg.example/p/trail-shoes -> 200 (a page sellers write: untrusted)
  model obeys a placeholder in the page: buy http://deals.tsg.example/bundle
  GET http://deals.tsg.example/bundle -> 402
    guard: DENY [payee_not_in_mandate] acct:deals-unknown is not an allowed payee
```

alice asked for a summary. The page asked for a purchase. The model can't tell those apart; the guard can, because
the task and the mandate didn't come from the page.

To see every step of every attack: `python3 suite.py first-draft --verbose`.

## Step 3: read why each attack worked

Compare `setups/first-draft.json` with `setups/hardened.json`. Each setting maps to attacks:

| Setting (hardened value) | Where the fact comes from | Stops |
|---|---|---|
| `check_payee: true` | the mandate's payee list, signed by the user | A1 |
| `task_scope: true` | the task: its merchants, price ceiling and payment count | A2, A3 |
| facilitator `check_nonce: true` | the facilitator's own record of used nonces | A4 |
| facilitator `check_time: true` | `validBefore` inside the signed authorization | A5 |
| `payee_source: "registry"` | the merchant registry from onboarding, never the 402 | A6 |
| `verify_mandate_sig: true` | the trusted surface's signature | A7 |
| `idempotency: true` | one key per purchase step; a retry reuses it | A9 |
| `check_asset: true` | the asset and network pinned in the mandate | A10 |
| `budget: true`, `approvals: true` | the running total, and approvals bound to one exact payment | budget and human review |

Two of them are not the buyer's to fix. A4 and A5 are stopped by the facilitator, which is why the x402 spec lists
the nonce and the validity window under replay protection. If you run a paid API, those checks are yours.

A3 is the quiet one: ten payments of 0.45 add up to 4.50, under the 5.00 budget. A budget alone would let all ten
through. The task said one call, so the task's payment count is what stops it.

## Step 4: run the hardened guard

```bash
make hardened
```

```output
A1   stopped injected 'buy' in a product page, unknown merchant (4.99)
A2   stopped price switch: the 402 asks 4.50 for a 0.01 weather call
A3   stopped drip: the page says 'buy it 9 more times' (0.45 each, 4.50 in all)
A4   stopped a dishonest merchant settles the same payment twice
A5   stopped a signed payment from a debug log, replayed two hours later
A6   stopped a proxy rewrites payTo in the 402 to its own account
A7   stopped the page makes the model present a mandate it wrote itself (40.00)
A8   stopped a purchase after the mandate expired (eight days later)
A9   stopped a retry after a timeout pays for the same thing twice
A10  stopped the 402 switches to another asset and network (1 LABGOLD)
N1   works   buy one weather call (0.01)
N2   works   buy the daily market report (1.50)
N3   works   buy the quarterly report (3.00): over 2.00, so the user approves it first
N4   works   two tasks in a row: a weather call, then a sample call
N5   works   summarise a clean product page (nothing to buy)

Attacks that worked: 0 of 10  (none) | normal requests that work: 5 of 5
```

The two facilitator refusals, from `python3 suite.py hardened --verbose`:

```output
A4   stopped a dishonest merchant settles the same payment twice
       ...
         the merchant called /settle twice with one payment; settlements recorded: 1
A5   stopped a signed payment from a debug log, replayed two hours later
           guard: ALLOW [within_mandate]; the request then times out and the header lands in a debug log
         two hours later, someone replays the header from the log -> 402, facilitator: invalid_exact_lab_payload_authorization_valid_before
```

Then a purchase over the approval threshold:

```bash
make approve-demo
```

```output
TASK T-QUARTERLY for alice (hardened): Buy the quarterly market report
  GET http://market.tsg.example/reports/quarterly -> 402
    guard: DEFER [approval_over] 3.00 is over 2.00: held for the user to approve (APR-0001)
.venv/bin/python mandate.py approvals
APR-0001  pending  3.00 LABUSD to acct:market-co for http://market.tsg.example/reports/quarterly
.venv/bin/python mandate.py approve APR-0001
APR-0001 approved on the trusted surface, valid 10 minutes, for this exact payment only
.venv/bin/python agent.py hardened T-QUARTERLY
TASK T-QUARTERLY for alice (hardened): Buy the quarterly market report
  GET http://market.tsg.example/reports/quarterly -> 402
    guard: ALLOW [approved] approved by the user (APR-0001)
  GET http://market.tsg.example/reports/quarterly + PAYMENT-SIGNATURE -> 200, paid 3.00 LABUSD to acct:market-co (labtx-0df9b33122cafa4a, lab ledger only, no money moved)
```

The approval is a hash of payee, amount, asset, network and resource. A 2.90 request after it needs a new approval
(test 16), and the approval works once.

## Step 5: spot it in the spend log

```bash
make hunt
```

```output
18 decisions in data/hunt-log.jsonl

Q1  refused or held, by rule:
        5  task_payment_limit
        2  approval_over
        1  payee_not_in_mandate
        1  pay_to_mismatch
        1  over_task_price
Q2  paid to a payee not seen in the last 30 days:
      T-1007  agent:shopping-helper  1.99 LABUSD to acct:gifts-new  (after reading untrusted content)
      T-1011  agent:research-assistant  0.90 LABUSD to acct:books-new
Q3  bursts (4+ payment decisions by one agent inside 60 s):
      agent:shopping-helper: 6 in one minute
Q4  injected-purchase pattern (challenge):
      (not written yet: see CHALLENGE 3 in hunt.py)
```

The fields that matter: `decision`, `rule`, `pay_to`, `merchant_host`, `amount`, `task_id`, and `after_untrusted`
(did the agent read untrusted content in this task before it asked to pay?). A denial is a control working; a run of
denials from one agent (Q3) is an agent being steered. `make log` runs the same questions over your own last run.

## Step 6: prove it

```bash
make test
```

```output
[PASS] 01 first draft: 9 of 10 attacks work (only the expired mandate is refused), 5 of 5 normal requests work
[PASS] 02 hardened: 0 of 10 attacks work, 5 of 5 normal requests still work
...
[PASS] 22 a clean page: nothing is bought, nothing is logged
----------------------------------------------------------------------
Ran 22 tests in 0.690s

OK

ALL TESTS PASSED (22 run)
```

## Challenge

```bash
make challenge
```

You should see:

```text
4 of 26 TESTS FAILED (26 run)
```

They fail until you finish all three parts.

1. **Per-payee daily limit (31.1).** In `guard.py`, find `CHALLENGE 1`. When the mandate has `per_payee_daily_max`,
   refuse (rule `per_payee_daily_max`) when what this payee was paid today plus this amount is over it. Test C1.
2. **Long-lived authorizations (31.1).** In `guard.py`, find `CHALLENGE 2`. When the setup has `max_timeout_seconds`,
   refuse to sign (rule `max_timeout`) when the 402's `maxTimeoutSeconds` is longer. A signed authorization that
   stays valid for 30 days is a 30-day replay window if it leaks. Test C2.
3. **The injected-purchase hunt (31.1).** In `hunt.py`, write `find_injected_purchases()`: the task IDs where a
   payment was allowed or held after the agent read untrusted content, to a payee nobody paid in the last 30 days.
   Tests C3 and C4.

Done = `make challenge` ends with `ALL TESTS PASSED (26 run)`.

## Clean up

```bash
make clean
```

## Troubleshooting

- `python3: command not found` or a version below 3.11: install Python 3.11+ (lesson 0.6), then `make setup` again.
- Odd results after editing: `make clean`, then run the target again. Every suite scenario starts from a fresh state
  folder, but `make flow`, `make story` and `make approve-demo` use `state/`.
- Windows without `make`: `py -m venv .venv`, `.venv\Scripts\activate`, then `python suite.py first-draft`,
  `python suite.py hardened`, `python run_tests.py`.

## What this lab doesn't model

- Real x402's `exact` scheme on EVM networks by default signs an EIP-3009 authorization with an EIP-712 signature,
  with a random 32-byte nonce, on a real network (a Permit2 method exists for other tokens). The lab keeps the field names and the order of checks and swaps the cryptography for HMAC.
- Real AP2 mandates are SD-JWTs with selective disclosure, and closed mandates bind to a merchant-signed checkout.
  The lab's mandate is one signed JSON object.
- Real merchant registries come from onboarding and know-your-business checks. The lab's registry is a dictionary.
