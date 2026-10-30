# Lab M28.4: invocation logs, a redaction pipeline, Macie, two KMS keys, retention

Companion to lesson **28.4** of *AI Security Engineer* (The Sec Guy), Part 5 (advanced track), with pieces of 28.1
(vectors in logs) and 28.3 (deletion). About 45 minutes, $0, all on your laptop, all on fake data. Nothing leaves this
folder: no network, no AWS account, no model.

The TSG Helpdesk's model calls go through Amazon Bedrock with **model invocation logging** turned on, so every prompt
and answer lands in an S3 bucket. A redaction pipeline copies each record into a second bucket with the personal data
taken out, for analysts. Amazon Macie checks both buckets. Each bucket has its own KMS key and a retention rule.

The "AWS" here is a set of small **local stand-ins** (`kms.py`, `s3.py`, `bedrock.py`, `macie.py`). They keep the
documented names and field shapes (key policies, the `aws:s3:arn` encryption context, versioning and lifecycle,
`ModelInvocationLog` records, Macie's finding fields and its `SKIPPED` / `INVALID_ENCRYPTION` result), and the
encryption is real AES-256-GCM. They are not AWS. The optional guided build (`GUIDED-BUILD.md`) does it for real.

You get two versions of the pipeline. The **first draft** works: logs arrive, the redacted copy appears, Macie runs,
nothing is red. The **hardened** one has the same calls, buckets and roles; only the setup files changed.

| | first draft | hardened |
|---|---|---|
| 7 leak checks | 7 leak | 0 leak |
| 3 normal jobs (analyst report, break-glass read, one record each) | 3 work | 3 work |

You will:

1. **Break it:** run the first draft and read the seven leaks (`make leak`).
2. **Read why:** each leak maps to one setting (the table in Step 2).
3. **Fix it:** run the hardened pipeline (`make hardened`), watch the second lock hold (`make two-locks`), compare
   Macie's two runs (`make macie`) and see keyed tokens at work (`make tokens`).
4. **Spot it:** hunt a day of KMS events in CloudTrail format (`make hunt`).
5. **Prove it:** `make test`, then the challenge (`make challenge`). Optional: the AWS guided build.

> **Safety and data.** Every person, e-mail address and phone number is invented (e-mail on the reserved
> `.example` domain, RFC 2606). The card, 4111 1111 1111 1111, is listed as a sandbox-only Visa test number in
> Cybersource's developer testing guide. The AWS keys are the example keys printed in AWS's own CLI documentation. The state
> folder holds lab key material in plain files: a real KMS key never leaves AWS's hardware.

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m28`.

## What's in this folder

| File | What it is |
|---|---|
| `setups/first-draft/`, `setups/hardened/` | Each setup's `pipeline.json` (logging, KMS key policies, buckets, redactor, Macie job) and `identifiers.json` (what to detect) |
| `bedrock.py` | Writes `ModelInvocationLog` records for 12 fake calls spread over 90 days; bodies over 100 KB go to a `data/` prefix |
| `kms.py` | Local KMS: key policies with or without IAM delegation, data keys, encryption context, a CloudTrail-style event per call |
| `s3.py` | Local S3: SSE-KMS per object, bucket policy, versioning, delete markers, lifecycle rules |
| `redact.py` | The redaction pipeline (a Lambda function in the guided build) |
| `detect.py` | The detectors: a subset of Macie's managed identifiers, custom data identifiers, your customer list |
| `macie.py` | Local Macie job: reads as Macie's service-linked role, `SKIPPED` / `INVALID_ENCRYPTION` when the key says no |
| `pipeline.py` | Builds a setup from zero, runs it, checks L1 to L7 and N1 to N3 |
| `explore.py` | The read-only helper for Step 1b: one idea at a time (a log record, a toy encoder and its inversion, a toy model that memorises, differential privacy, hiding versus removing, detectors, redaction, envelope encryption). It writes no file and opens no connection |
| `Makefile` | Short commands for Mac and Linux (`make setup`, `make check`, `make leak` ...); `make -n <target>` shows what one would run, without running it |
| `demo.py`, `hunt.py`, `forget.py` | Two demonstrations, the investigator's questions, the erasure challenge |
| `data/` | The calls, the fake customer list, a day of KMS events for the hunt |
| `cloud/`, `GUIDED-BUILD.md` | Optional: the same pipeline in your own AWS account |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | The tests |

## Needs

- Python **3.11 or newer** and one package, **cryptography 50.0.2** (Apache-2.0 or BSD-3-Clause; wheels for macOS,
  Windows and Linux).
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step inside a virtual
  environment (`py -m venv .venv`, `.venv\Scripts\activate`, `pip install -r requirements.txt`).

```bash
cd labs/m28
make setup
```

- `make setup`: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt
- `make check`: prints the Python and cryptography versions and `OK` (Windows: `.venv\Scripts\python -c "import cryptography; print(cryptography.__version__)"`)

Look before you run: `make -n setup check` prints the three commands those targets would run, without running them.

## Step 1b · Look at each privacy idea on its own (about 10 minutes)

New to logs, embeddings, differential privacy or KMS? Do this first. `explore.py` shows, one at a time, the ideas this
module is built on. It only reads the lab's data and setup files and builds everything in memory: it writes no file,
opens no connection and calls no AWS service. The toy encoder and the toy language model are teaching stand-ins, not
neural networks: the ideas carry over, the exact numbers don't. Windows: `.venv\Scripts\python explore.py ...`. The output below
is from a fresh Ubuntu machine (recording run 41090410255).

**1. One model call, as invocation logging stores it (lesson 28.4).** Bedrock's model invocation logging is off by
default; once on, it keeps the prompt and the answer word for word, with who asked and when:

```bash
.venv/bin/python explore.py log
```

```output
One model call, as Bedrock model invocation logging stores it (call c01, setup hardened)

  schemaType         ModelInvocationLog           the record's format
  timestamp          2027-04-01T09:00:00Z         when the call happened (the lab's clock)
  operation          Converse                     the API the app called
  modelId            amazon.nova-micro-v1:0       which model answered
  identity           tsg-helpdesk-app             who called: an IAM role (account hidden here)
  requestMetadata    {"app": "helpdesk", "customer_email": "dana.reyes@customer.example"}
                                                  labels the app added to the call
  input text         Hi, I'm Dana Reyes (dana.reyes@customer.example), account TSG-CUST-104233. My order still has...
                                                  the user's message, word for word
  inputTokenCount    15                           tokens in: what the call is billed on
  output text        Sorry about that, Dana. I've opened a delivery check and we'll write to dana.reyes@customer.e...
                                                  the model's answer, word for word
  outputTokenCount   22                           tokens out

Stored as one object in the raw bucket:
  s3://tsg-invocation-logs-raw/AWSLogs/<account>/BedrockModelInvocationLogs/us-east-1/2027/04/01/09/121f8bd5-lab0-4m28-c01-0000000000.json.gz

So the prompt and the answer are kept word for word, with who asked and when.
```

**2. A logged vector (lesson 28.1).** With the Embedding modality ticked, an embedding call's record holds the input
text and its vector side by side:

```bash
.venv/bin/python explore.py log c03 first-draft
```

```output
One model call, as Bedrock model invocation logging stores it (call c03, setup first-draft)

  schemaType         ModelInvocationLog           the record's format
  timestamp          2027-03-29T09:00:00Z         when the call happened (the lab's clock)
  operation          InvokeModel                  the API the app called
  modelId            amazon.titan-embed-text-v2:0 which model answered
  identity           tsg-rag-indexer              who called: an IAM role (account hidden here)
  requestMetadata    {"app": "indexer"}           labels the app added to the call
  input text         Ticket from Sam Okafor (TSG-CUST-104871): please refund order 7781, the parcel arrived damaged.
                                                  the text sent to the embedding model
  output embedding   [0.116, -0.054, 0.113, 0.055, -0.076, -0.044, ...]
                                                  256 numbers: the vector, next to its text
  dimensions         256                          how many numbers the app asked for

Stored as one object in the raw bucket:
  s3://tsg-invocation-logs-raw/AWSLogs/<account>/BedrockModelInvocationLogs/us-east-1/2027/03/29/09/ba6fe795-lab0-4m28-c03-0000000000.json.gz

The lab's vectors are random placeholders (no model runs). A real embedding model's numbers carry the
text's meaning, which is why `explore.py invert` matters.
```

**3. An encoder turns text into numbers (lesson 28.1).** A toy one: each word adds +1 or -1 in four of 256 places.
Texts that share words get numbers that point the same way:

```bash
.venv/bin/python explore.py embed
```

```output
A toy encoder: each word adds +1 or -1 in four of 256 places, then the list is scaled to length 1.
Real encoders are trained neural networks; this one only counts words. The idea is the same: text in, numbers out.

A  Ticket from Sam Okafor (TSG-CUST-104871): please refund order 7781, the parcel arrived damaged.
   256 numbers, most of them 0. The first others (place:value): 0:-0.14, 6:-0.14, 10:+0.14, 12:-0.14, 15:-0.14, 16:+0.14, ...
B  My parcel arrived damaged and I want a refund for the order.
   256 numbers, most of them 0. The first others (place:value): 0:-0.15, 1:+0.15, 4:+0.15, 10:+0.15, 15:-0.15, 16:+0.15, ...
C  What are your opening hours on public holidays?
   256 numbers, most of them 0. The first others (place:value): 4:+0.17, 27:+0.17, 31:+0.17, 39:+0.34, 59:+0.17, 63:+0.17, ...

Similarity (cosine: 1.00 = same direction, near 0.00 = unrelated):
  A and B  0.45
  A and C  -0.07
  B and C  0.05

A and B share words (parcel, arrived, damaged, refund, order), so their numbers point the same way.
A trained encoder would also match words that mean the same thing, like 'broken' and 'damaged'.
```

**4. Turning a vector back into words (lesson 28.1).** The attacker has one vector and a word list, and keeps the
guess whose vector comes closest. Against this toy the whole bag of words comes back:

```bash
.venv/bin/python explore.py invert
```

```output
The attacker has ONE vector from the logs (call c08, an embedding call) and no text.
Their word list: 229 words (common English words, plus every word in the other 11 logged calls).
They guess words one at a time, keeping the guess whose vector comes closest to the stolen one:

  step  1  + dana               similarity 0.395
  step  2  + delivery           similarity 0.559
  step  3  + address            similarity 0.639
  step  4  + change             similarity 0.712
  step  5  + to                 similarity 0.778
  step  6  + tsg-cust-104233    similarity 0.837
  step  7  + asked              similarity 0.866
  step  8  + reyes              similarity 0.922
  step  9  + for                similarity 0.949
  step 10  + her                similarity 1.000

Recovered words:  dana delivery address change to tsg-cust-104233 asked reyes for her
The real text:    Dana Reyes asked to change her delivery address for TSG-CUST-104233.

The toy keeps no word order, so the words come back as a bag. Real attacks rebuild the sentence itself:
Vec2Text (2023) recovered 92% of 32-token inputs exactly, from real embedding models.
```

**5. Training, and memorisation (lesson 28.2).** A toy language model counts which word followed every run of one to
three words. The card number it saw once comes back word for word:

```bash
.venv/bin/python explore.py memorise
```

```output
A toy language model, trained on the helpdesk's logged messages (9 calls: 18 texts, questions and answers).
Training = counting which word followed every run of 1 to 3 words. Those counts are its 'weights'.
  learned 475 word runs from 195 words

  prompt 'Can someone'    -> Can someone call me back on 312-555-0182? It's about my missing refund.
  prompt 'My order'       -> My order still hasn't arrived.
  prompt 'My card'        -> My card 4111 1111 1111 1111 was charged twice for one order.

The card number was in ONE training text (call c02), and it comes back word for word.
Entries in the weights that hold '4111': 8
That's memorisation. Real models memorise far less of what they see, but not nothing: a 2021 study pulled
names, phone numbers and e-mail addresses out of GPT-2.
```

**6. Differential privacy: noise, epsilon and the unit (lesson 28.2).** The same count, answered with Laplace noise.
Smaller epsilon, more noise. Protecting one PERSON instead of one record needs noise for all of her records:

```bash
.venv/bin/python explore.py dp
```

```output
The question: "How many of the 12 logged calls are about a refund?"   true answer: 5

Differential privacy answers with random noise added. Epsilon (e) sets how much: smaller e, more noise,
more privacy. Noise scale = (the most one unit can change the count) / e.

Unit = one record (one call changes the count by at most 1):
  e = 0.1   noise scale 10.0   five answers:   4.8   12.1    0.2    8.0   -8.5
  e = 1.0   noise scale  1.0   five answers:   4.9    4.8    0.9    0.9    2.8
  e = 10.0  noise scale  0.1   five answers:   5.0    5.1    4.9    5.0    5.0

But one customer, Dana Reyes, appears in 4 of the 12 calls. Remove HER and the count can move by 4.
Unit = one person needs noise for all of her records at once:
  e = 1.0   noise scale  4.0   five answers:   3.3   13.3    3.4    3.9   -0.6

Same e, four times the noise. 'e = 1' means little until someone says: per record, or per person?
And e is a budget: three questions at e = 1 each spend e = 3 in total (privacy losses add up).
```

Negative answers are normal for noisy counts: the noise doesn't know a count can't go below zero. The seed is fixed,
so you get the same numbers.

**7. Hide it or remove it (lesson 28.3).** An output filter hides the card number; retraining without the record
removes it:

```bash
.venv/bin/python explore.py unlearn
```

```output
The toy model from `memorise`. Request: "forget the card number in call c02".

1. Before:                  My card 4111 1111 1111 1111 was charged twice for one order.
   entries holding '4111':  8

2. Hide it: an output filter (Macie-style card detector) on every answer. The model is unchanged.
   answer:                  My card [CREDIT_CARD_NUMBER] was charged twice for one order.
   entries holding '4111':  8   <- still in the weights: a copy without the filter leaks

3. Remove it: retrain from zero without call c02 (exact unlearning).
   answer:                  My card   (nothing learned after 'My card')
   entries holding '4111':  0

Retraining is easy here: 16 short texts. For a large model it costs a full training run, so teams
fine-tune the model to stop saying it instead. Lesson 28.3 shows how often that only hides it.
```

**8. Which detector finds what (lesson 28.4).** Macie's managed identifiers (three of them, re-implemented), the first
draft's two patterns, and the hardened setup's custom identifiers plus the customer list:

```bash
.venv/bin/python explore.py detect
```

```output
c01: Hi, I'm Dana Reyes (dana.reyes@customer.example), account TSG-CUST-104233. My order still hasn't arrived.
c02: My card 4111 1111 1111 1111 was charged twice for one order.
c12: Yes. We replied to DANA.REYES@CUSTOMER.EXAMPLE an hour ago.

Macie's managed identifiers (the lab's copies of 3 of them):
  c01  nothing found
  c02  CREDIT_CARD_NUMBER   FINANCIAL_INFORMATION  4111 1111 1111 1111
  c12  nothing found

First draft redactor: two hand-written patterns:
  c01  EMAIL                CUSTOM_IDENTIFIER      dana.reyes@customer.example
  c02  nothing found
  c12  nothing found

Hardened: custom identifiers + the customer list:
  c01  CUSTOMER_NAME        PERSONAL_INFORMATION   Dana Reyes
  c01  EMAIL_ADDRESS        CUSTOM_IDENTIFIER      dana.reyes@customer.example
  c01  TSG_CUSTOMER_ID      CUSTOM_IDENTIFIER      TSG-CUST-104233
  c02  CREDIT_CARD_NUMBER   FINANCIAL_INFORMATION  4111 1111 1111 1111
  c12  EMAIL_ADDRESS        CUSTOM_IDENTIFIER      DANA.REYES@CUSTOMER.EXAMPLE

Macie has no managed identifier for e-mail addresses: add your own (a custom data identifier).
The card passes the Luhn check, with the word 'card' nearby. The draft's patterns miss spaces and capitals.
```

**9. Labels or keyed tokens (lesson 28.4).** Two ways to replace what the detectors find:

```bash
.venv/bin/python explore.py redact
```

```output
Redaction replaces what the detectors find. Two ways (the hardened setup's detectors):

Labels: the value is gone, and so is any link between records.
  c01  Hi, I'm [CUSTOMER_NAME] ([EMAIL_ADDRESS]), account [TSG_CUSTOMER_ID]. My order still hasn't arrived.
  c02  My card [CREDIT_CARD_NUMBER] was charged twice for one order.
  c12  Yes. We replied to [EMAIL_ADDRESS] an hour ago.

Keyed tokens: HMAC-SHA256 of the lower-cased value with a secret key, first 8 hex characters.
  c01  Hi, I'm [CUSTOMER_NAME:7c7f3c56] ([EMAIL_ADDRESS:537a3ecc]), account [TSG_CUSTOMER_ID:acc76c79]. My order still hasn't arrived.
  c02  My card [CREDIT_CARD_NUMBER:6d444fc5] was charged twice for one order.
  c12  Yes. We replied to [EMAIL_ADDRESS:537a3ecc] an hour ago.

The e-mail in c01 and the capitals in c12 get the SAME token: an analyst sees one customer wrote twice,
not who. Without the key the token can't be turned back. (This demo uses a fixed key; the lab's is random.)
```

**10. Envelope encryption and the key policy (lesson 28.4).** One record encrypted with its own data key, the data
key wrapped by the KMS key, and who may ask KMS to unwrap it:

```bash
.venv/bin/python explore.py kms
```

```output
Envelope encryption of one log record (call c01), in memory. Your bytes will differ: keys are random.

  1. KMS key           alias/tsg-logs-raw             32 random bytes. In AWS they never leave KMS unencrypted
  2. data key          32 random bytes                made for THIS object only
     wrapped data key  hRamwgcEBbaUD3ql31dMZEWn...    48 bytes: the data key, encrypted by the KMS key
  3. record            1116 bytes of JSON             {"schemaType": "ModelInvocationLog", "sch...
     encrypted record  29ac78274c1f76a4c846db1f...    1132 bytes, AES-256-GCM: stored with the wrapped key
     context           aws:s3:arn = the object's ARN  the encryption context: it must match to decrypt

4. Reading it back: ask KMS to unwrap the data key, then decrypt the record.
   right context   -> Hi, I'm Dana Reyes (dana.reyes@customer.example), account TSG-CUST-...
   wrong context   -> refused (InvalidTag): this data key only opens its own object

5. Who may ask KMS to unwrap? The key policy decides (kms:Decrypt on the raw-log key):
   role                           first draft                                  hardened
   tsg-analytics                  yes, root statement lets IAM grant it        no
   tsg-log-redactor               yes, root statement lets IAM grant it        yes, named in the key policy
   AWSServiceRoleForAmazonMacie   no                                           yes, named in the key policy
   tsg-incident-break-glass       yes, root statement lets IAM grant it        yes, named in the key policy

Two locks on a raw record: the bucket policy (S3) and the key policy (KMS). Both must say yes.
```

"Never leave KMS unencrypted" is AWS's own wording for KMS keys. The lab's stand-in keeps its key in memory (and,
in `kms.py`, in a file under `state/`), which a real KMS key never is.

## Step 1 · Break it

```bash
make leak
```

Same as `python3 pipeline.py first-draft`.

Real output (Linux, Python 3.13, cryptography 50.0.2):

```output
setup first-draft | 12 model calls logged | redactor: 12 records, 0 large bodies redacted, 1 copied as-is, 2 values replaced, 0 vectors removed
check what                                         lesson  result
L1    analyst reads a raw prompt                   28.4    LEAK    tsg-analytics read a raw record: the bucket policy allowed it and alias/tsg-invocation-logs let an IAM policy grant kms:Decrypt
L2    PII or secrets left in redacted records      28.4    LEAK    survived redaction: AWS_ACCESS_KEY_ID in 1 record(s), AWS_CREDENTIALS in 1 record(s), CREDIT_CARD_NUMBER in 1 record(s), CUSTOMER_NAME in 6 record(s), EMAIL_ADDRESS in 3 record(s), PHONE_NUMBER in 1 record(s), TSG_CUSTOMER_ID in 4 record(s)
L3    embedding vectors in the redacted copy       28.1    LEAK    6 embedding arrays readable by analysts (input text sits next to them in the raw log)
L4    large body (>100 KB) copied unredacted       28.4    LEAK    large body copied across unredacted: 59d7f60d-lab0-4m28-c06-0000000000-input.json.gz
L5    Macie skipped raw objects, said nothing      28.4    LEAK    Macie read 0 of 10 raw objects (9 SKIPPED INVALID_ENCRYPTION, 1 EXCLUDED_BY_SCOPE); findings on raw: 0
L6    kinds Macie's job can never detect           28.4    LEAK    this job can never find: EMAIL_ADDRESS, TSG_CUSTOMER_ID
L7    raw records kept past 30 days                28.3    LEAK    3 raw objects older than 30 days still stored (3 hidden behind delete markers, readable by version ID)
N1    analyst weekly usage report (redacted only)          works   tsg-dev-sandbox: 1 calls, 37 tokens, tsg-helpdesk-app: 4 calls, 119 tokens, tsg-rag-indexer: 1 calls, 16 tokens
N2    break-glass reads this week's raw record             works   read ff62523e-lab0-4m28-c04-0000000000 (Converse, amazon.nova-micro-v1:0)
N3    one redacted record per raw record                   works   9 raw records, 12 redacted records

Leaks: 7 of 7  (L1, L2, L3, L4, L5, L6, L7) | normal jobs that work: 3 of 3
```

Every normal job works. That's the trap: a pipeline can pass every functional test and still leak in seven ways.
(`EXCLUDED_BY_SCOPE` is this lab's own marker; real Macie writes no result for objects a job's scoping leaves out.)

## Step 2 · Read why each leak happened

Open `setups/first-draft/pipeline.json` and `setups/hardened/pipeline.json` side by side. Each block is one design
choice; the `_about` lines say why someone made it.

| Choice | First draft | Hardened | Leak it decides |
|---|---|---|---|
| KMS keys | one key for both buckets, with the default root statement, so an IAM policy can grant `kms:Decrypt` | two keys; the account may only **administer** them; `kms:Decrypt` goes to named roles | L1 |
| Raw bucket readers | redactor, analysts ("for debugging"), break-glass, Macie | redactor, break-glass, Macie; analysts explicitly denied | L1 |
| What the redactor reads | the user's text in the request only | every string in the record, response and `requestMetadata` included | L2 |
| What the redactor detects | two hand-written patterns, case sensitive | the managed detectors, the shared custom identifiers and your customer names | L2 |
| Embedding modality / vectors | logged, and kept in the copy | not logged, and stripped anyway if they appear | L3 |
| Bodies over 100 KB | copied across as they are | redacted like every other record | L4 |
| Macie on the raw key | no statement for its service-linked role | `kms:Decrypt` for `AWSServiceRoleForAmazonMacie` | L5 |
| Macie job scope | big objects under `data/` excluded "to save cost" | everything | L5 |
| Macie identifiers | managed only (there is no managed e-mail identifier) | the same custom identifiers the redactor uses | L6 |
| Raw retention | expire after 30 days in a versioned bucket, nothing for old versions | expire after 30 days **and** `NoncurrentVersionExpiration` after 1 day | L7 |

L5 is the one that fools dashboards. Macie couldn't use the key, so it read nothing and created no finding. "No
findings" meant "not read".

**India note.** The 30-day raw expiry is this lab's design choice, not a legal floor. From May 2027, India's DPDP
Rules, 2025 require keeping personal data, "associated traffic data and other logs of the processing for a minimum
period of one year" for the purposes in its Seventh Schedule, then erasing them (rule 8(3); rule 6(1)(e) asks the same of security logs;
[G.S.R. 846(E)](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf)). An
organisation covered by them would raise the raw expiry to at least a year and keep the rest of the hardened design.
The lab code stays at 30 days.

## Step 3 · Fix it

```bash
make hardened
```

Same as `python3 pipeline.py hardened`.

```output
setup hardened | 12 model calls logged | redactor: 12 records, 1 large bodies redacted, 0 copied as-is, 33 values replaced, 0 vectors removed
check what                                         lesson  result
L1    analyst reads a raw prompt                   28.4    closed  refused by the bucket policy; alias/tsg-logs-raw has no statement for tsg-analytics either (two locks)
L2    PII or secrets left in redacted records      28.4    closed  12 redacted records, no planted value left
L3    embedding vectors in the redacted copy       28.1    closed  no embedding arrays in the redacted copy
L4    large body (>100 KB) copied unredacted       28.4    closed  large bodies were redacted like every other record
L5    Macie skipped raw objects, said nothing      28.4    closed  Macie read all 10 raw objects; findings on raw: 8
L6    kinds Macie's job can never detect           28.4    closed  every planted kind has a detector in the job
L7    raw records kept past 30 days                28.3    closed  nothing in the raw bucket is older than 30 days
N1    analyst weekly usage report (redacted only)          works   tsg-dev-sandbox: 1 calls, 37 tokens, tsg-helpdesk-app: 4 calls, 119 tokens, tsg-rag-indexer: 1 calls, 16 tokens
N2    break-glass reads this week's raw record             works   read ff62523e-lab0-4m28-c04-0000000000 (Converse, amazon.nova-micro-v1:0)
N3    one redacted record per raw record                   works   9 raw records, 12 redacted records

Leaks: 0 of 7  (none) | normal jobs that work: 3 of 3
```

"0 vectors removed" is the logging setting doing its job: no vectors arrived. The redactor's vector stripping is the
second line, for the day someone ticks Embedding again (`test_11` proves it).

**Two locks.** Now loosen the raw bucket's policy by mistake and see what the key does:

```bash
make two-locks
```

Same as `python3 demo.py two-locks`.

```output
raw object: 0a8dc0ca-lab0-4m28-c08-0000000000.json.gz  (account IDs print as <account>)
1. tsg-analytics, bucket policy as built:  REFUSED  tsg-analytics may not s3:GetObject s3://tsg-invocation-logs-raw/AWSLogs/<account>/BedrockModelInvocationLogs/us-east-1/2027/03/14/09/0a8dc0ca-lab0-4m28-c08-0000000000.json.gz
2. after the bucket-policy mistake:        REFUSED  tsg-analytics may not use alias/tsg-logs-raw for kms:Decrypt

The refusal is in the trail (state/cloudtrail.jsonl), last event:
{
  "eventSource": "kms.amazonaws.com",
  "eventName": "Decrypt",
  "errorCode": "AccessDenied",
  "userIdentity.arn": "arn:aws:iam::<account>:role/tsg-analytics",
  "requestParameters.keyId": "arn:aws:kms:us-east-1:<account>:key/d2e8e3d7-5171-7003-8a49-bf0df5e7d330",
  "requestParameters.encryptionContext": {
    "aws:s3:arn": "arn:aws:s3:::tsg-invocation-logs-raw/AWSLogs/<account>/BedrockModelInvocationLogs/us-east-1/2027/03/14/09/0a8dc0ca-lab0-4m28-c08-0000000000.json.gz"
  }
}
```

Account IDs print as `<account>` (the lab uses AWS's documentation example account; the output hides it anyway).
The analyst's IAM policy still says `kms:Decrypt` on `*`. It doesn't matter: the raw key's policy delegates only
administration to the account, so IAM can't grant its use. (Lab shortcut: refusals carry `errorCode` `AccessDenied`;
read the value your real trail records.)

**Macie, before and after:**

```bash
make macie
```

Same as `python3 macie.py first-draft`, then `python3 macie.py hardened`.

```output
tsg-invocation-logs-raw: 1 EXCLUDED_BY_SCOPE, 9 SKIPPED (INVALID_ENCRYPTION) | findings: 0
tsg-invocation-logs-redacted: 1 EXCLUDED_BY_SCOPE, 12 SKIPPED (INVALID_ENCRYPTION) | findings: 0

tsg-invocation-logs-raw: 10 COMPLETE | findings: 8
tsg-invocation-logs-redacted: 13 COMPLETE | findings: 0
detections: AWS_ACCESS_KEY_ID x1, AWS_CREDENTIALS x1, CREDIT_CARD_NUMBER x1, EMAIL_ADDRESS x8, PHONE_NUMBER x6, TSG_CUSTOMER_ID x3
  SensitiveData:S3Object/CustomIdentifier  tsg-invocation-logs-raw/.../0a8dc0ca-lab0-4m28-c08-0000000000.json.gz
  SensitiveData:S3Object/Personal          tsg-invocation-logs-raw/.../ff62523e-lab0-4m28-c04-0000000000.json.gz
  SensitiveData:S3Object/CustomIdentifier  tsg-invocation-logs-raw/.../ba6fe795-lab0-4m28-c03-0000000000.json.gz
  SensitiveData:S3Object/Financial         tsg-invocation-logs-raw/.../31b1608f-lab0-4m28-c02-0000000000.json.gz
  SensitiveData:S3Object/CustomIdentifier  tsg-invocation-logs-raw/.../121f8bd5-lab0-4m28-c01-0000000000.json.gz
  SensitiveData:S3Object/Multiple          tsg-invocation-logs-raw/.../e51c453a-lab0-4m28-c05-0000000000.json.gz
  SensitiveData:S3Object/CustomIdentifier  tsg-invocation-logs-raw/.../ebbfb535-lab0-4m28-c12-0000000000.json.gz
  SensitiveData:S3Object/Multiple          tsg-invocation-logs-raw/.../59d7f60d-lab0-4m28-c06-0000000000-input.json.gz
```

Findings in the raw bucket are the good news here: they prove Macie can read it and knows what to look for. The
number that matters is the **0 on the redacted bucket**, from a job that read all 13 objects. The full findings are in
`state/macie-findings.json`, with `records[].jsonPath` showing where in each record the data sat.

**Keyed tokens.** Labels like `[EMAIL_ADDRESS]` lose one useful fact: whether two records came from the same person.

```bash
make tokens
```

Same as `python3 demo.py tokens`.

```output
2027-04-01T09:00:00Z  tsg-helpdesk-app  metadata  [EMAIL_ADDRESS:744c26c6]
2027-04-01T09:00:00Z  tsg-helpdesk-app  request   Hi, I'm [CUSTOMER_NAME:3196a361] ([EMAIL_ADDRESS:744c26c6]), account [TSG_CUSTOMER_ID:e3614350]. My order still hasn't arrived.
2027-04-01T09:00:00Z  tsg-helpdesk-app  response  Sorry about that, Dana. I've opened a delivery check and we'll write to [EMAIL_ADDRESS:744c26c6] within a day.
2027-04-02T21:00:00Z  tsg-helpdesk-app  response  Yes. We replied to [EMAIL_ADDRESS:744c26c6] an hour ago.

[EMAIL_ADDRESS:744c26c6] is the same customer each time. Who it is stays with the tokenisation key.
```

Your token values will differ: the tokenisation key is random for every run. The upper-case address in the last
line got the same token, because values are lower-cased first.

Now look again at the third line: **"Dana" on her own survived.** The name detector knows full names from the
customer list, and nothing more. L2 only searches for planted full values, so it stays "closed". This is the
residual risk lesson 4.2 warned about: detection is a best guess. It's also why Macie, with its own `NAME`
identifier in the guided build, checks the redacted bucket instead of trusting the redactor.

## Step 4 · Spot it

```bash
make hunt
```

Same as `python3 hunt.py`.

```output
32 KMS events
Q1  Calls per key (account IDs print as <account>):
    arn:aws:kms:us-east-1:<account>:key/d2e8e3d7-5171-7003-8a49-bf0df5e7d330
      AWSServiceRoleForAmazonMacie     Decrypt          ok       x4
      bedrock.amazonaws.com            GenerateDataKey  ok       x5
      tsg-analytics                    Decrypt          refused  x3
      tsg-incident-break-glass         Decrypt          ok       x1
      tsg-log-redactor                 Decrypt          ok       x5
      tsg-ml-training                  Decrypt          ok       x4
    arn:aws:kms:us-east-1:<account>:key/15241331-7bb2-ba5d-b389-7c9a87b3accd
      tsg-analytics                    Decrypt          ok       x5
      tsg-log-redactor                 GenerateDataKey  ok       x5
Q2  Break-glass uses (match each to an incident ticket):
    2027-04-02T11:02:00Z  rec-003.json.gz
Q3  (not answered yet: challenge 3, write find_raw_key_readers() in hunt.py)
```

The fixture (`data/hunt-cloudtrail.jsonl`) is invented and uses the field names of a real CloudTrail KMS event. Two
lines in Q1 should bother you. Someone in analytics tried the raw key three times. And a training role read four raw
records late in the evening: somebody gave it access, and lesson 28.2 says training data should come from the
redacted copy. Q3 turns that into a check you can schedule.

## Step 5 · Prove it

```bash
make test
```

You should see:

```text
ALL TESTS PASSED (20 run)
```

```output
ALL TESTS PASSED (20 run)
```

**Challenge** (`make challenge`: 4 of 24 tests fail until you finish; no solution included):

1. **28.4:** a loyalty-card number (`TSG-LOY-` and 8 digits) appears in a new call. Add ONE custom data identifier
   named `TSG_LOYALTY_CARD` to `setups/hardened/identifiers.json` and its name to the Macie job in
   `setups/hardened/pipeline.json`. One definition, two uses. Check with `python3 pipeline.py hardened --challenge`.
2. **28.3:** write `forget()` in `forget.py`: one customer's erasure request across both buckets, every version, raw
   values and tokens. Then `python3 pipeline.py hardened && python3 forget.py TSG-CUST-104233`.
3. **28.4:** write `find_raw_key_readers()` in `hunt.py`: who outside the expected list called `Decrypt` on the raw
   key, allowed or refused.

```output
4 of 24 TESTS FAILED (24 run)
```

**Guided build (your own AWS account, optional).** `GUIDED-BUILD.md` builds the same design for real: two KMS keys,
two buckets with retention, a redaction Lambda on S3 events, Bedrock invocation logging (text only), Macie custom
identifiers and a one-time job, five example requests, one setting changed, cost and teardown. Every response there
is labelled illustrative until you run it.

## Troubleshooting

| You see | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'cryptography'` | `make setup`, or activate `.venv` before running `python3 ...` |
| `pip` tries to build cryptography from source | Your Python is older than 3.11 or very new: use 3.11 to 3.14 |
| Token values or random IDs differ from this page | Expected: the tokenisation key and data keys are random per run. Counts and verdicts should match |
| Strange results after editing a setup | `make clean`, then run again: every `pipeline.py` run rebuilds `state/` from zero |
