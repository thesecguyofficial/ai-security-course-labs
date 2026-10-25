"""
pipeline.py: build one setup from zero in a fresh state folder, run it, and check it for leaks.

    python3 pipeline.py first-draft        # make leak:     7 of 7 leaks, 3 of 3 normal jobs still work
    python3 pipeline.py hardened           # make hardened: 0 of 7 leaks, 3 of 3 normal jobs still work
    python3 pipeline.py hardened --challenge   # adds the challenge's loyalty-card call (L8) to the run

The run, in order: create the KMS keys and buckets the setup describes; Bedrock writes the invocation logs (12 calls
spread over 90 days, all fake); the redactor copies each raw record into the redacted bucket; lifecycle rules run as if
S3 had applied them every day until the lab's pinned date (3 Apr 2027); the Macie stand-in runs its one-time job.
Then every check below runs as the principal it is about.

Leaks (each one is a question an auditor would ask):
  L1  Can an analyst read a raw prompt?
  L2  Does personal or secret data survive in the redacted records?
  L3  Are embedding vectors (text you can invert, lesson 28.1) in the redacted records?
  L4  Is a large request body (over 100 KB) readable unredacted outside the raw bucket?
  L5  Did Macie skip raw objects (key policy, scoping) while reporting nothing for them?
  L6  Which planted kinds of sensitive data can Macie's job not detect at all?
  L7  Do raw records older than the 30-day retention still exist (current or old versions)?
Normal jobs that must keep working:
  N1  An analyst answers "calls per app role in the last 7 days, and their tokens" from the redacted copy alone.
  N2  The break-glass role reads a raw record from this week (incident response).
  N3  Every raw record has exactly one redacted record (nothing silently dropped).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
from collections import Counter

import bedrock
import detect
import lab
import macie
import redact
from kms import AccessDenied, LocalKMS
from s3 import LocalS3

RETENTION_DAYS = 30


def canaries() -> dict[str, str]:
    """Every planted value, by kind. Searching for these is how the lab proves a leak (or its absence)."""
    out = {}
    for c in json.loads((lab.DATA / "crm.json").read_text())["customers"]:
        out[c["email"]] = "EMAIL_ADDRESS"
        out[c["name"]] = "CUSTOMER_NAME"
        out[c["id"]] = "TSG_CUSTOMER_ID"
        out[c["phone"]] = "PHONE_NUMBER"
    out["4111 1111 1111 1111"] = "CREDIT_CARD_NUMBER"
    out["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"] = "AWS_CREDENTIALS"
    out["AKIAIOSFODNN7EXAMPLE"] = "AWS_ACCESS_KEY_ID"
    return out


CHALLENGE_CANARIES = {"TSG-LOY-40417730": "TSG_LOYALTY_CARD"}

# One sample sentence per kind, the way it appears in the logs: used by L6 to ask "could this job ever find it?"
SAMPLES = {
    "EMAIL_ADDRESS": "we'll write to dana.reyes@customer.example within a day",
    "TSG_CUSTOMER_ID": "account TSG-CUST-104233",
    "CREDIT_CARD_NUMBER": "My card 4111 1111 1111 1111 was charged twice",
    "AWS_CREDENTIALS": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "PHONE_NUMBER": "call me back on 312-555-0182",
}
CHALLENGE_SAMPLES = {"TSG_LOYALTY_CARD": "Please add my points to loyalty card TSG-LOY-40417730"}


def build(setup_name: str, challenge: bool = False, state=None) -> dict:
    """Create everything from zero and run it. Returns the handles the checks need."""
    st = state or lab.state_dir()
    for child in ("kms", "s3"):
        shutil.rmtree(st / child, ignore_errors=True)
    for f in ("cloudtrail.jsonl", "macie-findings.json"):
        (st / f).unlink(missing_ok=True)
    setup = lab.load_setup(setup_name)
    kms = LocalKMS(st)
    for alias, k in setup["kms"].items():
        kms.create(alias, k["policy"], k.get("iam"))
    s3 = LocalS3(st, kms)
    for b in setup["buckets"]:
        s3.create_bucket(b)
    calls = bedrock.load_calls("calls.json", *(["challenge-calls.json"] if challenge else []))
    bedrock.deliver(s3, calls, setup)
    red = redact.run(s3, setup)
    life = {b["name"]: s3.apply_lifecycle(b["name"]) for b in setup["buckets"]}
    found = macie.run_job(s3, setup)
    return {"setup": setup, "kms": kms, "s3": s3, "calls": calls, "redactor": red, "lifecycle": life, "macie": found,
            "challenge": challenge}


# ---- checks: each returns (leaked: bool, detail: str) --------------------------------------------------------------

def _read_all(s3, bucket, principal, prefix_filter=None):
    out = {}
    for key in s3.list_objects(bucket):
        if prefix_filter and not prefix_filter(key):
            continue
        out[key] = s3.get_object(bucket, key, principal).decode()
    return out


def _canaries(env):
    c = canaries()
    if env["challenge"]:
        c.update(CHALLENGE_CANARIES)
    return c


def l1_analyst_reads_raw(env):
    s3, kms = env["s3"], env["kms"]
    key = s3.list_objects(lab.RAW_BUCKET)[0]
    alias = s3.object_info(lab.RAW_BUCKET, key)["sse"]["alias"]
    try:
        s3.get_object(lab.RAW_BUCKET, key, lab.ANALYST)
        return True, (f"tsg-analytics read a raw record: the bucket policy allowed it and {alias} let an IAM policy "
                      "grant kms:Decrypt")
    except AccessDenied as exc:
        first = "bucket policy" if "s3:GetObject" in str(exc) else "key policy"
    # Second lock: would the key still refuse if the bucket policy were ever loosened?
    if kms.allowed(alias, lab.ANALYST, "kms:Decrypt", {"aws:SourceAccount": lab.ACCOUNT}):
        return True, f"refused by the {first}, but {alias} would let tsg-analytics decrypt: one lock, not two"
    return False, f"refused by the {first}; {alias} has no statement for tsg-analytics either (two locks)"


def l2_pii_in_redacted(env):
    texts = _read_all(env["s3"], lab.REDACTED_BUCKET, lab.ANALYST, lambda k: "/data/" not in k)
    hits = Counter()
    for t in texts.values():
        low = t.lower()
        for value, kind in _canaries(env).items():
            if value.lower() in low:
                hits[kind] += 1
    if hits:
        return True, "survived redaction: " + ", ".join(f"{k} in {n} record(s)" for k, n in sorted(hits.items()))
    return False, f"{len(texts)} redacted records, no planted value left"


def l3_vectors_in_redacted(env):
    texts = _read_all(env["s3"], lab.REDACTED_BUCKET, lab.ANALYST)
    n = sum(len(list(detect.vector_paths(json.loads(t)))) for t in texts.values())
    if n:
        return True, f"{n} embedding arrays readable by analysts (input text sits next to them in the raw log)"
    return False, "no embedding arrays in the redacted copy"


def l4_large_body_unredacted(env):
    s3 = env["s3"]
    leaked = []
    for key in s3.list_objects(lab.REDACTED_BUCKET, ""):
        if "/data/" not in key:
            continue
        text = s3.get_object(lab.REDACTED_BUCKET, key, lab.ANALYST).decode().lower()
        if any(v.lower() in text for v in _canaries(env)):
            leaked.append(key.rsplit("/", 1)[-1])
    if leaked:
        return True, f"large body copied across unredacted: {', '.join(leaked)}"
    return False, "large bodies were redacted like every other record"


def l5_macie_blind(env):
    res = [r for r in env["macie"]["results"] if r["bucket"] == lab.RAW_BUCKET]
    not_read = [r for r in res if r["status"]["code"] != "COMPLETE"]
    raw_findings = [f for f in env["macie"]["findings"] if f["resourcesAffected"]["s3Bucket"]["name"] == lab.RAW_BUCKET]
    if not_read:
        why = Counter(f"{r['status']['code']}{' ' + r['status']['reason'] if r['status']['reason'] else ''}" for r in not_read)
        return True, (f"Macie read {len(res) - len(not_read)} of {len(res)} raw objects ("
                      + ", ".join(f"{n} {k}" for k, n in why.items()) + f"); findings on raw: {len(raw_findings)}")
    return False, f"Macie read all {len(res)} raw objects; findings on raw: {len(raw_findings)}"


def l6_macie_cannot_detect(env):
    job = env["setup"]["macie_job"]
    ids = [c for c in env["setup"]["identifiers"]["custom_data_identifiers"] if c["name"] in job["customDataIdentifiers"]]
    use_managed = job.get("managedDataIdentifierSelector") != "NONE"
    samples = dict(SAMPLES, **(CHALLENGE_SAMPLES if env["challenge"] else {}))
    missing = [kind for kind, text in samples.items() if not detect.find(text, use_managed=use_managed, custom_ids=ids)]
    if missing:
        return True, "this job can never find: " + ", ".join(missing)
    return False, "every planted kind has a detector in the job"


def l7_retention(env):
    s3 = env["s3"]
    cutoff = lab.NOW - dt.timedelta(days=RETENTION_DAYS)
    old = [(k, v) for k, v in s3.list_object_versions(lab.RAW_BUCKET) if lab.parse_time(v["last_modified"]) < cutoff]
    if old:
        hidden = sum(1 for k, v in old if k not in s3.list_objects(lab.RAW_BUCKET))
        return True, (f"{len(old)} raw objects older than {RETENTION_DAYS} days still stored "
                      f"({hidden} hidden behind delete markers, readable by version ID)")
    return False, f"nothing in the raw bucket is older than {RETENTION_DAYS} days"


def n1_analyst_report(env):
    texts = _read_all(env["s3"], lab.REDACTED_BUCKET, lab.ANALYST, lambda k: "/data/" not in k)
    since = lab.NOW - dt.timedelta(days=7)
    per_role, tokens = Counter(), Counter()
    for t in texts.values():
        rec = json.loads(t)
        if lab.parse_time(rec["timestamp"]) >= since:
            r = rec["identity"]["arn"].split("/")[1]
            per_role[r] += 1
            tokens[r] += rec["input"]["inputTokenCount"] + rec["output"]["outputTokenCount"]
    expected = Counter(c["role"] for c in env["calls"] if c["days_ago"] <= 7)
    ok = per_role == expected
    return ok, ", ".join(f"{r}: {n} calls, {tokens[r]} tokens" for r, n in sorted(per_role.items()))


def n2_break_glass(env):
    s3 = env["s3"]
    recent = [k for k in s3.list_objects(lab.RAW_BUCKET) if "/data/" not in k
              and lab.parse_time(s3.object_info(lab.RAW_BUCKET, k)["last_modified"]) >= lab.NOW - dt.timedelta(days=7)]
    try:
        rec = json.loads(s3.get_object(lab.RAW_BUCKET, recent[0], lab.BREAK_GLASS))
        return True, f"read {rec['requestId']} ({rec['operation']}, {rec['modelId']})"
    except AccessDenied as exc:
        return False, str(exc)


def n3_one_to_one(env):
    s3 = env["s3"]
    raw = {k for k in s3.list_objects(lab.RAW_BUCKET) if "/data/" not in k}
    red = {k for k in s3.list_objects(lab.REDACTED_BUCKET) if "/data/" not in k}
    # Raw records past retention are gone by design; the redacted copy keeps them longer.
    return raw <= red, f"{len(raw)} raw records, {len(red)} redacted records"


LEAKS = [("L1", "analyst reads a raw prompt", "28.4", l1_analyst_reads_raw),
         ("L2", "PII or secrets left in redacted records", "28.4", l2_pii_in_redacted),
         ("L3", "embedding vectors in the redacted copy", "28.1", l3_vectors_in_redacted),
         ("L4", "large body (>100 KB) copied unredacted", "28.4", l4_large_body_unredacted),
         ("L5", "Macie skipped raw objects, said nothing", "28.4", l5_macie_blind),
         ("L6", "kinds Macie's job can never detect", "28.4", l6_macie_cannot_detect),
         ("L7", "raw records kept past 30 days", "28.3", l7_retention)]
NORMAL = [("N1", "analyst weekly usage report (redacted only)", n1_analyst_report),
          ("N2", "break-glass reads this week's raw record", n2_break_glass),
          ("N3", "one redacted record per raw record", n3_one_to_one)]


def evaluate(env) -> dict:
    return {"leaks": {code: fn(env) for code, _, _, fn in LEAKS},
            "normal": {code: fn(env) for code, _, fn in NORMAL}}


def main(argv=None):
    ap = argparse.ArgumentParser(description="build a setup, run it, check it for leaks")
    ap.add_argument("setup")
    ap.add_argument("--challenge", action="store_true", help="add the challenge's loyalty-card call")
    a = ap.parse_args(argv)
    env = build(a.setup, a.challenge)
    r = evaluate(env)
    red = env["redactor"]
    print(f"setup {a.setup} | {len(env['calls'])} model calls logged | redactor: {red['records']} records, "
          f"{red['large_bodies']} large bodies redacted, {red['copied_unredacted']} copied as-is, "
          f"{red['replaced']} values replaced, {red['vectors_removed']} vectors removed")
    print(f"{'check':<5} {'what':<44} {'lesson':<7} result")
    for code, what, lesson, _ in LEAKS:
        leaked, detail = r["leaks"][code]
        print(f"{code:<5} {what:<44} {lesson:<7} {'LEAK   ' if leaked else 'closed '} {detail}")
    for code, what, _ in NORMAL:
        ok, detail = r["normal"][code]
        print(f"{code:<5} {what:<44} {'':<7} {'works  ' if ok else 'BROKEN '} {detail}")
    leaks = [c for c, (hit, _) in r["leaks"].items() if hit]
    works = sum(1 for ok, _ in r["normal"].values() if ok)
    print(f"\nLeaks: {len(leaks)} of {len(LEAKS)}  ({', '.join(leaks) or 'none'}) | normal jobs that work: "
          f"{works} of {len(NORMAL)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
