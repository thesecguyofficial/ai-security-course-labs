"""
explore.py: look at how AWS decides and records one API call, one step at a time, before you attack the lab
(M10 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON
files and prints what it finds; `sign` also does a little arithmetic (it computes a signature) and sends nothing.

    python3 explore.py org                     # 1. AnyCompany's accounts, its identities and their policies
    python3 explore.py sign                    # 2. how one API call is signed (SigV4), with AWS's example keys
    python3 explore.py policy examples/one-model-two-regions.json
                                               # 3. one policy, read statement by statement
    python3 explore.py decide DataScienceRole bedrock:InvokeModel \\
        arn:aws:bedrock:us-west-2::foundation-model/amazon.nova-lite-v1:0 --region us-west-2
                                               # 4. allowed or denied? the four checks, in order
    python3 explore.py call DataScienceRole amazon.nova-lite-v1:0 --region us-west-2
                                               # 5. one Converse call: the request, and every IAM check it needs
    python3 explore.py event Converse          # 6. one CloudTrail record, field by field

Everything is fake: AWS documentation example account IDs, key IDs and keys, and RFC 5737 IP addresses.
iam_eval.py, which `decide` and `call` use, is a teaching model of AWS policy evaluation, not the real engine.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import pathlib
import sys

import attack
from iam_eval import Request, _as_list, evaluate, load, statement_matches

HERE = pathlib.Path(__file__).resolve().parent
CLOUDTRAIL = HERE / "cloudtrail" / "anycompany-2026-10-09_14.json"


# ---------------------------------------------------------------- 1. org

def cmd_org(a) -> None:
    org = load("anycompany/principals.json")
    o = org["organization"]
    print("AnyCompany's AWS organization (fictional; account IDs are AWS documentation examples)\n")
    print(f"  management account  {o['management_account']}   (head office: SCPs never apply to it)")
    for acct, job in o["member_accounts"].items():
        print(f"  member account      {acct}   {job}")
    print(f"  SCPs on the root    {', '.join(pathlib.Path(s).stem for s in o['scps_on_root'])}")
    print("\nIdentities (who can make calls) and the policies that say what each may do:\n")
    for name, p in org["principals"].items():
        kind = p["arn"].split(":")[5].split("/")[0]        # role or user
        pols = ", ".join(pathlib.Path(x).stem for x in p["policies"])
        print(f"  {kind:<5} {name:<20} account {p['account']}   policies: {pols}")
        for k in p.get("bedrock_api_keys", []):
            exp = k["expires"] or "NEVER"
            print(f"        Bedrock API key {k['service_specific_credential_id']}  created {k['created']}  expires {exp}")


# ---------------------------------------------------------------- 2. sign (SigV4)

# AWS's own documentation example credentials (IAM user guide). They are not real and work nowhere.
EXAMPLE_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4(method: str, host: str, path: str, query: str, body: bytes, amz_date: str, region: str, service: str,
          key_id: str = EXAMPLE_KEY_ID, secret: str = EXAMPLE_SECRET) -> dict:
    """AWS Signature Version 4 for one request that signs only `host` and `x-amz-date`.
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html"""
    date = amz_date[:8]
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    canonical = "\n".join([method, path, query, canonical_headers, signed_headers, payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _hmac(("AWS4" + secret).encode(), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    k = _hmac(k, "aws4_request")
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    header = f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    return {"canonical": canonical, "to_sign": to_sign, "signature": signature, "authorization": header}


def cmd_sign(a) -> None:
    host = f"bedrock.{a.region}.amazonaws.com"
    s = sigv4("GET", host, "/foundation-models", "", b"", a.time, a.region, "bedrock")
    print("Signing one AWS API call with SigV4. Nothing is sent: this only computes the signature.")
    print("The keys are AWS's documentation examples; they work nowhere.\n")
    print(f"the call      ListFoundationModels = GET https://{host}/foundation-models")
    print(f"access key ID {EXAMPLE_KEY_ID}                        (travels with the request)")
    print(f"secret key    {EXAMPLE_SECRET}    (never leaves your computer)\n")
    print("1. canonical request: the call written out in a fixed order")
    for line in s["canonical"].split("\n"):
        print(f"     {line}")
    print("2. string to sign: the method, the time, the scope, and a SHA-256 fingerprint of step 1")
    for line in s["to_sign"].split("\n"):
        print(f"     {line}")
    print("3. signing key: the secret, mixed with the date, the Region, the service and 'aws4_request' (HMAC-SHA256 x4)")
    print("4. signature: HMAC-SHA256 of step 2 with that key")
    print(f"     {s['signature']}\n")
    print("the header AWS receives (one line, split here to fit):")
    cred, signed, sig = s["authorization"].split(", ")
    print(f"     Authorization: {cred},")
    print(f"                    {signed},")
    print(f"                    {sig}")
    print("AWS repeats steps 1 to 4 with its own copy of the secret. Change one character and the signatures differ.")


# ---------------------------------------------------------------- 3. policy

def _show(values) -> str:
    vals = _as_list(values)
    return ", ".join(vals) if len(vals) < 4 else f"{len(vals)} entries: " + ", ".join(vals[:2]) + ", ..."


def cmd_policy(a) -> None:
    path = pathlib.Path(a.file)
    doc = json.loads((path if path.is_absolute() or path.exists() else HERE / path).read_text())
    print(f"{a.file}\n")
    print(json.dumps(doc, indent=2))
    print(f"\nRead it statement by statement (Version {doc.get('Version', 'missing')} is the policy language version):")
    for i, st in enumerate(_as_list(doc.get("Statement")), 1):
        print(f"\n  statement {i}  Sid {st.get('Sid', '(none)')}: a label for people, AWS ignores it")
        print(f"    Effect     {st.get('Effect')}: what happens when the rest matches")
        if "Action" in st:
            print(f"    Action     {_show(st['Action'])}: the API calls it covers")
        else:
            print(f"    NotAction  {_show(st['NotAction'])}: every API call EXCEPT these")
        if "Resource" in st:
            print(f"    Resource   {_show(st['Resource'])}: the things those calls touch")
        else:
            print(f"    NotResource {_show(st['NotResource'])}: everything EXCEPT these")
        cond = st.get("Condition")
        if not cond:
            print("    Condition  none: it applies whatever the request's details")
        for op, keys in (cond or {}).items():
            for key, vals in keys.items():
                print(f"    Condition  {op} {key} = {_show(vals)}: only when the request's {key} matches")


# ---------------------------------------------------------------- 4. decide

def _first(statements, req, effect):
    for name, st in statements:
        if st.get("Effect") == effect and statement_matches(st, req):
            return f"{name} ({st.get('Sid', 'no Sid')})"
    return None


def cmd_decide(a) -> None:
    p = attack.principal(a.principal)
    ctx = attack.base_ctx(a.principal, a.region)
    req = Request(p["arn"], a.action, a.resource, ctx)
    idp = [(pathlib.Path(n).stem, st) for n, pol in attack.identity_policies(a.principal) for st in _as_list(pol["Statement"])]
    scp_docs = attack.scps_for("safe" if a.fixes else "vulnerable")
    scps = [(n, st) for n, pol in scp_docs for st in _as_list(pol["Statement"])]
    in_mgmt = p["account"] == attack.MGMT
    print(f"request   {a.principal} ({p['arn'].split(':')[5]}) wants {a.action}")
    print(f"resource  {a.resource}")
    print(f"context   " + "  ".join(f"{k}={v}" for k, v in ctx.items()))
    print(f"SCPs      {', '.join(n for n, _ in scp_docs)}\n")

    def done(allowed: bool, why: str) -> None:
        print(f"\n=> {'ALLOWED' if allowed else 'DENIED'}: {why}")

    hit = _first(idp, req, "Deny")
    print(f"step 1  a Deny in its own policies?   {'YES  ' + hit if hit else 'no'}")
    if hit:
        return done(False, "an explicit Deny always wins")
    if in_mgmt:
        print("step 2  SCPs                          skipped: SCPs never apply to the management account")
    else:
        hit = _first(scps, req, "Deny")
        print(f"step 2  a Deny in the SCPs?           {'YES  ' + hit if hit else 'no'}")
        if hit:
            print("        (steps 3 and 4 don't matter any more)")
            return done(False, "an explicit Deny always wins, whatever allows it")
        hit = _first(scps, req, "Allow")
        print(f"step 3  does an SCP allow it?         {'yes  ' + hit if hit else 'NO'}")
        if not hit:
            return done(False, "no SCP allows it: SCPs set the ceiling")
    hit = _first(idp, req, "Allow")
    print(f"step 4  does its own policy allow it? {'yes  ' + hit if hit else 'NO'}")
    if not hit:
        return done(False, "nothing allows it, so it is denied by default (implicit deny)")
    done(True, "allowed by its own policy, under the SCP ceiling, and nothing denies it")


# ---------------------------------------------------------------- 5. call

def cmd_call(a) -> None:
    host = f"bedrock-runtime.{a.region}.amazonaws.com"
    body = {"messages": [{"role": "user", "content": [{"text": "Summarise ticket 4521 in one line."}]}]}
    print("One Converse call, as the app would send it (illustrative; nothing is sent):\n")
    print(f"  POST https://{host}/model/{a.model}/converse")
    print(f"  Authorization: {'Bearer <a Bedrock API key>' if a.api_key else 'AWS4-HMAC-SHA256 Credential=... (SigV4, as in sign)'}")
    print(f"  {json.dumps(body)}\n")
    checks = attack.invoke(a.principal, a.model, region=a.region, bearer="LONG_TERM" if a.api_key else None)
    scps = attack.scps_for("safe" if a.fixes else "vulnerable")
    pols = attack.identity_policies(a.principal)
    print(f"Converse is authorized as bedrock:InvokeModel. IAM runs {len(checks)} check(s) for this one call:")

    ok = True
    for i, r in enumerate(checks, 1):
        d = evaluate(r, pols, scps, scps_apply=attack.principal(a.principal)["account"] != attack.MGMT)
        ok &= d.allowed
        extra = "  (" + ", ".join(f"{k}={v}" for k, v in r.context.items() if k.startswith(("bedrock", "bedrock-mantle"))) + ")" \
            if any(k.startswith("bedrock") for k in r.context) else ""
        print(f"  {i}. {r.action} on {r.resource}{extra}")
        print(f"       {'ALLOWED' if d.allowed else 'DENIED '}  {d.reason}")
    print(f"\n=> the call {'goes through' if ok else 'is refused'}: every check must pass. "
          "If it goes through, the bill counts input and output tokens.")


# ---------------------------------------------------------------- 6. event

FIELDS = [
    ("who", "userIdentity.type"), ("", "userIdentity.arn"),
    ("what", "eventSource"), ("", "eventName"), ("", "requestParameters"),
    ("where", "awsRegion"), ("", "sourceIPAddress"), ("", "userAgent"),
    ("when", "eventTime"),
    ("how", "additionalEventData"),
    ("result", "errorCode"),
]


def _get(rec: dict, dotted: str):
    cur = rec
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def cmd_event(a) -> None:
    records = json.loads(CLOUDTRAIL.read_text())["Records"]
    hits = [(i, r) for i, r in enumerate(records, 1) if r.get("eventName") == a.name
            and (not a.source_ip or r.get("sourceIPAddress") == a.source_ip)]
    if not hits:
        sys.exit(f"no {a.name} record" + (f" from {a.source_ip}" if a.source_ip else ""))
    i, rec = hits[min(a.nth, len(hits)) - 1]
    print(f"CloudTrail record {i} of {len(records)} (fake, with the same fields as AWS's examples)\n")
    for group, key in FIELDS:
        v = _get(rec, key)
        if v is None:
            shown = "-  (none: the call worked)" if key == "errorCode" else "-"
        else:
            shown = json.dumps(v) if isinstance(v, (dict, list, bool)) else str(v)
        print(f"  {group:<7}{key:<21}{shown}")
    print("\n  not here: the prompt and the answer. CloudTrail records the call, not the conversation.")


# ---------------------------------------------------------------- main

def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="Look at how AWS decides and records one API call (M10 lab, read-only).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("org"); s.set_defaults(fn=cmd_org)
    s = sub.add_parser("sign"); s.add_argument("--region", default="us-east-1")
    s.add_argument("--time", default="20261009T120000Z", help="the x-amz-date value (UTC)"); s.set_defaults(fn=cmd_sign)
    s = sub.add_parser("policy"); s.add_argument("file"); s.set_defaults(fn=cmd_policy)
    s = sub.add_parser("decide"); s.add_argument("principal", choices=sorted(attack.ORG["principals"]))
    s.add_argument("action"); s.add_argument("resource", nargs="?", default="*", help="an ARN (default *: no resource)")
    s.add_argument("--region", default="us-east-1")
    s.add_argument("--fixes", action="store_true", help="add the three SCPs in fixes/"); s.set_defaults(fn=cmd_decide)
    s = sub.add_parser("call"); s.add_argument("principal", choices=sorted(attack.ORG["principals"]))
    s.add_argument("model", help="a model ID or an inference profile ID"); s.add_argument("--region", default="us-east-1")
    s.add_argument("--api-key", action="store_true", help="the call uses a long-term Bedrock API key")
    s.add_argument("--fixes", action="store_true", help="add the three SCPs in fixes/"); s.set_defaults(fn=cmd_call)
    s = sub.add_parser("event"); s.add_argument("name", help="an eventName, e.g. Converse")
    s.add_argument("--from", dest="source_ip", help="only records from this IP address")
    s.add_argument("--nth", type=int, default=1, help="which matching record (1 = the earliest)"); s.set_defaults(fn=cmd_event)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
