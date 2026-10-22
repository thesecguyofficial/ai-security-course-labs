"""
hunt.py: hunt for LLMjacking in ExampleCo's sample Cloud Audit Logs.

    python3 hunt.py            # every rule (H01-H08, plus H09 once you write it)
    python3 hunt.py --naive    # the one rule many teams start with: "GenerateContent on a model we didn't approve"
    python3 hunt.py --summary --file my-audit.json   # your own export (gcloud logging read ... --format=json): what's in it

The sample file holds FAKE entries, shaped like Cloud Audit Logs (LogEntry + AuditLog, simplified).
Days 12-14 Oct are the baseline; the rules look at 15-16 Oct. H02, H04 and H07 borrow the idea of three Event Threat
Detection findings for AI services (Dormant Service Account Activity in AI Service, New Geography for AI Service, New
AI API Method). They are home-made rules, not Google's detectors: Google's dormant finding means inactive for more than
180 days, its new-geography finding uses the caller's location, and its new-method finding describes admin activity.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import ipaddress
import json
import pathlib

from gcp_eval import CORP, Corp, load_json

HERE = pathlib.Path(__file__).resolve().parent
LOGFILE = HERE / "auditlogs" / "examplecorp-2026-10-12_16.jsonl"
CUTOFF = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)
AI_SERVICES = {"aiplatform.googleapis.com", "generativelanguage.googleapis.com"}
INFERENCE = ("PredictionService.GenerateContent", "PredictionService.StreamGenerateContent",
             "PredictionService.RawPredict", "PredictionService.StreamRawPredict", "PredictionService.Predict")
DORMANT_DAYS = 180          # Event Threat Detection treats >180 days without activity as dormant
VOLUME_FLOOR = 20           # calls per principal per hour that always count as "a lot" in this lab
ATTACKER_NET = ipaddress.ip_network("203.0.113.0/24")   # lab ground truth only: rules never use it


@dataclasses.dataclass
class Hit:
    rule: str
    severity: str
    when: str
    who: str
    text: str
    details: list
    events: list


# --- helpers ---------------------------------------------------------------------------------------------------------
def load(path=LOGFILE):
    """JSON Lines (the sample) or a JSON array (what `gcloud logging read --format=json` prints)."""
    text = pathlib.Path(path).read_text().strip()
    raw = json.loads(text) if text.startswith("[") else [json.loads(x) for x in text.splitlines() if x.strip()]
    out = []
    for e in raw:
        if "protoPayload" not in e:
            continue
        stamp = e["timestamp"].replace("Z", "+00:00")
        if "." in stamp:  # real entries can carry nanoseconds; keep microseconds for fromisoformat
            head, tail = stamp.split(".", 1)
            frac, zone = tail[:-6], tail[-6:]
            stamp = f"{head}.{frac[:6].ljust(6, '0')}{zone}"
        e["_ts"] = dt.datetime.fromisoformat(stamp)
        out.append(e)
    return sorted(out, key=lambda e: e["_ts"])


def summary(records):
    """For your own export: what is actually in it, so you can match methodName and fields to the lab's rules."""
    c = collections.Counter((pp(e).get("serviceName"), method(e), who(e), ip(e)) for e in records)
    print(f"--- {len(records)} audit log entries · count by service, method, principal, caller IP ---")
    for (svc, m, p, addr), n in c.most_common():
        print(f"  {n:>5}  {svc}  {m}  {p}  {addr}")


def pp(e):
    return e["protoPayload"]


def who(e):
    return pp(e).get("authenticationInfo", {}).get("principalEmail", "?")


def ip(e):
    return pp(e).get("requestMetadata", {}).get("callerIp", "?")


def method(e):
    return pp(e).get("methodName", "")


def project(e):
    return e["logName"].split("/")[1]


def is_ai(e):
    return pp(e).get("serviceName") in AI_SERVICES


def is_inference(e):
    return is_ai(e) and method(e).endswith(INFERENCE)


def model_value(e):
    """publishers/P/models/M:ACTION for inference and deploy events, else ''."""
    if is_inference(e):
        res = pp(e).get("resourceName", "")
        i = res.find("publishers/")
        return res[i:] + ":predict" if i >= 0 else ""
    if method(e).endswith("EndpointService.DeployModel"):
        m = pp(e).get("request", {}).get("deployedModel", {}).get("model", "")
        return m + ":deploy" if m.startswith("publishers/") else ""
    return ""


def short(p):
    return p.split("@")[0] if p.endswith(".gserviceaccount.com") else p


def attacker_activity(records):
    """Lab ground truth: every entry from the attackers' documentation range (used by the tests, not by rules)."""
    return [e for e in records if ipaddress.ip_address(ip(e)) in ATTACKER_NET]


@dataclasses.dataclass
class Baseline:
    principals: set
    ips: dict
    methods: dict
    peak_per_hour: dict
    deployers: set


def build_baseline(records, cutoff=CUTOFF):
    ips, methods, per_hour = collections.defaultdict(set), collections.defaultdict(set), collections.Counter()
    principals, deployers = set(), set()
    for e in records:
        if e["_ts"] >= cutoff:
            continue
        p = who(e)
        principals.add(p)
        if is_ai(e):
            ips[p].add(ip(e))
            methods[p].add(method(e))
        if is_inference(e):
            per_hour[(p, e["_ts"].strftime("%Y-%m-%dT%H"))] += 1
        if method(e).endswith("DeployModel"):
            deployers.add(p)
    peak = collections.defaultdict(int)
    for (p, _), c in per_hour.items():
        peak[p] = max(peak[p], c)
    return Baseline(principals, ips, methods, peak, deployers)


def window(records, cutoff=CUTOFF):
    return [e for e in records if e["_ts"] >= cutoff]


def ts(e):
    return e["timestamp"][:19] + "Z"


# --- rules -------------------------------------------------------------------------------------------------------------
def rule_sa_key_created(records, base, corp):
    """H01 a user-managed service account key was created"""
    out = []
    for e in window(records):
        if method(e) == "google.iam.admin.v1.CreateServiceAccountKey":
            target = pp(e)["resourceName"].rsplit("/", 1)[-1]
            out.append(Hit("H01", "HIGH", ts(e), who(e), f"service account key created for {target}",
                           [f"from {ip(e)}  UA: {pp(e)['requestMetadata'].get('callerSuppliedUserAgent', '?')}"], [e]))
    return out


def rule_dormant_service_account(records, base, corp):
    """H02 a dormant user-managed service account acts (idea from ETD: Dormant Service Account Activity in AI Service)"""
    last = {sa["email"]: sa.get("lastAuthenticatedTime") for sa in corp.service_accounts}
    by = collections.defaultdict(list)
    for e in window(records):
        p = who(e)
        if p in last and p not in base.principals and last[p]:
            seen = dt.datetime.fromisoformat(last[p].replace("Z", "+00:00"))
            if (e["_ts"] - seen).days > DORMANT_DAYS:
                by[p].append(e)
    out = []
    for p, evs in by.items():
        seen = last[p][:10]
        out.append(Hit("H02", "HIGH", ts(evs[0]), p,
                       f"dormant service account active again ({(evs[0]['_ts'] - dt.datetime.fromisoformat(last[p].replace('Z', '+00:00'))).days} days since {seen})",
                       [f"{len(evs)} action(s): " + ", ".join(sorted({method(e).rsplit('.', 1)[-1] for e in evs})),
                        f"from {sorted({ip(e) for e in evs})}"], evs))
    return out


def rule_api_key_created(records, base, corp):
    """H03 an API key was created (HIGH when bound to a service account)"""
    out = []
    for e in window(records):
        if method(e) == "google.api.apikeys.v2.ApiKeys.CreateKey":
            key = pp(e).get("request", {}).get("key", {})
            sa = key.get("serviceAccountEmail")
            if sa:
                out.append(Hit("H03", "HIGH", ts(e), who(e),
                               f"authorization key '{key.get('displayName', '?')}' bound to {sa}",
                               [f"from {ip(e)}", "works like a long-lived token; its calls aren't in SA usage metrics"], [e]))
            else:
                out.append(Hit("H03", "LOW", ts(e), who(e), f"standard API key '{key.get('displayName', '?')}' created",
                               [f"from {ip(e)}"], [e]))
    return out


def rule_new_ip(records, base, corp):
    """H04 AI calls from an IP this principal never used (idea from ETD: New Geography for AI Service; the lab compares IPs, not locations)"""
    groups = collections.defaultdict(list)
    for e in window(records):
        if is_ai(e) and ip(e) not in base.ips.get(who(e), set()):
            groups[(who(e), ip(e))].append(e)
    return [Hit("H04", "HIGH" if who_ in base.principals else "MEDIUM", ts(evs[0]), who_,
                f"{len(evs)} AI call(s) from new source {addr}",
                [f"baseline IPs: {', '.join(sorted(base.ips.get(who_, set()))) or 'none: never seen before'}"], evs)
            for (who_, addr), evs in groups.items()]


def rule_unapproved_model(records, base, corp):
    """H05 inference or deployment of a model the governance board didn't approve for that environment"""
    groups = collections.defaultdict(list)
    for e in window(records):
        mv = model_value(e)
        if mv and project(e) in corp.projects:
            if mv not in corp.approved[corp.env_of(project(e))]:
                groups[(who(e), mv)].append(e)
    return [Hit("H05", "HIGH", ts(evs[0]), p, f"{len(evs)} call(s) on unapproved {mv}",
                [f"methods: {sorted({method(e).rsplit('.', 1)[-1] for e in evs})}  from {sorted({ip(e) for e in evs})}"],
                evs) for (p, mv), evs in groups.items()]


def rule_volume(records, base, corp):
    """H06 inference volume per principal per hour far above its baseline"""
    groups = collections.defaultdict(list)
    for e in window(records):
        if is_inference(e):
            groups[(who(e), e["_ts"].strftime("%Y-%m-%dT%H"))].append(e)
    out = []
    for (p, hour), evs in sorted(groups.items(), key=lambda kv: kv[0][1]):
        limit = max(VOLUME_FLOOR, 3 * base.peak_per_hour.get(p, 0))
        if len(evs) > limit:
            out.append(Hit("H06", "MEDIUM", ts(evs[0]), p, f"{len(evs)} inference calls in the hour {hour}:00Z (limit {limit})",
                           [f"baseline peak: {base.peak_per_hour.get(p, 0)} per hour"], evs))
    return out


def rule_new_method(records, base, corp):
    """H07 a principal uses an AI API method it never used before (idea from ETD: New AI API Method)"""
    groups = collections.defaultdict(list)
    for e in window(records):
        if is_ai(e) and who(e) in base.principals and method(e) not in base.methods.get(who(e), set()):
            groups[(who(e), method(e))].append(e)
    return [Hit("H07", "MEDIUM", ts(evs[0]), p, f"new AI method {m.rsplit('.', 1)[-1]} ({len(evs)} call(s))",
                [f"baseline methods: {sorted(x.rsplit('.', 1)[-1] for x in base.methods.get(p, set()))}"], evs)
            for (p, m), evs in groups.items()]


def rule_first_deployment(records, base, corp):
    """H08 a model deployed to an endpoint by a principal that never deployed before (endpoints bill while they run)"""
    out = []
    for e in window(records):
        if method(e).endswith("EndpointService.DeployModel") and who(e) not in base.deployers:
            out.append(Hit("H08", "MEDIUM", ts(e), who(e), f"first model deployment: {model_value(e) or '?'}",
                           [f"endpoint {pp(e)['resourceName'].rsplit('/', 1)[-1]}  from {ip(e)}"], [e]))
    return out


def rule_ai_enabled_in_unapproved_project(records, base, corp):
    """H09 (YOURS): an AI API was enabled in a project that isn't approved for AI"""
    # TODO (challenge, README Step 7): return one Hit("H09", "HIGH", ...) per EnableService event in the window
    # that enables aiplatform.googleapis.com or generativelanguage.googleapis.com in a project whose
    # "aiApproved" is false in examplecorp/hierarchy.json. Hints: method(e), pp(e)["resourceName"],
    # corp.by_number maps a project NUMBER to its project ID, corp.projects[pid]["aiApproved"].
    return []


RULES = [rule_sa_key_created, rule_dormant_service_account, rule_api_key_created, rule_new_ip,
         rule_unapproved_model, rule_volume, rule_new_method, rule_first_deployment,
         rule_ai_enabled_in_unapproved_project]


def rule_naive(records, base, corp):
    """NAIVE GenerateContent on a model we didn't approve"""
    out = []
    for e in window(records):
        if method(e).endswith("PredictionService.GenerateContent") and model_value(e) not in \
                corp.approved[corp.env_of(project(e))]:
            out.append(e)
    if not out:
        return []
    return [Hit("NAIVE", "HIGH", ts(out[0]), who(out[0]),
                f"{len(out)} GenerateContent call(s) on unapproved {sorted({model_value(e) for e in out})}", [], out)]


def hunt(naive=False, path=LOGFILE):
    records = load(path)
    corp = Corp()
    base = build_baseline(records)
    hits = []
    for r in ([rule_naive] if naive else RULES):
        hits += r(records, base, corp)
    return records, sorted(hits, key=lambda h: (h.when, h.rule))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--naive", action="store_true")
    ap.add_argument("--file", default=str(LOGFILE))
    ap.add_argument("--summary", action="store_true", help="just count what's in the file (use on your own export)")
    args = ap.parse_args(argv)
    if args.summary:
        summary(load(args.file))
        return
    records, hits = hunt(args.naive, args.file)
    print(f"--- GC10 LLMjacking hunt · {'NAIVE rule only' if args.naive else 'all rules'} · {len(records)} audit log entries ---\n")
    for h in hits:
        print(f"  {h.severity:<6} {h.rule:<5} {h.when}  {short(h.who)}")
        print(f"         {h.text}")
        for d in h.details:
            print(f"         - {d}")
    atk = attacker_activity(records)
    caught = {id(e) for h in hits for e in h.events}
    covered = sum(id(e) in caught for e in atk)
    print(f"\n{len(hits)} finding(s). Attacker entries covered by a finding: {covered} of {len(atk)}.")
    missed = collections.Counter(method(e).rsplit(".", 1)[-1] for e in atk if id(e) not in caught)
    if missed:
        print("Not covered: " + "; ".join(f"{c} x {m}" for m, c in sorted(missed.items())))
    print("Not in this file at all: the sandbox's Claude calls (Data Access audit logs are off there).")


if __name__ == "__main__":
    main()
