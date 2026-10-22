"""
hunt.py: hunt for LLMjacking in a CloudTrail export, the way a SOC analyst would.

    python3 hunt.py                 # every rule
    python3 hunt.py --naive         # the rule many teams start with: InvokeModel calls only
    python3 hunt.py --file other.json

Input: a CloudTrail file ({"Records": [...]}, the format CloudTrail delivers to S3). The sample in cloudtrail/ is
FAKE: it copies the shape of real records in the AWS docs and the attacker behaviour in Sysdig TRT's LLMjacking
reports, with documentation-only account IDs and IP addresses.

The baseline is everything before --baseline-until (default 2026-10-14T00:00:00Z): who normally calls which
Bedrock APIs, from where, and how often. Rules H02, H03, H07 and H08 compare against it.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import pathlib
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_FILE = HERE / "cloudtrail" / "anycompany-2026-10-09_14.json"
APPROVED = json.loads((HERE / "anycompany" / "approved-models.json").read_text())
PRINCIPALS = json.loads((HERE / "anycompany" / "principals.json").read_text())["principals"]

INVOKE = {"InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream"}
RECON = {"ListFoundationModels", "GetFoundationModelAvailability", "GetModelInvocationLoggingConfiguration",
         "GetUseCaseForModelAccess", "ListFoundationModelAgreementOffers"}
ENABLE = {"PutUseCaseForModelAccess", "CreateFoundationModelAgreement", "PutFoundationModelEntitlement"}
TAMPER = {("bedrock.amazonaws.com", "DeleteModelInvocationLoggingConfiguration"),
          ("bedrock.amazonaws.com", "PutModelInvocationLoggingConfiguration"),
          ("cloudtrail.amazonaws.com", "StopLogging"), ("cloudtrail.amazonaws.com", "DeleteTrail"),
          ("cloudtrail.amazonaws.com", "PutEventSelectors")}
SECURITY_ADMIN_ARNS = {p["arn"] for p in PRINCIPALS.values() if p.get("purpose") == "security-admin"}


@dataclass
class Hit:
    rule: str
    severity: str
    principal: str
    title: str
    evidence: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)

    def show(self) -> str:
        first = self.events[0]["eventTime"] if self.events else "?"
        lines = [f"  {self.severity:<6} {self.rule}  {first}  {short(self.principal)}", f"         {self.title}"]
        lines += [f"         - {e}" for e in self.evidence[:4]]
        return "\n".join(lines)


def short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def principal_of(r: dict) -> str:
    """The stable identity behind an event: the role ARN for role sessions, the user ARN for IAM users."""
    ui = r.get("userIdentity", {})
    issuer = ui.get("sessionContext", {}).get("sessionIssuer", {})
    return issuer.get("arn") or ui.get("arn", "?")


def ts(r: dict) -> dt.datetime:
    return dt.datetime.strptime(r["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def model_of(r: dict) -> str:
    p = r.get("requestParameters") or {}
    m = p.get("modelId") or p.get("model") or ""
    return m.split("/")[-1] if m.startswith("arn:") else m


def approved(model: str) -> bool:
    """bedrock-runtime takes foundation-model or inference-profile IDs; bedrock-mantle has its own model IDs."""
    return model in APPROVED["foundation_models"] or model in APPROVED["inference_profiles"] \
        or model in APPROVED.get("mantle_models", [])


def is_invocation(r: dict) -> bool:
    return (r.get("eventSource") == "bedrock.amazonaws.com" and r.get("eventName") in INVOKE
            and r.get("eventType") == "AwsApiCall")


def bearer(r: dict) -> bool:
    return bool((r.get("additionalEventData") or {}).get("callWithBearerToken")
                or (r.get("requestParameters") or {}).get("callWithBearerToken"))


def load_records(path: pathlib.Path) -> list[dict]:
    return sorted(json.loads(path.read_text())["Records"], key=lambda r: r["eventTime"])


# ---------------------------------------------------------------- baseline

@dataclass
class Baseline:
    ips: dict = field(default_factory=lambda: collections.defaultdict(set))
    invokers: set = field(default_factory=set)
    recon_callers: set = field(default_factory=set)
    max_hourly: dict = field(default_factory=lambda: collections.defaultdict(int))


def build_baseline(records: list[dict], until: dt.datetime) -> Baseline:
    b = Baseline()
    hourly = collections.Counter()
    for r in records:
        if ts(r) >= until:
            break
        p = principal_of(r)
        if r.get("eventType") == "AwsApiCall":
            b.ips[p].add(r.get("sourceIPAddress"))
        if is_invocation(r) and not r.get("errorCode"):
            b.invokers.add(p)
            hourly[(p, r["eventTime"][:13])] += 1
        if r.get("eventName") in RECON:
            b.recon_callers.add(p)
    for (p, _), c in hourly.items():
        b.max_hourly[p] = max(b.max_hourly[p], c)
    return b


# ---------------------------------------------------------------- rules

def rule_key_created(records, base, since) -> list[Hit]:
    """H01: a long-term Bedrock API key was created (CreateServiceSpecificCredential for bedrock.amazonaws.com),
    or the console made a 'BedrockAPIKey-...' IAM user for one."""
    hits = []
    for r in records:
        p = r.get("requestParameters") or {}
        if r.get("eventName") == "CreateServiceSpecificCredential" and \
                (p.get("serviceName") or p.get("service")) == "bedrock.amazonaws.com":
            age = p.get("credentialAgeDays")
            sev = "HIGH" if age is None or int(age) > 90 else "MEDIUM"
            hits.append(Hit("H01", sev, principal_of(r), f"long-term Bedrock API key created for user {p.get('userName')}",
                            ["credentialAgeDays: " + ("missing -> the key NEVER expires" if age is None else str(age))], [r]))
        if r.get("eventName") == "CreateUser" and str(p.get("userName", "")).startswith("BedrockAPIKey"):
            hits.append(Hit("H01", "LOW", principal_of(r), f"console-style API-key user created: {p['userName']}", [], [r]))
    return hits


def rule_recon(records, base, since) -> list[Hit]:
    """H02: someone new asks 'which models can I use, and is logging on?' (2+ different recon calls in 30 min)."""
    by_p = collections.defaultdict(list)
    for r in records:
        if ts(r) >= since and r.get("eventName") in RECON:
            by_p[principal_of(r)].append(r)
    hits = []
    for p, evs in by_p.items():
        if p in SECURITY_ADMIN_ARNS or p in base.recon_callers:
            continue
        window = [e for e in evs if (ts(e) - ts(evs[0])).total_seconds() <= 1800]
        names = sorted({e["eventName"] for e in window})
        if len(names) >= 2:
            hits.append(Hit("H02", "HIGH", p, "model and logging reconnaissance by a principal that never did this before",
                            [", ".join(names), f"from {window[0]['sourceIPAddress']}  UA: {window[0]['userAgent']}"], window))
    return hits


def rule_probe(records, base, since) -> list[Hit]:
    """H03: an invocation that fails with ValidationException from a principal with no successful invocations in the
    baseline. Sysdig saw attackers send deliberately invalid requests: a ValidationException means 'the key works'."""
    hits = []
    for r in records:
        if ts(r) >= since and is_invocation(r) and r.get("errorCode") == "ValidationException" \
                and principal_of(r) not in base.invokers:
            hits.append(Hit("H03", "MEDIUM", principal_of(r), "invalid-request probe (ValidationException) from a new invoker",
                            [f"{r['eventName']} {model_of(r)} from {r['sourceIPAddress']}"], [r]))
    return hits


def rule_logging_tamper(records, base, since) -> list[Hit]:
    """H04: Bedrock invocation logging or CloudTrail changed by anyone but the security admin."""
    return [Hit("H04", "HIGH", principal_of(r), f"{r['eventName']}: audit trail changed by a non-security principal",
                [f"from {r['sourceIPAddress']}  UA: {r['userAgent']}"], [r])
            for r in records if (r.get("eventSource"), r.get("eventName")) in TAMPER
            and principal_of(r) not in SECURITY_ADMIN_ARNS]


def rule_enablement(records, base, since) -> list[Hit]:
    """H05: model-enablement calls (Anthropic use-case form, Marketplace agreements; PutFoundationModelEntitlement is
    retired since Oct 2025 but is still a signal)."""
    return [Hit("H05", "MEDIUM", principal_of(r), f"{r['eventName']}: someone is enabling models",
                [f"from {r['sourceIPAddress']}"], [r])
            for r in records if r.get("eventName") in ENABLE and ts(r) >= since]


def rule_unapproved_model(records, base, since) -> list[Hit]:
    """H06: bedrock-runtime invocations of a model or profile that isn't on the approved list."""
    groups = collections.defaultdict(list)
    for r in records:
        if is_invocation(r) and not approved(model_of(r)):
            groups[(principal_of(r), model_of(r))].append(r)
    return [Hit("H06", "HIGH", p, f"{len(evs)} invocation(s) of unapproved model {m}",
                [f"events: {sorted({e['eventName'] for e in evs})}  from {sorted({e['sourceIPAddress'] for e in evs})}"], evs)
            for (p, m), evs in groups.items()]


def rule_new_source(records, base, since) -> list[Hit]:
    """H07: invocations from an IP the principal never used in the baseline (or from a principal with no baseline).
    API-key (bearer token) use is called out, because a key works from anywhere."""
    groups = collections.defaultdict(list)
    for r in records:
        if ts(r) >= since and is_invocation(r) and r.get("sourceIPAddress") not in base.ips.get(principal_of(r), set()):
            groups[(principal_of(r), r["sourceIPAddress"])].append(r)
    hits = []
    for (p, ip), evs in groups.items():
        how = "Bedrock API key (bearer token)" if any(bearer(e) for e in evs) else "SigV4 credentials"
        known = sorted(base.ips.get(p, set())) or ["none: never seen before"]
        hits.append(Hit("H07", "HIGH", p, f"{len(evs)} invocation(s) from a new source {ip} using {how}",
                        [f"baseline IPs: {', '.join(known)}"], evs))
    return hits


def rule_volume(records, base, since) -> list[Hit]:
    """H08: invocations per principal per hour above max(3 x baseline peak, 20)."""
    hourly = collections.defaultdict(list)
    for r in records:
        if ts(r) >= since and is_invocation(r):
            hourly[(principal_of(r), r["eventTime"][:13])].append(r)
    hits = []
    for (p, hour), evs in hourly.items():
        limit = max(3 * base.max_hourly.get(p, 0), 20)
        if len(evs) > limit:
            hits.append(Hit("H08", "MEDIUM", p, f"{len(evs)} invocations in the hour {hour}:00Z (limit {limit})",
                            [f"baseline peak: {base.max_hourly.get(p, 0)} per hour"], evs))
    return hits


def rule_mantle_inference(records, base, since) -> list[Hit]:
    """H09 (YOUR TURN, make challenge): inference on the bedrock-mantle endpoint.

    Mantle calls arrive as DATA events with eventSource 'bedrock-mantle.amazonaws.com' and eventName 'CreateInference';
    the model is in requestParameters['model'] (model_of() already reads it). Rules that only look at
    bedrock.amazonaws.com never see them.

    Return one Hit per (principal, model) for every CreateInference with a model that isn't approved:
    rule "H09", severity "HIGH", and put the matching events in Hit.events.
    Don't flag approved models (the chatbot uses anthropic.claude-haiku-4-5 there every hour; approved() already
    knows the mantle model IDs in approved-models.json).
    """
    return []


RULES = [rule_key_created, rule_recon, rule_probe, rule_logging_tamper, rule_enablement, rule_unapproved_model,
         rule_new_source, rule_volume, rule_mantle_inference]


def rule_naive(records, base, since) -> list[Hit]:
    """What many teams start with: alert on InvokeModel calls of unapproved models, on bedrock.amazonaws.com."""
    evs = [r for r in records if r.get("eventSource") == "bedrock.amazonaws.com" and r.get("eventName") == "InvokeModel"
           and not approved(model_of(r))]
    return [Hit("NAIVE", "HIGH", principal_of(e), f"InvokeModel of unapproved model {model_of(e)}", [], [e]) for e in evs]


def hunt(path: pathlib.Path = DEFAULT_FILE, baseline_until: str = "2026-10-14T00:00:00Z", naive: bool = False):
    records = load_records(path)
    since = dt.datetime.strptime(baseline_until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    base = build_baseline(records, since)
    hits = []
    for rule in ([rule_naive] if naive else RULES):
        hits += rule(records, base, since)
    return records, hits


def attacker_activity(records: list[dict]) -> list[dict]:
    """For the summary only: the events the sample's attackers made (any event from a 'new' attack IP)."""
    return [r for r in records if r.get("sourceIPAddress") in ("203.0.113.50", "198.51.100.77")]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default=str(DEFAULT_FILE))
    ap.add_argument("--baseline-until", default="2026-10-14T00:00:00Z")
    ap.add_argument("--naive", action="store_true")
    a = ap.parse_args()
    records, hits = hunt(pathlib.Path(a.file), a.baseline_until, a.naive)
    print(f"--- M10 LLMjacking hunt · {'NAIVE rule only' if a.naive else 'all rules'} · {len(records)} CloudTrail records ---\n")
    for h in sorted(hits, key=lambda h: h.events[0]["eventTime"] if h.events else ""):
        print(h.show())
    attack = attacker_activity(records)
    seen = {id(e) for h in hits for e in h.events}
    caught = [e for e in attack if id(e) in seen]
    by_source = collections.Counter(e["eventSource"] for e in attack)
    print(f"\n{len(hits)} finding{'' if len(hits) == 1 else 's'}. Attacker events covered by a finding: {len(caught)} of {len(attack)} "
          f"({', '.join(f'{v} on {k}' for k, v in sorted(by_source.items()))}).")
    missed = collections.Counter(f"{e['eventSource']} {e['eventName']}" for e in attack if id(e) not in seen)
    if missed:
        print("Not covered: " + "; ".join(f"{v} x {k}" for k, v in sorted(missed.items())))


if __name__ == "__main__":
    main()
