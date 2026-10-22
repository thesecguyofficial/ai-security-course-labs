"""
hunt.py: hunt for stolen-credential abuse of Azure AI (LLMjacking) in three log sources, the way a SOC analyst would.

    python3 hunt.py            # every rule
    python3 hunt.py --naive    # the only "detection" many teams have: a daily cost/usage check

Inputs (all FAKE, in logs/):
  activity-log.json                     Azure Monitor activity log: control plane (who listed keys, who deployed what)
  azurediagnostics-requestresponse.json resource logs, category RequestResponse: data plane (who called the model, from where)
  azuremetrics-tokens.json              platform metrics ProcessedPromptTokens + GeneratedTokens per hour

The baseline is everything before --baseline-until (default 2026-10-14T00:00:00Z). Rules H01, H04, H05 and H06
compare against it. H07 is yours to write (README, Step 7).
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import pathlib
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).resolve().parent
LOGS = HERE / "logs"
APPROVED_MODELS_DEF = "aafe3651-cb78-4f68-9f81-e7e41509110f"
SECURITY_ADMINS = {"platform-admin@contoso.com"}       # who is ALLOWED to change content filters at Contoso
SPIKE_FACTOR = 5


def parse(t: str) -> dt.datetime:
    return dt.datetime.fromisoformat(t.replace("Z", "+00:00"))


def account_of(resource_id: str) -> str:
    parts = resource_id.split("/")
    i = [p.lower() for p in parts].index("accounts")
    return parts[i + 1]


@dataclass
class Hit:
    rule: str
    severity: str
    who: str
    title: str
    evidence: list[str] = field(default_factory=list)
    when: str = ""
    count: int = 0

    def show(self) -> str:
        lines = [f"  {self.severity:<6} {self.rule}  {self.when}  {self.who}", f"         {self.title}"]
        lines += [f"         - {e}" for e in self.evidence[:5]]
        if len(self.evidence) > 5:
            lines.append(f"         - ... {len(self.evidence) - 5} more")
        return "\n".join(lines)


@dataclass
class Logs:
    activity: list[dict]
    requests: list[dict]
    metrics: list[dict]


def load_logs(folder: pathlib.Path = LOGS) -> Logs:
    j = lambda n: json.loads((folder / n).read_text())
    return Logs(j("activity-log.json")["value"], j("azurediagnostics-requestresponse.json")["rows"],
                j("azuremetrics-tokens.json")["rows"])


def op(e: dict) -> str:
    return e["operationName"]["value"]


def ip(e: dict) -> str:
    return e.get("httpRequest", {}).get("clientIpAddress", "?")


# ------------------------------------------------------------------------------------------------------- rules
def rule_list_keys(L: Logs, until: dt.datetime) -> list[Hit]:
    """H01: someone read a Foundry resource's keys who never did before, or from a new IP. Keys bypass RBAC,
    so a listKeys is the moment a role turns into a key that works anywhere."""
    base = collections.defaultdict(set)
    for e in L.activity:
        if parse(e["eventTimestamp"]) < until and op(e).lower().endswith("/listkeys/action"):
            base[e["caller"]].add(ip(e))
    hits: dict[str, Hit] = {}
    for e in L.activity:
        if parse(e["eventTimestamp"]) < until or not op(e).lower().endswith("/listkeys/action"):
            continue
        new_caller, new_ip = e["caller"] not in base, ip(e) not in base.get(e["caller"], set())
        if new_caller or new_ip:
            h = hits.setdefault(e["caller"], Hit("H01", "HIGH", e["caller"], "Keys listed by a caller that never did before"
                                                 if new_caller else "Keys listed from a new IP", when=e["eventTimestamp"]))
            h.evidence.append(f"{e['eventTimestamp']} listKeys {account_of(e['resourceId'])} from {ip(e)}")
            h.count += 1
    return list(hits.values())


def rule_unapproved_model(L: Logs, until: dt.datetime) -> list[Hit]:
    """H02: Azure Policy flagged a deployment against the approved-models policy (Audit = it went through)."""
    hits = []
    for e in L.activity:
        if e["category"]["value"] != "Policy" or APPROVED_MODELS_DEF not in e.get("properties", {}).get("policies", ""):
            continue
        effect = json.loads(e["properties"]["policies"])[0]["policyDefinitionEffect"]
        hits.append(Hit("H02", "HIGH" if effect == "Audit" else "MEDIUM", e["caller"],
                        f"Unapproved model deployment ({'it WENT THROUGH: effect Audit' if effect == 'Audit' else 'blocked by Deny'})",
                        [f"{e['eventTimestamp']} {e['resourceId'].split('/accounts/')[-1]} from {ip(e)}"], e["eventTimestamp"], 1))
    return hits


def rule_failed_authz_write(L: Logs, until: dt.datetime) -> list[Hit]:
    """H03: a failed write on Microsoft.Authorization (role or policy assignments): someone tried to escalate."""
    hits = []
    for e in L.activity:
        if e["status"]["value"] == "Failed" and op(e).startswith("Microsoft.Authorization/") and op(e).endswith(("/write", "/delete")):
            hits.append(Hit("H03", "HIGH", e["caller"], "Failed attempt to change role or policy assignments",
                            [f"{e['eventTimestamp']} {op(e)} from {ip(e)} -> {e['subStatus']['value']}"], e["eventTimestamp"], 1))
    return hits


def rule_token_spike(L: Logs, until: dt.datetime) -> list[Hit]:
    """H04: hourly tokens on a Foundry resource above SPIKE_FACTOR x its busiest baseline hour."""
    per_hour = collections.defaultdict(int)
    for m in L.metrics:
        per_hour[(account_of(m["_ResourceId"]), m["TimeGenerated"])] += m["Total"]
    peak = collections.defaultdict(int)
    for (acct, hour), total in per_hour.items():
        if parse(hour) < until:
            peak[acct] = max(peak[acct], total)
    hits: dict[str, Hit] = {}
    for (acct, hour), total in sorted(per_hour.items(), key=lambda kv: kv[0][1]):
        if parse(hour) >= until and total > SPIKE_FACTOR * peak[acct]:
            h = hits.setdefault(acct, Hit("H04", "MEDIUM", acct, f"Token use above {SPIKE_FACTOR}x the busiest normal hour "
                                          f"({peak[acct]:,} tokens)", when=hour))
            h.evidence.append(f"{hour} {total:,} tokens")
            h.count += 1
    return list(hits.values())


def rule_new_source_ip(L: Logs, until: dt.datetime) -> list[Hit]:
    """H05: data-plane calls from an IP never seen calling that resource in the baseline."""
    seen = collections.defaultdict(set)
    for r in L.requests:
        if parse(r["TimeGenerated"]) < until:
            seen[account_of(r["_ResourceId"])].add(r["CallerIPAddress"])
    first, n = {}, collections.Counter()
    for r in L.requests:
        acct, src = account_of(r["_ResourceId"]), r["CallerIPAddress"]
        if parse(r["TimeGenerated"]) >= until and src not in seen[acct]:
            first.setdefault((acct, src), r)
            n[(acct, src)] += 1
    hits: dict[str, Hit] = {}
    for (acct, src), r in sorted(first.items(), key=lambda kv: kv[1]["TimeGenerated"]):
        h = hits.setdefault(acct, Hit("H05", "MEDIUM", acct, "Model calls from IP addresses never seen on this resource",
                                      when=r["TimeGenerated"]))
        h.evidence.append(f"{src}: {n[(acct, src)]} calls, first {r['TimeGenerated']} ({r['OperationName']})")
        h.count += n[(acct, src)]
    return list(hits.values())


def rule_control_plane_new_ip(L: Logs, until: dt.datetime) -> list[Hit]:
    """H06: control-plane writes on Foundry by a caller from an IP that caller never used before."""
    base = collections.defaultdict(set)
    for e in L.activity:
        if parse(e["eventTimestamp"]) < until:
            base[e["caller"]].add(ip(e))
    hits: dict[str, Hit] = {}
    for e in L.activity:
        if (parse(e["eventTimestamp"]) < until or e["category"]["value"] != "Administrative"
                or not op(e).startswith("Microsoft.CognitiveServices/") or ip(e) in base[e["caller"]]):
            continue
        h = hits.setdefault(e["caller"], Hit("H06", "HIGH", e["caller"], "Foundry control-plane activity from a new IP for this caller",
                                             when=e["eventTimestamp"]))
        h.evidence.append(f"{e['eventTimestamp']} {op(e).split('Microsoft.CognitiveServices/')[-1]} "
                          f"{e['resourceId'].split('/accounts/')[-1]} from {ip(e)} ({e['status']['value']})")
        h.count += 1
    return list(hits.values())


def rule_content_filter_change(L: Logs, until: dt.datetime) -> list[Hit]:
    """H07 (YOUR CHALLENGE): flag any change to a content filter (raiPolicies write or delete) made by a caller who
    is not in SECURITY_ADMINS. Storm-2139 "altered the capabilities" of the services it broke into: on Foundry, a
    relaxed content filter is how that would show up in the control plane. Return one Hit per caller, rule "H07",
    severity "HIGH", one evidence line per event. See README Step 7."""
    return []


RULES = [rule_list_keys, rule_unapproved_model, rule_failed_authz_write, rule_token_spike, rule_new_source_ip,
         rule_control_plane_new_ip, rule_content_filter_change]


def naive(L: Logs, until: dt.datetime) -> list[Hit]:
    """The cost check many teams rely on: total tokens per DAY above 3x the average baseline day."""
    days = collections.defaultdict(int)
    for m in L.metrics:
        days[m["TimeGenerated"][:10]] += m["Total"]
    base = [v for d, v in days.items() if parse(d + "T00:00:00Z") < until]
    avg = sum(base) / len(base)
    return [Hit("N01", "LOW", "all resources", f"Daily tokens above 3x the normal day ({avg:,.0f})", [f"{d}: {v:,} tokens"], d, 1)
            for d, v in sorted(days.items()) if parse(d + "T00:00:00Z") >= until and v > 3 * avg]


def hunt(is_naive: bool = False, until: dt.datetime | None = None) -> tuple[Logs, list[Hit]]:
    until = until or dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)
    L = load_logs()
    hits = naive(L, until) if is_naive else [h for r in RULES for h in r(L, until)]
    return L, sorted(hits, key=lambda h: (h.when, h.rule))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--naive", action="store_true")
    ap.add_argument("--baseline-until", default="2026-10-14T00:00:00Z")
    a = ap.parse_args()
    L, hits = hunt(a.naive, parse(a.baseline_until))
    print(f"--- AZ10 hunt · {len(L.activity)} activity events, {len(L.requests)} request rows, {len(L.metrics)} metric rows · "
          f"baseline before {a.baseline_until} ---\n")
    for h in hits:
        print(h.show())
    print(f"\n{len(hits)} hit{'' if len(hits) == 1 else 's'}" + ("  (naive mode: one daily usage check)" if a.naive else ""))


if __name__ == "__main__":
    main()
