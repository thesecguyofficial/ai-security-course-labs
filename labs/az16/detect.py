"""
detect.py: run a detection rule pack over one setup's telemetry and print the alerts.

    python3 detect.py hardened                    # the az16 pack (this module's rules) on the hardened telemetry
    python3 detect.py first-draft --pack soc-v1   # the SOC's old rules on what was collected before this module
    python3 detect.py hardened --json             # alerts as JSON (report.py and evaluate.py use this)

Two packs:
    soc-v1  three rules a SOC often starts with: gateway call volume, diagnostic setting deleted, Defender High only
    az16    D01-D12 from lessons 16.2 to 16.5. D11 and D12 are YOUR challenge: they return nothing until you write them

Every rule reads only what a real SOC would have: the telemetry files of one setup, contoso.json and
data/baselines.json. It never reads out/<setup>/truth.json (that's the answer key evaluate.py uses).
Each alert names an *entity*: the thing a responder acts on (a service principal, an end user, a conversation,
a user account). The KQL version of each rule, for Log Analytics or Microsoft Sentinel, is in queries/.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent
COMPANY = json.loads((HERE / "contoso.json").read_text())
BASELINES = {k: v for k, v in json.loads((HERE / "data" / "baselines.json").read_text()).items() if not k.startswith("_")}
TUNE = COMPANY["detection_tuning"]
SOURCES = ["activity", "foundry", "gateway", "llm", "alerts", "traces", "blob", "deploy", "metrics", "app"]

TAMPER = {"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE", "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
          "MICROSOFT.SECURITY/PRICINGS/WRITE"}


# --------------------------------------------------------------------------------------------------- telemetry
class Telemetry:
    """One setup's files. A missing file means the setup never collected that source: the list is empty."""

    def __init__(self, setup: str):
        self.setup = setup
        folder = HERE / "out" / setup
        if not folder.exists():
            sys.exit(f"no telemetry in out/{setup}/: run  python3 simulate.py {setup}  first (or make simulate)")
        for k in SOURCES:
            setattr(self, k, load(folder / f"{k}.jsonl"))

    @classmethod
    def from_build(cls, built: dict):
        """Telemetry straight from simulate.build() (the tests use this: no files needed)."""
        t = cls.__new__(cls)
        t.setup = built["setup"]["name"]
        for k in SOURCES:
            setattr(t, k, built["out"][k])
        return t


def load(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def text_of(messages) -> str:
    return " ".join(str(m.get("content", "")) for m in (messages or []))


def ext(alert: dict) -> dict:
    return json.loads(alert.get("ExtendedProperties") or "{}")


def alert(rule, title, severity, time, entity, entity_type, evidence, detail) -> dict:
    return {"rule": rule, "title": title, "severity": severity, "time": time, "entity": entity,
            "entity_type": entity_type, "evidence": list(evidence), "detail": detail}


def known_ips() -> set[str]:
    return set(COMPANY["office_ips"]) | set(COMPANY["callers"].values()) | {COMPANY["apim_gateway_ip"]}


# ------------------------------------------------------------------------------------------- pack soc-v1 (naive)
def n1_gateway_volume(t: Telemetry) -> list[dict]:
    """More than N calls in an hour from one caller address, in the API Management gateway log."""
    buckets = defaultdict(list)
    for r in t.gateway:
        buckets[(r["CallerIpAddress"], r["TimeGenerated"][:13])].append(r)
    n = TUNE["old_rule_gateway_calls_per_hour"]
    return [alert("N1", "High call volume at the gateway", "MEDIUM", rs[0]["TimeGenerated"], ip, "ip-address",
                  [r["CorrelationId"] for r in rs[:5]], f"{len(rs)} calls in hour {hour[11:]}:00")
            for (ip, hour), rs in buckets.items() if len(rs) > n]


def n2_diagnostics_deleted(t: Telemetry) -> list[dict]:
    """Anyone deleting a diagnostic setting (Activity log)."""
    return [alert("N2", "Diagnostic setting deleted", "HIGH", e["TimeGenerated"], e["Caller"], "principal",
                  [e["CorrelationId"]], f"status {e['ActivityStatusValue']}")
            for e in t.activity if e["OperationNameValue"] == "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"]


def n3_defender_high_only(t: Telemetry) -> list[dict]:
    """Defender for Cloud alerts of High severity only: the default for alert email notifications."""
    return [alert("N3", a["AlertName"], "HIGH", a["TimeGenerated"], a["CompromisedEntity"], "resource",
                  [a["SystemAlertId"]], a["AlertType"])
            for a in t.alerts if a["AlertSeverity"] == "High"]


# ------------------------------------------------------------------------------------------------- pack az16
def d01_workload_identity_new_ip(t: Telemetry) -> list[dict]:
    """A workload identity (service principal) making control-plane calls from an address outside Contoso (16.5)."""
    known, sps = known_ips(), set(COMPANY["workload_identities"])
    by_caller = defaultdict(list)
    for e in t.activity:
        if e["Caller"] in sps and e["CallerIpAddress"] not in known:
            by_caller[e["Caller"]].append(e)
    return [alert("D01", "Workload identity used from an unknown address", "HIGH", es[0]["TimeGenerated"], c,
                  "service-principal", [e["CorrelationId"] for e in es],
                  f"{len(es)} operations from {sorted({e['CallerIpAddress'] for e in es})}: "
                  + ", ".join(e["OperationNameValue"].split("/", 1)[1] for e in es))
            for c, es in by_caller.items()]


def d02_calls_skip_gateway(t: Telemetry) -> list[dict]:
    """Data-plane calls to the Foundry resource from anywhere but the API Management gateway (AzureDiagnostics)."""
    gw = COMPANY["apim_gateway_ip"]
    by_ip = defaultdict(list)
    for r in t.foundry:
        if r["Category"] == "RequestResponse" and r["CallerIPAddress"] != gw:
            by_ip[r["CallerIPAddress"]].append(r)
    if not by_ip:
        return []
    rows = [r for rs in by_ip.values() for r in rs]
    return [alert("D02", "Foundry calls that skip the gateway (keys in use?)", "HIGH", min(r["TimeGenerated"] for r in rows),
                  COMPANY["foundry"], "resource-keys", [r["CorrelationId"] for r in rows[:5]],
                  f"{len(rows)} calls from {sorted(by_ip)}; the logs don't say which key: rotate both")]


def d03_defence_tamper(t: Telemetry) -> list[dict]:
    """Diagnostic setting or Defender plan changes by a non-admin, and a toolbox version without approval on writes."""
    out = []
    for e in t.activity:
        if e["OperationNameValue"] in TAMPER and e["Caller"] not in COMPANY["security_admins"]:
            out.append(alert("D03", f"Defence change: {e['OperationNameValue'].split('/', 1)[1]}", "HIGH",
                             e["TimeGenerated"], e["Caller"], "principal", [e["CorrelationId"]],
                             f"status {e['ActivityStatusValue']}"))
    for r in t.deploy:
        if r.get("require_approval") == "never":
            out.append(alert("D03", "Toolbox default version runs write tools without approval", "HIGH", r["time"],
                             r["actor"], "principal", [r["id"]],
                             f"{r['target']} default_version={r['default_version']} ({r['pipeline_run']})"))
    return out


def d04_defender_ai_all(t: Telemetry) -> list[dict]:
    """Every Defender for AI Services alert, whatever its severity. Names the end user when the app sent one."""
    out = []
    for a in t.alerts:
        if not a["AlertType"].startswith("AI."):
            continue
        e = ext(a)
        who, kind = (e["End user ID"], "end-user") if e.get("End user ID") else (a["CompromisedEntity"], "resource")
        out.append(alert("D04", a["AlertName"], a["AlertSeverity"].upper(), a["TimeGenerated"], who, kind,
                         [a["SystemAlertId"]], f"{a['AlertType']} ({a['AlertSeverity']}), count {e.get('Alert count')}"))
    return out


def d05_token_spike(t: Telemetry) -> list[dict]:
    """Tokens per APIM subscription per hour above factor x its 14-day baseline (or no baseline at all).
    The LLM log has the tokens, the gateway log has the subscription: join them on CorrelationId."""
    sub_of = {r["CorrelationId"]: r["ApimSubscriptionId"] for r in t.gateway}
    hours = defaultdict(lambda: [0, []])
    for r in t.llm:
        if r["ResponseMessages"] is None and r["CompletionTokens"]:
            continue  # count each call once: on its response row (blocked calls have only a request row)
        key = (sub_of.get(r["CorrelationId"], "unknown"), r["TimeGenerated"][:13])
        hours[key][0] += r["TotalTokens"]
        hours[key][1].append((r["TotalTokens"], r["RequestId"]))
    out = []
    for (sub, hour), (tokens, ids) in sorted(hours.items()):
        base = BASELINES.get(sub)
        if base is None or tokens > TUNE["tokens_per_subscription_per_hour_factor"] * base:
            why = "no baseline" if base is None else f"{tokens / base:.0f}x the baseline of {base:,}"
            top = [rid for _, rid in sorted(ids, reverse=True)[:5]]
            out.append(alert("D05", "Model token spike", "MEDIUM", f"{hour}:00:00Z", sub, "apim-subscription", top,
                             f"{tokens:,} tokens in hour {hour[11:]}:00 ({why})"))
    return out


def d06_content_filter_per_user(t: Telemetry) -> list[dict]:
    """An end user with N or more content-filter blocks in 10 minutes (the app log records the 400 content_filter)."""
    n = TUNE["content_filter_blocks_per_user_per_10_min"]
    per_user = defaultdict(list)
    for r in t.app:
        if r.get("content_filter_blocked"):
            per_user[r.get("signed_in_user") or "unknown"].append(r)
    out = []
    for user, rs in per_user.items():
        for i in range(len(rs) - n + 1):
            if ts(rs[i + n - 1]["time"]) - ts(rs[i]["time"]) <= timedelta(minutes=10):
                out.append(alert("D06", "Repeated content-filter blocks for one end user", "HIGH", rs[i]["time"], user,
                                 "end-user", [r["request_id"] for r in rs], f"{len(rs)} blocked calls"))
                break
    return out


def d07_canary_in_answer(t: Telemetry) -> list[dict]:
    """The system prompt's canary appears in a model answer (LLM log); the app log names who got it."""
    canary = COMPANY["system_prompt_canary"]
    user_of = {r.get("gateway_correlation_id"): r.get("signed_in_user") for r in t.app}
    return [alert("D07", "System prompt canary in an answer", "HIGH", r["TimeGenerated"],
                  user_of.get(r["CorrelationId"]) or r["CorrelationId"],
                  "end-user" if user_of.get(r["CorrelationId"]) else "correlation-id", [r["RequestId"]],
                  "the answer contains " + canary)
            for r in t.llm if canary in text_of(r["ResponseMessages"])]


def d08_write_tool_without_approval(t: Telemetry) -> list[dict]:
    """An execute_tool span for a write tool that ran without anyone approving it (Foundry traces)."""
    writes = set(COMPANY["write_tools"])
    by_conv = defaultdict(list)
    for s in t.traces:
        if s["span"] == "execute_tool" and s["lab.tool"] in writes and s.get("lab.approval") != "approved":
            by_conv[s["gen_ai.conversation.id"]].append(s)
    return [alert("D08", "Write tool ran without approval", "HIGH", ss[0]["time"], conv, "conversation",
                  [s["span_id"] for s in ss], ", ".join(f"{s['lab.tool']} (toolbox v{s['lab.toolbox_version']})" for s in ss))
            for conv, ss in by_conv.items()]


def d09_mail_out(t: Telemetry) -> list[dict]:
    """The agent's send_email tool ran for an address outside the company domain."""
    dom = COMPANY["company_email_domain"]
    out = []
    for s in t.traces:
        if s["span"] == "execute_tool" and s["lab.tool"] == "send_email":
            to = str(json.loads(s["gen_ai.tool.call.arguments"]).get("to", ""))
            if to and to.rsplit("@", 1)[-1].lower() != dom:
                out.append(alert("D09", "Agent emailed outside the company", "HIGH", s["time"],
                                 s["gen_ai.conversation.id"], "conversation", [s["span_id"]], f"to={to}"))
    return out


def d10_unknown_link_in_answer(t: Telemetry) -> list[dict]:
    """A model answer sends users to a web domain outside the allow-list (often the visible effect of a poisoned index)."""
    allowed = COMPANY["allowed_answer_domains"]
    by_dom = defaultdict(list)
    for r in t.llm:
        for host in re.findall(r"https?://([a-z0-9.-]+)", text_of(r["ResponseMessages"]).lower()):
            if not any(host == a or host.endswith("." + a) for a in allowed):
                by_dom[host].append(r)
    return [alert("D10", "Answer links to an unknown domain", "MEDIUM", rs[0]["TimeGenerated"], host, "domain",
                  [r["RequestId"] for r in rs], f"{len(rs)} answers")
            for host, rs in by_dom.items()]


def d11_kb_source_write(t: Telemetry) -> list[dict]:
    """CHALLENGE 1 (lessons 16.4 and 16.5). Search index poisoning: someone who isn't the knowledge base publisher
    writes a blob into the knowledge base container (StorageBlobLogs, OperationName PutBlob).

    Return one alert per writer, with the writer's RequesterUpn as the entity, entity_type "principal", and the
    CorrelationIds as evidence. The publisher is in COMPANY["kb"]["writers"], the account and container in
    COMPANY["kb"]. Normal traffic must not alert.
    """
    return []


def d12_wallet_per_end_user(t: Telemetry) -> list[dict]:
    """CHALLENGE 2 (lessons 16.1 and 16.5). Denial of wallet by one end user. Every call goes through the app's APIM
    subscription, so Defender and D05 can only name the resource or helpdesk-app. Use signed_in_user and the token
    counts in the app log to find an end user above COMPANY["detection_tuning"]["tokens_per_end_user_per_hour"]
    tokens (input + output) in any one hour.

    Return one alert per end user, entity = the end user ID, entity_type "end-user". Normal customers must not alert.
    """
    return []


PACKS = {
    "soc-v1": [n1_gateway_volume, n2_diagnostics_deleted, n3_defender_high_only],
    "az16": [d01_workload_identity_new_ip, d02_calls_skip_gateway, d03_defence_tamper, d04_defender_ai_all,
             d05_token_spike, d06_content_filter_per_user, d07_canary_in_answer, d08_write_tool_without_approval,
             d09_mail_out, d10_unknown_link_in_answer, d11_kb_source_write, d12_wallet_per_end_user],
}
CHALLENGE_RULES = {"d11_kb_source_write", "d12_wallet_per_end_user"}


def run(t: Telemetry, pack: str = "az16", challenge: bool = True) -> list[dict]:
    """All alerts of one pack, oldest first. challenge=False skips D11 and D12 (the tests pin the shipped rules)."""
    alerts = []
    for rule in PACKS[pack]:
        if not challenge and rule.__name__ in CHALLENGE_RULES:
            continue
        alerts += rule(t)
    return sorted(alerts, key=lambda a: (a["time"], a["rule"]))


def show(alerts: list[dict], setup: str, pack: str):
    print(f"Pack {pack} on {setup} telemetry: {len(alerts)} alerts\n")
    for a in alerts:
        print(f"[{a['severity']:6}] {a['time'][11:16]} {a['rule']} {a['title']}")
        print(f"         entity {a['entity_type']}: {a['entity']}   ({a['detail']})")
    if not alerts:
        print("(no alerts)")


def main(argv: list[str]):
    args = [a for a in argv if not a.startswith("--")]
    pack = argv[argv.index("--pack") + 1] if "--pack" in argv else "az16"
    if pack in args:
        args.remove(pack)
    setup = args[0] if args else "hardened"
    alerts = run(Telemetry(setup), pack)
    if "--json" in argv:
        print(json.dumps(alerts, indent=1))
    else:
        show(alerts, setup, pack)


if __name__ == "__main__":
    main(sys.argv[1:])
