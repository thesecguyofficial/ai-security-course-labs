"""
detect.py: run a detection rule pack over one setup's telemetry and print the alerts.

    python3 detect.py hardened                    # the gc16 pack (this module's rules) on the hardened telemetry
    python3 detect.py first-draft --pack soc-v1   # the SOC's old rules on what was collected before this module
    python3 detect.py hardened --json             # alerts as JSON (report.py and evaluate.py use this)

Two packs:
    soc-v1  three rules a SOC often starts with: Predict volume, audit config changed, SCC findings HIGH and CRITICAL
    gc16    D01-D13 from lessons 16.2 to 16.5. D11 and D12 are YOUR challenge: they return nothing until you write them

Every rule reads only what a real SOC would have: the telemetry files of one setup, exampleco.json and
data/baselines.json. It never reads out/<setup>/truth.json (that's the answer key evaluate.py uses).
Each alert names an *entity*: the thing a responder acts on (a service account, an end user, an agent session, a
domain). The Logs Explorer version of each rule is in queries/.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent
COMPANY = json.loads((HERE / "exampleco.json").read_text())
BASELINES = {k: v for k, v in json.loads((HERE / "data" / "baselines.json").read_text()).items() if not k.startswith("_")}
TUNE = COMPANY["detection_tuning"]

AI_FINDINGS = tuple(COMPANY["ai_finding_categories"])
P = "google.cloud.aiplatform.v1.PredictionService."
INFERENCE = {P + "GenerateContent", P + "StreamGenerateContent", P + "RawPredict", P + "StreamRawPredict",
             P + "Predict"}
TAMPER = {"SetIamPolicy", "google.cloud.aiplatform.v1beta1.EndpointService.SetPublisherModelConfig",
          "google.cloud.modelarmor.v1.ModelArmor.UpdateTemplate", "google.logging.v2.ConfigServiceV2.UpdateSink",
          "google.logging.v2.ConfigServiceV2.DeleteSink", "google.logging.v2.ConfigServiceV2.CreateExclusion",
          "google.logging.v2.ConfigServiceV2.UpdateBucket"}
AUTHZ_UPDATE = "google.cloud.networkservices.v1.DepService.UpdateAuthzExtension"


# --------------------------------------------------------------------------------------------------- telemetry
class Telemetry:
    """One setup's files. A missing file means the setup never collected that source: the list is empty."""
    SOURCES = ("audit", "requests", "armor", "scc", "gateway", "app")

    def __init__(self, setup: str):
        self.setup = setup
        folder = HERE / "out" / setup
        if not folder.exists():
            sys.exit(f"no telemetry in out/{setup}/: run  python3 simulate.py {setup}  first (or make simulate)")
        for k in self.SOURCES:
            setattr(self, k, load(folder / f"{k}.jsonl"))

    @classmethod
    def from_build(cls, built: dict):
        """Telemetry straight from simulate.build() (the tests use this: no files needed)."""
        t = cls.__new__(cls)
        t.setup = built["setup"]["name"]
        for k in cls.SOURCES:
            setattr(t, k, built["out"][k])
        return t


def load(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def principal(e: dict) -> str:
    """Who made a Cloud Audit Logs call: principalEmail, or principalSubject for an agent identity."""
    a = e["protoPayload"]["authenticationInfo"]
    return a.get("principalEmail") or a.get("principalSubject", "")


def short(p: str) -> str:
    """The name a responder uses: the service account's name, or the agent's reasoning engine ID."""
    if p.startswith("principal://"):
        return "reasoningEngines/" + p.rsplit("/", 1)[-1]
    return p.split("@", 1)[0]


def method(e: dict) -> str:
    return e["protoPayload"]["methodName"]


def failed(e: dict) -> bool:
    return bool((e["protoPayload"].get("status") or {}).get("code"))


def answer_text(r: dict) -> str:
    out = []
    for c in r["full_response"].get("candidates", []):
        out += [p.get("text", "") for p in c["content"]["parts"]]
    return " ".join(out)


def labels(r: dict) -> dict:
    return r["full_request"].get("labels") or {}


def tokens(r: dict) -> int:
    return r["full_response"]["usageMetadata"]["totalTokenCount"]


def alert(rule, title, severity, time, entity, entity_type, evidence, detail) -> dict:
    return {"rule": rule, "title": title, "severity": severity, "time": time, "entity": entity,
            "entity_type": entity_type, "evidence": list(evidence), "detail": detail}


# ------------------------------------------------------------------------------------------- pack soc-v1 (naive)
def n1_predict_volume(t: Telemetry) -> list[dict]:
    """More than 100 Predict calls in an hour from one principal (Data Access audit logs)."""
    buckets = defaultdict(list)
    for e in t.audit:
        if method(e) == P + "Predict":
            buckets[(principal(e), e["timestamp"][:13])].append(e)
    return [alert("N1", "High Predict volume", "MEDIUM", es[0]["timestamp"], short(p), "principal",
                  [e["insertId"] for e in es[:5]], f"{len(es)} Predict calls in hour {hour[11:]}:00")
            for (p, hour), es in buckets.items() if len(es) > 100]


def n2_audit_config_changed(t: Telemetry) -> list[dict]:
    """Anyone calling SetIamPolicy with auditConfigs in the update mask (Admin Activity: always on)."""
    out = []
    for e in t.audit:
        req = e["protoPayload"].get("request") or {}
        if method(e) == "SetIamPolicy" and "auditConfigs" in str(req.get("updateMask", "")):
            code = (e["protoPayload"].get("status") or {}).get("code", 0)
            out.append(alert("N2", "Audit log configuration changed", "HIGH", e["timestamp"], short(principal(e)),
                             "principal", [e["insertId"]], f"status code {code}"))
    return out


def n3_scc_high_plus(t: Telemetry) -> list[dict]:
    """SCC findings with severity HIGH or CRITICAL: a notification filter many teams start with."""
    return [alert("N3", f"SCC {f['category']}", "HIGH", f["eventTime"], short(f["access"]["principalEmail"]),
                  "principal", [f["name"].rsplit("/", 1)[-1]], f["severity"])
            for f in t.scc if f["severity"] in ("HIGH", "CRITICAL")]


# ------------------------------------------------------------------------------------------------- pack gc16
def d01_key_unknown_ip(t: Telemetry) -> list[dict]:
    """A service account key (serviceAccountKeyName in the audit entry) used from an address outside the office and
    the VPCs (16.2, 16.5). Works on Admin Activity alone; better with Data Access logs."""
    known = set(COMPANY["office_and_vpc_ips"])
    by_p = defaultdict(list)
    for e in t.audit:
        pp = e["protoPayload"]
        if pp["authenticationInfo"].get("serviceAccountKeyName") and pp["requestMetadata"]["callerIp"] not in known:
            by_p[principal(e)].append(e)
    return [alert("D01", "Service account key used from an unknown address", "HIGH", es[0]["timestamp"], short(p),
                  "service-account", [e["insertId"] for e in es[:5]],
                  f"{len(es)} calls from {sorted({e['protoPayload']['requestMetadata']['callerIp'] for e in es})}")
            for p, es in by_p.items()]


def d02_failed_ai_calls(t: Telemetry) -> list[dict]:
    """N or more failed Agent Platform calls by one principal in 10 minutes: probing for models it may use."""
    n = TUNE["failed_ai_calls_per_principal_per_10_min"]
    by_p = defaultdict(list)
    for e in t.audit:
        if e["protoPayload"]["serviceName"] == "aiplatform.googleapis.com" and failed(e):
            by_p[principal(e)].append(e)
    out = []
    for p, es in by_p.items():
        for i in range(len(es) - n + 1):
            if ts(es[i + n - 1]["timestamp"]) - ts(es[i]["timestamp"]) <= timedelta(minutes=10):
                out.append(alert("D02", "Failed AI calls (probing)", "MEDIUM", es[i]["timestamp"], short(p),
                                 "principal", [e["insertId"] for e in es],
                                 ", ".join(f"{method(e).rsplit('.', 1)[-1]} {e['protoPayload']['status']['code']}"
                                           for e in es)))
                break
    return out


def d03_defence_tamper(t: Telemetry) -> list[dict]:
    """Logging, Model Armor or audit config changes by anyone but the security admins, and any IAP authorization
    extension switched to DRY_RUN (the gateway stops enforcing its access policies)."""
    admins = set(COMPANY["security_admins"])
    out = []
    for e in t.audit:
        p, m = principal(e), method(e)
        req = e["protoPayload"].get("request") or {}
        if m in TAMPER and p not in admins:
            out.append(alert("D03", f"Defence change: {m.rsplit('.', 1)[-1]}", "HIGH", e["timestamp"], short(p),
                             "principal", [e["insertId"]],
                             f"status code {(e['protoPayload'].get('status') or {}).get('code', 0)}"))
        if m == AUTHZ_UPDATE:
            mode = (req.get("authzExtension", {}).get("metadata") or {}).get("iamEnforcementMode", "ENFORCE")
            if mode == "DRY_RUN":
                out.append(alert("D03", "Gateway authorization set to DRY_RUN", "HIGH", e["timestamp"], short(p),
                                 "principal", [e["insertId"]],
                                 f"{e['protoPayload']['resourceName'].rsplit('/', 1)[-1]} iamEnforcementMode=DRY_RUN"))
    return out


def d04_unapproved_inference(t: Telemetry) -> list[dict]:
    """Model inference (GenerateContent, StreamGenerateContent, RawPredict, Predict) by a principal not on the list."""
    approved = set(COMPANY["approved_inference_principals"])
    by_p = defaultdict(list)
    for e in t.audit:
        if method(e) in INFERENCE and principal(e) not in approved:
            by_p[principal(e)].append(e)
    return [alert("D04", "Model inference by an unapproved principal", "HIGH", es[0]["timestamp"], short(p),
                  "principal", [e["insertId"] for e in es[:5]],
                  f"{len(es)} calls; methods {sorted({method(e).rsplit('.', 1)[-1] for e in es})}")
            for p, es in by_p.items()]


def d05_scc_ai(t: Telemetry) -> list[dict]:
    """Every Security Command Center AI threat finding, whatever its severity (the examples show LOW)."""
    approved = {short(a) for a in COMPANY["approved_inference_principals"]}
    out = []
    for f in t.scc:
        if f["category"] not in AI_FINDINGS:
            continue
        who = short(f["access"]["principalEmail"])
        out.append(alert("D05", f["category"], "MEDIUM" if who in approved else "HIGH", f["eventTime"], who,
                         "principal", [f["name"].rsplit("/", 1)[-1]],
                         f"severity {f['severity']}, rule {f['sourceProperties']['detectionCategory']['ruleName']}; "
                         "the Google identity, not the end user"))
    return out


def d06_token_spike(t: Telemetry) -> list[dict]:
    """Tokens per model per hour above factor x the model's 14-day baseline (or no baseline at all).
    Request-response rows carry no caller identity, so this names the model."""
    hours = defaultdict(lambda: [0, []])
    for r in t.requests:
        key = (r["model"], r["logging_time"][:13])
        hours[key][0] += tokens(r)
        hours[key][1].append((tokens(r), r["request_id"]))
    out = []
    for (model, hour), (n, ids) in sorted(hours.items()):
        base = BASELINES.get(model)
        if base is None or n > TUNE["tokens_per_model_per_hour_factor"] * base:
            why = "no baseline" if base is None else f"{n / base:.0f}x the baseline of {base:,}"
            top = [rid for _, rid in sorted(ids, reverse=True)[:5]]  # evidence: the five biggest calls
            out.append(alert("D06", "Model token spike", "MEDIUM", f"{hour}:00:00Z", model, "model", top,
                             f"{n:,} tokens in hour {hour[11:]}:00 ({why})"))
    return out


def d07_blocked_prompts_per_user(t: Telemetry) -> list[dict]:
    """An end user with N or more prompts blocked by Model Armor in 10 minutes (request-response rows + labels)."""
    n = TUNE["blocked_prompts_per_user_per_10_min"]
    per_user = defaultdict(list)
    for r in t.requests:
        if (r["full_response"].get("promptFeedback") or {}).get("blockReason") == "MODEL_ARMOR":
            per_user[labels(r).get("end_user", "unknown")].append(r)
    out = []
    for user, rs in per_user.items():
        for i in range(len(rs) - n + 1):
            if ts(rs[i + n - 1]["logging_time"]) - ts(rs[i]["logging_time"]) <= timedelta(minutes=10):
                out.append(alert("D07", "Repeated blocked prompts from one end user", "HIGH", rs[i]["logging_time"],
                                 user, "end-user", [r["request_id"] for r in rs], f"{len(rs)} Model Armor blocks"))
                break
    return out


def d08_canary_in_answer(t: Telemetry) -> list[dict]:
    """The system prompt's canary string appears in a model answer: a jailbreak got through."""
    canary = COMPANY["system_prompt_canary"]
    return [alert("D08", "System prompt canary in an answer", "HIGH", r["logging_time"],
                  labels(r).get("end_user", "unknown"), "end-user", [r["request_id"]], "the answer contains " + canary)
            for r in t.requests if canary in answer_text(r)]


def d09_deny_not_enforced(t: Telemetry) -> list[dict]:
    """Agent tool calls the access policy denied but the gateway ran, because IAP was in DRY_RUN."""
    by_s = defaultdict(list)
    for g in t.gateway:
        if g["lab.policy_says"] == "DENY" and g["lab.enforcement"] == "DRY_RUN":
            by_s[g["lab.session_id"]].append(g)
    return [alert("D09", "Tool call denied by policy but executed (DRY_RUN)", "HIGH", gs[0]["timestamp"], sid,
                  "agent-session", [g["insertId"] for g in gs],
                  ", ".join(g["jsonPayload"]["mcpInfo"]["lab.tool"] for g in gs))
            for sid, gs in by_s.items()]


def d10_mail_out(t: Telemetry) -> list[dict]:
    """The agent's send_email tool was called for an address outside the company domain."""
    dom = COMPANY["company_email_domain"]
    out = []
    for g in t.gateway:
        to = str(g["lab.input"].get("to", ""))
        if g["jsonPayload"]["mcpInfo"]["lab.tool"] == "send_email" and to and not to.lower().endswith("@" + dom):
            out.append(alert("D10", "Agent emailed outside the company", "HIGH", g["timestamp"], g["lab.session_id"],
                             "agent-session", [g["insertId"]], f"to={to}; executed={g['lab.executed']}"))
    return out


def d11_rag_source_write(t: Telemetry) -> list[dict]:
    """CHALLENGE 1 (lessons 16.4 and 16.5). RAG corpus poisoning: someone who isn't the RAG pipeline writes into the
    corpus's source bucket (storage.objects.create, a Cloud Storage Data Access entry) or imports files into the
    corpus (methodName ending in ImportRagFiles, an Agent Platform DATA_WRITE entry).

    Return one alert per principal, with the principal's short name as the entity (use short(principal(e))),
    entity_type "principal", and the insertIds as evidence. The pipeline's service account is in
    COMPANY["kb"]["writers"], the bucket in COMPANY["kb"]["bucket"]. Normal traffic must not alert.
    """
    return []


def d12_wallet_per_end_user(t: Telemetry) -> list[dict]:
    """CHALLENGE 2 (lessons 16.1 and 16.5). Denial of wallet by one end user. Every call is made by the app's service
    account, so Google Cloud and D06 can't name the person. Use labels.end_user in the request-response rows
    (full_request) or signed_in_user in the app log to find an end user above
    COMPANY["detection_tuning"]["tokens_per_end_user_per_hour"] tokens (totalTokenCount) in any one hour.

    Return one alert per end user, entity = the end user ID, entity_type "end-user". Normal customers must not alert.
    """
    return []


def d13_unknown_link_in_answer(t: Telemetry) -> list[dict]:
    """A model answer sends users to a web domain outside the allow-list (often the visible effect of poisoned RAG)."""
    allowed = COMPANY["allowed_answer_domains"]
    by_dom = defaultdict(list)
    for r in t.requests:
        for host in re.findall(r"https?://([a-z0-9.-]+)", answer_text(r).lower()):
            if not any(host == a or host.endswith("." + a) for a in allowed):
                by_dom[host].append(r)
    return [alert("D13", "Answer links to an unknown domain", "MEDIUM", rs[0]["logging_time"], host, "domain",
                  [r["request_id"] for r in rs], f"{len(rs)} answers")
            for host, rs in by_dom.items()]


PACKS = {
    "soc-v1": [n1_predict_volume, n2_audit_config_changed, n3_scc_high_plus],
    "gc16": [d01_key_unknown_ip, d02_failed_ai_calls, d03_defence_tamper, d04_unapproved_inference, d05_scc_ai,
             d06_token_spike, d07_blocked_prompts_per_user, d08_canary_in_answer, d09_deny_not_enforced, d10_mail_out,
             d11_rag_source_write, d12_wallet_per_end_user, d13_unknown_link_in_answer],
}
CHALLENGE_RULES = {"d11_rag_source_write", "d12_wallet_per_end_user"}


def run(t: Telemetry, pack: str = "gc16", challenge: bool = True) -> list[dict]:
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
    pack = argv[argv.index("--pack") + 1] if "--pack" in argv else "gc16"
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
