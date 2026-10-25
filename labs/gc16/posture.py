"""
posture.py: settings checks for AI on Google Cloud (lessons 16.3 and 16.4), run offline on a setup's settings.

    python3 posture.py first-draft
    python3 posture.py hardened

Three kinds of check, and the difference is the lesson:
  framework   four of the 29 cloud controls in Security Command Center's "Google Recommended AI Essentials - Gemini
              Enterprise Agent Platform" framework (names exactly as Google lists them). How the lab evaluates each is
              our reading of the control's name, not Google's code: check what each control evaluates in your console.
  custom      settings this module's incidents depend on that none of the framework's 29 control names covers
              (as of Oct 2026): Data Access logs set at the organization, where SCC Premium is activated, Model Armor
              logging, request-response logging for every model in use, the gateway's enforcement mode, and log
              exclusions that drop evidence. You write these yourself (a scheduled script, or a custom SCC module)
  org policy  preventive constraints (16.4): an allow-list of models, and no new service account keys

Input: data/posture/<setup>.json (the Get/List responses, cut to the fields the checks read).
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
EVIDENCE_LOGS = ("networkservices.googleapis.com%2Fgateway_requests", "cloudaudit.googleapis.com%2Fdata_access",
                 "modelarmor.googleapis.com")


def framework_controls():
    """(control name as listed in the framework, check over the setup returning None if COMPLIANT else the reason)."""
    def model_armor(d):
        ma = d["project"]["modelArmor"]
        return None if ma["templates"] or ma["floorSetting"]["aiPlatformFloorSetting"]["inspectAndBlock"] else \
            "no Model Armor template or blocking floor setting"

    def cmek_endpoints(d):
        bad = [e["name"] for e in d["project"]["endpoints"] if not e.get("encryptionSpec")]
        return f"no CMEK on endpoint {', '.join(bad)}" if bad else None

    def public_ip(d):
        bad = [w["name"] for w in d["project"]["workbenchInstances"] if not w["disablePublicIp"]]
        return f"public IP on {', '.join(bad)}" if bad else None

    def labels(d):
        bad = [a["name"] for a in d["project"]["agents"] if not a.get("labels")]
        return f"no labels on {', '.join(bad)}" if bad else None

    return [("Enable Model Armor", model_armor),
            ("Enable CMEK for Agent Platform Model Endpoints", cmek_endpoints),
            ("Block Public IP Address for Agent Platform Workbench Instances", public_ip),
            ("Use labels for Agent Platform agents", labels)]


def custom_checks():
    def data_access(d):
        types = {c["logType"] for a in d["organization"]["auditConfigs"]
                 if a["service"] in ("aiplatform.googleapis.com", "allServices") for c in a["auditLogConfigs"]}
        missing = sorted({"DATA_READ", "DATA_WRITE"} - types)
        return f"aiplatform.googleapis.com missing {', '.join(missing)} at the organization (off by default)" \
            if missing else None

    def scc(d):
        s = d["organization"]["scc"]
        if s["tier"] != "PREMIUM":
            return f"SCC {s['tier']}: no Event Threat Detection AI rules"
        if s["activation"] != "organization":
            return "Premium activated per project: New Geography for AI Service isn't available"
        return None

    def armor_logs(d):
        ma = d["project"]["modelArmor"]
        off = [t["name"].rsplit("/", 1)[-1] for t in ma["templates"]
               if not t["templateMetadata"].get("logSanitizeOperations")]
        why = []
        if off:
            why.append(f"logSanitizeOperations off on {', '.join(off)}")
        if not ma["floorSetting"]["aiPlatformFloorSetting"].get("enableCloudLogging"):
            why.append("floor setting Cloud Logging off")
        return "; ".join(why) or None

    def rr_logging(d):
        off = sorted(m for m, c in d["project"]["publisherModelConfigs"].items()
                     if not c["loggingConfig"].get("enabled") or c["loggingConfig"].get("samplingRate", 0) < 1)
        return f"request-response logging off or sampled for {', '.join(off)}" if off else None

    def enforce(d):
        bad = [x["name"] for x in d["project"]["authzExtensions"]
               if x["service"] == "iap.googleapis.com" and x["metadata"].get("iamEnforcementMode") == "DRY_RUN"]
        return f"iamEnforcementMode DRY_RUN on {', '.join(bad)}" if bad else None

    def exclusions(d):
        bad = [f"{s['name']}/{x['name']}" for s in d["project"]["logSinks"] for x in s.get("exclusions", [])
               if any(k in x["filter"] for k in EVIDENCE_LOGS)]
        return f"exclusion drops evidence: {', '.join(bad)}" if bad else None

    return [("C01", "Data Access audit logs (DATA_READ, DATA_WRITE) for Agent Platform set at the organization", data_access),
            ("C02", "SCC Premium activated at the organization (Event Threat Detection AI rules)", scc),
            ("C03", "Model Armor sanitize operations logged (template and floor setting)", armor_logs),
            ("C04", "Request-response logging at sampling rate 1 for every model in use", rr_logging),
            ("C05", "Every IAP authorization extension enforces (no iamEnforcementMode DRY_RUN)", enforce),
            ("C06", "No log exclusion drops gateway, Data Access or Model Armor logs", exclusions)]


def org_policies():
    def allowed_models(d):
        v = d["organization"]["orgPolicies"].get("vertexai.allowedModels")
        return None if v and v.get("allowedValues") else "vertexai.allowedModels not set: any model, any publisher"

    def no_keys(d):
        pol = d["organization"]["orgPolicies"]
        if any((pol.get(c) or {}).get("enforce") for c in ("iam.managed.disableServiceAccountKeyCreation",
                                                              "iam.disableServiceAccountKeyCreation")):
            return None
        return (f"not enforced (organization created {d['organization']['created']}: before 3 May 2024 it isn't "
                "enforced by default)")

    return [("P01", "vertexai.allowedModels: an allow-list of models", allowed_models),
            ("P02", "iam.disableServiceAccountKeyCreation (legacy or managed): no new service account keys", no_keys)]


def run(setup: str) -> list[dict]:
    data = json.loads((HERE / "data" / "posture" / f"{setup}.json").read_text())
    out = []
    for kind, checks in (("framework", [(None, n, c) for n, c in framework_controls()]),
                         ("custom", custom_checks()), ("org policy", org_policies())):
        for cid, what, check in checks:
            why = check(data)
            out.append({"kind": kind, "id": cid or "", "check": what, "compliant": why is None, "why": why or ""})
    return out


def main(argv):
    setup = argv[0] if argv else "first-draft"
    res = run(setup)
    titles = {"framework": "Framework controls (Google Recommended AI Essentials; lab reading of each control)",
              "custom": "Custom checks (no framework control covers these: you write them)",
              "org policy": "Organization policies (preventive, lesson 16.4)"}
    print(f"Posture of the {setup} setup")
    for kind, title in titles.items():
        print(f"\n{title}")
        for r in res:
            if r["kind"] == kind:
                state = "COMPLIANT    " if r["compliant"] else "NON_COMPLIANT"
                label = f"{r['id']} " if r["id"] else ""
                print(f"  {state} {label}{r['check']}" + (f"\n                {r['why']}" if r["why"] else ""))
    bad = sum(not r["compliant"] for r in res)
    print(f"\n{bad} NON_COMPLIANT of {len(res)} checks")


if __name__ == "__main__":
    main(sys.argv[1:])
