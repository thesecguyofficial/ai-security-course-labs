"""
checker.py: review a Foundry guardrail setup BEFORE anyone attacks it. 16 rules, AZ12-01 to AZ12-16, each one tied
to a Microsoft Learn page (lessons 12.1 to 12.4). Offline, standard library only.

    python3 checker.py                 # make check:       Contoso's version 1 (contoso/)
    python3 checker.py --with-fixes    # make check-fixed: the hardened build (fixes/): 2 left, both your challenge
    python3 checker.py --dir <folder>  # any folder with the same files (e.g. your own exports)

What it reads: rai-policies.json, deployments.json, agents.json, app.json, policy-assignments.json,
content-safety.json, apim-policy.xml and alerts.json.
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET

import guardrail_twin as gt
import policy_eval

HERE = os.path.dirname(os.path.abspath(__file__))
HARMS = ["Hate", "Sexual", "Violence", "Selfharm"]


def enabled(policy: dict, name: str, source: str) -> dict | None:
    for f in policy["properties"].get("contentFilters", []):
        if f["name"] == name and f["source"] == source and f.get("enabled"):
            return f
    return None


def check(folder: str) -> list[tuple[str, str, str, str]]:
    """Returns [(rule, severity, where, message)]."""
    F = []
    add = lambda r, s, w, m: F.append((r, s, w, m))
    app = gt.load(folder, "app.json")
    deps = gt.load(folder, "deployments.json")["deployments"]
    agents = gt.load(folder, "agents.json")["agents"]
    bls = gt.load(folder, "blocklists.json")["blocklists"]

    for d in deps:
        where = f"deployment {d['name']}"
        pol = gt.resolve_policy(folder, d["properties"]["raiPolicyName"])
        pname = d["properties"]["raiPolicyName"]
        ia = enabled(pol, "Indirect Attack", "Prompt")
        if not ia:
            add("AZ12-01", "HIGH", where, f"guardrail {pname} has no Indirect Attack (document attack) control, but the app "
                "sends retrieved KB articles and tickets. The default text policy table lists jailbreak on prompts only.")
        elif not app.get("document_embedding"):
            add("AZ12-02", "HIGH", where, f"Indirect Attack is on in {pname}, but helpdesk-web sends documents untagged "
                "(app.json document_embedding=false). Document checks run on documents marked with the <documents> delimiter.")
        if not enabled(pol, "Indirect Attack Spotlighting", "Prompt"):
            if app.get("api") == "chat_completions":
                add("AZ12-03", "MEDIUM", where, "Spotlighting is off, and the app passes third-party documents through the Chat "
                    "Completions API (the only API Spotlighting supports). It is off by default.")
        if pol["properties"].get("mode") == "Asynchronous_filter":
            add("AZ12-04", "MEDIUM", where, "mode Asynchronous_filter on a user-facing deployment: content streams before the "
                "filter answers, so flagged text can already be on screen (signal within a ~1,000-character window).")
        for h in HARMS:
            c = enabled(pol, h, "Completion")
            if c and c.get("severityThreshold") == "High":
                add("AZ12-05", "MEDIUM", where, f"{h} on outputs filters only High severity: medium-severity output reaches users.")
            p = enabled(pol, h, "Prompt")
            if p and p.get("severityThreshold") == "Low":
                add("AZ12-06", "LOW", where, f"{h} on inputs filters from Low severity: expect false positives on ordinary "
                    "IT language. Measure them (make attack) before you keep it.")
        for b in pol["properties"].get("customBlocklists", []):
            if b["source"] == "Prompt" and any(i.get("isRegex") for i in bls.get(b["blocklistName"], [])):
                add("AZ12-07", "MEDIUM", where, f"regex blocklist '{b['blocklistName']}' on prompts used as an injection filter: "
                    "it blocks legitimate requests and misses paraphrases. Prompt Shields is the classifier for that job.")
        if app.get("retrieval_owner_check") is not True and not enabled(pol, "PII", "Completion"):
            add("AZ12-12", "MEDIUM", where, "no PII control on outputs and no per-caller retrieval filter, while tickets hold "
                "customer contact details. A PII filter can't tell the owner from a stranger: fix retrieval first.")

    for a in agents:
        where = f"agent {a['name']}"
        if a["kind"] == "prompt":
            dep = next(d for d in deps if d["name"] == a["model_deployment"])
            dpol = gt.resolve_policy(folder, dep["properties"]["raiPolicyName"])
            apol = gt.resolve_policy(folder, a.get("raiPolicyName") or dep["properties"]["raiPolicyName"])
            if a.get("raiPolicyName") and a["raiPolicyName"] != dep["properties"]["raiPolicyName"]:
                missing = [f"{f['name']}@{f['source']}" for f in dpol["properties"].get("contentFilters", [])
                           if f.get("enabled") and f["name"] not in ("Indirect Attack Spotlighting",)
                           and not enabled(apol, f["name"], f["source"]) and f["name"] != "PII"]
                no_tool_resp = not enabled(apol, "Indirect Attack", "PostToolCall")
                if missing or no_tool_resp:
                    add("AZ12-08", "HIGH", where, f"its guardrail {a['raiPolicyName']} fully overrides the deployment's "
                        f"{dep['properties']['raiPolicyName']}. Missing there: " + ", ".join(missing + (
                            ["Indirect Attack@PostToolCall (tool responses)"] if no_tool_resp else [])))
            unmoderated = [t["name"] for t in a.get("tools", []) if t["type"] not in gt.MODERATED_TOOL_TYPES]
            if unmoderated and not app.get("recipient_allowlist"):
                add("AZ12-09", "MEDIUM", where, "tools without moderation support (" + ", ".join(unmoderated) + "): tool call "
                    "and tool response controls don't run on them. Add deterministic checks (allow-lists, approval).")
        if a["kind"] == "hosted":
            rc = a.get("rai_config")
            name = (rc or {}).get("rai_policy_name", "")
            if rc is None:
                add("AZ12-10", "HIGH", where, "no rai_config: the hosted agent runs without a content safety guardrail.")
            elif name and not name.startswith("/subscriptions/"):
                add("AZ12-10", "HIGH", where, f"rai_policy_name '{name}' is not a full ARM resource ID. Microsoft: a policy "
                    "reference that doesn't exist can deploy and report active with no filtering (fails open).")
            if a.get("protocol") == "invocations" and rc and not rc.get("invocations_moderation"):
                add("AZ12-11", "HIGH", where, "invocations protocol without invocations_moderation: the policy is inert and "
                    "requests pass unfiltered, while the agent still returns HTTP 200.")

    assigns = gt.load(folder, "policy-assignments.json")["assignments"]
    if not assigns:
        add("AZ12-13", "MEDIUM", "resource group", "no Azure Policy assignment audits deployment guardrails. Built-in [Preview] "
            "definitions exist for prompt, completion, multi-severity and mode settings (Audit only).")
    for a in assigns:
        d = policy_eval.load_definition(a["definition"])
        params = {k: v.get("defaultValue") for k, v in d["properties"]["parameters"].items()}
        params.update(a.get("parameters", {}))
        if "raiPolicyMode" in params and set(params["raiPolicyMode"]) >= {"Default", "Asynchronous_filter"}:
            add("AZ12-13", "MEDIUM", f"assignment {a['name']}", "raiPolicyMode allows both Default and Asynchronous_filter "
                "(the definition's default), so this assignment can never report a deployment.")
        if "allowedSeveritiesForCompletion" in params and "High" in params["allowedSeveritiesForCompletion"]:
            add("AZ12-13", "MEDIUM", f"assignment {a['name']}", "allowedSeveritiesForCompletion includes High (the default "
                "is Medium and High), so an output threshold of High still counts as compliant.")

    cs = gt.load(folder, "content-safety.json")
    if not cs["properties"].get("disableLocalAuth"):
        add("AZ12-14", "MEDIUM", f"content safety {cs['name']}", "keys (local auth) are enabled. Use Microsoft Entra ID: "
            "create the resource with a custom subdomain and grant Cognitive Services User to the caller.")
    root = ET.parse(os.path.join(HERE, folder, "apim-policy.xml")).getroot()
    for el in root.iter("llm-content-safety"):
        if el.get("shield-prompt", "false").lower() != "true":
            add("AZ12-15", "MEDIUM", "apim llm-content-safety", "shield-prompt is not true (default false): APIM checks harm "
                "categories but not prompt attacks for the self-hosted model.")
    alerts = gt.load(folder, "alerts.json")["alerts"]
    if not any(al["metric"] in ("RAIRejectedRequests", "RAIHarmfulRequests") for al in alerts):
        add("AZ12-16", "LOW", "monitoring", "no alert on Blocked Volume (RAIRejectedRequests) or Harmful Volume Detected "
            "(RAIHarmfulRequests): a burst of blocked probes is an attacker testing your guardrail.")
    return F


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--with-fixes", action="store_true")
    p.add_argument("--dir")
    a = p.parse_args()
    folder = a.dir or ("fixes" if a.with_fixes else "contoso")
    findings = check(folder)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    print(f"Checked {folder}/ ({len(findings)} findings)\n")
    for r, s, w, m in sorted(findings, key=lambda f: (order[f[1]], f[0])):
        print(f"  {r}  {s:<6} {w}\n          {m}")
    counts = {s: sum(1 for f in findings if f[1] == s) for s in order}
    print(f"\n{len(findings)} findings: {counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW")
    return 0


if __name__ == "__main__":
    sys.exit(main())
