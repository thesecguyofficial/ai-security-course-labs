"""
checker.py: find the gaps in how the TSG Helpdesk uses Model Armor (lessons 12.1 to 12.4).

    python3 checker.py --twin today       # make check
    python3 checker.py --twin hardened    # make check-hardened (2 left: your challenge)

Reads twin/<name>/floor.json, templates.json and app.json (REST shapes of Model Armor's FloorSetting and Template,
plus how the app calls things) and twin/requirements.json. Rule GC12-12 doesn't trust a setting: it probes
app_guard.py with a skipped-filter result and an outage, and looks at what the code actually does.
Add --ci to exit with code 1 when there is any HIGH finding (to gate a pipeline).
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from dataclasses import dataclass

import app_guard
from armor_twin import HERE, LEVELS, load_json

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "WARNING": 3}


@dataclass
class Finding:
    sev: str
    rule: str
    where: str
    what: str
    fix: str


def _fc(cfg: dict) -> dict:
    return (cfg or {}).get("filterConfig", {})


def _pi(cfg: dict) -> tuple[bool, int]:
    s = _fc(cfg).get("piAndJailbreakFilterSettings", {})
    return s.get("filterEnforcement") == "ENABLED", LEVELS.get(s.get("confidenceLevel", "LOW_AND_ABOVE"), 1)


def _rai(cfg: dict) -> dict:
    return {f["filterType"]: LEVELS.get(f.get("confidenceLevel", "MEDIUM_AND_ABOVE"), 2)
            for f in _fc(cfg).get("raiSettings", {}).get("raiFilters", [])}


def _uri(cfg: dict) -> bool:
    return _fc(cfg).get("maliciousUriFilterSettings", {}).get("filterEnforcement") == "ENABLED"


def weaker_than(tpl: dict, floor: dict) -> list[str]:
    """Ways a template is less strict than the floor setting (higher number = stricter level = fewer matches)."""
    gaps = []
    f_on, f_lvl = _pi(floor)
    t_on, t_lvl = _pi(tpl)
    if f_on and not t_on:
        gaps.append("prompt injection and jailbreak filter disabled")
    elif f_on and t_lvl > f_lvl:
        gaps.append("prompt injection confidence level less strict")
    for ftype, lvl in _rai(floor).items():
        if ftype not in _rai(tpl):
            gaps.append(f"no {ftype} filter")
        elif _rai(tpl)[ftype] > lvl:
            gaps.append(f"{ftype} level less strict")
    if _uri(floor) and not _uri(tpl):
        gaps.append("malicious URL filter off")
    return gaps


def probe_guard() -> list[str]:
    """Run app_guard's decision functions on two bad days and report where it lets traffic through."""
    problems = []
    partial = {"sanitizationResult": {"filterMatchState": "NO_MATCH_FOUND", "invocationResult": "PARTIAL",
                                      "filterResults": {"pi_and_jailbreak": {"piAndJailbreakFilterResult": {
                                          "executionState": "EXECUTION_SKIPPED", "matchState": "NO_MATCH_FOUND"}}}}}
    if not app_guard.is_blocked(partial)[0]:
        problems.append("a result with a skipped filter (invocationResult PARTIAL) is allowed")
    if not app_guard.on_error(ConnectionError("probe"))[0]:
        problems.append("an outage lets the request through unscreened")
    return problems


def run(twin: str) -> list[Finding]:
    base = HERE / "twin" / twin
    floor, app = load_json(base / "floor.json"), load_json(base / "app.json")
    templates = {t["name"]: t for t in load_json(base / "templates.json")["templates"]}
    req = load_json(HERE / "twin" / "requirements.json")
    inline, sh = app["inline"], app["self_hosted"]
    mac = inline.get("model_armor_config") or {}
    used = {n: templates[n] for n in (mac.get("prompt_template_name"), mac.get("response_template_name"),
                                     sh.get("template")) if n in templates}
    fname = floor.get("name", "floorSetting")
    aip = floor.get("aiPlatformFloorSetting", {})
    out: list[Finding] = []
    add = lambda *a: out.append(Finding(*a))

    if not floor.get("enableFloorSettingEnforcement"):
        add("HIGH", "GC12-01", fname, "Floor setting enforcement is off: nothing sets a minimum for templates or "
            "screens Gemini traffic by default.", "Set enableFloorSettingEnforcement true (gcloud "
            "--enable-floor-setting-enforcement=TRUE), ideally on the folder or organization.")
    if "AI_PLATFORM" not in floor.get("integratedServices", []):
        add("HIGH", "GC12-02", fname, "Agent Platform isn't an integrated service: Gemini requests are screened only "
            "if the code names a template.", "Add AI_PLATFORM (gcloud --add-integrated-services=VERTEX_AI).")
    if aip.get("inspectOnly") and req.get("block_not_just_log"):
        add("MEDIUM", "GC12-03", fname, "Agent Platform floor setting is INSPECT_ONLY: matches are recorded, nothing is "
            "stopped. Fine for a first week of measurement, not as the end state.",
            "Switch to INSPECT_AND_BLOCK once you've measured false positives (gcloud "
            "--vertex-ai-enforcement-type=INSPECT_AND_BLOCK).")
    if "AI_PLATFORM" in floor.get("integratedServices", []) and not aip.get("enableCloudLogging"):
        add("MEDIUM", "GC12-04", fname, "Cloud Logging is off for the Agent Platform floor setting: no record of what "
            "was screened or matched.", "Set aiPlatformFloorSetting.enableCloudLogging true "
            "(--enable-vertex-ai-cloud-logging); restrict who can read those logs (GC12-15).")

    for name, cfg in [(fname, floor)] + list(used.items()):
        short = name.rsplit("/", 1)[-1]
        if not _pi(cfg)[0]:
            add("HIGH", "GC12-05", short, "Prompt injection and jailbreak filter is disabled.",
                "Enable it (filterEnforcement ENABLED) at MEDIUM_AND_ABOVE, then tune with `make sweep`.")
        if not _uri(cfg):
            add("MEDIUM", "GC12-06", short, "Malicious URL filter is off: phishing links in tickets and answers pass.",
                "Set maliciousUriFilterSettings.filterEnforcement ENABLED.")

    if mac.get("prompt_template_name") in templates:
        gaps = weaker_than(templates[mac["prompt_template_name"]], floor)
        if gaps and floor.get("enableFloorSettingEnforcement"):
            tpl = templates[mac["prompt_template_name"]]
            older = tpl.get("createTime", "") < floor.get("updateTime", "")
            add("HIGH", "GC12-07", mac["prompt_template_name"].rsplit("/", 1)[-1],
                "The app names this template in every request, and a request template overrides the floor setting. "
                f"It is weaker than the floor ({'; '.join(gaps)})" + (", and older than it, so the floor never "
                "checked it." if older else "."),
                "Drop modelArmorConfig and let the floor apply, or bring the template up to the floor. Security "
                "Command Center Premium/Enterprise reports templates that violate floor settings.")
    if mac.get("prompt_template_name") and not mac.get("response_template_name"):
        add("HIGH", "GC12-08", "inline modelArmorConfig", "Request names a prompt template but no response template: "
            "Gemini's answers aren't screened.", "Add response_template_name, or rely on the floor setting.")
    if not sh.get("screen_response"):
        add("HIGH", "GC12-08", "self-hosted path", "app_guard never calls sanitizeModelResponse: keys, links and "
            "harmful text in answers go straight to the user.", "Set screen_response true and check the reply.")

    for name, cfg in used.items():
        md = cfg.get("templateMetadata", {})
        if md.get("ignorePartialInvocationFailures"):
            add("MEDIUM", "GC12-09", name.rsplit("/", 1)[-1], "ignorePartialInvocationFailures is true: a filter that "
                "failed or was skipped doesn't count against the request.", "Set it false and fail closed (GC12-12).")
        sdp = _fc(cfg).get("sdpSettings", {})
        if "basicConfig" in sdp and set(req.get("customer_regions", [])) - {"United States"}:
            add("MEDIUM", "GC12-10", name.rsplit("/", 1)[-1], "Sensitive Data Protection basic config: six fixed info "
                f"types, mainly US. Customers are in {', '.join(req['customer_regions'])}.",
                "Use advancedConfig with an inspect template that lists your own info types (and a de-identify "
                "template if you want redaction instead of blocking).")
        if _pi(cfg)[0] and _pi(cfg)[1] == 1 and md.get("enforcementType", "INSPECT_AND_BLOCK") == "INSPECT_AND_BLOCK":
            add("WARNING", "GC12-17", name.rsplit("/", 1)[-1], "Prompt injection filter at LOW_AND_ABOVE in a blocking "
                "template: the setting with the most false positives.", "Measure both sides with `make sweep` and pick "
                "the level your suite supports.")

    if sh.get("screen") == "user_text":
        add("HIGH", "GC12-11", "self-hosted path", "Only the user's own words are screened. Ticket text added to the "
            "prompt (retrieved content) reaches the model unscreened.", "Screen everything the model will see "
            "(screen: assembled_prompt).")
    for p in probe_guard():
        add("HIGH", "GC12-12", "app_guard.py", f"Fails open: {p}.", "Block when invocationResult isn't SUCCESS "
            "and when Model Armor can't be reached (README Step 7).")
    if (mac or floor.get("integratedServices")) and "roles/modelarmor.user" not in inline.get("service_agent_roles", []):
        add("HIGH", "GC12-13", inline.get("service_agent", "service agent"), "The Agent Platform service agent lacks "
            "Model Armor User (roles/modelarmor.user).", "Grant roles/modelarmor.user to "
            "service-PROJECT_NUMBER@gcp-sa-aiplatform.iam.gserviceaccount.com.")
    if sh.get("endpoint", "").endswith(".rep.googleapis.com") and sh.get("private_path") in ("psc-global-apis", "pga"):
        add("MEDIUM", "GC12-14", sh["endpoint"], "The regional Model Armor endpoint is reached through Private Google "
            "Access or the global-APIs PSC bundle, which don't serve *.rep.googleapis.com (GC11-16).",
            "Create a Private Service Connect endpoint for the Model Armor regional API.")
    allowed = set(req.get("sanitize_log_readers_allowed", []))
    extra = sorted(set(app.get("sanitize_log_readers", [])) - allowed)
    logs_on = aip.get("enableCloudLogging") or any(t.get("templateMetadata", {}).get("logSanitizeOperations")
                                                     for t in used.values())
    if logs_on and extra:
        add("MEDIUM", "GC12-15", "sanitize logs", f"Sanitize logs hold raw prompts and responses and are readable by "
            f"{', '.join(extra)}.", "Route them to a log bucket only the incident group can read (and set "
            "its retention).")
    if app.get("secrets_in_prompt"):
        add("MEDIUM", "GC12-16", "system prompt", "Secrets (an escalation code and an API key) sit in the system "
            "prompt: any guard miss becomes a leak.", "Take them out of the prompt; let a tool fetch what's needed "
            "after an authorisation check.")
    return sorted(out, key=lambda f: (SEV_ORDER[f.sev], f.rule, f.where))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--twin", default="today", choices=["today", "hardened"])
    ap.add_argument("--ci", action="store_true", help="exit 1 if any HIGH finding")
    a = ap.parse_args()
    findings = run(a.twin)
    print(f"--- GC12 checker · {a.twin} ---\n")
    for f in findings:
        print(f"  {f.sev:8}{f.rule}  {f.where}")
        pad = " " * 10
        print(textwrap.fill(f.what, 110, initial_indent=pad, subsequent_indent=pad,
                            break_on_hyphens=False, break_long_words=False))
        print(textwrap.fill(f"fix: {f.fix}", 110, initial_indent=pad, subsequent_indent=pad + "     ",
                            break_on_hyphens=False, break_long_words=False))
    counts = {s: sum(1 for f in findings if f.sev == s) for s in SEV_ORDER}
    print(f"\n{counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW, {counts['WARNING']} WARNING  "
          f"({len(findings)} findings)")
    return 1 if a.ci and counts["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
