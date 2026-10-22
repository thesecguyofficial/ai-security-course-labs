"""
checker.py: review a guardrail rollout BEFORE it ships: the guardrail itself, the request the app sends, the IAM role
that should enforce it, and the organization-level Amazon Bedrock policy. Rules M12-01 to M12-16, plus M12-17, which
you write (challenge).

    python3 checker.py first-draft    # make check:        the Friday pull request
    python3 checker.py tuned          # make check-tuned:  the reviewed version
Exit code 1 if there is any HIGH finding, so it can gate a CI pipeline.

Every rule cites the lesson that explains it. The rules read plain JSON: a CreateGuardrail request body, a Converse
request template, an IAM policy, an AWS Organizations Bedrock policy.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from dataclasses import dataclass

import enforce
import guardrail_twin as twin
import iam_eval

HERE = pathlib.Path(__file__).resolve().parent
CO = json.loads((HERE / "anycompany.json").read_text(encoding="utf-8"))

SETUPS = {
    "first-draft": {"guardrail": "guardrails/first-draft.json", "integration": "app/integration.first-draft.json",
                    "role": "first-draft", "org_policy": "org/bedrock-policy.first-draft.json",
                    "org_guardrail": "guardrails/org-baseline.first-draft.json",
                    "org_rbp": "org/guardrail-resource-policy.json"},
    "tuned": {"guardrail": "guardrails/tuned.json", "integration": "app/integration.tuned.json",
              "role": "enforced", "org_policy": "org/bedrock-policy.fixed.json",
              "org_guardrail": "guardrails/org-baseline.json", "org_rbp": "org/guardrail-resource-policy.json"},
}


@dataclass
class Finding:
    rule: str
    severity: str
    lesson: str
    message: str


class Setup:
    def __init__(self, files: dict):
        self.files = files
        rd = lambda p: json.loads((HERE / p).read_text(encoding="utf-8"))  # noqa: E731
        self.guardrail = rd(files["guardrail"])
        self.integration = rd(files["integration"])
        self.role_variant = files["role"]
        self.role = rd(f"policies/helpdesk-role.{files['role']}.json")
        self.org_policy = rd(files["org_policy"])
        self.org_guardrail = rd(files["org_guardrail"])
        self.org_rbp = rd(files["org_rbp"])
        self.principal_policies = {name: rd(p["policy_file"]) for name, p in CO["principals"].items()}
        self.principal_policies["helpdesk"] = self.role


def _filters(cfg):
    return {f["type"]: f for f in (cfg.get("contentPolicyConfig") or {}).get("filtersConfig") or []}


def _pii(cfg):
    return {e["type"]: e for e in (cfg.get("sensitiveInformationPolicyConfig") or {}).get("piiEntitiesConfig") or []}


# ---- the guardrail (lesson 12.1) ------------------------------------------------------------------------------------
def rule_01(s):
    pa = _filters(s.guardrail).get("PROMPT_ATTACK")
    if not pa or (pa.get("inputStrength") or "NONE") == "NONE" or (pa.get("inputAction") or "BLOCK") == "NONE":
        return [Finding("M12-01", "HIGH", "12.1", "no prompt attack filter blocking on input")]
    return []


def rule_02(s):
    if twin.tier_of(s.guardrail) == "CLASSIC" or twin.tier_of(s.guardrail, "topicPolicyConfig") == "CLASSIC":
        missing = sorted(set(CO["staff_languages"]) - twin.CLASSIC_LANGUAGES)
        return [Finding("M12-02", "MEDIUM", "12.1",
                        "Classic tier: English, French and Spanish only, and no prompt leakage detection"
                        + (f"; AnyCompany staff also write in: {', '.join(missing)}" if missing else ""))]
    return []


def rule_03(s):
    prof = (s.guardrail.get("crossRegionConfig") or {}).get("guardrailProfileIdentifier")
    if prof and prof.split("/")[-1] not in CO["data_residency"]["allowed_guardrail_profiles"]:
        return [Finding("M12-03", "HIGH", "12.1",
                        f"guardrail profile {prof} routes prompts outside the residency rule (M11: US Regions only)")]
    return []


def rule_04(s):
    out = []
    for f in _filters(s.guardrail).values():
        for side in ("input", "output"):
            if (f.get(f"{side}Action") or "BLOCK") == "NONE" and (f.get(f"{side}Strength") or "NONE") != "NONE":
                out.append(Finding("M12-04", "MEDIUM", "12.4", f"{f['type']} {side}: detect mode (action NONE) in the production guardrail"))
    return out


def rule_05(s):
    out, pii = [], _pii(s.guardrail)
    for t in ("AWS_ACCESS_KEY", "AWS_SECRET_KEY"):
        e = pii.get(t)
        if not e or twin._action(e, "OUTPUT")[1] != "BLOCK":
            out.append(Finding("M12-05", "HIGH", "12.1", f"{t} is not blocked in answers"))
    for t in ("EMAIL", "PHONE"):
        e = pii.get(t)
        if not e or twin._action(e, "OUTPUT")[1] not in ("ANONYMIZE", "BLOCK"):
            out.append(Finding("M12-05", "MEDIUM", "12.1", f"{t} is neither masked nor blocked in answers"))
    return out


def rule_06(s):
    out = []
    for t in (s.guardrail.get("topicPolicyConfig") or {}).get("topicsConfig") or []:
        d = t.get("definition", "")
        if re.search(r"(?i)^\s*(block|deny|avoid)\b|\bexcept\b|\banything\b|\bnot containing\b", d):
            out.append(Finding("M12-06", "MEDIUM", "12.4",
                               f"denied topic {t['name']!r}: an instruction, exception or catch-all, not a crisp definition"))
    return out


def rule_07(s):
    if CO["helpdesk"]["answers_from_knowledge_base"] and not s.guardrail.get("contextualGroundingPolicyConfig"):
        return [Finding("M12-07", "MEDIUM", "12.1", "answers come from a knowledge base but there is no contextual grounding check")]
    return []


# ---- the request the app sends (lessons 12.1, 12.3) ---------------------------------------------------------------
def rule_08(s):
    if str(s.integration["guardrailConfig"].get("guardrailVersion")).upper() == "DRAFT":
        return [Finding("M12-08", "HIGH", "12.3", "the app calls the DRAFT version: anyone who can edit the guardrail changes production")]
    return []


def rule_09(s):
    blocks = [b for m in s.integration["messages"] for b in m["content"]]
    uses_gc = any("guardContent" in b for b in blocks)
    q_in_gc = any("guardContent" in b and "{question}" in b["guardContent"]["text"]["text"]
                  and ("guard_content" in (b["guardContent"]["text"].get("qualifiers") or ["guard_content"])) for b in blocks)
    if uses_gc and not q_in_gc:
        return [Finding("M12-09", "HIGH", "12.1",
                        "guardContent is used, but the user's question is outside it: the guardrail never evaluates user input")]
    return []


def rule_10(s):
    async_mode = (s.integration["guardrailConfig"].get("streamProcessingMode") or "sync") == "async"
    masks = any(twin._action(e, "OUTPUT")[1] == "ANONYMIZE" for e in _pii(s.guardrail).values())
    if async_mode:
        return [Finding("M12-10", "MEDIUM", "12.1", "asynchronous streaming: users see chunks before the scan finishes"
                        + ("; masking is not supported in this mode" if masks else ""))]
    return []


def rule_11(s):
    if (s.integration["guardrailConfig"].get("trace") or "disabled") == "disabled":
        return [Finding("M12-11", "LOW", "12.4", "guardrail trace disabled: the app can't log which policy fired")]
    return []


# ---- IAM enforcement (lesson 12.3) -------------------------------------------------------------------------------
def _sim():
    return {r["id"]: r for r in enforce.simulate(_current.role_variant, "none")}


def rule_12(s):
    if _sim()["R2"]["allowed"]:
        return [Finding("M12-12", "HIGH", "12.3", "the Helpdesk role can call the model with no guardrail (no bedrock:GuardrailIdentifier deny)")]
    return []


def rule_13(s):
    sim = _sim()
    if not sim["R2"]["allowed"] and (sim["R3"]["allowed"] or sim["R4"]["allowed"]):
        return [Finding("M12-13", "MEDIUM", "12.3", "IAM enforcement accepts the DRAFT version or another guardrail: pin ARN:version")]
    return []


# ---- the organization-level Amazon Bedrock policy (lesson 12.3) ---------------------------------------------------
def _org_cfgs(s):
    return [c for region in s.org_policy["bedrock"]["guardrail_inference"].values() for c in region.values()]


def rule_14(s):
    out = []
    for c in _org_cfgs(s):
        ok, why = enforce.org_identifier_valid(c)
        if not ok:
            out.append(Finding("M12-14", "HIGH", "12.3", f"org Bedrock policy: {why}"))
    rbp_ok = any(st.get("Condition", {}).get("StringEquals", {}).get("aws:PrincipalOrgID") == CO["organization"]["id"]
                 and "bedrock:ApplyGuardrail" in st.get("Action", []) for st in s.org_rbp.get("Statement", []))
    if not rbp_ok:
        out.append(Finding("M12-14", "HIGH", "12.3", "the org guardrail has no resource-based policy letting the organization call ApplyGuardrail"))
    return out


def rule_15(s):
    if s.org_guardrail.get("automatedReasoningPolicyConfig"):
        return [Finding("M12-15", "HIGH", "12.3", "the enforced guardrail includes an Automated Reasoning policy: unsupported for enforcement, runtime failures")]
    return []


def rule_16(s):
    out = []
    for c in _org_cfgs(s):
        scg = c.get("selective_content_guarding", {})
        for part in ("system", "messages"):
            if scg.get(part, {}).get("@@assign") == "selective":
                out.append(Finding("M12-16", "MEDIUM", "12.3", f"org policy: {part} = selective, so callers decide what gets evaluated"))
        excl = c.get("model_enforcement", {}).get("excluded_models", {}).get("@@assign", [])
        if CO["helpdesk"]["foundation_model"] in excl:
            out.append(Finding("M12-16", "MEDIUM", "12.3", "org policy excludes the Helpdesk's text model from enforcement"))
    return out


def rule_17(s):
    """CHALLENGE (lesson 12.3): Guardrails is not supported on the bedrock-mantle endpoint.

    For every principal ARN in CO["guardrails_required_for"], find its policy in s.principal_policies (match the ARN in
    CO["principals"]) and use iam_eval to check whether it may call "bedrock-mantle:CreateInference" on "*". If it may,
    return a HIGH finding "M12-17" for lesson "12.3" that names the principal. Return [] when nobody can.
    """
    return []  # TODO (challenge)


RULES = [rule_01, rule_02, rule_03, rule_04, rule_05, rule_06, rule_07, rule_08, rule_09, rule_10, rule_11,
         rule_12, rule_13, rule_14, rule_15, rule_16, rule_17]
_current: Setup


def run(name: str) -> list[Finding]:
    global _current
    _current = Setup(SETUPS[name])
    return [f for r in RULES for f in r(_current)]


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    name = argv[0] if argv else "first-draft"
    findings = run(name)
    print(f"== Guardrail rollout review: {name}\n")
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for f in sorted(findings, key=lambda f: (order[f.severity], f.rule)):
        print(f"[{f.severity:6}] {f.rule} ({f.lesson}) {f.message}")
    counts = {sev: sum(f.severity == sev for f in findings) for sev in ("HIGH", "MEDIUM", "LOW")}
    print(f"\n{counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW  ({len(findings)} findings)")
    return 1 if counts["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
