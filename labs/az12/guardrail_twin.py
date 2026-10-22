"""
guardrail_twin.py: a TEACHING MODEL of a Microsoft Foundry guardrail (RAI policy) in front of a model or an agent.

What it copies from Microsoft Learn (Oct 2026), so the lab behaves like the real thing in the ways that matter:
  - A guardrail is a named collection of controls; each control = a risk, an intervention point, an action.
  - Intervention points: user input, tool call (agents, preview), tool response (agents, preview), output.
    The policy JSON uses the ARM `source` values: Prompt, Completion, PreToolCall, PostToolCall (lab reading:
    PreToolCall = tool call, PostToolCall = tool response).
  - severityThreshold Low blocks low+medium+high, Medium blocks medium+high, High blocks high only.
  - Document checks (indirect attacks, Spotlighting) only see documents the app TAGS as documents.
  - Spotlighting base-64 encodes tagged documents; Chat Completions API only; not supported for agents.
  - "The agentic guardrail fully overrides the model's guardrail."
  - Tool call / tool response controls only work for tools with moderation support (MCP is not on that list).
  - mode Asynchronous_filter streams tokens before the filter answers, so flagged output may already be on screen.
  - Blocked input: HTTP 400 with code content_filter. Blocked output: HTTP 200 with finish_reason content_filter.
What it does NOT copy: the real classifiers (see detectors.py), latency, and Azure's exact message texts.
"""

import base64
import copy
import json
import os

import detectors

HERE = os.path.dirname(os.path.abspath(__file__))
HARMS = ["Hate", "Sexual", "Violence", "Selfharm"]
# Tools Microsoft lists with moderation support for tool call / tool response controls (intervention points page).
MODERATED_TOOL_TYPES = {"azure_ai_search", "azure_functions", "openapi", "sharepoint_grounding", "fabric_data_agent",
                        "bing_grounding", "bing_custom_search", "browser_automation"}


def load(folder: str, name: str):
    with open(os.path.join(HERE, folder, name), encoding="utf-8") as f:
        return json.load(f)


def resolve_policy(folder: str, name: str) -> dict:
    """Policy by name from <folder>/rai-policies.json, falling back to the shared Microsoft defaults."""
    own = load(folder, "rai-policies.json")["policies"]
    if name in own:
        return own[name]
    defaults = load("contoso", "rai-policies.json")["policies"]
    if name in defaults:
        return defaults[name]
    raise KeyError(f"RAI policy '{name}' not found")


def _filters(policy: dict, name: str, source: str) -> list[dict]:
    return [f for f in policy["properties"].get("contentFilters", [])
            if f["name"] == name and f["source"] == source and f.get("enabled")]


def _blocklists(policy: dict, source: str, folder: str) -> list[tuple[str, list[dict], bool]]:
    defs = load(folder, "blocklists.json")["blocklists"]
    out = []
    for b in policy["properties"].get("customBlocklists", []):
        if b["source"] == source:
            out.append((b["blocklistName"], defs.get(b["blocklistName"], []), b.get("blocking", True)))
    return out


class Blocked(Exception):
    def __init__(self, stage: str, control: str, response: dict):
        super().__init__(f"{stage}: {control}")
        self.stage, self.control, self.response = stage, control, response


def check_text(policy: dict, folder: str, text: str, source: str, results: dict, extra_harm_text: str = "") -> list[str]:
    """Run the harm, blocklist (and for Prompt: user prompt attack) controls of one source. Fills `results` with
    Azure-shaped annotations and returns the names of the BLOCKING controls that fired."""
    fired = []
    sev = detectors.harm_severities(text + " " + extra_harm_text)
    for cat in HARMS:
        key = {"Selfharm": "self_harm"}.get(cat, cat.lower())
        conf = _filters(policy, cat, source)
        filtered = bool(conf) and sev[cat] >= detectors.THRESHOLD_MIN[conf[0].get("severityThreshold", "Medium")] and conf[0].get("blocking", True)
        results[key] = {"filtered": filtered, "severity": detectors.SEVERITY_NAME[sev[cat]]}
        if filtered:
            fired.append(f"{cat} (severity {detectors.SEVERITY_NAME[sev[cat]]})")
    for name, items, blocking in _blocklists(policy, source, folder):
        hits = detectors.blocklist_hits(text, items)
        if hits:
            if source == "Prompt":   # prompt shape in Microsoft's example: {"details": [...], "filtered": bool}
                results.setdefault("custom_blocklists", {"filtered": False, "details": []})
                results["custom_blocklists"]["details"].append({"id": name, "filtered": blocking})
                results["custom_blocklists"]["filtered"] = results["custom_blocklists"]["filtered"] or blocking
            else:                    # completion shape in Microsoft's example: [{"filtered": bool, "id": name}]
                results.setdefault("custom_blocklists", []).append({"filtered": blocking, "id": name})
            if blocking:
                fired.append(f"custom blocklist '{name}'")
    if source in ("Prompt",):
        jb = _filters(policy, "Jailbreak", source)
        if jb:
            r = detectors.user_prompt_attack(text)
            results["jailbreak"] = {"detected": r["attackDetected"], "filtered": r["attackDetected"] and jb[0].get("blocking", True)}
            if results["jailbreak"]["filtered"]:
                fired.append("Prompt Shields: user prompt attack (" + ", ".join(r["classes"]) + ")")
    return fired


def check_documents(policy: dict, docs: list[dict], source: str, results: dict) -> list[str]:
    ia = _filters(policy, "Indirect Attack", source)
    if not ia or not docs:
        return []
    fired = []
    for d in docs:
        r = detectors.document_attack(d["text"])
        if r["attackDetected"]:
            results["indirect_attack"] = {"detected": True, "filtered": ia[0].get("blocking", True)}
            if ia[0].get("blocking", True):
                fired.append(f"Prompt Shields: document attack in {d['id']}")
    results.setdefault("indirect_attack", {"detected": False, "filtered": False})
    return fired


def check_output(policy: dict, folder: str, text: str, results: dict) -> list[str]:
    fired = check_text(policy, folder, text, "Completion", results)
    pm = _filters(policy, "Protected Material Text", "Completion")
    if pm:
        r = detectors.protected_material_text(text)
        results["protected_material_text"] = {"detected": r["detected"], "filtered": r["detected"] and pm[0].get("blocking", True)}
        if results["protected_material_text"]["filtered"]:
            fired.append("Protected material (text)")
    pii_conf = _filters(policy, "PII", "Completion")
    if pii_conf:
        found = detectors.pii(text)
        modes = pii_conf[0].get("x-twinCategories", {})   # twin-only field: per-category annotate/block
        blocked = [c for c in found if modes.get(c) == "block"]
        results["pii"] = {"detected": bool(found), "filtered": bool(blocked), "categories": sorted(found)}
        if blocked:
            fired.append("PII (" + ", ".join(sorted(blocked)) + ")")
    return fired


def spotlight(docs: list[dict]) -> list[dict]:
    """Base-64 encode each tagged document, as Spotlighting does."""
    return [{"id": d["id"], "text": base64.b64encode(d["text"].encode("utf-8")).decode("ascii")} for d in docs]


def spotlighting_on(policy: dict, api: str, is_agent: bool) -> bool:
    return bool(_filters(policy, "Indirect Attack Spotlighting", "Prompt")) and api == "chat_completions" and not is_agent


def input_error(results: dict) -> dict:
    return {"status": 400, "body": {"error": {"code": "content_filter", "status": 400, "param": "prompt",
                                              "message": "(lab twin) blocked at input",
                                              "innererror": {"code": "ResponsibleAIPolicyViolation",
                                                             "content_filter_result": copy.deepcopy(results)}}}}


def output_response(content: str, results: dict, filtered: bool) -> dict:
    return {"status": 200, "body": {"choices": [{"finish_reason": "content_filter" if filtered else "stop",
                                                 "message": {"role": "assistant", "content": "" if filtered else content},
                                                 "content_filter_results": copy.deepcopy(results)}]}}
