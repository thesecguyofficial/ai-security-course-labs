"""
agent_platform.py: an OFFLINE teaching model of Gemini on Agent Platform calling Model Armor inline
(the "Agent Platform integration", lesson 12.3). Not Google's service.

What it models, each from Google's integration page (README, Sources):
  - which configuration applies, by the page's precedence table:
      request template + safety settings   -> error: you can't send both
      request template                     -> the template runs; safety settings ignored; it overrides floor settings
      no template, floor + safety settings -> both run, the most restrictive outcome wins
      no template, floor only              -> the floor setting runs
      no template, safety settings only    -> only Gemini's safety filters; Model Armor isn't called
      nothing                              -> only the model's own behaviour
  - floor settings apply "even if the modelArmorConfig parameter is omitted from the API request"
  - inspect only = record, don't stop; inspect and block = stop, with blockReason / finishReason MODEL_ARMOR
  - fail open: if Model Armor is unavailable, "the request continues without prompt and response sanitization"
  - results are only visible in Cloud Logging if logging is on

Twin assumptions (not stated by Google, said plainly): a request template's own enforcementType decides block vs
inspect (the API says an unspecified enforcement type is "Same as INSPECT_AND_BLOCK"); Gemini's safety filters are
approximated with the twin's responsible-AI word lists.
"""

from __future__ import annotations

import armor_twin
import helpdesk

MODEL = helpdesk.StandInModel()
SAFETY_LEVEL = {"BLOCK_LOW_AND_ABOVE": 1, "BLOCK_MEDIUM_AND_ABOVE": 2, "BLOCK_ONLY_HIGH": 3}
SAFETY_CAT = {"HARM_CATEGORY_DANGEROUS_CONTENT": "dangerous", "HARM_CATEGORY_HARASSMENT": "harassment",
              "HARM_CATEGORY_HATE_SPEECH": "hate_speech", "HARM_CATEGORY_SEXUALLY_EXPLICIT": "sexually_explicit"}


def _safety_blocks(settings: list | None, text: str) -> str | None:
    for s in settings or []:
        key, lvl = SAFETY_CAT.get(s["category"]), SAFETY_LEVEL.get(s["threshold"])
        if key and lvl and armor_twin._score(armor_twin.RAI_RULES[key], text) >= lvl:
            return s["category"]
    return None


def effective_config(request: dict, project: dict) -> dict:
    """Which screening applies to this request (the precedence table)."""
    mac, safety, floor = request.get("model_armor_config"), request.get("safety_settings"), project["floor"]
    floor_on = bool(floor and floor.get("enableFloorSettingEnforcement")
                    and "AI_PLATFORM" in floor.get("integratedServices", []))
    if mac and safety:
        return {"error": "INVALID_ARGUMENT: you can't specify a Model Armor template and safety settings in the same request"}
    if mac:
        t = project["templates"]
        ptpl, rtpl = t.get(mac.get("prompt_template_name")), t.get(mac.get("response_template_name"))
        missing = [n for n in (mac.get("prompt_template_name"), mac.get("response_template_name")) if n and n not in t]
        if missing:
            return {"error": f"NOT_FOUND: Template not found ({missing[0]})"}
        mode = lambda tpl: (tpl or {}).get("templateMetadata", {}).get("enforcementType", "INSPECT_AND_BLOCK")
        log = lambda tpl: bool((tpl or {}).get("templateMetadata", {}).get("logSanitizeOperations"))
        return {"source": "request template (overrides the floor setting)", "prompt": ptpl, "response": rtpl,
                "prompt_mode": mode(ptpl), "response_mode": mode(rtpl), "log": log(ptpl) or log(rtpl), "safety": None}
    if floor_on:
        aip = floor.get("aiPlatformFloorSetting", {})
        m = "INSPECT_AND_BLOCK" if aip.get("inspectAndBlock") else "INSPECT_ONLY"
        return {"source": "floor setting" + (" + Gemini safety filters" if safety else ""), "prompt": floor,
                "response": floor, "prompt_mode": m, "response_mode": m, "log": bool(aip.get("enableCloudLogging")),
                "safety": safety}
    if safety:
        return {"source": "Gemini safety filters only (Model Armor not called)", "prompt": None, "response": None,
                "safety": safety, "log": False}
    return {"source": "nothing: model behaviour only", "prompt": None, "response": None, "safety": None, "log": False}


def generate_content(request: dict, project: dict, available: bool = True) -> dict:
    """Returns {"response": ..., "log": [...], "source": ...}. The response mimics generateContent's fields."""
    cfg = effective_config(request, project)
    if "error" in cfg:
        return {"error": cfg["error"], "log": [], "source": "rejected"}
    prompt, logs, notes = request["prompt"], [], []
    screened = helpdesk.screened_part(prompt)

    def screen(tpl, text, stage, mode):
        if tpl is None:
            return False
        if not available:
            notes.append(f"Model Armor unavailable: {stage} continued without sanitization (fail open)")
            return False
        res = armor_twin.sanitize(tpl, text, stage)
        hits = armor_twin.matched_filters(res)
        if cfg["log"]:
            logs.append({"@type": "type.googleapis.com/google.cloud.modelarmor.logging.v1.SanitizeOperationLogEntry",
                         "stage": stage, "filterMatchState": res["sanitizationResult"]["filterMatchState"],
                         "matched": hits, "enforcement": mode})
        if hits and mode == "INSPECT_ONLY":
            notes.append(f"{stage}: matched {', '.join(hits)} but inspect only, so not stopped")
        return bool(hits) and mode == "INSPECT_AND_BLOCK"

    if screen(cfg["prompt"], screened, "prompt", cfg.get("prompt_mode")):
        return {"response": {"promptFeedback": {"blockReason": "MODEL_ARMOR"}}, "log": logs, "source": cfg["source"],
                "notes": notes}
    cat = _safety_blocks(cfg["safety"], screened)
    if cat:
        return {"response": {"promptFeedback": {"blockReason": "SAFETY", "category": cat}}, "log": logs,
                "source": cfg["source"], "notes": notes}
    reply = MODEL.generate(prompt)
    if screen(cfg["response"], reply, "response", cfg.get("response_mode")):
        return {"response": {"candidates": [{"finishReason": "MODEL_ARMOR"}]}, "log": logs, "source": cfg["source"],
                "notes": notes}
    cat = _safety_blocks(cfg["safety"], reply)
    if cat:
        return {"response": {"candidates": [{"finishReason": "SAFETY", "category": cat}]}, "log": logs,
                "source": cfg["source"], "notes": notes}
    return {"response": {"candidates": [{"finishReason": "STOP", "content": reply}]}, "log": logs,
            "source": cfg["source"], "notes": notes}


def load_project(twin: str) -> tuple[dict, dict]:
    base = armor_twin.HERE / "twin" / twin
    app = armor_twin.load_json(base / "app.json")
    templates = {t["name"]: t for t in armor_twin.load_json(base / "templates.json")["templates"]}
    project = {"floor": armor_twin.load_json(base / "floor.json"), "templates": templates,
               "service_agent_roles": app["inline"]["service_agent_roles"]}
    return app, project
