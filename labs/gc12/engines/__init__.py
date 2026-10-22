"""Pluggable guardrail engines. Every engine returns Model-Armor-shaped results, so app_guard.py works with any."""


def get_engine(name: str, **kw):
    if name == "twin":
        from engines.twin import TwinEngine
        return TwinEngine(**kw)
    if name == "model-armor":
        from engines.model_armor import ModelArmorEngine
        return ModelArmorEngine(**kw)
    if name == "llm-guard":
        from engines.llm_guard_engine import LlmGuardEngine
        return LlmGuardEngine(**kw)
    raise SystemExit(f"unknown engine {name!r}: use twin, model-armor or llm-guard")
