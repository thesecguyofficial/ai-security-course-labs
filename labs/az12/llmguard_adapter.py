"""
llmguard_adapter.py: OPTIONAL. Swap the rule-based prompt-attack stand-ins for a real open-source ML classifier,
LLM Guard's PromptInjection scanner, and re-run the same suite:  make llmguard

    python3 -m venv .venv && . .venv/bin/activate && pip install llm-guard
    python3 run_suite.py --compare --detector llmguard

LLM Guard downloads its model from Hugging Face the first time (several hundred MB). The usage below is the one in
LLM Guard's documentation ("scanner = PromptInjection(threshold=0.5, match_type=MatchType.FULL)" and
"sanitized_prompt, is_valid, risk_score = scanner.scan(prompt)").

Not run by the course team: Hugging Face downloads are blocked in the course build, so this adapter is untested.
Expect DIFFERENT numbers from the stand-ins, in both directions. Write both down: that comparison is the exercise.
"""

import detectors


def install(threshold: float = 0.5):
    from llm_guard.input_scanners import PromptInjection
    from llm_guard.input_scanners.prompt_injection import MatchType

    scanner = PromptInjection(threshold=threshold, match_type=MatchType.FULL)

    def ml_user(text: str) -> dict:
        _, is_valid, score = scanner.scan(text)
        return {"attackDetected": not is_valid, "classes": [f"LLM Guard PromptInjection score {score:.2f}"]}

    def ml_doc(text: str) -> dict:
        _, is_valid, score = scanner.scan(text)
        return {"attackDetected": not is_valid, "classes": [f"LLM Guard PromptInjection score {score:.2f}"]}

    detectors.user_prompt_attack = ml_user
    detectors.document_attack = ml_doc
