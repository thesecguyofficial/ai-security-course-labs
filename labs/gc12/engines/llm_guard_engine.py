"""
OPTIONAL: a local open-source guardrail, LLM Guard (Protect AI), as a second opinion on your laptop.

    pip install llm-guard        # large download (PyTorch + a model from Hugging Face on first use)
    python3 run_suite.py --engine llm-guard

Only its PromptInjection input scanner is wired in here (usage as in LLM Guard's docs:
docs/input_scanners/prompt_injection.md). Not run by the lab authors: Hugging Face model downloads weren't
possible in the build environment. Results are mapped onto the Model Armor result shape so app_guard.py works
unchanged.
"""


class LlmGuardEngine:
    name = "LLM Guard (local, optional)"

    def __init__(self, threshold: float = 0.5, **_):
        try:
            from llm_guard.input_scanners import PromptInjection
            from llm_guard.input_scanners.prompt_injection import MatchType
        except ImportError as e:
            raise SystemExit("LLM Guard isn't installed: pip install llm-guard") from e
        self.scanner = PromptInjection(threshold=threshold, match_type=MatchType.FULL)

    @staticmethod
    def _shape(hit: bool) -> dict:
        state = "MATCH_FOUND" if hit else "NO_MATCH_FOUND"
        return {"sanitizationResult": {"filterMatchState": state, "invocationResult": "SUCCESS", "filterResults": {
            "pi_and_jailbreak": {"piAndJailbreakFilterResult": {"executionState": "EXECUTION_SUCCESS",
                                                                "matchState": state}}}}}

    def sanitize_user_prompt(self, text: str) -> dict:
        _, is_valid, _ = self.scanner.scan(text)
        return self._shape(not is_valid)

    def sanitize_model_response(self, text: str, user_prompt: str = "") -> dict:
        return self._shape(False)      # no output scanners wired in: add llm_guard.output_scanners yourself
