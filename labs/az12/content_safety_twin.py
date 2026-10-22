"""
content_safety_twin.py: an offline TWIN of two Azure AI Content Safety REST operations (api-version 2024-09-01):

    POST {endpoint}/contentsafety/text:shieldPrompt   body {"userPrompt": str, "documents": [str, ...]}
         -> {"userPromptAnalysis": {"attackDetected": bool}, "documentsAnalysis": [{"attackDetected": bool}, ...]}
    POST {endpoint}/contentsafety/text:analyze        body {"text": str, "categories": [...], "outputType": "FourSeverityLevels"}
         -> {"blocklistsMatch": [], "categoriesAnalysis": [{"category": "Hate", "severity": 0}, ...]}

Request and response shapes and the input limits are from Microsoft Learn (quickstarts and "Input requirements"):
Prompt Shields "Maximum prompt length: 10K characters" and "Up to five documents with a total of 10K characters";
text:analyze "Default maximum length: 10K characters". The classifiers are the stand-ins in detectors.py, and the error
bodies are the twin's own (Azure's exact error codes for these limits are not reproduced).

Remember what Microsoft says about this API: "the API doesn't itself block or route content. Customers decide how to
use the results in their application." Blocking is YOUR code's job: see selfhosted.py.
"""

import detectors

LIMIT = 10_000
CATEGORY_NAMES = {"Hate": "Hate", "Sexual": "Sexual", "Violence": "Violence", "SelfHarm": "Selfharm"}


def _err(msg: str) -> tuple[int, dict]:
    return 400, {"error": {"code": "LabTwinInvalidRequest", "message": msg}}


def shield_prompt(body: dict) -> tuple[int, dict]:
    user = body.get("userPrompt", "")
    docs = body.get("documents", [])
    if len(user) > LIMIT:
        return _err("userPrompt longer than 10K characters")
    if len(docs) > 5 or sum(len(d) for d in docs) > LIMIT:
        return _err("documents: up to five documents with a total of 10K characters")
    return 200, {"userPromptAnalysis": {"attackDetected": detectors.user_prompt_attack(user)["attackDetected"]},
                 "documentsAnalysis": [{"attackDetected": detectors.document_attack(d)["attackDetected"]} for d in docs]}


def analyze_text(body: dict) -> tuple[int, dict]:
    text = body.get("text", "")
    if len(text) > LIMIT:
        return _err("text longer than 10K characters (split longer texts)")
    sev = detectors.harm_severities(text)
    cats = body.get("categories") or list(CATEGORY_NAMES)
    return 200, {"blocklistsMatch": [], "categoriesAnalysis": [{"category": c, "severity": sev[CATEGORY_NAMES[c]]} for c in cats]}


def text_records(*texts: str) -> int:
    """Billing estimate: Microsoft's pricing page counts one text record per started 1,000 characters (Standard tier).
    How a Prompt Shields call with documents is counted is not stated there, so this sums all the text sent."""
    total = sum(len(t) for t in texts)
    return max(1, -(-total // 1000))
