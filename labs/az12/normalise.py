"""
normalise.py: clean text BEFORE it reaches the guardrail (challenge 1).

Attack A08 hides "Ignore all previous instructions" behind invisible zero-width characters. The guardrail reads the
raw characters and sees nothing; the model reads straight through them and obeys. Published research found the same
gap in real detectors: character-injection tricks such as zero-width characters, homoglyphs and Unicode tag
smuggling evaded the guardrails they tested, Azure Prompt Shield included (Hackett et al., arXiv 2504.11168, 2025).
OWASP LLM01:2026, mitigation 5: strip tag-block, variation-selector and zero-width characters "at every ingest and
render boundary". It also warns: "Stripping does not stop visible-text payloads".

The app turns this step on with "normalise_input": true in app.json (fixes/app.json already does).
"""

import unicodedata


def normalise(text: str) -> str:
    """Return the text the guardrail should see.

    YOUR TURN (challenge 1). Right now this returns the text unchanged, so A08 still works on the hardened build.
    Make it remove the characters a human can't see but a model still reads, without changing normal text
    (test_challenge.py checks both). Hints:
      - zero-width characters: U+200B, U+200C, U+200D, U+2060, U+FEFF
      - Unicode "tag" characters: U+E0000 to U+E007F
      - variation selectors: U+FE00 to U+FE0F (OWASP LLM01:2026 lists all three groups to strip at every ingest boundary)
      - unicodedata.normalize("NFKC", ...) folds full-width and many look-alike forms to plain ones
    """
    return text
