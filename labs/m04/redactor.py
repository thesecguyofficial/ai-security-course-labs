"""
M4.6 lab: the redaction layer.

This file turns text like
    "I'm Jane Doe, jane.doe@example.com"
into
    "I'm <PERSON>, <EMAIL_ADDRESS>"

It uses Presidio, an open-source PII (personally identifiable information) toolkit, MIT licence.
Presidio has two parts:
  * the ANALYZER finds sensitive things in text (it returns "what, where, how sure")
  * the ANONYMIZER replaces what the analyzer found (here: with a label like <EMAIL_ADDRESS>)

Important: Presidio's own README warns that automated detection can't guarantee it finds ALL
sensitive data. Redaction is one layer, not the whole defence.
"""

import logging
import re

# Presidio is chatty about recognizers it skips; keep the lab output readable.
logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
# Presidio checks e-mail domains with a helper library (tldextract). On first use that helper tries to
# download the public list of domain endings (publicsuffix.org). If it can't, it quietly uses a built-in
# copy. None of YOUR text is sent anywhere. We silence its error message so an offline run stays tidy.
logging.getLogger("tldextract").setLevel(logging.CRITICAL)

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer  # noqa: E402
from presidio_analyzer.nlp_engine import NlpEngineProvider  # noqa: E402
from presidio_analyzer.predefined_recognizers import InAadhaarRecognizer, InPanRecognizer  # noqa: E402
from presidio_anonymizer import AnonymizerEngine  # noqa: E402

# ------------------------------------------------------------------ 1. what we redact (a decision, not a default)
# Pick entity types on purpose. More types = fewer leaks but more false alarms ("May" read as a date).
ENTITIES = [
    "PERSON",          # names (found by the spaCy language model, so it's a best guess)
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",     # checked with the Luhn checksum, so random 16-digit numbers are ignored
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_SSN",
    "IN_PAN",          # Indian PAN card number: shipped with Presidio but OFF by default, we switch it on below
    "IN_AADHAAR",      # Indian Aadhaar number: also off by default
    "AWS_ACCESS_KEY",  # not built in: we add our own recognizer below
]

# Only act on findings Presidio is at least this sure about (0 = any guess, 1 = certain).
# Lower it and you catch more but redact innocent words too. Try changing it in the lab.
SCORE_THRESHOLD = 0.35

# ------------------------------------------------------------------ 2. build the analyzer
# Presidio's default is spaCy's large English model (en_core_web_lg, several hundred MB).
# For this lab we use the small one (en_core_web_sm) so set-up is quick. It is worse at spotting names.
NLP_CONFIG = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    # Ignore spaCy labels we don't care about (organisations, quantities...), as Presidio's default config does.
    "ner_model_configuration": {
        "labels_to_ignore": ["ORG", "ORGANIZATION", "CARDINAL", "EVENT", "LANGUAGE", "LAW", "MONEY",
                             "ORDINAL", "PERCENT", "PRODUCT", "QUANTITY", "WORK_OF_ART"],
    },
}

# AWS access key IDs start with AKIA (long-term keys) or ASIA (temporary STS keys), then 16 more
# upper-case letters or digits. (AWS IAM docs: "Unique ID prefixes".) A leaked key in a prompt or a
# log is a credential leak, not just a privacy problem.
AWS_KEY_RECOGNIZER = PatternRecognizer(
    supported_entity="AWS_ACCESS_KEY",
    patterns=[Pattern(name="aws_access_key_id", regex=r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", score=0.9)],
)


def build_analyzer() -> AnalyzerEngine:
    """Create the Presidio analyzer once (loading the language model takes a second or two)."""
    nlp_engine = NlpEngineProvider(nlp_configuration=NLP_CONFIG).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    analyzer.registry.add_recognizer(InPanRecognizer())
    analyzer.registry.add_recognizer(InAadhaarRecognizer())
    analyzer.registry.add_recognizer(AWS_KEY_RECOGNIZER)

    # ---- YOUR TURN (lab challenge) -------------------------------------------------------------
    # The company's employee IDs look like EMP-482913 ("EMP-" then 6 digits). They are internal
    # identifiers and must not reach logs. Add a PatternRecognizer for a new entity "EMPLOYEE_ID"
    # (copy the AWS one above), register it here, and add "EMPLOYEE_ID" to ENTITIES.
    # Then run:  make challenge
    # ---------------------------------------------------------------------------------------------
    return analyzer


_analyzer = None
_anonymizer = AnonymizerEngine()


def find_pii(text: str):
    """Return Presidio's findings for `text`: a list of (entity type, start, end, score)."""
    global _analyzer
    if _analyzer is None:
        _analyzer = build_analyzer()
    return _analyzer.analyze(text=text, language="en", entities=ENTITIES, score_threshold=SCORE_THRESHOLD)


# A label we already put in, like <EMAIL_ADDRESS>. Text often passes through redaction twice (once in the
# code, once in the log filter). Without this check the second pass can mistake a label for a name:
# the small model read "AWS_ACCESS_KEY>" as a PERSON and turned it into "<<PERSON>".
PLACEHOLDER = re.compile(r"<[A-Z_]+>")


def redact(text: str) -> str:
    """Replace every finding with its label, e.g. jane.doe@example.com -> <EMAIL_ADDRESS>."""
    if not text:
        return text
    labels = [m.span() for m in PLACEHOLDER.finditer(text)]
    findings = [f for f in find_pii(text)
                if not any(f.start < end and f.end > start for start, end in labels)]  # skip our own labels
    # The anonymizer's default operator is "replace with <ENTITY_TYPE>". Presidio also offers
    # mask, hash and encrypt operators; labels are the easiest to read in logs.
    return _anonymizer.anonymize(text=text, analyzer_results=findings).text


class RedactingLogFilter(logging.Filter):
    """
    A safety net for log files. Attached to a logger, it redacts EVERY message before it is written,
    including messages from careless debug lines nobody remembered to clean.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())  # getMessage() merges "%s"-style arguments first
        record.args = None
        return True  # True = keep the (now cleaned) record
