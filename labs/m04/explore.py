"""
explore.py: look at each step on its own, before you run the lab (M4 lab, "Understand the lab").

Nothing here changes the lab. Each command shows one piece of what the chat app and the redactor do:

    python explore.py trace "My email is jane.doe@example.com"   # 1. every copy ONE message leaves behind
    python explore.py recognizers                                # 2. the detectors Presidio loads, and how each one works
    python explore.py ner "Hi, I am Jane Doe from London."       # 3. what the spaCy language model guesses on its own
    python explore.py analyze "My phone is +1 202-555-0143"      # 4. Presidio's findings, how each score was built,
                                                                 #    what the lab would redact, and the result

`trace` runs one chat turn with NO redaction and writes its logs to a temporary folder that is deleted at the end,
so your logs/ folder is never touched. Fake data only. Nothing here uses the network.
"""

import argparse
import logging
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent


def show(text: str, width: int = 96) -> str:
    """Shorten long lines so the output fits a normal terminal."""
    return text if len(text) <= width else text[: width - 1] + "…"


# ------------------------------------------------------------------------------------------------- 1. trace
def cmd_trace(a):
    import chat_app
    import stub_llm

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="m04-trace-"))
    chat_app.LOG_DIR = stub_llm.LOG_DIR = tmp  # the app and the stand-in model write here, not to logs/
    chat_app.setup_app_log(redact_logs=False)
    args = argparse.Namespace(redact=False, backend="stub", model="")
    history = [{"role": "system", "content": chat_app.SYSTEM_PROMPT}]
    reply = chat_app.handle_turn(a.message, history, args)
    for h in logging.getLogger("app").handlers + logging.getLogger("provider").handlers:
        h.flush()
        h.close()

    msg = a.message
    print(f'one message, redaction OFF: "{msg}"\n')
    print("1. the app's memory: the list of messages it sends to the model (working memory, the context window)")
    for m in history:
        print(f"   [{m['role']}] {show(m['content'], 92)}")
    copies = {"app memory": sum(msg in m["content"] for m in history)}
    for n, (name, job) in enumerate([("app.log", "your company's log file"),
                                     ("provider.log", "what the AI provider received")], start=2):
        lines = (tmp / name).read_text("utf-8").splitlines()
        print(f"\n{n}. logs/{name}: {job}, {len(lines)} line(s)")
        for ln in lines:
            print(f"   {show(ln[24:], 92)}")  # [24:] drops the date and time at the start of each line
        copies[name] = sum(msg in ln for ln in lines)
    print(f"\n4. the screen: the reply the user sees\n   {show(reply, 92)}")
    copies["screen"] = int(msg in reply)
    total = sum(copies.values())
    print(f"\ncopies of your message: {total}  (" + ", ".join(f"{k} {v}" for k, v in copies.items()) + ")")
    for f in tmp.iterdir():
        f.unlink()
    tmp.rmdir()


# ------------------------------------------------------------------------------------------------- 2. recognizers
def _analyzer():
    import redactor
    return redactor, redactor.build_analyzer()


def how_it_finds(r) -> str:
    from presidio_analyzer import PatternRecognizer
    kind = type(r).__name__
    if kind == "SpacyRecognizer":
        return "language model guess (spaCy NER)"
    if kind == "PhoneRecognizer":
        return "phone library parses the number"
    base = "/".join(f"{s:g}" for s in sorted({p.score for p in (getattr(r, "patterns", None) or [])}))
    checked = type(r).validate_result is not PatternRecognizer.validate_result
    return f"pattern{' + validity check' if checked else ''}, start {base}"


def cmd_recognizers(a):
    redactor, an = _analyzer()
    recs = an.registry.get_recognizers(language="en", all_fields=True)
    print(f"Presidio analyzer: {len(recs)} recognizers loaded (3 of them added by the lab: IN_PAN, IN_AADHAAR, AWS_ACCESS_KEY)\n")
    print(f"  {'finds':<20} {'how':<40} context words that raise the score")
    for r in sorted(recs, key=lambda r: "PERSON" if "PERSON" in r.supported_entities else r.supported_entities[0]):
        ents = r.supported_entities
        name = "PERSON, LOCATION..." if "PERSON" in ents else ents[0]
        ctx = ", ".join((getattr(r, "context", None) or [])[:3]) or "-"
        print(f"  {name:<20} {how_it_finds(r):<40} {show(ctx, 40)}")
    print(f"\nthe lab redacts only these {len(redactor.ENTITIES)} types (ENTITIES in redactor.py), "
          f"and only when the score is at least {redactor.SCORE_THRESHOLD}:")
    print("  " + ", ".join(redactor.ENTITIES))


# ------------------------------------------------------------------------------------------------- 3. ner
def cmd_ner(a):
    import spacy
    import redactor
    model = redactor.NLP_CONFIG["models"][0]["model_name"]
    nlp = spacy.load(model)
    print(f"spaCy model {model}: named entity recognition (NER) on its own, before Presidio\n")
    for t in a.texts:
        ents = nlp(t).ents
        print(f'"{t}"')
        if not ents:
            print("   (no entities found)")
        for e in ents:
            print(f"   {e.label_:<9} {e.text!r}")


# ------------------------------------------------------------------------------------------------- 4. analyze
def cmd_analyze(a):
    redactor, an = _analyzer()
    text = a.text
    found = an.analyze(text=text, language="en", return_decision_process=True)
    found = sorted(found, key=lambda f: f.start)
    print(f'text: "{text}"\n')
    print(f"Presidio found {len(found)}. The lab redacts a finding if its type is in ENTITIES "
          f"and its score is at least {redactor.SCORE_THRESHOLD}.\n")
    for f in found:
        e = f.analysis_explanation
        if e.recognizer == "SpacyRecognizer":
            steps = [f"NER guess {e.original_score:g}"]
        elif e.pattern_name:
            steps = [f"pattern '{e.pattern_name}' {e.original_score:g}"]
        else:
            steps = [f"library {e.original_score:g}"]
        if e.validation_result is True:
            steps.append("valid")
        if e.supportive_context_word:
            steps.append(f"word '{e.supportive_context_word}' nearby")
        if len(steps) > 1:
            steps.append(f"{f.score:.2f}")
        listed = f.entity_type in redactor.ENTITIES
        keep = listed and f.score >= redactor.SCORE_THRESHOLD
        why = "REDACT" if keep else ("skip: type not in ENTITIES" if not listed else "skip: score too low")
        print(f"  {f.entity_type:<17} {text[f.start:f.end]!r:<23} score {f.score:.2f}  {why}")
        print(f"  {'':<17} {e.recognizer}: " + " -> ".join(steps))
    print(f"\nredacted: {redactor.redact(text)}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Look at each step of the M4 lab on its own.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("trace"); s.add_argument("message"); s.set_defaults(fn=cmd_trace)
    s = sub.add_parser("recognizers"); s.set_defaults(fn=cmd_recognizers)
    s = sub.add_parser("ner"); s.add_argument("texts", nargs="+"); s.set_defaults(fn=cmd_ner)
    s = sub.add_parser("analyze"); s.add_argument("text"); s.set_defaults(fn=cmd_analyze)
    a = p.parse_args(argv)
    sys.path.insert(0, str(HERE))
    a.fn(a)


if __name__ == "__main__":
    main()
