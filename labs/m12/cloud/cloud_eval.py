#!/usr/bin/env python3
"""
cloud_eval.py: OPTIONAL. Run the same M12 suite against the REAL Bedrock guardrail with ApplyGuardrail (lesson 12.2).

It needs boto3 (`pip install boto3`), AWS credentials for YOUR sandbox account, and the guardrail from `make cloud-up`.
It never calls a model: for every case it sends
  * the question to ApplyGuardrail with source=INPUT, and
  * the answer the offline stand-in model gives WITHOUT a guardrail (helpdesk.py) to ApplyGuardrail with source=OUTPUT,
    with the knowledge-base article and the question as grounding_source and query when the app would use them.
Then it prints catch rate and false positives, the same two numbers as `make tuned`. Expect them to DIFFER from the
offline twin: Bedrock's classifiers are real models, the twin's are short pattern lists. That difference is the lesson.

    python3 cloud/cloud_eval.py --guardrail-id <id> --version 1 [--region us-east-1]

Cost: one ApplyGuardrail call per case and direction, about 60 calls of 1 text unit per configured policy each. At the
list prices in the README that is a few US cents. Nothing is stored by this script.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import helpdesk  # noqa: E402  (the offline app: used only to produce the unguarded answers)


def build_output_content(question: str, answer: str) -> list[dict]:
    art = None if re.search(r"(?i)\bticket \d{4}\b", question) else helpdesk.retrieve(question)
    content = []
    if art:
        content.append({"text": {"text": art["text"], "qualifiers": ["grounding_source"]}})
        content.append({"text": {"text": question, "qualifiers": ["query"]}})
    content.append({"text": {"text": answer or "(empty answer)"}})
    return content


def apply(client, gid: str, version: str, source: str, content: list[dict]) -> dict:
    return client.apply_guardrail(guardrailIdentifier=gid, guardrailVersion=version, source=source,
                                  content=content, outputScope="INTERVENTIONS")


def run(client, gid: str, version: str) -> dict:
    cases = json.loads((HERE / "suite/cases.json").read_text(encoding="utf-8"))
    rows = []
    for kind in ("attacks", "benign"):
        for c in cases[kind]:
            unguarded = helpdesk.ask(c["question"])  # offline, no guardrail: what the model would have said
            r_in = apply(client, gid, version, "INPUT", [{"text": {"text": c["question"]}}])
            r_out = apply(client, gid, version, "OUTPUT", build_output_content(c["question"], unguarded["answer"]))
            hit = "GUARDRAIL_INTERVENED" in (r_in["action"], r_out["action"])
            rows.append({"id": c["id"], "kind": kind, "category": c["category"], "input": r_in["action"],
                         "output": r_out["action"], "intervened": hit})
    attacks = [r for r in rows if r["kind"] == "attacks"]
    benign = [r for r in rows if r["kind"] == "benign"]
    return {"rows": rows, "stopped": sum(r["intervened"] for r in attacks), "attacks": len(attacks),
            "false_positives": sum(r["intervened"] for r in benign), "benign": len(benign)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Run the M12 suite against a real Bedrock guardrail (ApplyGuardrail).")
    p.add_argument("--guardrail-id", required=True)
    p.add_argument("--version", default="1")
    p.add_argument("--region", default="us-east-1")
    a = p.parse_args(argv)
    import boto3  # imported here so the offline lab never needs it
    client = boto3.client("bedrock-runtime", region_name=a.region)
    res = run(client, a.guardrail_id, a.version)
    for r in res["rows"]:
        print(f"{r['id']:4} {r['category'][:40]:40} input={r['input']:21} output={r['output']}")
    print(f"\nReal guardrail: stopped {res['stopped']} of {res['attacks']} attacks; "
          f"blocked or changed {res['false_positives']} of {res['benign']} normal questions.")
    print("Note: an attack counts as 'stopped' here if either direction intervened. Compare with `make tuned`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
