"""
gates.py: the pre/post-quantization eval gate (lesson 25.2). CI calls it before it signs anything.

The idea in one line: evaluate the artefact you will SHIP, not only the one you trained, and compare the two.
Research on quantization attacks (Egashira et al., NeurIPS 2024 and ICML 2025) built models that look fine in full
precision and change behaviour once quantized, so a full-precision eval tells you nothing about the quantized file.

evaluate() runs one model over data/evals/*.jsonl. compare() turns two runs into the numbers the gate reads.
"""

from __future__ import annotations

import lab
import toymodel


def load_evals() -> list[dict]:
    return lab.read_jsonl(lab.DATA / "evals" / "risky.jsonl") + lab.read_jsonl(lab.DATA / "evals" / "normal.jsonl")


def evaluate(model: toymodel.Guard, cases: list[dict]) -> dict[str, str]:
    return {c["id"]: model.decide(c["text"]) for c in cases}


def recall(decisions: dict[str, str], cases: list[dict], slice_name: str | None = None) -> float:
    risky = [c for c in cases if c["expect"] == "ESCALATE" and (slice_name is None or c["slice"] == slice_name)]
    return sum(decisions[c["id"]] == "ESCALATE" for c in risky) / len(risky)


def compare(full: dict[str, str], shipped: dict[str, str], cases: list[dict]) -> dict:
    slices = sorted({c["slice"] for c in cases if c["expect"] == "ESCALATE"})
    return {
        "cases": len(cases),
        "agreement": sum(full[c["id"]] == shipped[c["id"]] for c in cases) / len(cases),
        "recall_full": recall(full, cases),
        "recall_shipped": recall(shipped, cases),
        "false_escalations_shipped": sum(shipped[c["id"]] == "ESCALATE" for c in cases if c["expect"] == "AUTO"),
        "slices": {s: {"recall_full": recall(full, cases, s), "recall_shipped": recall(shipped, cases, s)}
                   for s in slices},
        "flipped": [c["id"] for c in cases if full[c["id"]] != shipped[c["id"]]],
    }


def overall_gate(metrics: dict, rules: dict) -> list[str]:
    """Problems with the whole eval set. An empty list means this gate passes."""
    problems = []
    if metrics["recall_full"] < rules["min_recall"]:
        problems.append(f"full-precision recall {metrics['recall_full']:.3f} < {rules['min_recall']}")
    if "min_agreement" in rules and metrics["agreement"] < rules["min_agreement"]:
        problems.append(f"shipped artefact agrees with full precision on {metrics['agreement']:.3f} of cases "
                        f"< {rules['min_agreement']} (flipped: {', '.join(metrics['flipped'])})")
    if "max_recall_drop" in rules:
        drop = metrics["recall_full"] - metrics["recall_shipped"]
        if drop > rules["max_recall_drop"] + 1e-9:
            problems.append(f"recall drops by {drop:.3f} after quantization > {rules['max_recall_drop']}")
    return problems


def slice_gate(metrics: dict, rules: dict) -> list[str]:
    """CHALLENGE 1 (lesson 25.2): per-slice check.

    An overall number can hide a targeted change: the quantization attacks in the research go after ONE behaviour
    (insecure code, injected content, refusals), not the average. data/community-quant-v2.json passes overall_gate()
    and still lets one data-export request through.

    Return one problem string for every slice in metrics["slices"] whose shipped recall is lower than its
    full-precision recall by more than rules["max_slice_drop"] (0.0 in setups/hardened/ci.json).
    Until you write it, this gate passes everything.
    """
    return []


def main() -> None:
    """python3 gates.py MODEL_FOLDER [--ticket TEXT]: evaluate one model folder against the approved base."""
    import argparse
    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("model")
    ap.add_argument("--ticket", default=None, help="also show the decision for this one ticket")
    a = ap.parse_args()
    cases = load_evals()
    base, other = toymodel.load(lab.MODELS / "tsg-guard-base"), toymodel.load(lab.HERE / a.model)
    m = compare(evaluate(base, cases), evaluate(other, cases), cases)
    print(f"{a.model}: {m['cases']} eval cases, agreement with tsg-guard-base {m['agreement']:.3f}, "
          f"escalation recall {m['recall_shipped']:.3f} (base {m['recall_full']:.3f}), "
          f"false escalations {m['false_escalations_shipped']}")
    for s, v in m["slices"].items():
        print(f"  slice {s:<12} recall {v['recall_shipped']:.3f} (base {v['recall_full']:.3f})")
    if a.ticket:
        print(f"ticket: {a.ticket!r}\n  tsg-guard-base -> {base.decide(a.ticket)}   {a.model} -> {other.decide(a.ticket)}")


if __name__ == "__main__":
    main()
