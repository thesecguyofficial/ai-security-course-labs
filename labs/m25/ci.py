"""
ci.py: the CI job (lessons 25.2 and 25.5). Build, evaluate, write the ML-BOM, sign. In that order, every time.

    python3 ci.py build                                    # write models/ from data/ (the lab's model files)
    python3 ci.py release hardened --version 1.1.0         # quantize the approved base, gate, BOM, sign
    python3 ci.py release hardened --version 1.1.1 --quant models/community-quant     # ship a community quant
    python3 ci.py release first-draft --version 1.1.0      # the first draft's CI, for comparison

A release is a folder release/<version>-<setup>/ with:
    model/             the files that ship, ALL of them signed: model.safetensors, config.json, eval-report.json,
                       ml-bom.json (CycloneDX 1.6), and README.md if --docs
    model.sig          the OpenSSF model-signing bundle (Sigstore bundle format, signed here with a local key)
    keys/ci.pub        first draft only: the public key shipped next to the model (a habit the deploy gate abuses)

Signing uses the real `model_signing` library with the lab's own ECDSA P-256 key (keys/ci.priv), so nothing goes to
Sigstore or anywhere else. In a real pipeline you would sign keyless with the CI's identity (GUIDED-BUILD.md).
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import sys
import uuid

import gates
import lab
import toymodel


# ---------- make the model files ----------

def build() -> None:
    m = lab.MODELS
    for src, name in [("base-model.json", "tsg-guard-base"), ("old-base-model.json", "tsg-guard-base-1.0"),
                      ("unapproved-base.json", "unapproved-base")]:
        d = lab.read_json(lab.DATA / src)
        toymodel.save_fp32(m / name, d["vocab"], d["weights"], d["bias"], d["name"])
    for src, name in [("community-quant.json", "community-quant"), ("community-quant-v2.json", "community-quant-v2")]:
        d = lab.read_json(lab.DATA / src)
        folder = m / name
        folder.mkdir(parents=True, exist_ok=True)
        toymodel.write_safetensors(folder / "model.safetensors",
                                   {"weight": ("I8", d["weight_q"]), "scale": ("F32", [d["scale"]]),
                                    "bias": ("F32", [d["bias"]])},
                                   {"format": "pt", "model": d["name"], "precision": d["precision"]})
        lab.write_json(folder / "config.json", {"model": d["name"], "architecture": "linear-bag-of-words",
                                                "precision": d["precision"], "vocab": d["vocab"],
                                                "uploaded_by": d["uploaded_by"]})
    print(f"wrote {', '.join(sorted(p.name for p in m.iterdir()))} in models/")


# ---------- the ML-BOM ----------

def ml_bom(version: str, base: pathlib.Path, shipped_file: pathlib.Path, precision: str, metrics: dict | None,
           rich: bool) -> dict:
    base_cfg = lab.read_json(base / "config.json")
    component = {
        "type": "machine-learning-model",
        "bom-ref": f"tsg-guard-{precision}@{version}",
        "name": f"tsg-guard-{precision}",
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": lab.sha256_file(shipped_file)}],
    }
    if rich:
        component["pedigree"] = {"ancestors": [{
            "type": "machine-learning-model", "name": base_cfg["model"],
            "hashes": [{"alg": "SHA-256", "content": lab.sha256_file(base / "model.safetensors")}]}]}
        component["modelCard"] = {
            "modelParameters": {"task": "text-classification", "architectureFamily": "linear-bag-of-words"},
            "quantitativeAnalysis": {"performanceMetrics": [
                {"type": "escalation-recall", "value": f"{metrics['recall_shipped']:.3f}", "slice": "risky"},
                {"type": "agreement-with-full-precision", "value": f"{metrics['agreement']:.3f}"},
            ] + [{"type": "escalation-recall", "value": f"{v['recall_shipped']:.3f}", "slice": s}
                 for s, v in metrics["slices"].items()]},
        }
        component["properties"] = [{"name": "tsg:precision", "value": precision},
                                   {"name": "tsg:eval-cases", "value": str(metrics["cases"])}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'tsg-guard/' + version)}",
        "version": 1,
        "metadata": {"timestamp": lab.CLOCK, "component": {"type": "application", "name": "tsg-helpdesk"}},
        "components": [component],
    }


# ---------- signing ----------

def sign(model_dir: pathlib.Path, sig: pathlib.Path, private_key: pathlib.Path) -> None:
    import model_signing
    model_signing.signing.Config().use_elliptic_key_signer(private_key=private_key).sign(model_dir, sig)


# ---------- the CI job ----------

def release(setup: str, version: str, base: pathlib.Path, quant: pathlib.Path | None, docs: bool = False,
            key: pathlib.Path | None = None, quiet: bool = False,
            gate_override: dict | None = None) -> pathlib.Path | None:
    cfg = lab.setup_config(setup, "ci")
    if gate_override:                      # suite.py only: release 1.0.0 was built under February's looser rules
        cfg["gate"] = {**cfg["gate"], **gate_override}
    say = (lambda *a: None) if quiet else print
    lab.ensure_keys()
    out = lab.fresh_dir(lab.RELEASE / f"{version}-{setup}")
    work = lab.fresh_dir(lab.STATE / "ci-work" / f"{version}-{setup}")

    # 1. the artefact we ship: our own int8 quantization of the base, or a quant someone handed us
    if quant is None:
        shipped = work / "int8"
        toymodel.quantize_int8(base, shipped)
        precision = "int8"
    else:
        shipped = quant
        precision = lab.read_json(quant / "config.json").get("precision", "unknown")
    say(f"CI [{setup}] release {version}: base {base.name}, shipping {precision} ({shipped.name})")

    # 2. the eval gate
    cases = gates.load_evals()
    full = gates.evaluate(toymodel.load(base), cases)
    shipped_decisions = gates.evaluate(toymodel.load(shipped), cases)
    metrics = gates.compare(full, shipped_decisions, cases)
    rules = cfg["gate"]
    problems = gates.overall_gate(metrics, rules)
    if cfg.get("slice_gate"):
        problems += gates.slice_gate(metrics, rules)
    evaluated = "full precision AND the shipped artefact" if cfg["evaluate_shipped"] else "full precision only"
    say(f"  eval ({evaluated}): recall fp32 {metrics['recall_full']:.3f}"
        + (f", shipped {metrics['recall_shipped']:.3f}, agreement {metrics['agreement']:.3f}"
           if cfg["evaluate_shipped"] else ""))
    if problems:
        for p in problems:
            say(f"  GATE FAILED: {p}")
        say("  REFUSED: nothing signed, nothing released")
        shutil.rmtree(out)
        return None

    # 3. the files that ship, then the BOM and eval report INSIDE the signed folder
    model_dir = out / "model"
    model_dir.mkdir()
    shutil.copy(shipped / "model.safetensors", model_dir / "model.safetensors")
    shutil.copy(shipped / "config.json", model_dir / "config.json")
    report = {"version": version, "base": base.name, "precision": precision,
              "base_sha256": lab.sha256_file(base / "model.safetensors"),
              "shipped_sha256": lab.sha256_file(model_dir / "model.safetensors"),
              "evaluated": evaluated, "rules": rules, "passed": True}
    if cfg["evaluate_shipped"]:
        report["metrics"] = metrics
    else:
        report["metrics"] = {"recall_full": metrics["recall_full"], "cases": metrics["cases"]}
    lab.write_json(model_dir / "eval-report.json", report)
    lab.write_json(model_dir / "ml-bom.json",
                   ml_bom(version, base, model_dir / "model.safetensors", precision, metrics, cfg["rich_bom"]))
    if docs:
        (model_dir / "README.md").write_text(f"# tsg-guard {version}\n\nTicket guard for the TSG Helpdesk.\n")

    # 4. sign the whole folder
    sign(model_dir, out / "model.sig", key or lab.KEYS / "ci.priv")
    if cfg.get("ship_public_key"):
        (out / "keys").mkdir()
        shutil.copy(lab.KEYS / "ci.pub", out / "keys" / "ci.pub")
    say(f"  signed {len(list(model_dir.iterdir()))} files -> {out.name}/model.sig")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    r = sub.add_parser("release")
    r.add_argument("setup")
    r.add_argument("--version", default="1.1.0")
    r.add_argument("--base", default="models/tsg-guard-base")
    r.add_argument("--quant", default=None)
    r.add_argument("--docs", action="store_true")
    a = ap.parse_args()
    if a.cmd == "build":
        build()
        return
    if not (lab.HERE / a.base).exists():
        build()
    out = release(a.setup, a.version, lab.HERE / a.base, lab.HERE / a.quant if a.quant else None, a.docs)
    sys.exit(0 if out else 1)


if __name__ == "__main__":
    main()
