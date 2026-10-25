"""
deploy.py: the deploy gate in front of SageMaker AI (lesson 25.5 and the lab, 25.6). Verify, then register.

    python3 deploy.py hardened release/1.1.0-hardened
    python3 deploy.py first-draft release/1.1.0-first-draft
    python3 deploy.py hardened release/1.1.0-hardened --emit state/create-model-package.json

It runs on the deploy side, after the files came back from storage. It checks, in this order:
    1. a signature exists                         (require_signature)
    2. it verifies with the key WE trust          (trusted_key; model_signing, strict about extra files)
    3. only allowed file types are present        (allowed_files)
    4. the ML-BOM matches the signed weights      (check_bom)
    5. the eval report says the shipped file passed  (check_eval)
    6. the weights are not on the revoked list    (check_revoked, data/revoked.json)
    7. the base model is one we approved          (check_lineage: challenge 2)
Then it registers a model package version in the registry twin (state/registry.json), with the evidence in
CustomerMetadataProperties, and writes one line to state/deploy-log.jsonl.

The registry twin is not AWS. It stores the same fields SageMaker AI's CreateModelPackage takes, so --emit writes
a request body you can send with `aws sagemaker create-model-package --cli-input-json` (GUIDED-BUILD.md).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

import lab

M15_IMAGE = "763104351884.dkr.ecr.us-east-1.amazonaws.com/djl-inference:0.38.0-lmi30.0.0-cu130"


class Refused(Exception):
    pass


def verify_signature(model_dir: pathlib.Path, sig: pathlib.Path, public_key: pathlib.Path,
                     ignore_unsigned: bool) -> dict:
    """model_signing does the work: the signature must be valid for this key AND every file hash must match.
    Returns the signed manifest {file name: sha256} read from the bundle's in-toto statement."""
    import base64

    import model_signing
    (model_signing.verifying.Config()
        .use_elliptic_key_verifier(public_key=public_key)
        .set_ignore_unsigned_files(ignore_unsigned)
        .verify(model_dir, sig))
    statement = json.loads(base64.b64decode(json.loads(sig.read_text())["dsseEnvelope"]["payload"]))
    return {r["name"]: r["digest"] for r in statement["predicate"]["resources"]}


def short_reason(text: str) -> str:
    """model_signing's message, without the raw digest bytes: 'Signature mismatch: Hash mismatch for 'x''."""
    msg = re.sub(r": Expected.*", "", text.splitlines()[0]).replace("\\'", "'")
    return re.sub(r"\[[\"']|[\"']\]$", "", msg)


def check_lineage(bom: dict, approved_bases: list[dict]) -> list[str]:
    """CHALLENGE 2 (lessons 25.3 to 25.5): refuse a model whose base nobody approved.

    The ML-BOM's model component lists the model it was quantized from in pedigree.ancestors, with a SHA-256.
    data/approved-bases.json lists the base models the security team reviewed. A fine-tune swapped in from a public
    hub can pass every eval you have (data/unapproved-base.json does) and still carry a backdoor; provenance is the
    control that doesn't depend on finding the trigger.

    Return a problem string when the component has no pedigree ancestor, or when an ancestor's SHA-256 is not in
    approved_bases. Until you write it, this check passes everything.
    """
    return []


def gate(setup: str, release_dir: pathlib.Path, say=print) -> dict:
    """Run every check the setup asks for. Returns the evidence; raises Refused (fail closed) or logs and carries
    on (fail open), depending on on_verify_error."""
    cfg = lab.setup_config(setup, "deploy")
    model_dir, sig = release_dir / "model", release_dir / "model.sig"
    evidence = {"verify": "skipped", "warnings": []}

    def problem(msg: str) -> None:
        if cfg["on_verify_error"] == "refuse":
            raise Refused(msg)
        evidence["warnings"].append(msg)
        say(f"  WARNING: {msg} (continuing)")

    if not model_dir.is_dir():
        raise Refused("no model/ folder in the release")

    # 1-2. signature
    key = release_dir / "keys" / "ci.pub" if cfg["trusted_key"] == "release" else lab.HERE / cfg["trusted_key"]
    evidence["signer_key_sha256"] = lab.sha256_file(key) if key.exists() else None
    manifest = None
    if not sig.exists():
        if cfg["require_signature"]:
            raise Refused("no model.sig: unsigned releases are not deployed")
        problem("no model.sig")
    elif not key.exists():
        problem(f"trusted key {key.relative_to(lab.HERE)} not found")
    else:
        try:
            manifest = verify_signature(model_dir, sig, key, cfg["ignore_unsigned_files"])
            evidence["verify"] = "verified"
            evidence["signature_sha256"] = lab.sha256_file(sig)
        except Exception as e:                            # noqa: BLE001: any failure is a failure
            evidence["verify"] = "failed"
            msg = short_reason(str(e))
            problem(f"signature check failed: {msg[:160]}")

    # 3. file types
    present = sorted(p.name for p in model_dir.rglob("*") if p.is_file())
    if cfg["allowed_files"] is not None:
        extra = [n for n in present if n not in cfg["allowed_files"]]
        if extra:
            raise Refused(f"files not on the allow-list: {', '.join(extra)}")

    # 4. ML-BOM
    bom = lab.read_json(model_dir / "ml-bom.json") if (model_dir / "ml-bom.json").exists() else None
    weights_sha = lab.sha256_file(model_dir / "model.safetensors")
    if cfg["check_bom"]:
        if bom is None:
            raise Refused("no ml-bom.json")
        model = [c for c in bom.get("components", []) if c.get("type") == "machine-learning-model"]
        hashes = {h["content"] for c in model for h in c.get("hashes", []) if h.get("alg") == "SHA-256"}
        if weights_sha not in hashes:
            raise Refused("the ML-BOM does not list the SHA-256 of model.safetensors")
        if manifest is None or manifest.get("ml-bom.json") is None:
            raise Refused("the ML-BOM is not covered by the signature")

    # 5. eval report
    if cfg["check_eval"]:
        report = lab.read_json(model_dir / "eval-report.json") if (model_dir / "eval-report.json").exists() else {}
        if not report.get("passed"):
            raise Refused("no passing eval report")
        if report.get("shipped_sha256") != weights_sha:
            raise Refused("the eval report is for different weights")
        if "agreement" not in report.get("metrics", {}):
            raise Refused("the eval report never evaluated the shipped (quantized) file")

    # 6. revoked releases
    if cfg["check_revoked"]:
        revoked = {r["sha256"]: r for r in lab.read_json(lab.DATA / "revoked.json")["revoked"]}
        if weights_sha in revoked:
            r = revoked[weights_sha]
            raise Refused(f"revoked: release {r['version']} ({r['reason']})")

    # 7. lineage (challenge 2)
    if cfg["check_lineage"]:
        approved = lab.read_json(lab.DATA / "approved-bases.json")["approved"]
        lineage_problems = check_lineage(bom or {}, approved)
        if lineage_problems:
            raise Refused("; ".join(lineage_problems))

    evidence.update(weights_sha256=weights_sha, files=present,
                    version=(bom or {}).get("components", [{}])[0].get("version", "?"))
    return evidence


def model_package_request(release_dir: pathlib.Path, evidence: dict) -> dict:
    """The CreateModelPackage body (SageMaker AI API field names). Status starts at PendingManualApproval."""
    props = {"signature-verify": evidence["verify"],
             "weights-sha256": evidence["weights_sha256"],
             "signer-key-sha256": evidence.get("signer_key_sha256") or "none"}
    if evidence.get("signature_sha256"):
        props["signature-sha256"] = evidence["signature_sha256"]
    return {
        "ModelPackageGroupName": "tsg-guard-lab",
        "ModelPackageDescription": f"tsg-guard {evidence['version']}: passed the M25 deploy gate",
        "InferenceSpecification": {
            "Containers": [{
                "Image": M15_IMAGE,
                "ModelDataSource": {"S3DataSource": {"S3Uri": "s3://${BUCKET}/tsg-guard/" + release_dir.name +
                                                      "/model/", "S3DataType": "S3Prefix",
                                                      "CompressionType": "None"}},
            }],
            "SupportedContentTypes": ["application/json"],
            "SupportedResponseMIMETypes": ["application/json"],
        },
        "ModelApprovalStatus": "PendingManualApproval",
        "CustomerMetadataProperties": props,
    }


def register(request: dict, evidence: dict) -> str:
    """Registry twin: one 'model package version' per distinct weights hash; approved after the gate passed."""
    path = lab.STATE / "registry.json"
    reg = lab.read_json(path) if path.exists() else {"tsg-guard-lab": []}
    versions = reg["tsg-guard-lab"]
    for v in versions:
        if v["CustomerMetadataProperties"]["weights-sha256"] == evidence["weights_sha256"]:
            return f"already registered as version {v['ModelPackageVersion']} ({v['ModelApprovalStatus']})"
    entry = {"ModelPackageVersion": len(versions) + 1, **request, "ModelApprovalStatus": "Approved"}
    versions.append(entry)
    lab.write_json(path, reg)
    return f"registered as version {entry['ModelPackageVersion']}, ModelApprovalStatus Approved"


def deploy(setup: str, release_dir: pathlib.Path, emit: pathlib.Path | None = None, quiet: bool = False) -> bool:
    say = (lambda *a: None) if quiet else print
    say(f"DEPLOY [{setup}] {release_dir.name}")
    row = {"time": lab.CLOCK, "setup": setup, "release": release_dir.name}
    try:
        evidence = gate(setup, release_dir, say)
    except Refused as e:
        say(f"  REFUSED: {e}")
        lab.append_jsonl(lab.STATE / "deploy-log.jsonl", {**row, "decision": "refused", "reason": str(e)})
        return False
    request = model_package_request(release_dir, evidence)
    if emit:
        lab.write_json(emit, request)
    result = register(request, evidence)
    say(f"  signature: {evidence['verify']}" + (f" ({len(evidence['warnings'])} warning(s))"
                                                if evidence["warnings"] else ""))
    say(f"  DEPLOYED: {result}")
    lab.append_jsonl(lab.STATE / "deploy-log.jsonl",
                     {**row, "decision": "deployed", "verify": evidence["verify"],
                      "signer_key_sha256": evidence.get("signer_key_sha256"),
                      "weights_sha256": evidence["weights_sha256"], "warnings": evidence["warnings"]})
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("setup")
    ap.add_argument("release")
    ap.add_argument("--emit", default=None, help="write the CreateModelPackage request body here")
    a = ap.parse_args()
    ok = deploy(a.setup, lab.HERE / a.release, lab.HERE / a.emit if a.emit else None)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
