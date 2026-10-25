"""
macie.py: a local stand-in for an Amazon Macie sensitive data discovery job (ONE_TIME) over the lab's buckets.

    python3 macie.py <setup>          # build the setup's buckets, run its job, print a summary and the findings

It reads each object the way Macie does: as Macie's service-linked role, AWSServiceRoleForAmazonMacie. So two things
the lessons care about behave like the real service:
- If the key policy doesn't let that role call kms:Decrypt, the object is not analysed. The discovery result says
  SKIPPED with reason INVALID_ENCRYPTION, the reason code Macie uses when "Macie isn't allowed to use the key", and
  no finding is created. "No findings" then means "not read", not "clean".
- There is no managed identifier for e-mail addresses. A setup must add one as a custom data identifier.

Findings use Macie's field names (type, severity, resourcesAffected.s3Object.key, classificationDetails.result with
status, sensitiveData[].category / detections[].type / count / occurrences.records[].jsonPath, and
customDataIdentifiers.detections[]). The detectors are the lab's own (detect.py), not Macie's.
"""

from __future__ import annotations

import json
import sys
from collections import Counter

import detect
import lab
from kms import AccessDenied
from s3 import LocalS3

TYPE = {"CREDENTIALS": "SensitiveData:S3Object/Credentials", "FINANCIAL_INFORMATION": "SensitiveData:S3Object/Financial",
        "PERSONAL_INFORMATION": "SensitiveData:S3Object/Personal", "CUSTOM_IDENTIFIER": "SensitiveData:S3Object/CustomIdentifier"}


def in_scope(key: str, job: dict) -> bool:
    for term in job.get("excludes", []):
        if term["comparator"] == "STARTS_WITH" and any(key.startswith(v) for v in term["values"]):
            return False
        if term["comparator"] == "CONTAINS" and any(v in key for v in term["values"]):
            return False
    return True


def run_job(s3: LocalS3, setup: dict) -> dict:
    job = setup["macie_job"]
    ids = setup["identifiers"]
    use_managed = job.get("managedDataIdentifierSelector", "RECOMMENDED") != "NONE"
    custom_ids = [c for c in ids.get("custom_data_identifiers", []) if c["name"] in job.get("customDataIdentifiers", [])]
    results, findings = [], []
    for bucket in job["buckets"]:
        for key in s3.list_objects(bucket):
            if not in_scope(key, job):
                # Lab-only marker: Macie itself writes no result for objects the job's scoping excludes.
                results.append({"bucket": bucket, "key": key, "status": {"code": "EXCLUDED_BY_SCOPE", "reason": None}})
                continue
            try:
                body = s3.get_object(bucket, key, lab.MACIE)
            except AccessDenied as exc:
                reason = "INVALID_ENCRYPTION" if "kms:" in str(exc) else "PERMISSION_DENIED"
                results.append({"bucket": bucket, "key": key, "status": {"code": "SKIPPED", "reason": reason}})
                continue
            results.append({"bucket": bucket, "key": key, "status": {"code": "COMPLETE", "reason": None}})
            doc = json.loads(body)
            per_type: dict[str, list[str]] = {}
            category_of: dict[str, str] = {}
            for path, text in detect.walk_strings(doc):
                for m in detect.find(text, use_managed=use_managed, custom_ids=custom_ids):
                    per_type.setdefault(m.type, []).append(path)
                    category_of[m.type] = m.category
            if per_type:
                findings.append(_finding(bucket, key, per_type, category_of, s3.object_info(bucket, key)))
    out = {"jobType": "ONE_TIME", "results": results, "findings": findings}
    (lab.state_dir() / "macie-findings.json").write_text(json.dumps(out, indent=1))
    return out


def _finding(bucket, key, per_type, category_of, info) -> dict:
    cats = sorted({category_of[t] for t in per_type})
    sensitive, custom = [], []
    for cat in cats:
        if cat == "CUSTOM_IDENTIFIER":
            continue
        dets = [{"type": t, "count": len(p), "occurrences": {"records": [{"jsonPath": x, "recordIndex": 0} for x in p[:15]]}}
                for t, p in sorted(per_type.items()) if category_of[t] == cat]
        sensitive.append({"category": cat, "detections": dets, "totalCount": sum(d["count"] for d in dets)})
    for t, p in sorted(per_type.items()):
        if category_of[t] == "CUSTOM_IDENTIFIER":
            custom.append({"name": t, "count": len(p),
                           "occurrences": {"records": [{"jsonPath": x, "recordIndex": 0} for x in p[:15]]}})
    ftype = TYPE[cats[0]] if len(cats) == 1 else "SensitiveData:S3Object/Multiple"
    return {"type": ftype, "severity": {"description": "High" if "CREDENTIALS" in cats else "Medium"},
            "resourcesAffected": {"s3Bucket": {"name": bucket},
                                  "s3Object": {"key": key, "versionId": info["version_id"], "size": info["size"],
                                               "serverSideEncryption": {"encryptionType": "aws:kms",
                                                                        "kmsMasterKeyId": info["sse"]["alias"]}}},
            "classificationDetails": {"result": {"status": {"code": "COMPLETE"}, "mimeType": "application/json",
                                                 "sensitiveData": sensitive,
                                                 "customDataIdentifiers": {"detections": custom,
                                                                           "totalCount": sum(c["count"] for c in custom)}}}}


def summary(out: dict) -> str:
    lines = []
    by_bucket: dict[str, Counter] = {}
    for r in out["results"]:
        c = by_bucket.setdefault(r["bucket"], Counter())
        c[r["status"]["code"] + (f" ({r['status']['reason']})" if r["status"]["reason"] else "")] += 1
    for b, c in by_bucket.items():
        found = sum(1 for f in out["findings"] if f["resourcesAffected"]["s3Bucket"]["name"] == b)
        lines.append(f"{b}: " + ", ".join(f"{n} {k}" for k, n in sorted(c.items())) + f" | findings: {found}")
    types = Counter()
    for f in out["findings"]:
        for sd in f["classificationDetails"]["result"]["sensitiveData"]:
            for d in sd["detections"]:
                types[d["type"]] += d["count"]
        for d in f["classificationDetails"]["result"]["customDataIdentifiers"]["detections"]:
            types[d["name"]] += d["count"]
    if types:
        lines.append("detections: " + ", ".join(f"{t} x{n}" for t, n in sorted(types.items())))
    return "\n".join(lines)


if __name__ == "__main__":
    import pipeline
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 macie.py <first-draft|hardened>")
    env = pipeline.build(sys.argv[1])
    print(summary(env["macie"]))
    for f in env["macie"]["findings"]:
        r = f["resourcesAffected"]
        print(f"  {f['type']:<40} {r['s3Bucket']['name']}/.../{r['s3Object']['key'].rsplit('/', 1)[-1]}")
