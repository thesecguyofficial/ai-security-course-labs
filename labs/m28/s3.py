"""
s3.py: a small local stand-in for Amazon S3 buckets with SSE-KMS, a bucket policy, versioning and lifecycle rules.

Objects are encrypted with a fresh data key from kms.py (AES-256-GCM), bound to the encryption context
{"aws:s3:arn": "arn:aws:s3:::<bucket>/<key>"}, the context S3 uses for SSE-KMS without an S3 Bucket Key. So reading
an object needs BOTH: the bucket policy must allow s3:GetObject, and the key policy must allow kms:Decrypt.

Lifecycle follows the documented behaviour that matters here: in a versioned bucket, Expiration only turns the current
version into a noncurrent one behind a delete marker ("Object expiration applies only to an object's current
version"). The old version stays until a NoncurrentVersionExpiration rule removes it.

Simplified: no IAM identity policies for S3 (the bucket policy is the only S3 permission), no ACLs, one Region.
"""

from __future__ import annotations

import base64
import datetime as dt
import fnmatch
import gzip
import json
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import lab
from kms import AccessDenied, LocalKMS, _aad


class LocalS3:
    def __init__(self, state=None, kms: LocalKMS | None = None):
        self.root = (state or lab.state_dir()) / "s3"
        self.root.mkdir(parents=True, exist_ok=True)
        self.kms = kms or LocalKMS(state)

    # ---- buckets ---------------------------------------------------------------------------------------------------
    def _cfg_path(self, bucket):
        return self.root / bucket / "bucket.json"

    def _index_path(self, bucket):
        return self.root / bucket / "index.json"

    def create_bucket(self, cfg: dict):
        d = self.root / cfg["name"]
        (d / "blobs").mkdir(parents=True, exist_ok=True)
        self._cfg_path(cfg["name"]).write_text(json.dumps(cfg, indent=1))
        if not self._index_path(cfg["name"]).exists():
            self._index_path(cfg["name"]).write_text("{}")

    def config(self, bucket) -> dict:
        return json.loads(self._cfg_path(bucket).read_text())

    def _index(self, bucket) -> dict:
        return json.loads(self._index_path(bucket).read_text())

    def _save_index(self, bucket, idx):
        self._index_path(bucket).write_text(json.dumps(idx, indent=1))

    def buckets(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if (p / "bucket.json").exists())

    # ---- bucket policy ---------------------------------------------------------------------------------------------
    def policy_allows(self, bucket: str, principal: str, action: str, key: str) -> bool:
        arn = f"arn:aws:s3:::{bucket}/{key}"
        verdict = False
        for st in self.config(bucket).get("policy", {}).get("Statement", []):
            acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            if action not in acts and "s3:*" not in acts:
                continue
            res = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
            if not any(fnmatch.fnmatchcase(arn, r) for r in res):
                continue
            p = st.get("Principal", {})
            names = p.get("AWS", []) + [f"service:{s}" for s in p.get("Service", [])]
            if principal not in names:
                continue
            if st["Effect"] == "Deny":
                return False
            verdict = True
        return verdict

    # ---- objects ---------------------------------------------------------------------------------------------------
    def put_object(self, bucket: str, key: str, body: bytes, principal: str, last_modified: dt.datetime | None = None):
        if not self.policy_allows(bucket, principal, "s3:PutObject", key):
            raise AccessDenied(f"{lab.short(principal)} may not s3:PutObject to s3://{bucket}/{key}")
        cfg = self.config(bucket)
        context = {"aws:s3:arn": f"arn:aws:s3:::{bucket}/{key}"}
        data_key, wrapped = self.kms.generate_data_key(cfg["kms_key"], principal, context)
        plain = gzip.compress(body, mtime=0) if key.endswith(".gz") else body
        nonce = os.urandom(12)
        blob_name = uuid.uuid4().hex
        (self.root / bucket / "blobs" / blob_name).write_bytes(AESGCM(data_key).encrypt(nonce, plain, _aad(context)))
        version = {"version_id": uuid.uuid4().hex[:16] if cfg.get("versioning") else "null",
                   "last_modified": lab.iso(last_modified or lab.NOW), "size": len(plain), "blob": blob_name,
                   "nonce": base64.b64encode(nonce).decode(), "sse": wrapped, "delete_marker": False}
        idx = self._index(bucket)
        versions = idx.setdefault(key, [])
        if not cfg.get("versioning"):
            versions.clear()
        versions.append(version)
        self._save_index(bucket, idx)

    def get_object(self, bucket: str, key: str, principal: str, version_id: str | None = None) -> bytes:
        if not self.policy_allows(bucket, principal, "s3:GetObject", key):
            raise AccessDenied(f"{lab.short(principal)} may not s3:GetObject s3://{bucket}/{key}")
        versions = self._index(bucket).get(key, [])
        if version_id:
            versions = [v for v in versions if v["version_id"] == version_id]
        if not versions or versions[-1]["delete_marker"]:
            raise KeyError(f"s3://{bucket}/{key}: NoSuchKey")
        v = versions[-1]
        context = {"aws:s3:arn": f"arn:aws:s3:::{bucket}/{key}"}
        data_key = self.kms.decrypt(v["sse"], principal, context)
        plain = AESGCM(data_key).decrypt(base64.b64decode(v["nonce"]),
                                         (self.root / bucket / "blobs" / v["blob"]).read_bytes(), _aad(context))
        return gzip.decompress(plain) if key.endswith(".gz") else plain

    def list_objects(self, bucket: str, prefix: str = "") -> list[str]:
        """Current, non-deleted keys (what ListObjectsV2 shows)."""
        return sorted(k for k, vs in self._index(bucket).items()
                      if k.startswith(prefix) and vs and not vs[-1]["delete_marker"])

    def list_object_versions(self, bucket: str, prefix: str = "") -> list[tuple[str, dict]]:
        """Every stored version that still holds data, current or noncurrent (what ListObjectVersions shows)."""
        out = []
        for k, vs in sorted(self._index(bucket).items()):
            if k.startswith(prefix):
                out += [(k, v) for v in vs if not v["delete_marker"]]
        return out

    def object_info(self, bucket: str, key: str) -> dict:
        return self._index(bucket)[key][-1]

    def delete_object(self, bucket: str, key: str, principal: str, version_id: str | None = None):
        if not self.policy_allows(bucket, principal, "s3:DeleteObject", key):
            raise AccessDenied(f"{lab.short(principal)} may not s3:DeleteObject s3://{bucket}/{key}")
        idx = self._index(bucket)
        versions = idx.get(key, [])
        if version_id:  # permanent delete of one version
            for v in [v for v in versions if v["version_id"] == version_id]:
                self._drop_blob(bucket, v)
            idx[key] = [v for v in versions if v["version_id"] != version_id]
        elif self.config(bucket).get("versioning"):
            versions.append({"version_id": uuid.uuid4().hex[:16], "last_modified": lab.iso(lab.NOW),
                             "delete_marker": True})
        else:
            for v in versions:
                self._drop_blob(bucket, v)
            idx[key] = []
        self._save_index(bucket, idx)

    def _drop_blob(self, bucket, v):
        if not v.get("delete_marker"):
            p = self.root / bucket / "blobs" / v["blob"]
            if p.exists():
                p.unlink()

    # ---- lifecycle -------------------------------------------------------------------------------------------------
    def apply_lifecycle(self, bucket: str, now: dt.datetime | None = None) -> dict:
        """Run the bucket's lifecycle rules as if S3 had been applying them every day up to `now`."""
        now = now or lab.NOW
        cfg = self.config(bucket)
        idx = self._index(bucket)
        expired = removed = 0
        for key, versions in idx.items():
            for rule in cfg.get("lifecycle", []):
                if rule.get("Status", "Enabled") != "Enabled" or not key.startswith(rule.get("Prefix", "")):
                    continue
                exp = rule.get("Expiration", {}).get("Days")
                nc = rule.get("NoncurrentVersionExpiration", {}).get("NoncurrentDays")
                if exp is None or not versions or versions[-1]["delete_marker"]:
                    continue
                current = versions[-1]
                expires_at = lab.parse_time(current["last_modified"]) + dt.timedelta(days=exp)
                if now < expires_at:
                    continue
                expired += 1
                if cfg.get("versioning"):
                    versions.append({"version_id": uuid.uuid4().hex[:16], "last_modified": lab.iso(expires_at),
                                     "delete_marker": True})
                    if nc is not None and now >= expires_at + dt.timedelta(days=nc):
                        for v in [v for v in versions if not v["delete_marker"]]:
                            self._drop_blob(bucket, v)
                            removed += 1
                        versions[:] = [v for v in versions if v["delete_marker"]]
                else:
                    for v in versions:
                        self._drop_blob(bucket, v)
                        removed += 1
                    versions.clear()
                break
        self._save_index(bucket, idx)
        return {"expired": expired, "removed": removed}
