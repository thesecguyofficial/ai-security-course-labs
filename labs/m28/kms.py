"""
kms.py: a tiny local stand-in for AWS KMS (envelope encryption with real AES-256-GCM).

    key = LocalKMS.create(alias, policy)          # 32 random bytes of key material + a key policy
    data_key, wrapped = kms.generate_data_key(alias, principal, context)
    data_key = kms.decrypt(wrapped, principal, context)

What it copies from KMS, because the lesson depends on it:
- A KMS key policy "does not automatically give permission to the account or any of its identities". Only a statement
  whose Principal is the account root (the default "Enable IAM User Permissions" statement) lets IAM policies grant
  access as well.
- The encryption context must match on decrypt. S3 uses {"aws:s3:arn": <object ARN>}, so a data key can't be moved to
  another object.
- Every GenerateDataKey and Decrypt call, allowed or refused, is written to state/cloudtrail.jsonl with the field names
  of a real CloudTrail KMS event (eventSource, eventName, userIdentity.arn, requestParameters.keyId and
  encryptionContext). Lab shortcut: refusals carry errorCode "AccessDenied".

What it simplifies: one Region, no grants, no key rotation, policy conditions limited to StringEquals on
aws:SourceAccount. Key material lives in a JSON file under state/ (a real KMS key never leaves the HSM).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import lab


class AccessDenied(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())


def _aad(context: dict) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode()


class LocalKMS:
    def __init__(self, state=None):
        self.dir = (state or lab.state_dir()) / "kms"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.keys_file = self.dir / "keys.json"
        self.trail = (state or lab.state_dir()) / "cloudtrail.jsonl"
        self.keys = json.loads(self.keys_file.read_text()) if self.keys_file.exists() else {}

    # ---- set-up ----------------------------------------------------------------------------------------------------
    def create(self, alias: str, policy: dict, iam: dict | None = None) -> str:
        # Key IDs are derived from the alias so runs print the same ARNs; the key material is random every time.
        key_id = str(uuid.UUID(bytes=hashlib.sha256(alias.encode()).digest()[:16]))
        self.keys[alias] = {"key_id": key_id, "arn": f"arn:aws:kms:{lab.REGION}:{lab.ACCOUNT}:key/{key_id}",
                            "material": _b64(AESGCM.generate_key(bit_length=256)), "policy": policy,
                            "iam": iam or {}}
        self._save()
        return key_id

    def _save(self):
        self.keys_file.write_text(json.dumps(self.keys, indent=1))

    def arn(self, alias: str) -> str:
        return self.keys[alias]["arn"]

    # ---- policy evaluation -----------------------------------------------------------------------------------------
    def allowed(self, alias: str, principal: str, action: str, request: dict | None = None) -> bool:
        key = self.keys[alias]
        verdict = False
        for st in key["policy"].get("Statement", []):
            if not _matches(st, principal, action, request or {}):
                continue
            if st["Effect"] == "Deny":
                return False
            if _is_root(st):
                # IAM delegation: the key policy lets IAM policies in the account grant this action.
                verdict = verdict or _iam_allows(key["iam"].get(principal, []), action, alias, key["arn"])
            else:
                verdict = True
        return verdict

    def _log(self, name: str, alias: str, principal: str, context: dict, error: str | None):
        event = {
            "eventVersion": "1.11",
            "userIdentity": {"type": "AWSService" if principal.startswith("service:") else "AssumedRole",
                             "arn": principal if not principal.startswith("service:") else None,
                             "invokedBy": principal.split(":", 1)[1] if principal.startswith("service:") else None},
            "eventTime": lab.iso(lab.NOW),
            "eventSource": "kms.amazonaws.com",
            "eventName": name,
            "awsRegion": lab.REGION,
            "requestParameters": {"keyId": self.keys[alias]["arn"], "encryptionContext": context,
                                  **({"encryptionAlgorithm": "SYMMETRIC_DEFAULT"} if name == "Decrypt" else
                                     {"keySpec": "AES_256"})},
            "resources": [{"accountId": lab.ACCOUNT, "type": "AWS::KMS::Key", "ARN": self.keys[alias]["arn"]}],
            "readOnly": name == "Decrypt",
            "eventCategory": "Management",
        }
        if error:
            event["errorCode"] = error
        with self.trail.open("a") as f:
            f.write(json.dumps(event) + "\n")

    # ---- operations ------------------------------------------------------------------------------------------------
    def generate_data_key(self, alias: str, principal: str, context: dict) -> tuple[bytes, dict]:
        request = {"aws:SourceAccount": lab.ACCOUNT}
        if not self.allowed(alias, principal, "kms:GenerateDataKey", request):
            self._log("GenerateDataKey", alias, principal, context, "AccessDenied")
            raise AccessDenied(f"{lab.short(principal)} may not use {alias} for kms:GenerateDataKey")
        self._log("GenerateDataKey", alias, principal, context, None)
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        wrapped = AESGCM(_unb64(self.keys[alias]["material"])).encrypt(nonce, data_key, _aad(context))
        return data_key, {"alias": alias, "nonce": _b64(nonce), "blob": _b64(wrapped)}

    def decrypt(self, wrapped: dict, principal: str, context: dict) -> bytes:
        alias = wrapped["alias"]
        if alias not in self.keys:
            raise AccessDenied(f"key {alias} no longer exists: the data under it is unrecoverable")
        if not self.allowed(alias, principal, "kms:Decrypt", {"aws:SourceAccount": lab.ACCOUNT}):
            self._log("Decrypt", alias, principal, context, "AccessDenied")
            raise AccessDenied(f"{lab.short(principal)} may not use {alias} for kms:Decrypt")
        self._log("Decrypt", alias, principal, context, None)
        try:
            return AESGCM(_unb64(self.keys[alias]["material"])).decrypt(
                _unb64(wrapped["nonce"]), _unb64(wrapped["blob"]), _aad(context))
        except Exception as exc:  # wrong encryption context or tampered blob
            raise AccessDenied(f"decrypt failed (encryption context or ciphertext does not match): {exc!r}")

    def schedule_deletion(self, alias: str):
        """Lab shortcut: deletes at once. Real KMS makes you wait 7 to 30 days (default 30)."""
        self.keys.pop(alias, None)
        self._save()


def _is_root(st: dict) -> bool:
    aws = st.get("Principal", {}).get("AWS", [])
    aws = [aws] if isinstance(aws, str) else aws
    return lab.ROOT in aws


def _matches(st: dict, principal: str, action: str, request: dict) -> bool:
    actions = st.get("Action", [])
    actions = [actions] if isinstance(actions, str) else actions
    if not any(a == action or a == "kms:*" for a in actions):
        return False
    p = st.get("Principal", {})
    aws = p.get("AWS", [])
    aws = [aws] if isinstance(aws, str) else aws
    service = p.get("Service", [])
    service = [service] if isinstance(service, str) else service
    if principal.startswith("service:"):
        ok = principal.split(":", 1)[1] in service
    else:
        ok = principal in aws or lab.ROOT in aws
    if not ok:
        return False
    for key, want in st.get("Condition", {}).get("StringEquals", {}).items():
        if request.get(key) != want:
            return False
    return True


def _iam_allows(statements: list, action: str, alias: str, arn: str) -> bool:
    for st in statements:
        acts = st.get("Action", [])
        acts = [acts] if isinstance(acts, str) else acts
        res = st.get("Resource", [])
        res = [res] if isinstance(res, str) else res
        if (action in acts or "kms:*" in acts) and ("*" in res or arn in res or alias in res):
            return True
    return False
