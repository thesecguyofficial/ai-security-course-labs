"""
forget.py: handle one erasure request for a customer across the invocation-log buckets (CHALLENGE 2, lesson 28.3).

    python3 forget.py TSG-CUST-104233      # after: python3 pipeline.py hardened

Write forget(s3, customer_id) so that, when it returns, NO stored object version in either bucket (current or
noncurrent, records and large bodies) still contains that customer's e-mail address, name, phone number or customer
ID, in any letter case, nor the redactor's tokens for them. Every other customer's records must stay.

Rules:
- Work as the erasure role, lab.ERASURE. The hardened setup lets it read and delete in both buckets.
- Raw bucket: you'll have to decrypt to find the records. Redacted bucket: the values are tokens now; compute the
  tokens with redact.token(kind, value) and search for those instead.
- In a versioned bucket a plain delete only adds a delete marker. Delete every version by its version ID
  (s3.list_object_versions, then s3.delete_object(..., version_id=...)).
- Return a report: {"raw_deleted": <versions removed>, "redacted_deleted": <versions removed>}.
No solution is included in this repo.
"""

from __future__ import annotations

import json
import sys

import lab
from s3 import LocalS3


def forget(s3: LocalS3, customer_id: str) -> dict:
    raise NotImplementedError("challenge 2: write forget() (see the docstring)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 forget.py <customer id>   (run python3 pipeline.py hardened first)")
    print(json.dumps(forget(LocalS3(), sys.argv[1]), indent=2))
