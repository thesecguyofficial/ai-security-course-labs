"""
sync_check.py: which documents need their permissions re-synced into the index?

Microsoft: permission changes in the source "are only reflected in search results after that metadata is synchronized
to the index", and for ADLS Gen2: "If you change permissions on indexed documents and don't trigger one of the
mechanisms above, the search index continues serving outdated ACL or RBAC data." The mechanisms: touch the blob's
Last-Modified, POST /indexers/{name}/resetdocs with the document keys, or POST /indexers/{name}/resync with
{"options": ["permissions"]} (all preview).

The hardened build sets resync_after_acl_change = true and calls this function after every ACL change event.

CHALLENGE 1 (lesson 13.1): return the IDs of every document whose ACL changed AFTER the last permission sync.
Each doc has "id" and, if its permissions ever changed, "acl_history": [{"at": ISO time, "acl": [...]}, ...].
"""


def stale_documents(docs: list[dict], last_sync: str) -> list[str]:
    return []
