"""
test_challenge.py: the YOUR TURN extension behind `make challenge`.

Alpha wants a document removed from the knowledge base. Deleting the file isn't enough: its chunks (vectors and
payloads) stay in the store and keep being retrieved, and vectors can be turned back into text (lesson 6.5).
delete_document() in rag_app.py only logs today. These tests FAIL until you implement it.
"""

import logging
import unittest

import rag_app as app
from llm import StandInModel

logging.disable(logging.CRITICAL)
ALICE, BOB = app.LOGIN["alice"], app.LOGIN["bob"]


def chunks_for(store, tenant, source):
    return [c for c in store.all_chunks() if c["tenant"] == tenant and c["source"] == source]


class T6_Challenge_DeleteMeansDelete(unittest.TestCase):
    def setUp(self):
        self.store, _ = app.build("safe")

    def test_17_other_documents_untouched(self):
        """challenge: deleting one document leaves every other document in place"""
        before = len(self.store.all_chunks())
        target = len(chunks_for(self.store, "alpha", "docs/alpha/refund-policy.md"))
        try:
            app.delete_document(self.store, ALICE, "docs/alpha/refund-policy.md")
        except Exception:
            pass
        self.assertGreaterEqual(len(self.store.all_chunks()), before - target)

    def test_18_vectors_really_deleted(self):
        """challenge: every chunk of the deleted document is gone, and the count is returned"""
        n = len(chunks_for(self.store, "alpha", "docs/alpha/refund-policy.md"))
        deleted = app.delete_document(self.store, ALICE, "docs/alpha/refund-policy.md")
        left = len(chunks_for(self.store, "alpha", "docs/alpha/refund-policy.md"))
        self.assertEqual(left, 0, f"{left} of {n} chunks of docs/alpha/refund-policy.md are still in the store")
        self.assertEqual(deleted, n, "delete_document should return how many chunks it deleted")

    def test_19_same_name_other_tenant_survives(self):
        """challenge: Bravo's refund-policy.md is untouched when Alpha deletes its own"""
        n_bravo = len(chunks_for(self.store, "bravo", "docs/bravo/refund-policy.md"))
        app.delete_document(self.store, ALICE, "docs/alpha/refund-policy.md")
        left = len(chunks_for(self.store, "alpha", "docs/alpha/refund-policy.md"))
        self.assertEqual(left, 0, f"{left} chunks of Alpha's refund policy are still in the store")
        self.assertEqual(len(chunks_for(self.store, "bravo", "docs/bravo/refund-policy.md")), n_bravo,
                         "Bravo's refund policy lost chunks")

    def test_20_cannot_delete_other_tenants_document(self):
        """challenge: Alice can't delete Bravo's document (PermissionError), and it stays"""
        with self.assertRaises(PermissionError):
            app.delete_document(self.store, ALICE, "docs/bravo/pricing-2027-confidential.md")
        self.assertTrue(chunks_for(self.store, "bravo", "docs/bravo/pricing-2027-confidential.md"))

    def test_21_deleted_document_no_longer_answers(self):
        """challenge: after deletion, the refund question is refused instead of answered from the old policy"""
        app.delete_document(self.store, ALICE, "docs/alpha/refund-policy.md")
        r = app.answer_safe(self.store, StandInModel(), "How do I get a refund?", ALICE)
        self.assertNotIn("docs/alpha/refund-policy.md", [h["source"] for h in r["hits"]],
                         "the deleted policy is still being retrieved")
        self.assertTrue(r["refused"] or r["blocked"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
