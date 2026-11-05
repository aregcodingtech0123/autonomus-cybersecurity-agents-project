"""Unit tests for the document store fixtures."""

import unittest

from portal.documents import DOCUMENTS


class DocumentFixtureTests(unittest.TestCase):
    def test_every_document_names_a_tenant(self):
        for document in DOCUMENTS.values():
            self.assertTrue(document["tenant"])

    def test_tenants_are_distinct(self):
        self.assertEqual(len({d["tenant"] for d in DOCUMENTS.values()}), len(DOCUMENTS))
