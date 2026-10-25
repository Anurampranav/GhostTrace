"""
Unit and Integration Tests for EvidenceIndexer.

Tests manifest loading, SQL extraction, JSON extraction, log parsing,
PDF extraction, OCR handling, temporal filtering, and integration with IdentityResolver.
"""

import sys
import unittest
from pathlib import Path

# Ensure code/ is on python path
sys.path.insert(0, str(Path(__file__).parent))

from evidence_indexer import EvidenceIndexer, ManifestEntry, EvidenceFinding
from identity_resolver import IdentityResolver


class TestEvidenceIndexer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.indexer = EvidenceIndexer()
        cls.indexer.index_all()
        cls.resolver = IdentityResolver()

    def test_manifest_loading(self):
        """Manifest loads all 94 declared evidence entries with zero missing files."""
        self.assertEqual(len(self.indexer.manifest_entries), 94)
        self.assertEqual(len(self.indexer.missing_files), 0)

    def test_evidence_path_resolution(self):
        """Every entry resolves to an existing file on disk."""
        for entry in self.indexer.manifest_entries:
            self.assertTrue(entry.resolved_path.exists(), f"Path not found: {entry.resolved_path}")

    def test_sql_record_extraction(self):
        """SQL snapshots parse into structured EvidenceFinding rows."""
        sql_findings = self.indexer.by_format.get("sql", [])
        self.assertGreater(len(sql_findings), 500)

        # Inspect evidence_54 (customer_accounts_failover_replica_20260902.sql)
        ev54_findings = self.indexer.by_evidence_id.get("evidence_54", [])
        self.assertGreater(len(ev54_findings), 0)
        
        # Check Leila Haddad (user_05, account_005) present in failover replica
        user05_findings = [f for f in ev54_findings if "user_05" in f.identifiers]
        self.assertGreater(len(user05_findings), 0)
        f05 = user05_findings[0]
        self.assertEqual(f05.provenance_type, "stored_record")
        self.assertIn("leila.haddad@yahoo.com", f05.identifiers)
        self.assertEqual(f05.resource_id, "account_005")

    def test_json_record_extraction(self):
        """JSON records parse correctly with metadata and identifiers."""
        json_findings = self.indexer.by_format.get("json", [])
        self.assertGreater(len(json_findings), 10)
        for f in json_findings:
            self.assertEqual(f.file_format, "json")
            self.assertTrue(f.evidence_id.startswith("evidence_"))

    def test_log_line_provenance(self):
        """Log entries retain line numbers, file origin, and timestamps."""
        log_findings = self.indexer.by_format.get("log", [])
        self.assertGreater(len(log_findings), 50)
        for f in log_findings[:5]:
            self.assertEqual(f.file_format, "log")
            self.assertIsNotNone(f.line_or_page)
            self.assertGreater(f.line_or_page, 0)

    def test_pdf_page_provenance(self):
        """PDF documents extract page text and retain 1-indexed page numbers."""
        pdf_findings = self.indexer.by_format.get("pdf", [])
        self.assertGreater(len(pdf_findings), 0)
        for f in pdf_findings:
            self.assertEqual(f.file_format, "pdf")
            self.assertGreaterEqual(f.line_or_page, 1)
            self.assertIsInstance(f.data, str)
            self.assertGreater(len(f.data), 0)

    def test_exact_identifier_matching(self):
        """Exact identifier queries match expected findings without false-positive leakage."""
        # Query for user_05
        findings = self.indexer.find_by_identifier("user_05")
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn("user_05", f.identifiers)

        # Nonexistent user
        none_findings = self.indexer.find_by_identifier("user_999999_nonexistent")
        self.assertEqual(len(none_findings), 0)

    def test_temporal_filtering(self):
        """Temporal filtering respects audit_at cutoff."""
        # Query before 2026-01-01 should filter out 2026 evidence captures
        early_findings = self.indexer.find_by_identifier("user_05", audit_at="2025-01-01T00:00:00Z")
        late_findings = self.indexer.find_by_identifier("user_05", audit_at="2026-10-01T00:00:00Z")
        self.assertLess(len(early_findings), len(late_findings))

    def test_integration_with_identity_resolver(self):
        """Integration with IdentityResolver retrieves all relevant findings for a user."""
        closure = self.resolver.resolve_email("leila.haddad@yahoo.com")
        self.assertIsNotNone(closure)
        self.assertEqual(closure.user_id, "user_05")

        matched = self.indexer.find_for_identity_closure(closure)
        self.assertGreater(len(matched), 0)

        # Verify evidence_54 is included for Leila Haddad
        ev_ids = {m.evidence_id for m in matched}
        self.assertIn("evidence_54", ev_ids)

    def test_extraction_report_completeness(self):
        """Extraction audit report verifies completeness across all 94 files."""
        report = self.indexer.get_extraction_report()
        self.assertEqual(report["manifest_entries_total"], 94)
        self.assertEqual(report["manifest_entries_processed"], 94)
        self.assertEqual(report["missing_files_count"], 0)
        self.assertEqual(report["parsing_errors_count"], 0)
        self.assertGreater(report["total_extracted_findings"], 1000)
        self.assertEqual(report["findings_with_provenance"], report["total_extracted_findings"])


if __name__ == "__main__":
    unittest.main()
