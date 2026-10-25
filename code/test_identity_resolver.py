"""
Unit and Integration Tests for IdentityResolver.

Validates exact matching, historical audit tracing, collision prevention,
temporal filtering, and coverage across sample deletion requests.
"""

import csv
import unittest
from pathlib import Path

from identity_resolver import IdentityResolver


class TestIdentityResolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver(
            identities_path="dataset/user_identities.csv",
            audit_log_path="dataset/user_audit_log.csv",
        )

    def test_current_email_resolution(self):
        """Current email in user_identities.csv resolves directly."""
        closure = self.resolver.resolve_email("amina.elmasri@gmail.com")
        self.assertIsNotNone(closure)
        self.assertEqual(closure.user_id, "user_01")
        self.assertEqual(closure.name, "Amina El-Masri")
        self.assertEqual(closure.current_phone, "+971 50 482 7316")
        self.assertIn("amina.elmasri@gmail.com", closure.emails)
        self.assertIn("+971 50 482 7316", closure.phones)

    def test_case_and_whitespace_normalization(self):
        """Resolution is resilient to case variations and leading/trailing whitespace."""
        closure = self.resolver.resolve_email("  Amina.ElMasri@Gmail.COM  ")
        self.assertIsNotNone(closure)
        self.assertEqual(closure.user_id, "user_01")

        # Case from deletion_requests case_38
        closure_upper = self.resolver.resolve_email("SIPHO.MOKOENA@GMAIL.COM")
        self.assertIsNotNone(closure_upper)
        self.assertEqual(closure_upper.user_id, "user_36")

    def test_historical_email_resolution(self):
        """Historical email changed in user_audit_log.csv resolves to canonical user_id."""
        # Find a known user who changed email from audit log
        closure = self.resolver.resolve_email("n.petrescu@yahoo.com")
        self.assertIsNotNone(closure)
        self.assertEqual(closure.user_id, "user_10")
        self.assertIn("n.petrescu@yahoo.com", closure.emails)
        self.assertIn("nadia.petrescu@yahoo.com", closure.emails)

    def test_multi_change_history(self):
        """Users with multiple audit changes trace all historical identifiers."""
        closure = self.resolver.resolve_user_id("user_10")
        self.assertIsNotNone(closure)
        self.assertGreaterEqual(len(closure.emails), 2)
        self.assertGreaterEqual(len(closure.email_hashes), 2)
        self.assertTrue(closure.contains_email("n.petrescu@yahoo.com"))
        self.assertTrue(closure.contains_email("nadia.petrescu@yahoo.com"))

    def test_unknown_and_invalid_emails(self):
        """Non-existent emails, empty strings, and None return None cleanly."""
        self.assertIsNone(self.resolver.resolve_email("nonexistent.user.99999@domain.org"))
        self.assertIsNone(self.resolver.resolve_email(""))
        self.assertIsNone(self.resolver.resolve_email(None))

    def test_prevention_of_substring_and_superstring_collisions(self):
        """Similar or overlapping emails must never produce false-positive matches."""
        # Exact email is amina.elmasri@gmail.com
        self.assertIsNone(self.resolver.resolve_email("amina.elmasri@gmail.com.br"))
        self.assertIsNone(self.resolver.resolve_email("fake_amina.elmasri@gmail.com"))
        self.assertIsNone(self.resolver.resolve_email("amina.elmasri@gmail"))
        self.assertIsNone(self.resolver.resolve_email("amina.elmasri"))

    def test_temporal_identifier_filtering(self):
        """identifiers_as_of properly filters identifiers by audit cutoff time."""
        closure = self.resolver.resolve_user_id("user_10")
        self.assertIsNotNone(closure)

        # Before any audit events (e.g. year 2020)
        early_identifiers = closure.identifiers_as_of("2020-01-01T00:00:00Z")
        self.assertIn("user_10", closure.user_id)
        self.assertIn(closure.current_email.lower(), early_identifiers["emails"])

        # After all audit events (e.g. year 2027)
        late_identifiers = closure.identifiers_as_of("2027-01-01T00:00:00Z")
        self.assertEqual(len(late_identifiers["emails"]), len(closure.emails))

    def test_sample_deletion_requests_resolution(self):
        """All 32 requests in sample_deletion_requests.csv resolve to a valid identity."""
        sample_path = Path("dataset/sample_deletion_requests.csv")
        self.assertTrue(sample_path.exists())

        resolved_count = 0
        with open(sample_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = row["email"]
                closure = self.resolver.resolve_email(email)
                self.assertIsNotNone(
                    closure,
                    f"Sample case {row['case_id']} with email '{email}' failed to resolve!"
                )
                self.assertTrue(closure.user_id.startswith("user_"))
                resolved_count += 1

        self.assertEqual(resolved_count, 32)


if __name__ == "__main__":
    unittest.main()
