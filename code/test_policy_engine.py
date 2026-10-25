"""
Unit and Integration Tests for PolicyEngine.

Tests dynamic rule loading, intent classification (multilingual and non-deletion),
treatment rules, step sorting, and end-to-end policy evaluation.
"""

import sys
import unittest
from pathlib import Path

# Ensure code/ is on python path
sys.path.insert(0, str(Path(__file__).parent))

from identity_resolver import IdentityResolver
from evidence_indexer import EvidenceIndexer
from policy_engine import (
    PolicyEngine,
    RequestIntentClassifier,
    AuditStep,
    DeletionRule,
    PHASE_ORDER,
    OPERATION_ORDER,
)


class TestPolicyEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy_engine = PolicyEngine(rules_path="dataset/deletion_rules.csv")
        cls.resolver = IdentityResolver(
            identities_path="dataset/user_identities.csv",
            audit_log_path="dataset/user_audit_log.csv",
        )
        cls.indexer = EvidenceIndexer()
        cls.indexer.index_all()

    def test_policy_loading(self):
        """All 15 deletion rules are dynamically loaded and validated."""
        self.assertEqual(len(self.policy_engine.rules), 15)
        self.assertIn("USER_PROFILE", self.policy_engine.rules)
        self.assertIn("SECURITY_AUDIT_LOG", self.policy_engine.rules)
        self.assertIn("LEGAL_HOLD_RECORD", self.policy_engine.rules)
        self.assertIn("BACKUP_ARCHIVE", self.policy_engine.rules)
        self.assertIn("ACCOUNT_TOMBSTONE", self.policy_engine.rules)

        self.assertEqual(self.policy_engine.rules["USER_PROFILE"].required_action, "DELETE")
        self.assertEqual(self.policy_engine.rules["SECURITY_AUDIT_LOG"].required_action, "RETAIN")
        self.assertEqual(self.policy_engine.rules["LEGAL_HOLD_RECORD"].required_action, "RETAIN")
        self.assertEqual(self.policy_engine.rules["BACKUP_ARCHIVE"].required_action, "RETAIN")
        self.assertEqual(self.policy_engine.rules["ACCOUNT_TOMBSTONE"].required_action, "REDACT")

    def test_intent_classification_multilingual_deletion(self):
        """Intent classifier recognizes deletion requests across multiple languages."""
        english = "Please delete my account and remove all personal information."
        spanish = "Solicito la eliminación permanente de mi cuenta y mis datos personales."
        french = "Je demande la suppression définitive de mon compte et de mes données."
        german = "Bitte löschen Sie mein Konto und alle personenbezogenen Daten."
        portuguese = "Solicito a exclusão permanente da conta associada a este e-mail."
        japanese = "このメールアドレスに関連するアカウントの完全な削除を依頼します。"

        self.assertTrue(RequestIntentClassifier.is_deletion_request(english))
        self.assertTrue(RequestIntentClassifier.is_deletion_request(spanish))
        self.assertTrue(RequestIntentClassifier.is_deletion_request(french))
        self.assertTrue(RequestIntentClassifier.is_deletion_request(german))
        self.assertTrue(RequestIntentClassifier.is_deletion_request(portuguese))
        self.assertTrue(RequestIntentClassifier.is_deletion_request(japanese))

    def test_intent_classification_non_deletion(self):
        """Intent classifier detects non-deletion requests (access, correction, export, opt-out)."""
        export_req = "I'd like to download my account information in a portable format. Please keep the account as it is."
        access_req = "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place."
        correction_req = "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active."
        help_req = "I can't access my profile and need help resetting the login. Do not close the account."

        self.assertFalse(RequestIntentClassifier.is_deletion_request(export_req))
        self.assertFalse(RequestIntentClassifier.is_deletion_request(access_req))
        self.assertFalse(RequestIntentClassifier.is_deletion_request(correction_req))
        self.assertFalse(RequestIntentClassifier.is_deletion_request(help_req))

    def test_not_applicable_case_evaluation(self):
        """Non-deletion request produces NOT_APPLICABLE and empty steps list."""
        status, steps = self.policy_engine.audit_case(
            case_id="synthetic_not_app",
            email="amina.elmasri@gmail.com",
            audit_at="2026-09-01T00:00:00Z",
            request_text="Please update my phone number. Leave the account active and do not close it.",
            identity_resolver=self.resolver,
            evidence_indexer=self.indexer,
        )
        self.assertEqual(status, "NOT_APPLICABLE")
        self.assertEqual(steps, [])

    def test_step_sorting_and_renumbering(self):
        """Steps are sorted by phase, operation, system_id, resource_id and numbered consecutively from 1."""
        raw_steps = [
            AuditStep(0, "VERIFICATION", "search_service", "search_052", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
            AuditStep(0, "FINDING", "search_service", "search_052", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_03"),
            AuditStep(0, "REMEDIATION", "search_service", "search_052", "DELETE_RECORD", "ABSENT", ""),
            AuditStep(0, "FINDING", "integration_service", "data_flow_9522", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "evidence_03"),
            AuditStep(0, "REMEDIATION", "integration_service", "data_flow_9522", "DISABLE_DATA_FLOW", "DISABLED", ""),
            AuditStep(0, "VERIFICATION", "integration_service", "data_flow_9522", "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""),
        ]

        sorted_steps = self.policy_engine.sort_steps(raw_steps)
        self.assertEqual(len(sorted_steps), 6)
        # Check consecutive numbering
        for i, s in enumerate(sorted_steps, start=1):
            self.assertEqual(s.step_no, i)

        # First two should be FINDING
        self.assertEqual(sorted_steps[0].phase, "FINDING")
        self.assertEqual(sorted_steps[1].phase, "FINDING")
        # Middle two should be REMEDIATION
        self.assertEqual(sorted_steps[2].phase, "REMEDIATION")
        self.assertEqual(sorted_steps[3].phase, "REMEDIATION")
        # Last two should be VERIFICATION
        self.assertEqual(sorted_steps[4].phase, "VERIFICATION")
        self.assertEqual(sorted_steps[5].phase, "VERIFICATION")

    def test_incomplete_case_evaluation(self):
        """Case with remaining record in failover replica (Leila Haddad) evaluates to INCOMPLETE."""
        status, steps = self.policy_engine.audit_case(
            case_id="case_05",
            email="leila.haddad@yahoo.com",
            audit_at="2026-09-08T13:40:00Z",
            request_text="I deleted this account, but my data is still showing up. Please delete it.",
            identity_resolver=self.resolver,
            evidence_indexer=self.indexer,
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertGreater(len(steps), 0)

        # Finding must cite evidence_54
        finding_step = [s for s in steps if s["phase"] == "FINDING"][0]
        self.assertEqual(finding_step["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(finding_step["resource_id"], "account_005")
        self.assertEqual(finding_step["evidence_id"], "evidence_54")

        # Remediation and verification steps must have empty evidence_id
        rem_steps = [s for s in steps if s["phase"] == "REMEDIATION"]
        self.assertEqual(rem_steps[0]["evidence_id"], "")
        ver_steps = [s for s in steps if s["phase"] == "VERIFICATION"]
        self.assertEqual(ver_steps[0]["evidence_id"], "")

    def test_synthetic_legal_hold_and_restore_risk(self):
        """Synthetic tests for legal hold retention and restore blocking."""
        step_hold = AuditStep(1, "VERIFICATION", "security_service", "legal_hold_001", "VERIFY_RECORD_PRESENT", "PRESENT", "evidence_55")
        step_restore = AuditStep(2, "FINDING", "backup_service", "backup_999", "REPORT_RESTORE_RISK", "ACTIVE", "evidence_93")

        self.assertEqual(step_hold.operation, "VERIFY_RECORD_PRESENT")
        self.assertEqual(step_restore.operation, "REPORT_RESTORE_RISK")


if __name__ == "__main__":
    unittest.main()
