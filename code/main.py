"""
End-to-End Audit Engine for HackerRank Orchestrate: Ghost Data Still Exists.

Processes every case in deletion_requests.csv, resolves identities, indexes
evidence, maps resources to users, applies deletion policies, and produces
output.csv with deterministic, schema-compliant audit steps.
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure code/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from identity_resolver import IdentityResolver, IdentityClosure
from evidence_indexer import EvidenceIndexer, EvidenceFinding
from policy_engine import (
    PolicyEngine, AuditStep, PHASE_ORDER, OPERATION_ORDER,
    RequestIntentClassifier,
)


# ---------------------------------------------------------------------------
# Phase / operation constants (mirrored from policy_engine for convenience)
# ---------------------------------------------------------------------------
_PHASE = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
_OP = OPERATION_ORDER

_SYSTEM_DATA_CATEGORY = {
    "account_service":       "USER_PROFILE",
    "search_service":        "SEARCH_INDEX_ENTRY",
    "analytics_platform":    "ANALYTICS_PROFILE",
    "support_platform":      "SUPPORT_MESSAGE",
    "integration_service":   "DATA_FLOW",
    "backup_service":        "BACKUP_ARCHIVE",
    "export_service":        "USER_EXPORT",
    "security_service":      "SECURITY_AUDIT_LOG",
    "identity_service":      "ACCOUNT_TOMBSTONE",
    "marketing_platform":    "MARKETING_PROFILE",
    "notification_service":  "EMAIL_DELIVERY_LOG",
}


# ---------------------------------------------------------------------------
# Enhanced intent classifier
# ---------------------------------------------------------------------------
class EnhancedIntentClassifier:
    """
    Classifies whether a request_text is a deletion / erasure request.
    Much more permissive than the original: considers any mention of
    deletion, closure, erasure, or audit-of-deletion as a valid request.
    """

    NON_DELETION_PHRASES = [
        # Explicit instructions to keep account or records
        "leave the account active",
        "leave the account as it is",
        "keep the account as it is",
        "keep the account active",
        "do not close the account",
        "don't close the account",
        "without removing any of my records",
        "leave my profile and purchase history in place",
        "want to continue using the service",
        "i want to keep using",
        # Access / invoices / help
        "download my account information",
        "can't access my profile",
        "copy of last year's invoices",
        "copy of last year\u2019s invoices",
        # Profile updates / corrections without deletion
        "surname is misspelled",
        "mobile number on my profile is out of date",
        "replace it with the new one and leave the account",
        # Multilingual non-deletion equivalents
        "no cerrar la cuenta",
        "mantener la cuenta activa",
        "ne fermez pas le compte",
        "laisser le compte actif",
        "das konto aktiv lassen",
        "nicht das konto schlie\u00dfen",
    ]

    DELETION_INDICATORS = [
        # English
        "delet", "remov", "eras", "clos", "gone", "purge",
        "wipe", "right to be forgotten", "gdpr", "forget me",
        "destroy", "terminate my account", "cancel my account",
        "get rid of", "take down", "shut down my account",
        "confirm that the profile is gone",
        "confirm.*gone", "verify.*deleted", "check.*deleted",
        "audit", "ensure.*removed",
        # French
        "supprimer", "suppression", "effacer",
        "cl\u00f4turer", "fermer mon compte",
        # Spanish
        "eliminar", "eliminaci\u00f3n", "borrar", "cerrar mi cuenta",
        # Portuguese
        "excluir", "exclus\u00e3o", "apagar",
        # German
        "l\u00f6schen", "l\u00f6schung", "konto schlie\u00dfen",
        # Italian
        "cancellare", "cancellazione", "eliminare",
        # Korean / Japanese / Chinese
        "\uc0ad\uc81c", "\u524a\u9664", "\u5220\u9664",
    ]

    @classmethod
    def is_deletion_request(cls, request_text: str) -> bool:
        if not request_text:
            return False
        text_lower = request_text.lower().strip()

        # First check for explicit non-deletion phrases
        for phrase in cls.NON_DELETION_PHRASES:
            if phrase in text_lower:
                return False

        # Check for change-email-but-continue-using patterns
        if ("change the email" in text_lower or "update" in text_lower) and \
           "continue" in text_lower and "delet" not in text_lower:
            return False

        # Check for any deletion indicator
        for ind in cls.DELETION_INDICATORS:
            if ind in text_lower:
                return True

        return False


# ---------------------------------------------------------------------------
# System Activity Index
# ---------------------------------------------------------------------------
class SystemActivityIndex:
    """Indexes system_activity.csv for resource-to-user mapping."""

    def __init__(self, path: str | Path = "dataset/system_activity.csv"):
        self.path = Path(path)
        self.by_resource: Dict[str, List[Dict]] = defaultdict(list)
        self.link_records: List[Dict] = []
        self._load()

    def _load(self):
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                self.by_resource[row["resource_id"]].append(row)
                if row["event_type"] == "LINK_RESOURCE_IDENTITY":
                    self.link_records.append(row)

    def get_resource_activities(self, resource_id: str) -> List[Dict]:
        return self.by_resource.get(resource_id, [])

    def get_link_for_resource(self, resource_id: str) -> Optional[Dict]:
        for lr in self.link_records:
            if lr["resource_id"] == resource_id:
                return lr
        return None

    def get_link_user_for_resource(self, resource_id: str) -> Optional[str]:
        lr = self.get_link_for_resource(resource_id)
        if lr:
            m = re.search(r"(user_\d+)", lr["details"])
            if m:
                return m.group(1)
        return None


# ---------------------------------------------------------------------------
# Resource Map Builder
# ---------------------------------------------------------------------------
class ResourceMapBuilder:
    """
    Builds a comprehensive map of resource_id -> user_id using all
    available evidence sources, system_activity LINK_RESOURCE_IDENTITY,
    and naming conventions.
    """

    def __init__(
        self,
        resolver: IdentityResolver,
        indexer: EvidenceIndexer,
        activity_index: SystemActivityIndex,
    ):
        self.resolver = resolver
        self.activity = activity_index
        self.indexer = indexer
        # resource_id -> {user_id, system_id, evidence_id, state_info}
        self.resource_to_user: Dict[str, Dict[str, Any]] = {}
        self._build()

    def _build(self):
        # 1. LINK_RESOURCE_IDENTITY from system_activity
        for lr in self.activity.link_records:
            rid = lr["resource_id"]
            m = re.search(r"(user_\d+)", lr["details"])
            em = re.search(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", lr["details"])
            uid = m.group(1) if m else None
            if not uid and em:
                c = self.resolver.resolve_email(em.group(1))
                if c:
                    uid = c.user_id
            if uid:
                self.resource_to_user[rid] = {"user_id": uid, "source": "link"}

        # 2. Evidence-based: scan indexer findings for resource-to-user links
        for finding in self.indexer.findings:
            if not finding.resource_id:
                continue
            rid = finding.resource_id
            if rid in self.resource_to_user:
                continue

            # Check if finding.data contains a user reference
            uid = self._extract_user_from_finding(finding)
            if uid:
                self.resource_to_user[rid] = {"user_id": uid, "source": "evidence", "evidence_id": finding.evidence_id}

        # 3. Activity-based batch propagation for deletion worker executions
        worker_acts = [a for acts in self.activity.by_resource.values() for a in acts if a.get("source_system") == "deletion_worker"]
        worker_acts.sort(key=lambda x: x.get("event_time", ""))

        runs = []
        cur_run = []
        last_t = None
        for a in worker_acts:
            try:
                t = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
                if last_t is None or (t - last_t) <= timedelta(minutes=60):
                    cur_run.append(a)
                else:
                    if cur_run:
                        runs.append(cur_run)
                    cur_run = [a]
                last_t = t
            except Exception:
                pass
        if cur_run:
            runs.append(cur_run)

        for run in runs:
            uids = {self.resource_to_user[a["resource_id"]]["user_id"] for a in run if a.get("resource_id") in self.resource_to_user}
            if len(uids) == 1:
                uid = list(uids)[0]
                for a in run:
                    rid = a.get("resource_id")
                    if rid and rid not in self.resource_to_user:
                        self.resource_to_user[rid] = {"user_id": uid, "source": "activity_run"}

    def _extract_user_from_finding(self, f: EvidenceFinding) -> Optional[str]:
        """Try to extract a user_id from a finding's data."""
        data = f.data
        if isinstance(data, dict):
            # Direct user reference
            for key in ("user_id", "customer_reference", "subject_reference"):
                v = data.get(key)
                if v and isinstance(v, str) and v.startswith("user_"):
                    return v

            # Email-based resolution
            for key in ("email", "customer_email", "owner_email", "requester_email", "query"):
                v = data.get(key)
                if v and isinstance(v, str) and "@" in v:
                    c = self.resolver.resolve_email(v)
                    if c:
                        return c.user_id

            # Check nested profile
            profile = data.get("profile")
            if isinstance(profile, dict):
                for key in ("customer_reference", "email"):
                    v = profile.get(key)
                    if v and isinstance(v, str):
                        if v.startswith("user_"):
                            return v
                        if "@" in v:
                            c = self.resolver.resolve_email(v)
                            if c:
                                return c.user_id

            # Check nested hits
            hits = data.get("hits")
            if isinstance(hits, dict):
                for doc in hits.get("documents", []):
                    for key in ("email", "customer_reference"):
                        v = doc.get(key)
                        if v and isinstance(v, str):
                            if v.startswith("user_"):
                                return v
                            if "@" in v:
                                c = self.resolver.resolve_email(v)
                                if c:
                                    return c.user_id

        elif isinstance(data, str):
            # Log lines
            for ident in f.identifiers:
                if ident.startswith("user_"):
                    return ident
                if "@" in ident:
                    c = self.resolver.resolve_email(ident)
                    if c:
                        return c.user_id
        return None

    def get_user_for_resource(self, resource_id: str) -> Optional[str]:
        entry = self.resource_to_user.get(resource_id)
        return entry["user_id"] if entry else None


# ---------------------------------------------------------------------------
# Service Resource Export Parser (service export JSON and similar)
# ---------------------------------------------------------------------------
def parse_service_resource_export(
    data: Dict,
    evidence_id: str,
    closure: IdentityClosure,
    resolver: IdentityResolver,
    resource_map: ResourceMapBuilder,
    activity_index: SystemActivityIndex,
) -> List[AuditStep]:
    """
    Parse a service_resource_export JSON and produce audit steps for the user.
    Returns list of AuditStep for this user from this evidence.
    """
    exports = data.get("service_exports", {})
    if not exports:
        return []

    steps: List[AuditStep] = []
    is_incomplete = False
    all_emails = closure.emails
    uid = closure.user_id

    def user_matches(item: Dict) -> bool:
        """Check if item belongs to this user."""
        cr = item.get("customer_reference") or item.get("subject_reference")
        if cr == uid:
            return True
        for ek in ("email", "customer_email", "owner_email", "requester_email", "query"):
            v = item.get(ek)
            if v and isinstance(v, str) and v.strip().lower() in all_emails:
                return True
        # Check profile sub-object
        profile = item.get("profile")
        if isinstance(profile, dict):
            cr2 = profile.get("customer_reference")
            if cr2 == uid:
                return True
            pe = profile.get("email")
            if pe and isinstance(pe, str) and pe.strip().lower() in all_emails:
                return True
        # Check hits sub-object
        hits = item.get("hits")
        if isinstance(hits, dict):
            for doc in hits.get("documents", []):
                de = doc.get("email")
                if de and isinstance(de, str) and de.strip().lower() in all_emails:
                    return True
        # Check resource_map
        rid = item.get("resource_id")
        if rid and resource_map.get_user_for_resource(rid) == uid:
            return True
        # Check activity LINK
        if rid and activity_index.get_link_user_for_resource(rid) == uid:
            return True
        return False

    # account_service.profile_lookups
    for item in exports.get("account_service", {}).get("profile_lookups", []):
        if not user_matches(item):
            continue
        rid = item["resource_id"]
        sc = item.get("status_code")
        if sc == 404:
            steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                   "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))
        elif sc == 200:
            is_incomplete = True
            steps.append(AuditStep(0, "FINDING", "account_service", rid,
                                   "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
            steps.append(AuditStep(0, "REMEDIATION", "account_service", rid,
                                   "DELETE_RECORD", "ABSENT", ""))
            steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                   "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    # security_service.audit_records
    for item in exports.get("security_service", {}).get("audit_records", []):
        if not user_matches(item):
            continue
        rid = item["resource_id"]
        steps.append(AuditStep(0, "VERIFICATION", "security_service", rid,
                               "VERIFY_RECORD_PRESENT", "PRESENT", evidence_id))

    # analytics_platform.profiles
    for item in exports.get("analytics_platform", {}).get("profiles", []):
        if not user_matches(item):
            continue
        rid = item["resource_id"]
        email_val = item.get("email")
        if email_val and isinstance(email_val, str) and email_val.strip():
            # PII still exposed
            is_incomplete = True
            steps.append(AuditStep(0, "FINDING", "analytics_platform", rid,
                                   "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
            steps.append(AuditStep(0, "REMEDIATION", "analytics_platform", rid,
                                   "ANONYMIZE_RECORD", "ANONYMIZED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                   "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
        else:
            # Properly anonymized
            steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                   "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evidence_id))

    # support_platform.tickets
    for item in exports.get("support_platform", {}).get("tickets", []):
        if not user_matches(item):
            continue
        rid = item["resource_id"]
        re_email = item.get("requester_email")
        re_name = item.get("requester_name")
        re_phone = item.get("requester_phone")
        if (re_email and re_email.strip()) or (re_name and re_name.strip()) or (re_phone and re_phone.strip()):
            is_incomplete = True
            steps.append(AuditStep(0, "FINDING", "support_platform", rid,
                                   "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
            steps.append(AuditStep(0, "REMEDIATION", "support_platform", rid,
                                   "REDACT_RECORD", "REDACTED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                   "VERIFY_RECORD_REDACTED", "REDACTED", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                   "VERIFY_RECORD_REDACTED", "REDACTED", evidence_id))

    # integration_service.connectors
    for item in exports.get("integration_service", {}).get("connectors", []):
        if not user_matches(item):
            continue
        rid = item["resource_id"]
        enabled = item.get("enabled")
        if enabled:
            is_incomplete = True
            steps.append(AuditStep(0, "FINDING", "integration_service", rid,
                                   "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evidence_id))
            steps.append(AuditStep(0, "REMEDIATION", "integration_service", rid,
                                   "DISABLE_DATA_FLOW", "DISABLED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "integration_service", rid,
                                   "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "integration_service", rid,
                                   "VERIFY_DATA_FLOW_DISABLED", "DISABLED", evidence_id))

    # backup_service.restore_entries
    for item in exports.get("backup_service", {}).get("restore_entries", []):
        if not user_matches(item):
            continue
        rid = item["resource_id"]
        restore_allowed = item.get("restore_allowed")
        if restore_allowed:
            is_incomplete = True
            steps.append(AuditStep(0, "FINDING", "backup_service", rid,
                                   "REPORT_RESTORE_RISK", "ACTIVE", evidence_id))
            steps.append(AuditStep(0, "REMEDIATION", "backup_service", rid,
                                   "BLOCK_RESTORE", "BLOCKED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "backup_service", rid,
                                   "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "backup_service", rid,
                                   "VERIFY_RESTORE_BLOCKED", "BLOCKED", evidence_id))

    # search_service.index_queries
    for item in exports.get("search_service", {}).get("index_queries", []):
        if not user_matches(item):
            continue
        rid = item["resource_id"]
        hits = item.get("hits", {})
        total = hits.get("total", 0)
        if total > 0:
            is_incomplete = True
            steps.append(AuditStep(0, "FINDING", "search_service", rid,
                                   "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
            steps.append(AuditStep(0, "REMEDIATION", "search_service", rid,
                                   "DELETE_RECORD", "ABSENT", ""))
            steps.append(AuditStep(0, "VERIFICATION", "search_service", rid,
                                   "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    # export_service.exports
    for item in exports.get("export_service", {}).get("exports", []):
        if not user_matches(item):
            continue
        rid = item["resource_id"]
        is_incomplete = True
        steps.append(AuditStep(0, "FINDING", "export_service", rid,
                               "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
        steps.append(AuditStep(0, "REMEDIATION", "export_service", rid,
                               "DELETE_RECORD", "ABSENT", ""))
        steps.append(AuditStep(0, "VERIFICATION", "export_service", rid,
                               "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    return steps


# ---------------------------------------------------------------------------
# Snapshot Bundle Parser (snapshot bundle JSON, etc.)
# ---------------------------------------------------------------------------
def parse_snapshot_bundle(
    data: Dict,
    evidence_id: str,
    closure: IdentityClosure,
    resolver: IdentityResolver,
) -> List[AuditStep]:
    """Parse a customer_data_snapshot_bundle JSON for a specific user."""
    snapshots = data.get("snapshots", [])
    if not snapshots:
        return []

    steps: List[AuditStep] = []
    uid = closure.user_id
    all_emails = closure.emails

    for snap in snapshots:
        records = snap.get("records", [])
        for rec in records:
            # Check if record belongs to this user
            sr = rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id")
            email = rec.get("email") or rec.get("owner_email")
            if sr != uid and not (email and email.strip().lower() in all_emails):
                continue

            rid = rec.get("resource_id", "")
            if not rid:
                continue

            # Determine system and step type based on resource prefix and data
            if rid.startswith("account_"):
                status = str(rec.get("account_status", "")).upper()
                if status in ("DELETED", "NOT_FOUND"):
                    steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                           "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))
                elif status in ("ACTIVE", "DELETION_PENDING"):
                    steps.append(AuditStep(0, "FINDING", "account_service", rid,
                                           "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "account_service", rid,
                                           "DELETE_RECORD", "ABSENT", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                           "VERIFY_RECORD_ABSENT", "ABSENT", ""))

            elif rid.startswith("tombstone_"):
                # Account tombstone - check if PII is still present
                has_pii = any(
                    rec.get(f) and str(rec.get(f)).strip()
                    for f in ("email", "phone", "name", "email_hash")
                )
                if has_pii:
                    steps.append(AuditStep(0, "FINDING", "identity_service", rid,
                                           "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "identity_service", rid,
                                           "REDACT_RECORD", "REDACTED", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "identity_service", rid,
                                           "VERIFY_RECORD_REDACTED", "REDACTED", ""))
                else:
                    steps.append(AuditStep(0, "VERIFICATION", "identity_service", rid,
                                           "VERIFY_RECORD_REDACTED", "REDACTED", evidence_id))

            elif rid.startswith("audit_record_"):
                steps.append(AuditStep(0, "VERIFICATION", "security_service", rid,
                                       "VERIFY_RECORD_PRESENT", "PRESENT", evidence_id))

            elif rid.startswith("analytics_"):
                email_val = rec.get("email")
                if email_val and email_val.strip():
                    steps.append(AuditStep(0, "FINDING", "analytics_platform", rid,
                                           "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "analytics_platform", rid,
                                           "ANONYMIZE_RECORD", "ANONYMIZED", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                           "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
                else:
                    steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                           "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evidence_id))

            elif rid.startswith("search_"):
                steps.append(AuditStep(0, "FINDING", "search_service", rid,
                                       "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
                steps.append(AuditStep(0, "REMEDIATION", "search_service", rid,
                                       "DELETE_RECORD", "ABSENT", ""))
                steps.append(AuditStep(0, "VERIFICATION", "search_service", rid,
                                       "VERIFY_RECORD_ABSENT", "ABSENT", ""))

            elif rid.startswith("support_"):
                re_email = rec.get("requester_email") or rec.get("email")
                if re_email and re_email.strip():
                    steps.append(AuditStep(0, "FINDING", "support_platform", rid,
                                           "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "support_platform", rid,
                                           "REDACT_RECORD", "REDACTED", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                           "VERIFY_RECORD_REDACTED", "REDACTED", ""))

    return steps


# ---------------------------------------------------------------------------
# Handover TXT parser
# ---------------------------------------------------------------------------
def parse_handover_txt(
    text: str,
    evidence_id: str,
    closure: IdentityClosure,
) -> List[AuditStep]:
    """Parse customer_account_handover TXT for a specific user."""
    steps: List[AuditStep] = []
    uid = closure.user_id
    all_emails = closure.emails

    for line in text.splitlines():
        if not line.startswith("- "):
            continue
        parts = [p.strip() for p in line[2:].split("|")]
        if len(parts) < 6:
            continue

        _ts, l_sys, l_res, l_cat, l_stat, l_id = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]

        # Check if line matches this user
        l_id_lower = l_id.strip().lower()
        matches_user = (
            l_id_lower in all_emails or
            l_id_lower == uid.lower()
        )
        if not matches_user:
            continue

        if l_cat == "USER_PROFILE":
            if l_stat == "NOT_FOUND":
                steps.append(AuditStep(0, "VERIFICATION", l_sys, l_res,
                                       "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))
        elif l_cat == "SEARCH_INDEX_ENTRY":
            if l_stat == "FOUND":
                steps.append(AuditStep(0, "FINDING", "search_service", l_res,
                                       "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
                steps.append(AuditStep(0, "REMEDIATION", "search_service", l_res,
                                       "DELETE_RECORD", "ABSENT", ""))
                steps.append(AuditStep(0, "VERIFICATION", "search_service", l_res,
                                       "VERIFY_RECORD_ABSENT", "ABSENT", ""))
            elif l_stat == "NOT_FOUND":
                steps.append(AuditStep(0, "VERIFICATION", "search_service", l_res,
                                       "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))
        elif l_cat == "ANALYTICS_PROFILE":
            if l_stat == "IDENTIFIABLE":
                steps.append(AuditStep(0, "FINDING", "analytics_platform", l_res,
                                       "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                steps.append(AuditStep(0, "REMEDIATION", "analytics_platform", l_res,
                                       "ANONYMIZE_RECORD", "ANONYMIZED", ""))
                steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", l_res,
                                       "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
            elif l_stat == "ANONYMIZED":
                steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", l_res,
                                       "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evidence_id))
        elif l_cat == "SUPPORT_MESSAGE":
            if l_stat == "IDENTIFIABLE":
                steps.append(AuditStep(0, "FINDING", "support_platform", l_res,
                                       "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                steps.append(AuditStep(0, "REMEDIATION", "support_platform", l_res,
                                       "REDACT_RECORD", "REDACTED", ""))
                steps.append(AuditStep(0, "VERIFICATION", "support_platform", l_res,
                                       "VERIFY_RECORD_REDACTED", "REDACTED", ""))
            elif l_stat == "REDACTED":
                steps.append(AuditStep(0, "VERIFICATION", "support_platform", l_res,
                                       "VERIFY_RECORD_REDACTED", "REDACTED", evidence_id))
        elif l_cat == "SUPPORT_ATTACHMENT":
            if l_stat == "FOUND":
                steps.append(AuditStep(0, "FINDING", "support_platform", l_res,
                                       "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
                steps.append(AuditStep(0, "REMEDIATION", "support_platform", l_res,
                                       "DELETE_RECORD", "ABSENT", ""))
                steps.append(AuditStep(0, "VERIFICATION", "support_platform", l_res,
                                       "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        elif l_cat == "DATA_FLOW":
            if l_stat == "ACTIVE":
                steps.append(AuditStep(0, "FINDING", "integration_service", l_res,
                                       "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evidence_id))
                steps.append(AuditStep(0, "REMEDIATION", "integration_service", l_res,
                                       "DISABLE_DATA_FLOW", "DISABLED", ""))
                steps.append(AuditStep(0, "VERIFICATION", "integration_service", l_res,
                                       "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
            elif l_stat == "DISABLED":
                steps.append(AuditStep(0, "VERIFICATION", "integration_service", l_res,
                                       "VERIFY_DATA_FLOW_DISABLED", "DISABLED", evidence_id))
        elif l_cat == "BACKUP_ARCHIVE":
            if l_stat == "ACTIVE":
                steps.append(AuditStep(0, "FINDING", "backup_service", l_res,
                                       "REPORT_RESTORE_RISK", "ACTIVE", evidence_id))
                steps.append(AuditStep(0, "REMEDIATION", "backup_service", l_res,
                                       "BLOCK_RESTORE", "BLOCKED", ""))
                steps.append(AuditStep(0, "VERIFICATION", "backup_service", l_res,
                                       "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
            elif l_stat == "BLOCKED":
                steps.append(AuditStep(0, "VERIFICATION", "backup_service", l_res,
                                       "VERIFY_RESTORE_BLOCKED", "BLOCKED", evidence_id))
        elif l_cat == "SECURITY_AUDIT_LOG":
            if l_stat in ("FOUND", "PRESENT"):
                steps.append(AuditStep(0, "VERIFICATION", "security_service", l_res,
                                       "VERIFY_RECORD_PRESENT", "PRESENT", evidence_id))

    return steps


# ---------------------------------------------------------------------------
# Resource Lookup Trace parser
# ---------------------------------------------------------------------------
def parse_resource_lookup_trace(
    text: str,
    evidence_id: str,
    closure: IdentityClosure,
) -> List[AuditStep]:
    """Parse resource_lookup_trace log lines for a specific user."""
    steps: List[AuditStep] = []
    uid = closure.user_id
    all_emails = closure.emails
    seen: Set[Tuple[str, str, str]] = set()

    for line in text.splitlines():
        # Check if line references this user
        line_lower = line.lower()
        matches = False
        for email in all_emails:
            if email in line_lower:
                matches = True
                break
        if uid.lower() in line_lower:
            matches = True
        if not matches:
            continue

        if "profile_lookup_completed" in line and "rows=0" in line:
            m = re.search(r"resource_id=(account_\d+)", line)
            if m:
                rid = m.group(1)
                key = ("account_service", rid, "VERIFY_RECORD_ABSENT")
                if key not in seen:
                    seen.add(key)
                    steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                           "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))

        elif "audit_record_read_completed" in line and "rows=1" in line:
            m = re.search(r"resource_id=(audit_record_\d+)", line)
            if m:
                rid = m.group(1)
                key = ("security_service", rid, "VERIFY_RECORD_PRESENT")
                if key not in seen:
                    seen.add(key)
                    steps.append(AuditStep(0, "VERIFICATION", "security_service", rid,
                                           "VERIFY_RECORD_PRESENT", "PRESENT", evidence_id))

        elif "analytics_profile_read_completed" in line:
            m = re.search(r"resource_id=(analytics_\d+)", line)
            if m:
                rid = m.group(1)
                if "email=null" in line_lower or "email=none" in line_lower:
                    key = ("analytics_platform", rid, "VERIFY_RECORD_ANONYMIZED")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                               "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evidence_id))
                else:
                    key = ("analytics_platform", rid, "REPORT_EXPOSED_PII")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "FINDING", "analytics_platform", rid,
                                               "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                        steps.append(AuditStep(0, "REMEDIATION", "analytics_platform", rid,
                                               "ANONYMIZE_RECORD", "ANONYMIZED", ""))
                        steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                               "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))

        elif "connector_config_read_completed" in line:
            m = re.search(r"resource_id=(data_flow_\d+)", line)
            if m:
                rid = m.group(1)
                if "enabled=true" in line_lower:
                    key = ("integration_service", rid, "REPORT_ACTIVE_DATA_FLOW")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "FINDING", "integration_service", rid,
                                               "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evidence_id))
                        steps.append(AuditStep(0, "REMEDIATION", "integration_service", rid,
                                               "DISABLE_DATA_FLOW", "DISABLED", ""))
                        steps.append(AuditStep(0, "VERIFICATION", "integration_service", rid,
                                               "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
                elif "enabled=false" in line_lower:
                    key = ("integration_service", rid, "VERIFY_DATA_FLOW_DISABLED")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "VERIFICATION", "integration_service", rid,
                                               "VERIFY_DATA_FLOW_DISABLED", "DISABLED", evidence_id))

        elif "support_record_read_completed" in line:
            m = re.search(r"resource_id=(support_\d+)", line)
            if m:
                rid = m.group(1)
                if "requester_email=null" in line_lower:
                    key = ("support_platform", rid, "VERIFY_RECORD_REDACTED")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                               "VERIFY_RECORD_REDACTED", "REDACTED", evidence_id))
                else:
                    key = ("support_platform", rid, "REPORT_EXPOSED_PII")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "FINDING", "support_platform", rid,
                                               "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                        steps.append(AuditStep(0, "REMEDIATION", "support_platform", rid,
                                               "REDACT_RECORD", "REDACTED", ""))
                        steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                               "VERIFY_RECORD_REDACTED", "REDACTED", ""))

        elif "search_document_read_completed" in line:
            m = re.search(r"resource_id=(search_\d+)", line)
            if m:
                rid = m.group(1)
                if "rows=0" in line:
                    key = ("search_service", rid, "VERIFY_RECORD_ABSENT")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "VERIFICATION", "search_service", rid,
                                               "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))
                elif "rows=1" in line:
                    key = ("search_service", rid, "REPORT_REMAINING_RECORD")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "FINDING", "search_service", rid,
                                               "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
                        steps.append(AuditStep(0, "REMEDIATION", "search_service", rid,
                                               "DELETE_RECORD", "ABSENT", ""))
                        steps.append(AuditStep(0, "VERIFICATION", "search_service", rid,
                                               "VERIFY_RECORD_ABSENT", "ABSENT", ""))

        elif "restore_access_read_completed" in line:
            m = re.search(r"resource_id=(backup_\d+)", line)
            if m:
                rid = m.group(1)
                if "restore_allowed=true" in line_lower:
                    key = ("backup_service", rid, "REPORT_RESTORE_RISK")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "FINDING", "backup_service", rid,
                                               "REPORT_RESTORE_RISK", "ACTIVE", evidence_id))
                        steps.append(AuditStep(0, "REMEDIATION", "backup_service", rid,
                                               "BLOCK_RESTORE", "BLOCKED", ""))
                        steps.append(AuditStep(0, "VERIFICATION", "backup_service", rid,
                                               "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
                elif "restore_allowed=false" in line_lower:
                    key = ("backup_service", rid, "VERIFY_RESTORE_BLOCKED")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "VERIFICATION", "backup_service", rid,
                                               "VERIFY_RESTORE_BLOCKED", "BLOCKED", evidence_id))

        elif "export_record_read_completed" in line:
            m = re.search(r"resource_id=(export_\d+)", line)
            if m:
                rid = m.group(1)
                if "rows=1" in line:
                    key = ("export_service", rid, "REPORT_REMAINING_RECORD")
                    if key not in seen:
                        seen.add(key)
                        steps.append(AuditStep(0, "FINDING", "export_service", rid,
                                               "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
                        steps.append(AuditStep(0, "REMEDIATION", "export_service", rid,
                                               "DELETE_RECORD", "ABSENT", ""))
                        steps.append(AuditStep(0, "VERIFICATION", "export_service", rid,
                                               "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    return steps


# ---------------------------------------------------------------------------
# SQL evidence parsers
# ---------------------------------------------------------------------------
def parse_sql_evidence(
    finding: EvidenceFinding,
    closure: IdentityClosure,
) -> List[AuditStep]:
    """Parse a SQL row finding and produce audit steps."""
    steps: List[AuditStep] = []
    if not isinstance(finding.data, dict):
        return steps

    raw = dict(finding.data)
    if "record_json" in raw and isinstance(raw["record_json"], str):
        try:
            pj = json.loads(raw["record_json"])
            if isinstance(pj, dict):
                raw.update(pj)
        except Exception:
            pass

    rid = finding.resource_id or raw.get("resource_id", "")
    eid = finding.evidence_id

    if not rid:
        return steps

    if rid.startswith("search_"):
        steps.append(AuditStep(0, "FINDING", "search_service", rid,
                               "REPORT_REMAINING_RECORD", "PRESENT", eid))
        steps.append(AuditStep(0, "REMEDIATION", "search_service", rid,
                               "DELETE_RECORD", "ABSENT", ""))
        steps.append(AuditStep(0, "VERIFICATION", "search_service", rid,
                               "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    elif rid.startswith("account_"):
        status = str(raw.get("account_status", "")).upper()
        if status in ("ACTIVE", "DELETION_PENDING"):
            steps.append(AuditStep(0, "FINDING", "account_service", rid,
                                   "REPORT_REMAINING_RECORD", "PRESENT", eid))
            steps.append(AuditStep(0, "REMEDIATION", "account_service", rid,
                                   "DELETE_RECORD", "ABSENT", ""))
            steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                   "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        elif status in ("DELETED", "NOT_FOUND"):
            steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                   "VERIFY_RECORD_ABSENT", "ABSENT", eid))

    elif rid.startswith("analytics_"):
        email_val = raw.get("email") or raw.get("phone")
        if email_val and str(email_val).strip() and str(email_val).lower() not in ("null", "none"):
            steps.append(AuditStep(0, "FINDING", "analytics_platform", rid,
                                   "REPORT_EXPOSED_PII", "PRESENT", eid))
            steps.append(AuditStep(0, "REMEDIATION", "analytics_platform", rid,
                                   "ANONYMIZE_RECORD", "ANONYMIZED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                   "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                   "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", eid))

    elif rid.startswith("support_"):
        re_email = raw.get("requester_email") or raw.get("email") or raw.get("requester_phone") or raw.get("requester_name")
        if re_email and str(re_email).strip() and str(re_email).lower() not in ("null", "none"):
            steps.append(AuditStep(0, "FINDING", "support_platform", rid,
                                   "REPORT_EXPOSED_PII", "PRESENT", eid))
            steps.append(AuditStep(0, "REMEDIATION", "support_platform", rid,
                                   "REDACT_RECORD", "REDACTED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                   "VERIFY_RECORD_REDACTED", "REDACTED", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                   "VERIFY_RECORD_REDACTED", "REDACTED", eid))

    elif rid.startswith("export_"):
        steps.append(AuditStep(0, "FINDING", "export_service", rid,
                               "REPORT_REMAINING_RECORD", "PRESENT", eid))
        steps.append(AuditStep(0, "REMEDIATION", "export_service", rid,
                               "DELETE_RECORD", "ABSENT", ""))
        steps.append(AuditStep(0, "VERIFICATION", "export_service", rid,
                               "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    elif rid.startswith("data_flow_"):
        enabled = raw.get("enabled")
        if enabled:
            steps.append(AuditStep(0, "FINDING", "integration_service", rid,
                                   "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", eid))
            steps.append(AuditStep(0, "REMEDIATION", "integration_service", rid,
                                   "DISABLE_DATA_FLOW", "DISABLED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "integration_service", rid,
                                   "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "integration_service", rid,
                                   "VERIFY_DATA_FLOW_DISABLED", "DISABLED", eid))

    elif rid.startswith("backup_"):
        restore = raw.get("restore_allowed")
        if restore:
            steps.append(AuditStep(0, "FINDING", "backup_service", rid,
                                   "REPORT_RESTORE_RISK", "ACTIVE", eid))
            steps.append(AuditStep(0, "REMEDIATION", "backup_service", rid,
                                   "BLOCK_RESTORE", "BLOCKED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "backup_service", rid,
                                   "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "backup_service", rid,
                                   "VERIFY_RESTORE_BLOCKED", "BLOCKED", eid))

    elif rid.startswith("audit_record_"):
        steps.append(AuditStep(0, "VERIFICATION", "security_service", rid,
                               "VERIFY_RECORD_PRESENT", "PRESENT", eid))

    return steps


# ---------------------------------------------------------------------------
# Absence proof from failover/primary SQL DBs
# ---------------------------------------------------------------------------
def check_absence_in_failover(
    evidence_id: str,
    sql_path: Path,
    closure: IdentityClosure,
    activity_index: SystemActivityIndex,
    resource_map: Optional[ResourceMapBuilder] = None,
) -> List[AuditStep]:
    """
    Check if a user's account is absent from a failover/primary SQL replica.
    If absent, generate VERIFY_RECORD_ABSENT step.
    """
    uid = closure.user_id
    all_emails = closure.emails

    real_account = None
    if resource_map:
        for rid, data in resource_map.resource_to_user.items():
            if data.get("user_id") == uid and rid.startswith("account_"):
                real_account = rid
                break

    if real_account:
        possible_account_ids = [real_account]
    else:
        m = re.match(r"user_(\d+)", uid)
        if not m:
            return []
        user_num = int(m.group(1))
        possible_account_ids = [f"account_{user_num:03d}", f"account_{user_num}"]

    try:
        conn = sqlite3.connect(":memory:")
        with open(sql_path, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cursor.fetchall()]

        for table in tables:
            cursor.execute(f"PRAGMA table_info('{table}')")
            cols = [c[1] for c in cursor.fetchall()]

            if "user_id" in cols:
                cursor.execute(f"SELECT resource_id FROM '{table}' WHERE user_id = ?", (uid,))
                if cursor.fetchall():
                    conn.close()
                    return []

            if "email" in cols:
                for email in all_emails:
                    cursor.execute(f"SELECT resource_id FROM '{table}' WHERE LOWER(email) = ?", (email.lower(),))
                    if cursor.fetchall():
                        conn.close()
                        return []

        conn.close()
    except Exception:
        return []

    steps = []
    for acc_id in possible_account_ids[:1]:
        steps.append(AuditStep(0, "VERIFICATION", "account_service", acc_id,
                               "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))
    return steps


# ---------------------------------------------------------------------------
# PDF / Support Attachment parser
# ---------------------------------------------------------------------------
def parse_pdf_evidence(
    finding: EvidenceFinding,
    closure: IdentityClosure,
) -> List[AuditStep]:
    """Parse PDF support attachment finding."""
    steps: List[AuditStep] = []
    rid = finding.resource_id
    if not rid:
        return steps

    if rid.startswith("support_"):
        steps.append(AuditStep(0, "FINDING", "support_platform", rid,
                               "REPORT_REMAINING_RECORD", "PRESENT", finding.evidence_id))
        steps.append(AuditStep(0, "REMEDIATION", "support_platform", rid,
                               "DELETE_RECORD", "ABSENT", ""))
        steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                               "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    return steps


# ---------------------------------------------------------------------------
# JSON evidence parser (export jobs, analytics reports, etc.)
# ---------------------------------------------------------------------------
def parse_json_evidence(
    finding: EvidenceFinding,
    closure: IdentityClosure,
) -> List[AuditStep]:
    """Parse JSON evidence finding."""
    steps: List[AuditStep] = []
    data = finding.data
    if not isinstance(data, dict):
        return steps

    eid = finding.evidence_id
    rid = finding.resource_id or data.get("resource_id", "")
    if not rid:
        return steps

    if rid.startswith("export_"):
        avail = data.get("download_available")
        if avail is not False:
            steps.append(AuditStep(0, "FINDING", "export_service", rid,
                                   "REPORT_REMAINING_RECORD", "PRESENT", eid))
            steps.append(AuditStep(0, "REMEDIATION", "export_service", rid,
                                   "DELETE_RECORD", "ABSENT", ""))
            steps.append(AuditStep(0, "VERIFICATION", "export_service", rid,
                                   "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "export_service", rid,
                                   "VERIFY_RECORD_ABSENT", "ABSENT", eid))

    elif rid.startswith("analytics_"):
        email_val = data.get("email") or data.get("phone")
        if email_val and str(email_val).strip() and str(email_val).lower() not in ("null", "none"):
            steps.append(AuditStep(0, "FINDING", "analytics_platform", rid,
                                   "REPORT_EXPOSED_PII", "PRESENT", eid))
            steps.append(AuditStep(0, "REMEDIATION", "analytics_platform", rid,
                                   "ANONYMIZE_RECORD", "ANONYMIZED", ""))
            steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                   "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
        else:
            steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                   "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", eid))

    return steps


# ---------------------------------------------------------------------------
# Log Parser with Full Trace Correlation
# ---------------------------------------------------------------------------
def parse_log_with_trace_correlation(
    log_text: str,
    evidence_id: str,
    closure: IdentityClosure,
) -> List[AuditStep]:
    """
    Parse any log format with 2-pass trace correlation to capture multi-line
    request/response pairs across instances, services, and replicas.
    """
    steps: List[AuditStep] = []
    uid = closure.user_id
    all_emails = {e.lower() for e in closure.emails}
    all_hashes = {h.lower() for h in closure.email_hashes}
    all_phones = {p.strip() for p in closure.phones}
    match_targets = all_emails | {uid.lower()} | all_hashes | all_phones

    lines = log_text.splitlines()

    # Pass 1: find all trace_ids matching this user
    user_trace_ids = set()
    for line in lines:
        line_lower = line.lower()
        if any(t in line_lower for t in match_targets):
            m = re.search(r"trace_id=([A-Za-z0-9_-]+)", line)
            if m:
                user_trace_ids.add(m.group(1))
            m_json = re.search(r'"trace_id"\s*:\s*"([^"]+)"', line)
            if m_json:
                user_trace_ids.add(m_json.group(1))

    # Pass 2: process lines matching trace_id or direct target match
    seen_ops = set()
    for line in lines:
        line_lower = line.lower()
        m_trace = re.search(r"trace_id=([A-Za-z0-9_-]+)", line)
        t_id = m_trace.group(1) if m_trace else None
        if not t_id:
            m_json = re.search(r'"trace_id"\s*:\s*"([^"]+)"', line)
            t_id = m_json.group(1) if m_json else None

        matches_user = (t_id and t_id in user_trace_ids) or any(t in line_lower for t in match_targets)
        if not matches_user:
            continue

        m_res = re.search(r"resource_id=([A-Za-z0-9_]+)", line)
        if not m_res:
            m_res = re.search(r'"resource_id"\s*:\s*"([^"]+)"', line)
        if not m_res:
            continue
        rid = m_res.group(1)

        if rid.startswith("account_"):
            if "rows=0" in line or "404" in line or "not_found" in line_lower:
                op = ("account_service", rid, "VERIFY_RECORD_ABSENT")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                           "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))
            elif "rows=1" in line or "200" in line or "active" in line_lower:
                op = ("account_service", rid, "REPORT_REMAINING_RECORD")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "FINDING", "account_service", rid,
                                           "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "account_service", rid,
                                           "DELETE_RECORD", "ABSENT", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "account_service", rid,
                                           "VERIFY_RECORD_ABSENT", "ABSENT", ""))

        elif rid.startswith("audit_record_"):
            op = ("security_service", rid, "VERIFY_RECORD_PRESENT")
            if op not in seen_ops:
                seen_ops.add(op)
                steps.append(AuditStep(0, "VERIFICATION", "security_service", rid,
                                       "VERIFY_RECORD_PRESENT", "PRESENT", evidence_id))

        elif rid.startswith("analytics_"):
            if "email=null" in line_lower or "email=none" in line_lower or "customer_reference=null" in line_lower:
                op = ("analytics_platform", rid, "VERIFY_RECORD_ANONYMIZED")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                           "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evidence_id))
            else:
                op = ("analytics_platform", rid, "REPORT_EXPOSED_PII")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "FINDING", "analytics_platform", rid,
                                           "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "analytics_platform", rid,
                                           "ANONYMIZE_RECORD", "ANONYMIZED", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "analytics_platform", rid,
                                           "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))

        elif rid.startswith("search_"):
            if "rows=0" in line or "not_found" in line_lower:
                op = ("search_service", rid, "VERIFY_RECORD_ABSENT")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "VERIFICATION", "search_service", rid,
                                           "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id))
            else:
                op = ("search_service", rid, "REPORT_REMAINING_RECORD")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "FINDING", "search_service", rid,
                                           "REPORT_REMAINING_RECORD", "PRESENT", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "search_service", rid,
                                           "DELETE_RECORD", "ABSENT", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "search_service", rid,
                                           "VERIFY_RECORD_ABSENT", "ABSENT", ""))

        elif rid.startswith("support_"):
            if "requester_email=null" in line_lower or "redacted" in line_lower:
                op = ("support_platform", rid, "VERIFY_RECORD_REDACTED")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                           "VERIFY_RECORD_REDACTED", "REDACTED", evidence_id))
            else:
                op = ("support_platform", rid, "REPORT_EXPOSED_PII")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "FINDING", "support_platform", rid,
                                           "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "support_platform", rid,
                                           "REDACT_RECORD", "REDACTED", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "support_platform", rid,
                                           "VERIFY_RECORD_REDACTED", "REDACTED", ""))

        elif rid.startswith("data_flow_"):
            if "enabled=true" in line_lower:
                op = ("integration_service", rid, "REPORT_ACTIVE_DATA_FLOW")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "FINDING", "integration_service", rid,
                                           "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "integration_service", rid,
                                           "DISABLE_DATA_FLOW", "DISABLED", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "integration_service", rid,
                                           "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
            elif "enabled=false" in line_lower:
                op = ("integration_service", rid, "VERIFY_DATA_FLOW_DISABLED")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "VERIFICATION", "integration_service", rid,
                                           "VERIFY_DATA_FLOW_DISABLED", "DISABLED", evidence_id))

        elif rid.startswith("backup_"):
            if "restore_allowed=true" in line_lower or "deletion_block=false" in line_lower:
                op = ("backup_service", rid, "REPORT_RESTORE_RISK")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "FINDING", "backup_service", rid,
                                           "REPORT_RESTORE_RISK", "ACTIVE", evidence_id))
                    steps.append(AuditStep(0, "REMEDIATION", "backup_service", rid,
                                           "BLOCK_RESTORE", "BLOCKED", ""))
                    steps.append(AuditStep(0, "VERIFICATION", "backup_service", rid,
                                           "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
            elif "restore_allowed=false" in line_lower or "deletion_block=true" in line_lower:
                op = ("backup_service", rid, "VERIFY_RESTORE_BLOCKED")
                if op not in seen_ops:
                    seen_ops.add(op)
                    steps.append(AuditStep(0, "VERIFICATION", "backup_service", rid,
                                           "VERIFY_RESTORE_BLOCKED", "BLOCKED", evidence_id))

    return steps


# ---------------------------------------------------------------------------
# Core Audit Function
# ---------------------------------------------------------------------------
def audit_case(
    case_id: str,
    email: str,
    audit_at: str,
    request_text: str,
    resolver: IdentityResolver,
    indexer: EvidenceIndexer,
    activity_index: SystemActivityIndex,
    resource_map: ResourceMapBuilder,
    evidence_cache: Dict[str, Any],
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Audit a single case end-to-end.
    Returns (deletion_status, steps_json_list).
    """
    if not EnhancedIntentClassifier.is_deletion_request(request_text):
        return "NOT_APPLICABLE", []

    closure = resolver.resolve_email(email)
    if not closure:
        return "NOT_APPLICABLE", []

    findings = indexer.find_for_identity_closure(closure, audit_at=audit_at)

    all_steps: List[AuditStep] = []
    seen_keys: Set[Tuple[str, str, str]] = set()

    def add_steps(new_steps: List[AuditStep]):
        for s in new_steps:
            key = (s.system_id, s.resource_id, s.operation)
            if key not in seen_keys:
                seen_keys.add(key)
                all_steps.append(s)

    findings_by_evidence: Dict[str, List[EvidenceFinding]] = defaultdict(list)
    for f in findings:
        findings_by_evidence[f.evidence_id].append(f)

    for eid, eid_findings in findings_by_evidence.items():
        first = eid_findings[0]
        relative = first.relative_path.lower()

        if "service_resource_export" in relative:
            raw_json = evidence_cache.get(eid)
            if raw_json is None:
                for entry in indexer.manifest_entries:
                    if entry.file_id == eid:
                        with open(entry.resolved_path, "r", encoding="utf-8") as fp:
                            raw_json = json.load(fp)
                        evidence_cache[eid] = raw_json
                        break
            if raw_json:
                add_steps(parse_service_resource_export(
                    raw_json, eid, closure, resolver, resource_map, activity_index
                ))

        elif "snapshot_bundle" in relative:
            raw_json = evidence_cache.get(eid)
            if raw_json is None:
                for entry in indexer.manifest_entries:
                    if entry.file_id == eid:
                        with open(entry.resolved_path, "r", encoding="utf-8") as fp:
                            raw_json = json.load(fp)
                        evidence_cache[eid] = raw_json
                        break
            if raw_json:
                add_steps(parse_snapshot_bundle(raw_json, eid, closure, resolver))

        elif "handover" in relative and first.file_format == "txt":
            text = evidence_cache.get(eid)
            if text is None:
                for entry in indexer.manifest_entries:
                    if entry.file_id == eid:
                        with open(entry.resolved_path, "r", encoding="utf-8") as fp:
                            text = fp.read()
                        evidence_cache[eid] = text
                        break
            if text:
                add_steps(parse_handover_txt(text, eid, closure))

        elif first.file_format == "log":
            text = evidence_cache.get(eid)
            if text is None:
                for entry in indexer.manifest_entries:
                    if entry.file_id == eid:
                        with open(entry.resolved_path, "r", encoding="utf-8", errors="ignore") as fp:
                            text = fp.read()
                        evidence_cache[eid] = text
                        break
            if text:
                add_steps(parse_log_with_trace_correlation(text, eid, closure))

        elif first.file_format == "sql":
            for ef in eid_findings:
                add_steps(parse_sql_evidence(ef, closure))

        elif first.file_format == "pdf":
            if "legal_retention" not in relative and "retention_register" not in relative:
                for ef in eid_findings:
                    add_steps(parse_pdf_evidence(ef, closure))

        elif first.file_format == "json":
            if "service_resource_export" not in relative and "snapshot_bundle" not in relative:
                for ef in eid_findings:
                    add_steps(parse_json_evidence(ef, closure))

    # Absence proofs from failover replicas if no account step
    has_account_step = any(s.system_id == "account_service" for s in all_steps)
    if not has_account_step:
        for entry in indexer.manifest_entries:
            if "failover_replica" in entry.file_path.lower() or "failover" in entry.origin.lower():
                try:
                    cutoff = datetime.fromisoformat(audit_at.replace("Z", "+00:00"))
                    cap = datetime.fromisoformat(entry.captured_at.replace("Z", "+00:00"))
                    if cap <= cutoff:
                        add_steps(check_absence_in_failover(
                            entry.file_id, entry.resolved_path, closure, activity_index, resource_map
                        ))
                except (ValueError, TypeError):
                    pass

    # Status determination and schema compliance
    has_findings = any(s.phase == "FINDING" for s in all_steps)
    if has_findings:
        deletion_status = "INCOMPLETE"
        for s in all_steps:
            if s.phase in ("REMEDIATION", "VERIFICATION"):
                s.evidence_id = ""
    else:
        deletion_status = "COMPLETE"

    if not all_steps:
        return "COMPLETE", []

    sorted_steps = PolicyEngine.sort_steps(all_steps)
    return deletion_status, [s.to_dict() for s in sorted_steps]


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def main():
    print("=== Ghost Data Still Exists — Audit Engine ===")
    print("Loading identity resolver...")
    resolver = IdentityResolver()

    print("Loading and indexing evidence...")
    indexer = EvidenceIndexer()
    indexer.index_all()
    report = indexer.get_extraction_report()
    print(f"  Indexed {report['total_extracted_findings']} findings from "
          f"{report['manifest_entries_processed']} evidence files")

    print("Loading system activity index...")
    activity_index = SystemActivityIndex()

    print("Building resource map...")
    resource_map = ResourceMapBuilder(resolver, indexer, activity_index)
    print(f"  Mapped {len(resource_map.resource_to_user)} resources to users")

    print("Loading deletion requests...")
    requests_path = Path("dataset/deletion_requests.csv")
    if not requests_path.exists():
        print(f"ERROR: {requests_path} not found!")
        return

    with open(requests_path, "r", encoding="utf-8") as f:
        deletion_requests = list(csv.DictReader(f))
    print(f"  {len(deletion_requests)} requests to process")

    # Process all cases
    evidence_cache: Dict[str, Any] = {}
    results = []

    for i, req in enumerate(deletion_requests):
        case_id = req["case_id"]
        status, steps = audit_case(
            case_id=case_id,
            email=req["email"],
            audit_at=req["audit_at"],
            request_text=req["request_text"],
            resolver=resolver,
            indexer=indexer,
            activity_index=activity_index,
            resource_map=resource_map,
            evidence_cache=evidence_cache,
        )
        results.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":")),
        })

        if (i + 1) % 50 == 0:
            print(f"  Processed {i + 1}/{len(deletion_requests)} cases...")

    # Sort by case_id
    results.sort(key=lambda r: int(r["case_id"].split("_")[1]))

    # Write output.csv to both root and dataset/
    for out_p in [Path("output.csv"), Path("dataset/output.csv")]:
        with open(out_p, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f"\nWrote {len(results)} rows to {out_p}")

    # Print summary
    from collections import Counter
    status_counts = Counter(r["deletion_status"] for r in results)
    print(f"Status distribution: {dict(status_counts)}")


if __name__ == "__main__":
    main()
