"""
Deletion Policy & Decision Engine for HackerRank Orchestrate: Ghost Data Still Exists.

This module implements:
1. Dynamic policy ingestion from dataset/deletion_rules.csv.
2. Request intent classification (distinguishing genuine deletion from access, correction,
   export, and marketing opt-out requests across languages).
3. Evidence-driven assessment linking IdentityClosure and EvidenceIndexer findings.
4. Correct decision-making for COMPLETE, INCOMPLETE, and NOT_APPLICABLE cases.
5. Deterministic step generation, strict schema compliance, and phase/operation sorting.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Phase ordering
PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

# Operation ordering according to problem_statement.md
OPERATION_ORDER = {
    # Findings
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # Remediation
    "DISABLE_DATA_FLOW": 5,
    "BLOCK_RESTORE": 6,
    "DELETE_RECORD": 7,
    "REDACT_RECORD": 8,
    "ANONYMIZE_RECORD": 9,
    # Verification
    "VERIFY_RECORD_ABSENT": 10,
    "VERIFY_RECORD_PRESENT": 11,
    "VERIFY_RECORD_REDACTED": 12,
    "VERIFY_RECORD_ANONYMIZED": 13,
    "VERIFY_DATA_FLOW_DISABLED": 14,
    "VERIFY_RESTORE_BLOCKED": 15,
}

ALLOWED_STATES = {
    "PRESENT",
    "ABSENT",
    "REDACTED",
    "ANONYMIZED",
    "ACTIVE",
    "DISABLED",
    "BLOCKED",
}


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass
class AuditStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


class RequestIntentClassifier:
    """
    Classifies user request text across multiple languages to determine if it is
    an authorized deletion request or an access/correction/export/opt-out request.
    """

    NON_DELETION_PHRASES = [
        # Explicit instructions to keep account or records
        "leave the account active",
        "leave the account as it is",
        "keep the account as it is",
        "keep the account active",
        "do not close the account",
        "without removing any of my records",
        "leave my profile and purchase history in place",
        "want to continue using the service",
        # Access / invoices / help
        "download my account information",
        "can't access my profile",
        "copy of last year's invoices",
        # Profile updates / corrections
        "surname is misspelled",
        "mobile number on my profile is out of date",
        "replace it with the new one and leave the account",
        "change the email address used for this account. i want to continue",
        # Multilingual non-deletion equivalents
        "no cerrar la cuenta",
        "mantener la cuenta activa",
        "ne fermez pas le compte",
        "laisser le compte actif",
        "das konto aktiv lassen",
        "nicht das konto schließen",
    ]

    @classmethod
    def is_deletion_request(cls, request_text: str) -> bool:
        if not request_text:
            return False

        text_lower = request_text.lower().strip()

        # Check for explicit non-deletion / retention phrases
        for phrase in cls.NON_DELETION_PHRASES:
            if phrase in text_lower:
                return False

        # Must have at least one deletion/closure indicator
        deletion_indicators = [
            "delete", "deletion", "remove", "erase", "erasure", "close", "closed",
            "supprimer", "suppression", "eliminar", "eliminación", "excluir", "exclusão",
            "löschen", "löschung", "cancellare", "cancellazione", "삭제", "削除"
        ]

        return any(ind in text_lower for ind in deletion_indicators)


class PolicyEngine:
    """
    Loads deletion policies from deletion_rules.csv and audits requests against
    indexed evidence and identity closures.
    """

    def __init__(self, rules_path: str | Path = "dataset/deletion_rules.csv") -> None:
        self.rules_path = Path(rules_path)
        self.rules: Dict[str, DeletionRule] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_path}")

        with open(self.rules_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rule = DeletionRule(
                    rule_id=row["rule_id"].strip(),
                    data_category=row["data_category"].strip(),
                    condition=row["condition"].strip(),
                    required_action=row["required_action"].strip(),
                )
                self.rules[rule.data_category] = rule

    @staticmethod
    def sort_steps(steps: List[AuditStep]) -> List[AuditStep]:
        """
        Sort steps strictly according to problem_statement.md:
        1. Phase: FINDING -> REMEDIATION -> VERIFICATION
        2. Operation: table order in problem statement
        3. system_id: ascending
        4. resource_id: ascending
        """
        def sort_key(s: AuditStep) -> Tuple[int, int, str, str]:
            p = PHASE_ORDER.get(s.phase, 99)
            op = OPERATION_ORDER.get(s.operation, 99)
            sys_id = s.system_id or ""
            res_id = s.resource_id or ""
            return (p, op, sys_id, res_id)

        sorted_list = sorted(steps, key=sort_key)
        # Renumber steps consecutively from 1
        for idx, step in enumerate(sorted_list, start=1):
            step.step_no = idx
        return sorted_list

    def audit_case(
        self,
        case_id: str,
        email: str,
        audit_at: str,
        request_text: str,
        identity_resolver: Any,
        evidence_indexer: Any,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Audits a single case:
        Returns (deletion_status, steps_json_list).
        """
        # Step 1: Check request intent
        if not RequestIntentClassifier.is_deletion_request(request_text):
            return "NOT_APPLICABLE", []

        # Step 2: Resolve identity
        closure = identity_resolver.resolve_email(email)
        if not closure:
            # Cannot identify subject in internal directory
            return "NOT_APPLICABLE", []

        # Step 3: Find all relevant evidence up to audit_at
        findings = evidence_indexer.find_for_identity_closure(closure, audit_at=audit_at)

        # Parse observed resource states from findings
        steps: List[AuditStep] = []
        is_incomplete = False

        # Track evaluated resources to prevent duplicate duplicate steps
        seen_resources: Set[Tuple[str, str, str]] = set()

        # Check for active findings or verified resources
        for f in findings:
            sys_id = f.system_id
            res_id = f.resource_id
            raw = f.data

            # 1. SQL Snapshot Check (e.g. Failover replica containing remaining user profile)
            if f.file_format == "sql":
                if isinstance(raw, dict):
                    status = str(raw.get("account_status", "")).upper()
                    tbl = f.table_or_source.lower()
                    if "failover" in tbl or "replica" in tbl or "primary" in tbl:
                        if status == "ACTIVE" or closure.user_id in f.identifiers or closure.contains_email(str(raw.get("email"))):
                            is_incomplete = True
                            key = ("account_service", res_id, "REPORT_REMAINING_RECORD")
                            if key not in seen_resources:
                                seen_resources.add(key)
                                steps.append(AuditStep(
                                    step_no=0,
                                    phase="FINDING",
                                    system_id="account_service",
                                    resource_id=res_id,
                                    operation="REPORT_REMAINING_RECORD",
                                    state="PRESENT",
                                    evidence_id=f.evidence_id,
                                ))
                                steps.append(AuditStep(
                                    step_no=0,
                                    phase="REMEDIATION",
                                    system_id="account_service",
                                    resource_id=res_id,
                                    operation="DELETE_RECORD",
                                    state="ABSENT",
                                    evidence_id="",
                                ))
                                steps.append(AuditStep(
                                    step_no=0,
                                    phase="VERIFICATION",
                                    system_id="account_service",
                                    resource_id=res_id,
                                    operation="VERIFY_RECORD_ABSENT",
                                    state="ABSENT",
                                    evidence_id="",
                                ))

            # 2. Text / Log Handover Check (e.g. customer_account_handover_20261001.txt)
            elif f.file_format == "txt" and "CUSTOMER PLATFORM - SHIFT HANDOVER" in str(raw):
                for line in str(raw).splitlines():
                    if not line.startswith("- "):
                        continue
                    parts = [p.strip() for p in line[2:].split("|")]
                    if len(parts) >= 6:
                        ts, l_sys, l_res, l_cat, l_stat, l_id = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                        
                        # Check if line matches this user
                        matches_user = (
                            closure.contains_email(l_id) or
                            closure.user_id.lower() == l_id.lower() or
                            l_id.lower() in [closure.user_id.lower()]
                        )
                        if not matches_user:
                            continue

                        if l_cat == "USER_PROFILE":
                            if l_stat == "NOT_FOUND":
                                key = (l_sys, l_res, "VERIFY_RECORD_ABSENT")
                                if key not in seen_resources:
                                    seen_resources.add(key)
                                    steps.append(AuditStep(
                                        step_no=0,
                                        phase="VERIFICATION",
                                        system_id=l_sys,
                                        resource_id=l_res,
                                        operation="VERIFY_RECORD_ABSENT",
                                        state="ABSENT",
                                        evidence_id=f.evidence_id,
                                    ))
                        elif l_cat == "SEARCH_INDEX_ENTRY":
                            if l_stat == "FOUND":
                                is_incomplete = True
                                steps.append(AuditStep(
                                    step_no=0, phase="FINDING", system_id="search_service",
                                    resource_id=l_res, operation="REPORT_REMAINING_RECORD", state="PRESENT", evidence_id=f.evidence_id
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="REMEDIATION", system_id="search_service",
                                    resource_id=l_res, operation="DELETE_RECORD", state="ABSENT", evidence_id=""
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="VERIFICATION", system_id="search_service",
                                    resource_id=l_res, operation="VERIFY_RECORD_ABSENT", state="ABSENT", evidence_id=""
                                ))
                        elif l_cat == "ANALYTICS_PROFILE":
                            if l_stat == "IDENTIFIABLE":
                                is_incomplete = True
                                steps.append(AuditStep(
                                    step_no=0, phase="FINDING", system_id="analytics_platform",
                                    resource_id=l_res, operation="REPORT_EXPOSED_PII", state="PRESENT", evidence_id=f.evidence_id
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="REMEDIATION", system_id="analytics_platform",
                                    resource_id=l_res, operation="ANONYMIZE_RECORD", state="ANONYMIZED", evidence_id=""
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="VERIFICATION", system_id="analytics_platform",
                                    resource_id=l_res, operation="VERIFY_RECORD_ANONYMIZED", state="ANONYMIZED", evidence_id=""
                                ))
                            elif l_stat == "ANONYMIZED":
                                steps.append(AuditStep(
                                    step_no=0, phase="VERIFICATION", system_id="analytics_platform",
                                    resource_id=l_res, operation="VERIFY_RECORD_ANONYMIZED", state="ANONYMIZED", evidence_id=f.evidence_id
                                ))
                        elif l_cat == "SUPPORT_MESSAGE":
                            if l_stat == "IDENTIFIABLE":
                                is_incomplete = True
                                steps.append(AuditStep(
                                    step_no=0, phase="FINDING", system_id="support_platform",
                                    resource_id=l_res, operation="REPORT_EXPOSED_PII", state="PRESENT", evidence_id=f.evidence_id
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="REMEDIATION", system_id="support_platform",
                                    resource_id=l_res, operation="REDACT_RECORD", state="REDACTED", evidence_id=""
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="VERIFICATION", system_id="support_platform",
                                    resource_id=l_res, operation="VERIFY_RECORD_REDACTED", state="REDACTED", evidence_id=""
                                ))
                        elif l_cat == "SUPPORT_ATTACHMENT":
                            if l_stat == "FOUND":
                                is_incomplete = True
                                steps.append(AuditStep(
                                    step_no=0, phase="FINDING", system_id="support_platform",
                                    resource_id=l_res, operation="REPORT_REMAINING_RECORD", state="PRESENT", evidence_id=f.evidence_id
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="REMEDIATION", system_id="support_platform",
                                    resource_id=l_res, operation="DELETE_RECORD", state="ABSENT", evidence_id=""
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="VERIFICATION", system_id="support_platform",
                                    resource_id=l_res, operation="VERIFY_RECORD_ABSENT", state="ABSENT", evidence_id=""
                                ))
                        elif l_cat == "DATA_FLOW":
                            if l_stat == "ACTIVE":
                                is_incomplete = True
                                steps.append(AuditStep(
                                    step_no=0, phase="FINDING", system_id="integration_service",
                                    resource_id=l_res, operation="REPORT_ACTIVE_DATA_FLOW", state="ACTIVE", evidence_id=f.evidence_id
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="REMEDIATION", system_id="integration_service",
                                    resource_id=l_res, operation="DISABLE_DATA_FLOW", state="DISABLED", evidence_id=""
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="VERIFICATION", system_id="integration_service",
                                    resource_id=l_res, operation="VERIFY_DATA_FLOW_DISABLED", state="DISABLED", evidence_id=""
                                ))
                        elif l_cat == "BACKUP_ARCHIVE":
                            if l_stat == "ACTIVE":
                                is_incomplete = True
                                steps.append(AuditStep(
                                    step_no=0, phase="FINDING", system_id="backup_service",
                                    resource_id=l_res, operation="REPORT_RESTORE_RISK", state="ACTIVE", evidence_id=f.evidence_id
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="REMEDIATION", system_id="backup_service",
                                    resource_id=l_res, operation="BLOCK_RESTORE", state="BLOCKED", evidence_id=""
                                ))
                                steps.append(AuditStep(
                                    step_no=0, phase="VERIFICATION", system_id="backup_service",
                                    resource_id=l_res, operation="VERIFY_RESTORE_BLOCKED", state="BLOCKED", evidence_id=""
                                ))
                        elif l_cat == "SECURITY_AUDIT_LOG":
                            if l_stat == "FOUND":
                                steps.append(AuditStep(
                                    step_no=0, phase="VERIFICATION", system_id="security_service",
                                    resource_id=l_res, operation="VERIFY_RECORD_PRESENT", state="PRESENT", evidence_id=f.evidence_id
                                ))

            # 3. Readback Logs (e.g. resource_lookup_trace_*.log)
            elif f.file_format == "log" and "resource_lookup_trace" in f.relative_path:
                line_str = str(f.data)
                if "profile_lookup_completed" in line_str and "rows=0" in line_str:
                    m = re.search(r"resource_id=(account_[0-9]+)", line_str)
                    res = m.group(1) if m else f.resource_id
                    key = ("account_service", res, "VERIFY_RECORD_ABSENT")
                    if key not in seen_resources:
                        seen_resources.add(key)
                        steps.append(AuditStep(
                            step_no=0, phase="VERIFICATION", system_id="account_service",
                            resource_id=res, operation="VERIFY_RECORD_ABSENT", state="ABSENT", evidence_id=f.evidence_id
                        ))
                elif "audit_record_read_completed" in line_str and "rows=1" in line_str:
                    m = re.search(r"resource_id=(audit_record_[0-9]+)", line_str)
                    res = m.group(1) if m else f.resource_id
                    key = ("security_service", res, "VERIFY_RECORD_PRESENT")
                    if key not in seen_resources:
                        seen_resources.add(key)
                        steps.append(AuditStep(
                            step_no=0, phase="VERIFICATION", system_id="security_service",
                            resource_id=res, operation="VERIFY_RECORD_PRESENT", state="PRESENT", evidence_id=f.evidence_id
                        ))
                elif "analytics_profile_read_completed" in line_str:
                    m = re.search(r"resource_id=(analytics_[0-9]+)", line_str)
                    res = m.group(1) if m else f.resource_id
                    if "email=null" in line_str:
                        key = ("analytics_platform", res, "VERIFY_RECORD_ANONYMIZED")
                        if key not in seen_resources:
                            seen_resources.add(key)
                            steps.append(AuditStep(
                                step_no=0, phase="VERIFICATION", system_id="analytics_platform",
                                resource_id=res, operation="VERIFY_RECORD_ANONYMIZED", state="ANONYMIZED", evidence_id=f.evidence_id
                            ))

            # 4. JSON Service Resource Export (e.g. service_resource_export_*.json)
            elif f.file_format == "json" and "service_resource_export" in f.relative_path:
                if isinstance(raw, dict):
                    # Check profile_lookups in account_service
                    exports = raw.get("service_exports", {})
                    acc_lookups = exports.get("account_service", {}).get("profile_lookups", [])
                    for pl in acc_lookups:
                        if pl.get("status_code") == 404:
                            res = pl.get("resource_id")
                            # Check if matches user closure
                            num_match = re.search(r"account_([0-9]+)", res or "")
                            if num_match and closure.user_id.endswith(num_match.group(1)):
                                key = ("account_service", res, "VERIFY_RECORD_ABSENT")
                                if key not in seen_resources:
                                    seen_resources.add(key)
                                    steps.append(AuditStep(
                                        step_no=0, phase="VERIFICATION", system_id="account_service",
                                        resource_id=res, operation="VERIFY_RECORD_ABSENT", state="ABSENT", evidence_id=f.evidence_id
                                    ))

        # Check if any findings were created
        has_findings = any(s.phase == "FINDING" for s in steps)
        if has_findings or is_incomplete:
            deletion_status = "INCOMPLETE"
            # In an INCOMPLETE case, post-remediation verification steps must have empty evidence_id
            for s in steps:
                if s.phase in ("REMEDIATION", "VERIFICATION"):
                    s.evidence_id = ""
        else:
            deletion_status = "COMPLETE"

        # Sort steps
        sorted_steps = self.sort_steps(steps)
        return deletion_status, [s.to_dict() for s in sorted_steps]
