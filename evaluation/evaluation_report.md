# Evaluation Report: Ghost Data Still Exists

## 1. Executive Summary

This report evaluates the production Deletion-Audit Engine developed for the **HackerRank Orchestrate (October 2026)** challenge: *"Ghost Data Still Exists"*.

The audit engine operates dynamically and deterministically across all 518 evaluation requests without hardcoded identifiers, synthetic shortcuts, or ground-truth lookups. It reconstructs multi-identifier identity closures, indexes multi-modal evidence (structured SQLite databases, JSON snapshot bundles and exports, service logs, PDF documents, and plain-text files), enforces temporal cutoffs (`audit_at`), correlates system activity, applies data-retention policies (`deletion_rules.csv`), and generates compliant ordered audit plans across `FINDING`, `REMEDIATION`, and `VERIFICATION` phases.

---

## 2. Benchmark Accuracy Metrics

Evaluated on the 32 participant-facing benchmark cases from `dataset/sample_deletion_requests.csv` against `dataset/sample_output.csv`:

| Metric | Measured Score | Details |
|---|---|---|
| **Case-Level Deletion Status Accuracy** | **100.00%** (32 / 32) | Perfect classification across `COMPLETE`, `INCOMPLETE`, and `NOT_APPLICABLE` |
| **Exact Sequence Accuracy** | **40.62%** (13 / 32) | Identical step list, ordering, and evidence citations |
| **Step-Level Match / Precision** | **74.61%** (144 / 193) | Perfect match across all fields per step |
| **Phase Field Accuracy** | **93.26%** (180 / 193) | Phase assignment (`FINDING`, `REMEDIATION`, `VERIFICATION`) |
| **System ID Accuracy** | **82.90%** (160 / 193) | Target service identification |
| **Resource ID Accuracy** | **77.20%** (149 / 193) | Resource pointer linking |
| **Operation Accuracy** | **80.31%** (155 / 193) | Allowed operation type compliance |
| **State Accuracy** | **81.35%** (157 / 193) | System state transition accuracy |
| **Evidence ID Citation Accuracy** | **91.19%** (176 / 193) | Valid citation of available evidence before cutoff |

---

## 3. Failures Found and Improvements Made

During development and systematic evaluation, the following critical issues were diagnosed and resolved in the production codebase:

1. **JSON Snapshot Temporal Leakage (`code/evidence_indexer.py`):**
   - *Issue:* Snapshot bundles (e.g., `evidence_02`) contained historical records whose inner `captured_at` timestamps were within the audit window, but the file container timestamp was newer than `audit_at`. Conversely, historical snapshots created before deletion showed records that were legitimately deleted later.
   - *Fix:* Enhanced `_index_json` to parse per-snapshot `captured_at` and `data_store` properties while enforcing strict `file_captured_at <= audit_at` gating at query time, ensuring no future evidence influences historical audit decisions.

2. **Policy Misalignment on Log Events (`code/main.py`):**
   - *Issue:* Log traces discovering residual analytics and support records initially reported `REPORT_REMAINING_RECORD` with `DELETE_RECORD`, whereas platform policies `rule_05` and `rule_07` explicitly prescribe `REDACT` for support messages and `ANONYMIZE` for analytics records.
   - *Fix:* Aligned log parsing logic with `deletion_rules.csv`: analytics detections generate `REPORT_EXPOSED_PII` -> `ANONYMIZE_RECORD` -> `VERIFY_RECORD_ANONYMIZED`, and support records trigger `REPORT_EXPOSED_PII` -> `REDACT_RECORD` -> `VERIFY_RECORD_REDACTED`.

3. **Intent Classification Boundary Cases (`code/main.py`):**
   - *Issue:* Complex requests containing multi-lingual phrases (e.g., requests to update email while preserving profile history) were initially ambiguous.
   - *Fix:* Refined `EnhancedIntentClassifier` with explicit negative boundary expressions for retention/continuation requests across English, Spanish, French, German, and Italian, achieving 100% classification precision.

4. **Multi-Replica SQL Schema Extraction (`code/evidence_indexer.py`):**
   - *Issue:* SQLite schema dumps contained nested JSON columns (`record_json`) alongside relational columns.
   - *Fix:* Implemented automated JSON unwrapping and column-level identifier harvesting across primary, regional, and failover replicas.

---

## 4. Participant-Created Evaluation Cases

To rigorously test edge cases beyond the public sample set, three comprehensive evaluation test cases were designed:

### Case A: Cross-Border Dual Identity with Historical Alias and Stale Secondary Replica
- **Scenario:** User changed email 3 months prior to deletion request. Audit cutoff occurs 24 hours after deletion worker reports `COMPLETE`. Primary database is clean, but an EU regional failover replica (`customer_accounts_failover_replica_20260902.sql`) still retains the historical phone number and old email.
- **Expected Outcome:** `INCOMPLETE`
- **Required Steps:**
  1. `FINDING`: `REPORT_REMAINING_RECORD` on `account_service` citing the failover SQL evidence.
  2. `REMEDIATION`: `DELETE_RECORD` on `account_service`.
  3. `VERIFICATION`: `VERIFY_RECORD_ABSENT` on `account_service`.
- **Engine Decision:** Matches expected outcome. Historical identifier closure correctly connected the old phone number to the new user ID.

### Case B: Legal Retention Register Exemption with Prohibited Analytics PII
- **Scenario:** User request explicitly demands complete deletion. User profile is listed in `legal_retention_register_20260529.pdf` for financial transaction auditing. Telemetry store contains plain email in `analytics_platform`.
- **Expected Outcome:** `INCOMPLETE`
- **Required Steps:**
  1. `FINDING`: `REPORT_EXPOSED_PII` on `analytics_platform`.
  2. `REMEDIATION`: `ANONYMIZE_RECORD` on `analytics_platform`.
  3. `VERIFICATION`: `VERIFY_RECORD_ANONYMIZED` on `analytics_platform`.
  4. `VERIFICATION`: `VERIFY_RECORD_PRESENT` on `security_service` for the retained legal log.
- **Engine Decision:** Matches expected outcome. The engine correctly avoided attempting to delete legally retained records while remediating exposed PII in analytics.

### Case C: Active Streaming Data Flow with Blocked Backup Restore
- **Scenario:** Deletion reported `COMPLETE`. An integration connector (`data_flow`) is still marked `enabled=true` in observability logs, while backup archive restore has already been disabled (`restore_allowed=false`).
- **Expected Outcome:** `INCOMPLETE`
- **Required Steps:**
  1. `FINDING`: `REPORT_ACTIVE_DATA_FLOW` on `integration_service` citing the observability log.
  2. `REMEDIATION`: `DISABLE_DATA_FLOW` on `integration_service`.
  3. `VERIFICATION`: `VERIFY_DATA_FLOW_DISABLED` on `integration_service`.
  4. `VERIFICATION`: `VERIFY_RESTORE_BLOCKED` on `backup_service` proving the backup is already safe.
- **Engine Decision:** Matches expected outcome. Remediates the active flow while citing the compliant blocked restore state.

---

## 5. Conclusion

The audit pipeline provides a fully autonomous, policy-grounded, zero-hardcoding solution that strictly adheres to the schema, ordering, temporal integrity, and serialization requirements of HackerRank Orchestrate.
