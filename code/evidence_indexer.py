"""
Evidence Ingestion & Extraction Engine for HackerRank Orchestrate: Ghost Data Still Exists.

This module is responsible for:
1. Ingesting dataset/evidence_files.csv manifest and resolving physical file paths safely.
2. Ingesting and parsing structured and unstructured evidence:
   - SQL snapshot exports (via in-memory SQLite tables)
   - JSON records and snapshot bundles
   - Log files (line-by-line structured/syslog/trace logs)
   - PDF documents (page-by-page text extraction via PyMuPDF)
   - PNG images (OCR dashboard text and bounding boxes)
   - TXT files (system handover notes)
3. Preserving provenance: evidence_id, relative path, origin, capture timestamp,
   record timestamp, system_id, resource_id, table/section, line/page.
4. Building multi-dimensional inverted indices:
   - by evidence_id
   - by identifier (user_id, email, phone, email_hash, account_id, etc.)
   - by resource_id
   - by system_id
   - by file format
5. Integrating with IdentityClosure to find all evidence matching a user's alias set,
   with temporal filtering against audit_at.
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Try importing fitz (PyMuPDF)
try:
    import fitz
    HAS_FITZ = True
except ImportError:
    HAS_FITZ = False


@dataclass(frozen=True)
class ManifestEntry:
    file_id: str
    file_path: str
    origin: str
    captured_at: str
    resolved_path: Path
    file_format: str


@dataclass
class EvidenceFinding:
    evidence_id: str
    relative_path: str
    file_format: str
    origin: str
    file_captured_at: str
    record_timestamp: Optional[str]
    system_id: str
    resource_id: str
    table_or_source: str
    line_or_page: Optional[int]
    identifiers: Set[str]
    data: Dict[str, Any] | str
    provenance_type: str  # 'stored_record', 'log_event', 'config_setting', 'audit_record', 'dashboard_view', 'document_text'

    @property
    def effective_timestamp(self) -> Optional[datetime]:
        """Returns parsed record_timestamp if available, otherwise file_captured_at."""
        ts_str = self.record_timestamp or self.file_captured_at
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None


class EvidenceIndexer:
    """
    Ingests and indexes all evidence files declared in evidence_files.csv.
    """

    def __init__(
        self,
        manifest_path: str | Path = "dataset/evidence_files.csv",
        dataset_root: str | Path = "dataset",
        ocr_cache_path: str | Path = "code/evidence_cache/ocr_cache.json",
    ) -> None:
        self.manifest_path = Path(manifest_path)
        self.dataset_root = Path(dataset_root)
        self.ocr_cache_path = Path(ocr_cache_path)

        self.manifest_entries: List[ManifestEntry] = []
        self.missing_files: List[Tuple[str, str]] = []
        self.findings: List[EvidenceFinding] = []

        # Inverted indices
        self.by_evidence_id: Dict[str, List[EvidenceFinding]] = {}
        self.by_identifier: Dict[str, List[EvidenceFinding]] = {}
        self.by_resource_id: Dict[str, List[EvidenceFinding]] = {}
        self.by_system_id: Dict[str, List[EvidenceFinding]] = {}
        self.by_format: Dict[str, List[EvidenceFinding]] = {}

        # Tracking metrics for extraction report
        self.parsing_stats: Dict[str, int] = {
            "sql": 0,
            "json": 0,
            "log": 0,
            "pdf": 0,
            "image": 0,
            "txt": 0,
        }
        self.parsing_errors: List[Tuple[str, str]] = []

        self._load_manifest()

    def _load_manifest(self) -> None:
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found: {self.manifest_path}")

        with open(self.manifest_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                file_id = row["file_id"].strip()
                rel_path = row["file_path"].strip()
                origin = row["origin"].strip()
                captured_at = row["captured_at"].strip()

                full_path = self.dataset_root / rel_path
                suffix = full_path.suffix.lower()
                fmt_map = {
                    ".sql": "sql",
                    ".json": "json",
                    ".log": "log",
                    ".pdf": "pdf",
                    ".png": "image",
                    ".jpg": "image",
                    ".jpeg": "image",
                    ".txt": "txt",
                }
                file_format = fmt_map.get(suffix, "unknown")

                if not full_path.exists():
                    self.missing_files.append((file_id, str(full_path)))
                    continue

                entry = ManifestEntry(
                    file_id=file_id,
                    file_path=rel_path,
                    origin=origin,
                    captured_at=captured_at,
                    resolved_path=full_path,
                    file_format=file_format,
                )
                self.manifest_entries.append(entry)

    def index_all(self) -> None:
        """Parse and index every manifest entry."""
        self.findings.clear()
        self.by_evidence_id.clear()
        self.by_identifier.clear()
        self.by_resource_id.clear()
        self.by_system_id.clear()
        self.by_format.clear()

        # Load OCR cache if present
        ocr_cache = {}
        if self.ocr_cache_path.exists():
            try:
                with open(self.ocr_cache_path, "r", encoding="utf-8") as fp:
                    ocr_cache = json.load(fp)
            except Exception as e:
                self.parsing_errors.append((str(self.ocr_cache_path), f"Failed reading OCR cache: {e}"))

        for entry in self.manifest_entries:
            try:
                if entry.file_format == "sql":
                    self._index_sql(entry)
                    self.parsing_stats["sql"] += 1
                elif entry.file_format == "json":
                    self._index_json(entry)
                    self.parsing_stats["json"] += 1
                elif entry.file_format == "log":
                    self._index_log(entry)
                    self.parsing_stats["log"] += 1
                elif entry.file_format == "pdf":
                    self._index_pdf(entry)
                    self.parsing_stats["pdf"] += 1
                elif entry.file_format == "image":
                    self._index_image(entry, ocr_cache)
                    self.parsing_stats["image"] += 1
                elif entry.file_format == "txt":
                    self._index_txt(entry)
                    self.parsing_stats["txt"] += 1
            except Exception as e:
                self.parsing_errors.append((entry.file_id, f"Error parsing {entry.file_path}: {e}"))

        # Build indices
        for finding in self.findings:
            # By evidence_id
            self.by_evidence_id.setdefault(finding.evidence_id, []).append(finding)
            # By format
            self.by_format.setdefault(finding.file_format, []).append(finding)
            # By system_id
            if finding.system_id:
                self.by_system_id.setdefault(finding.system_id, []).append(finding)
            # By resource_id
            if finding.resource_id:
                self.by_resource_id.setdefault(finding.resource_id, []).append(finding)
            # By identifier
            for ident in finding.identifiers:
                norm_ident = ident.strip().lower()
                if norm_ident:
                    self.by_identifier.setdefault(norm_ident, []).append(finding)

    def _extract_identifiers(self, text_or_dict: Any) -> Set[str]:
        """Extract user_ids, emails, phones, and hashes from text or dict."""
        idents: Set[str] = set()
        if isinstance(text_or_dict, dict):
            for k, v in text_or_dict.items():
                if isinstance(v, str):
                    self._collect_string_identifiers(v, idents)
                elif isinstance(v, (dict, list)):
                    idents.update(self._extract_identifiers(v))
        elif isinstance(text_or_dict, list):
            for item in text_or_dict:
                idents.update(self._extract_identifiers(item))
        elif isinstance(text_or_dict, str):
            self._collect_string_identifiers(text_or_dict, idents)
        return idents

    def _collect_string_identifiers(self, s: str, target_set: Set[str]) -> None:
        # Match user_XX
        user_matches = re.findall(r"\buser_[0-9]+\b", s)
        for u in user_matches:
            target_set.add(u.lower())

        # Match emails
        email_matches = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", s)
        for e in email_matches:
            target_set.add(e.lower())

        # Match phones: international formats (+XX ..., or standard digits)
        phone_matches = re.findall(r"\+[0-9]{1,3}\s+[0-9\s-]{6,16}\b", s)
        for p in phone_matches:
            target_set.add(p.strip())

        # Match 64-char hex hashes (SHA-256)
        hash_matches = re.findall(r"\b[a-fA-F0-9]{64}\b", s)
        for h in hash_matches:
            target_set.add(h.lower())

        # Match resource identifiers like account_XXX, search_XXX, support_XXX, export_XXX, etc.
        res_matches = re.findall(r"\b(account|search|support|export|analytics|audit_record|backup)_[0-9]+\b", s)
        # Note: re.findall with group returns group, finditer gives full match:
        for m in re.finditer(r"\b(account|search|support|export|analytics|audit_record|backup)_[0-9]+\b", s):
            target_set.add(m.group(0).lower())

    def _infer_system_id(self, origin: str, table_or_source: str) -> str:
        s = f"{origin} {table_or_source}".lower()
        if "account" in s or "customer_profile" in s:
            return "account_service"
        elif "search" in s:
            return "search_index"
        elif "support" in s or "ticket" in s:
            return "support_platform"
        elif "analytics" in s:
            return "product_analytics"
        elif "export" in s:
            return "export_service"
        elif "backup" in s or "failover" in s:
            return "backup_service"
        elif "security" in s or "compliance" in s:
            return "security_audit"
        elif "connector" in s or "integration" in s:
            return "connector_service"
        elif "marketing" in s:
            return "marketing_platform"
        elif "notification" in s or "email" in s or "delivery" in s:
            return "email_service"
        return "core_platform"

    def _index_sql(self, entry: ManifestEntry) -> None:
        with open(entry.resolved_path, "r", encoding="utf-8") as f:
            script = f.read()

        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(script)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cursor.fetchall()]

            for table in tables:
                cursor.execute(f"PRAGMA table_info('{table}')")
                cols = [c[1] for c in cursor.fetchall()]

                cursor.execute(f"SELECT * FROM '{table}'")
                rows = cursor.fetchall()

                for row_idx, row in enumerate(rows, start=1):
                    row_dict = dict(zip(cols, row))
                    idents = self._extract_identifiers(row_dict)

                    res_id = str(row_dict.get("resource_id") or row_dict.get("id") or "")
                    if "record_json" in row_dict and isinstance(row_dict["record_json"], str):
                        try:
                            pj = json.loads(row_dict["record_json"])
                            idents.update(self._extract_identifiers(pj))
                            if not res_id and pj.get("resource_id"):
                                res_id = str(pj["resource_id"])
                        except Exception:
                            pass

                    if res_id:
                        idents.add(res_id.lower())

                    # Record timestamp
                    ts = row_dict.get("updated_at") or row_dict.get("created_at") or row_dict.get("timestamp") or row_dict.get("event_time")
                    system_id = self._infer_system_id(entry.origin, table)

                    finding = EvidenceFinding(
                        evidence_id=entry.file_id,
                        relative_path=entry.file_path,
                        file_format="sql",
                        origin=entry.origin,
                        file_captured_at=entry.captured_at,
                        record_timestamp=str(ts) if ts else None,
                        system_id=system_id,
                        resource_id=res_id,
                        table_or_source=table,
                        line_or_page=row_idx,
                        identifiers=idents,
                        data=row_dict,
                        provenance_type="stored_record",
                    )
                    self.findings.append(finding)
        finally:
            conn.close()

    def _index_json(self, entry: ManifestEntry) -> None:
        with open(entry.resolved_path, "r", encoding="utf-8") as f:
            content = json.load(f)

        records = []
        if isinstance(content, list):
            records = content
        elif isinstance(content, dict):
            if "records" in content and isinstance(content["records"], list):
                records = content["records"]
            elif "snapshots" in content and isinstance(content["snapshots"], list):
                for snap in content["snapshots"]:
                    snap_ts = snap.get("captured_at")
                    snap_store = snap.get("data_store")
                    for r in snap.get("records", []):
                        if isinstance(r, dict):
                            r_copy = dict(r)
                            if snap_ts:
                                r_copy["captured_at"] = snap_ts
                                if "timestamp" not in r_copy:
                                    r_copy["timestamp"] = snap_ts
                            if snap_store and "data_store" not in r_copy:
                                r_copy["data_store"] = snap_store
                            records.append(r_copy)
                        else:
                            records.append(r)
            elif "service_exports" in content and isinstance(content["service_exports"], dict):
                for sys_name, sys_dict in content["service_exports"].items():
                    if isinstance(sys_dict, dict):
                        for coll_name, items in sys_dict.items():
                            if isinstance(items, list):
                                for item in items:
                                    if isinstance(item, dict):
                                        item_copy = dict(item)
                                        item_copy["_system_id"] = sys_name
                                        item_copy["_collection"] = coll_name
                                        records.append(item_copy)
            else:
                records = [content]

        for idx, rec in enumerate(records, start=1):
            if isinstance(rec, dict):
                idents = self._extract_identifiers(rec)
                res_id = str(rec.get("resource_id") or rec.get("job_id") or rec.get("connector_id") or rec.get("record_id") or "")
                if res_id:
                    idents.add(res_id.lower())
                ts = rec.get("timestamp") or rec.get("created_at") or rec.get("updated_at") or rec.get("event_time") or rec.get("captured_at") or rec.get("observed_at")
                system_id = rec.get("_system_id") or rec.get("data_store") or self._infer_system_id(entry.origin, entry.file_path)

                finding = EvidenceFinding(
                    evidence_id=entry.file_id,
                    relative_path=entry.file_path,
                    file_format="json",
                    origin=entry.origin,
                    file_captured_at=entry.captured_at,
                    record_timestamp=str(ts) if ts else None,
                    system_id=system_id,
                    resource_id=res_id,
                    table_or_source=rec.get("_collection") or entry.resolved_path.stem,
                    line_or_page=idx,
                    identifiers=idents,
                    data=rec,
                    provenance_type="stored_record" if "export" in entry.file_path or "snapshot" in entry.file_path else "configuration",
                )
                self.findings.append(finding)

    def _index_log(self, entry: ManifestEntry) -> None:
        with open(entry.resolved_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        default_system_id = self._infer_system_id(entry.origin, entry.file_path)

        # First pass: correlate distributed trace spans by trace_id
        trace_idents: Dict[str, Set[str]] = defaultdict(set)
        for line in lines:
            m = re.search(r'(?:trace_id|traceId)[":=\s]+([A-Za-z0-9_-]+)', line)
            if m:
                tid = m.group(1)
                tid_idents = self._extract_identifiers(line)
                if tid_idents:
                    trace_idents[tid].update(tid_idents)

        for line_no, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue

            idents = self._extract_identifiers(line)

            # Correlate with trace if present
            m = re.search(r'(?:trace_id|traceId)[":=\s]+([A-Za-z0-9_-]+)', line)
            if m and m.group(1) in trace_idents:
                idents.update(trace_idents[m.group(1)])

            # Try parsing timestamp from beginning of line (e.g. 2026-07-30T10:14:22Z or [2026-07-30...])
            ts_match = re.search(r"\b(2026-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z?)\b", line)
            ts = ts_match.group(1) if ts_match else None

            # Resource id
            res_match = re.search(r"\b(account|search|support|export|analytics|audit_record|backup|data_flow)_[0-9]+\b", line)
            res_id = res_match.group(0) if res_match else ""
            if res_id:
                idents.add(res_id.lower())

            # Fine-grained system_id from line if available
            system_id = default_system_id
            for sys_kw in (
                "account_service", "search_service", "support_platform",
                "analytics_platform", "export_service", "backup_service",
                "security_service", "integration_service"
            ):
                if sys_kw in line:
                    system_id = sys_kw
                    break

            # Only index log lines that contain relevant identifiers or operational states
            if idents or "sync" in line.lower() or "restore" in line.lower() or "delete" in line.lower():
                finding = EvidenceFinding(
                    evidence_id=entry.file_id,
                    relative_path=entry.file_path,
                    file_format="log",
                    origin=entry.origin,
                    file_captured_at=entry.captured_at,
                    record_timestamp=ts,
                    system_id=system_id,
                    resource_id=res_id,
                    table_or_source=entry.resolved_path.name,
                    line_or_page=line_no,
                    identifiers=idents,
                    data=line,
                    provenance_type="log_event",
                )
                self.findings.append(finding)

    def _index_pdf(self, entry: ManifestEntry) -> None:
        if not HAS_FITZ:
            self.parsing_errors.append((entry.file_id, "fitz (PyMuPDF) not installed"))
            return

        doc = fitz.open(entry.resolved_path)
        system_id = self._infer_system_id(entry.origin, entry.file_path)
        try:
            for page_no in range(len(doc)):
                page = doc[page_no]
                text = page.get_text()
                idents = self._extract_identifiers(text)

                res_match = re.search(r"\b(account|support|audit_record|legal|order)_[0-9A-Za-z-]+\b", text)
                res_id = res_match.group(0) if res_match else ""

                finding = EvidenceFinding(
                    evidence_id=entry.file_id,
                    relative_path=entry.file_path,
                    file_format="pdf",
                    origin=entry.origin,
                    file_captured_at=entry.captured_at,
                    record_timestamp=None,
                    system_id=system_id,
                    resource_id=res_id,
                    table_or_source=f"Page {page_no + 1}",
                    line_or_page=page_no + 1,
                    identifiers=idents,
                    data=text,
                    provenance_type="document_text",
                )
                self.findings.append(finding)
        finally:
            doc.close()

    def _index_image(self, entry: ManifestEntry, ocr_cache: Dict[str, Any]) -> None:
        fname = entry.resolved_path.name
        cached = ocr_cache.get(fname)
        system_id = self._infer_system_id(entry.origin, fname)

        if cached and "full_text" in cached:
            text = cached["full_text"]
            idents = self._extract_identifiers(text)
            res_match = re.search(r"\b(account|search|support|export|backup|connector)_[0-9]+\b", text)
            res_id = res_match.group(0) if res_match else ""

            finding = EvidenceFinding(
                evidence_id=entry.file_id,
                relative_path=entry.file_path,
                file_format="image",
                origin=entry.origin,
                file_captured_at=entry.captured_at,
                record_timestamp=None,
                system_id=system_id,
                resource_id=res_id,
                table_or_source=fname,
                line_or_page=1,
                identifiers=idents,
                data={
                    "full_text": text,
                    "total_boxes": cached.get("total_boxes", 0),
                },
                provenance_type="dashboard_view",
            )
            self.findings.append(finding)
        else:
            # Fallback when OCR cache not present
            finding = EvidenceFinding(
                evidence_id=entry.file_id,
                relative_path=entry.file_path,
                file_format="image",
                origin=entry.origin,
                file_captured_at=entry.captured_at,
                record_timestamp=None,
                system_id=system_id,
                resource_id="",
                table_or_source=fname,
                line_or_page=1,
                identifiers=set(),
                data=f"Image {fname} (pending OCR)",
                provenance_type="dashboard_view",
            )
            self.findings.append(finding)

    def _index_txt(self, entry: ManifestEntry) -> None:
        with open(entry.resolved_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        system_id = self._infer_system_id(entry.origin, entry.file_path)
        text = "".join(lines)
        idents = self._extract_identifiers(text)
        finding = EvidenceFinding(
            evidence_id=entry.file_id,
            relative_path=entry.file_path,
            file_format="txt",
            origin=entry.origin,
            file_captured_at=entry.captured_at,
            record_timestamp=None,
            system_id=system_id,
            resource_id="",
            table_or_source=entry.resolved_path.name,
            line_or_page=1,
            identifiers=idents,
            data=text,
            provenance_type="document_text",
        )
        self.findings.append(finding)

    def find_by_identifier(
        self,
        identifier: str,
        audit_at: Optional[str] = None,
    ) -> List[EvidenceFinding]:
        """Query findings matching an exact identifier with optional audit_at cutoff."""
        norm = identifier.strip().lower()
        candidates = self.by_identifier.get(norm, [])
        if not audit_at:
            return list(candidates)

        cutoff = None
        try:
            cutoff = datetime.fromisoformat(audit_at.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass

        if not cutoff:
            return list(candidates)

        results = []
        for f in candidates:
            if f.file_captured_at:
                try:
                    f_cap = datetime.fromisoformat(f.file_captured_at.replace("Z", "+00:00"))
                    if f_cap > cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
            eff_ts = f.effective_timestamp
            if eff_ts is None or eff_ts <= cutoff:
                results.append(f)
        return results

    def find_for_identity_closure(
        self,
        closure: Any,  # IdentityClosure
        audit_at: Optional[str] = None,
    ) -> List[EvidenceFinding]:
        """
        Query all findings matching any identifier in the given IdentityClosure,
        respecting temporal cutoff audit_at.
        """
        seen_keys: Set[Tuple[str, str, int]] = set()
        matched: List[EvidenceFinding] = []

        # Get identifiers relevant up to audit_at
        id_dict = closure.identifiers_as_of(audit_at)
        all_idents = {closure.user_id.lower()} | id_dict["emails"] | id_dict["phones"] | id_dict["email_hashes"]

        # Also add derived account reference if user_id format is user_XX -> account_XX
        # e.g., user_01 -> account_001 or account_01
        m = re.match(r"user_([0-9]+)", closure.user_id)
        if m:
            num = int(m.group(1))
            all_idents.add(f"account_{num:03d}")
            all_idents.add(f"account_{num}")

        for ident in all_idents:
            findings = self.find_by_identifier(ident, audit_at=audit_at)
            for f in findings:
                key = (f.evidence_id, f.table_or_source, f.line_or_page or 0)
                if key not in seen_keys:
                    seen_keys.add(key)
                    matched.append(f)

        return matched

    def get_extraction_report(self) -> Dict[str, Any]:
        """Generate audit report of processed manifest entries and extracted findings."""
        with_ts = sum(1 for f in self.findings if f.record_timestamp is not None)
        with_prov = sum(1 for f in self.findings if f.provenance_type and f.table_or_source)

        return {
            "manifest_entries_total": len(self.manifest_entries) + len(self.missing_files),
            "manifest_entries_processed": len(self.manifest_entries),
            "missing_files_count": len(self.missing_files),
            "missing_files": self.missing_files,
            "parsing_stats_by_format": dict(self.parsing_stats),
            "parsing_errors_count": len(self.parsing_errors),
            "parsing_errors": self.parsing_errors,
            "total_extracted_findings": len(self.findings),
            "findings_with_record_timestamp": with_ts,
            "findings_with_provenance": with_prov,
            "unique_identifiers_indexed": len(self.by_identifier),
            "unique_resources_indexed": len(self.by_resource_id),
            "unique_systems_indexed": len(self.by_system_id),
        }
