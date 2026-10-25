"""
Identity Resolver Module for HackerRank Orchestrate: Ghost Data Still Exists.

This module resolves and tracks identities across current snapshots (user_identities.csv)
and historical change logs (user_audit_log.csv).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class AuditEvent:
    audit_id: str
    user_id: str
    event_time: str
    field_name: str
    old_value: str
    new_value: str

    @property
    def timestamp(self) -> Optional[datetime]:
        try:
            # Format: 2026-05-28T04:03:00Z or similar ISO 8601
            return datetime.fromisoformat(self.event_time.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None


@dataclass
class IdentityClosure:
    user_id: str
    name: str
    current_email: str
    current_phone: str
    current_email_hash: str
    updated_at: str
    is_resolved: bool = True
    
    # Complete alias closures (current + historical)
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)
    
    # Audit history timeline
    audit_history: List[AuditEvent] = field(default_factory=list)

    def identifiers_as_of(self, as_of_iso: Optional[str] = None) -> Dict[str, Set[str]]:
        """
        Return the set of identifiers that existed at or prior to `as_of_iso`.
        If as_of_iso is None, returns all identifiers in the closure.
        """
        if not as_of_iso:
            return {
                "emails": set(self.emails),
                "phones": set(self.phones),
                "email_hashes": set(self.email_hashes),
            }

        try:
            cutoff = datetime.fromisoformat(as_of_iso.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            # Fallback to full closure if date parsing fails
            return {
                "emails": set(self.emails),
                "phones": set(self.phones),
                "email_hashes": set(self.email_hashes),
            }

        # Filter audit events that occurred before or at cutoff
        emails = {self.current_email.strip().lower()}
        phones = {self.current_phone.strip()}
        hashes = {self.current_email_hash.strip().lower()}

        for event in self.audit_history:
            if event.timestamp and event.timestamp <= cutoff:
                if event.field_name == "email":
                    if event.old_value:
                        emails.add(event.old_value.strip().lower())
                    if event.new_value:
                        emails.add(event.new_value.strip().lower())
                elif event.field_name == "phone":
                    if event.old_value:
                        phones.add(event.old_value.strip())
                    if event.new_value:
                        phones.add(event.new_value.strip())
                elif event.field_name == "email_hash":
                    if event.old_value:
                        hashes.add(event.old_value.strip().lower())
                    if event.new_value:
                        hashes.add(event.new_value.strip().lower())

        return {
            "emails": emails,
            "phones": phones,
            "email_hashes": hashes,
        }

    def contains_email(self, email: str) -> bool:
        """Exact case-insensitive match for any email associated with this user."""
        if not email:
            return False
        return email.strip().lower() in self.emails

    def contains_phone(self, phone: str) -> bool:
        """Exact match for any phone associated with this user."""
        if not phone:
            return False
        return phone.strip() in self.phones

    def contains_hash(self, email_hash: str) -> bool:
        """Exact case-insensitive match for any email hash associated with this user."""
        if not email_hash:
            return False
        return email_hash.strip().lower() in self.email_hashes


class IdentityResolver:
    """
    Builds and manages exact identity graphs from user_identities.csv and user_audit_log.csv.
    """

    def __init__(
        self,
        identities_path: str | Path = "dataset/user_identities.csv",
        audit_log_path: str | Path = "dataset/user_audit_log.csv",
    ) -> None:
        self.identities_path = Path(identities_path)
        self.audit_log_path = Path(audit_log_path)
        
        # Primary lookup tables
        self.users_by_id: Dict[str, IdentityClosure] = {}
        self.email_to_user_id: Dict[str, str] = {}
        self.phone_to_user_id: Dict[str, str] = {}
        self.hash_to_user_id: Dict[str, str] = {}
        
        # Ambiguity / collision tracking
        self.ambiguous_emails: Set[str] = set()

        self._load_identities()
        self._load_audit_log()

    @staticmethod
    def normalize_email(email: Optional[str]) -> str:
        """Normalize email string: strip whitespace and lowercase."""
        if not email:
            return ""
        return email.strip().lower()

    @staticmethod
    def normalize_phone(phone: Optional[str]) -> str:
        """Normalize phone string: strip outer whitespace."""
        if not phone:
            return ""
        return phone.strip()

    @staticmethod
    def normalize_hash(email_hash: Optional[str]) -> str:
        """Normalize hash string: strip whitespace and lowercase."""
        if not email_hash:
            return ""
        return email_hash.strip().lower()

    def _load_identities(self) -> None:
        if not self.identities_path.exists():
            raise FileNotFoundError(f"Identities file not found: {self.identities_path}")

        with open(self.identities_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                user_id = row["user_id"].strip()
                name = row["name"].strip()
                email = row["email"].strip()
                phone = row["phone"].strip()
                email_hash = row["email_hash"].strip()
                updated_at = row["updated_at"].strip()

                norm_email = self.normalize_email(email)
                norm_phone = self.normalize_phone(phone)
                norm_hash = self.normalize_hash(email_hash)

                closure = IdentityClosure(
                    user_id=user_id,
                    name=name,
                    current_email=email,
                    current_phone=phone,
                    current_email_hash=email_hash,
                    updated_at=updated_at,
                    emails={norm_email},
                    phones={norm_phone},
                    email_hashes={norm_hash},
                )
                self.users_by_id[user_id] = closure

                # Map current identifiers
                if norm_email:
                    if norm_email in self.email_to_user_id and self.email_to_user_id[norm_email] != user_id:
                        self.ambiguous_emails.add(norm_email)
                    else:
                        self.email_to_user_id[norm_email] = user_id

                if norm_phone:
                    self.phone_to_user_id[norm_phone] = user_id

                if norm_hash:
                    self.hash_to_user_id[norm_hash] = user_id

    def _load_audit_log(self) -> None:
        if not self.audit_log_path.exists():
            raise FileNotFoundError(f"Audit log file not found: {self.audit_log_path}")

        with open(self.audit_log_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                audit_id = row["audit_id"].strip()
                user_id = row["user_id"].strip()
                event_time = row["event_time"].strip()
                field_name = row["field_name"].strip()
                old_val = row["old_value"].strip()
                new_val = row["new_value"].strip()

                event = AuditEvent(
                    audit_id=audit_id,
                    user_id=user_id,
                    event_time=event_time,
                    field_name=field_name,
                    old_value=old_val,
                    new_value=new_val,
                )

                closure = self.users_by_id.get(user_id)
                if not closure:
                    continue

                closure.audit_history.append(event)

                if field_name == "email":
                    for val in (old_val, new_val):
                        norm = self.normalize_email(val)
                        if norm:
                            closure.emails.add(norm)
                            if norm in self.email_to_user_id and self.email_to_user_id[norm] != user_id:
                                self.ambiguous_emails.add(norm)
                            else:
                                self.email_to_user_id[norm] = user_id

                elif field_name == "phone":
                    for val in (old_val, new_val):
                        norm = self.normalize_phone(val)
                        if norm:
                            closure.phones.add(norm)
                            if norm not in self.phone_to_user_id:
                                self.phone_to_user_id[norm] = user_id

                elif field_name == "email_hash":
                    for val in (old_val, new_val):
                        norm = self.normalize_hash(val)
                        if norm:
                            closure.email_hashes.add(norm)
                            if norm not in self.hash_to_user_id:
                                self.hash_to_user_id[norm] = user_id

    def resolve_email(self, email: Optional[str]) -> Optional[IdentityClosure]:
        """
        Resolve an email address (current or historical) to its canonical IdentityClosure.
        Returns None if not found or ambiguous.
        """
        norm_email = self.normalize_email(email)
        if not norm_email or norm_email in self.ambiguous_emails:
            return None

        user_id = self.email_to_user_id.get(norm_email)
        if not user_id:
            return None

        return self.users_by_id.get(user_id)

    def resolve_user_id(self, user_id: Optional[str]) -> Optional[IdentityClosure]:
        """Retrieve IdentityClosure by canonical user_id."""
        if not user_id:
            return None
        return self.users_by_id.get(user_id.strip())

    def resolve_phone(self, phone: Optional[str]) -> Optional[IdentityClosure]:
        """Resolve a phone number to its canonical IdentityClosure."""
        norm_phone = self.normalize_phone(phone)
        if not norm_phone:
            return None
        user_id = self.phone_to_user_id.get(norm_phone)
        if not user_id:
            return None
        return self.users_by_id.get(user_id)

    def resolve_hash(self, email_hash: Optional[str]) -> Optional[IdentityClosure]:
        """Resolve an email hash to its canonical IdentityClosure."""
        norm_hash = self.normalize_hash(email_hash)
        if not norm_hash:
            return None
        user_id = self.hash_to_user_id.get(norm_hash)
        if not user_id:
            return None
        return self.users_by_id.get(user_id)
