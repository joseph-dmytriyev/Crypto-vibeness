"""Authentication and password storage helpers for Crypto Vibeness."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bcrypt

DEFAULT_PASSWORD_DB = "this_is_safe.txt"
DEFAULT_RULES_FILE = "password_rules.json"
DEFAULT_BCRYPT_COST = 12
DEFAULT_SALT_BYTES = 12

LEGACY_ALGO = "md5"
MODERN_ALGO = "bcrypt"


@dataclass
class AuthRecord:
    """Represents one user entry in the password database."""

    username: str
    algo: str
    cost: int
    salt_b64: str
    hash_b64: str

    @property
    def is_legacy_md5(self) -> bool:
        """Return True if this record is in the old MD5 format."""
        return self.algo == LEGACY_ALGO


def _encode_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _load_rules(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        return []
    return [rule for rule in rules if isinstance(rule, dict)]


def validate_password(password: str, rules: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Validate a password against JSON-defined rules."""
    errors: list[str] = []

    for rule in rules:
        rule_type = str(rule.get("type", "")).strip()
        message = str(rule.get("message", "Password rule failed.")).strip()

        if rule_type == "min_length":
            min_len = int(rule.get("value", 0))
            if len(password) < min_len:
                errors.append(message)
        elif rule_type == "has_digit":
            if not any(ch.isdigit() for ch in password):
                errors.append(message)
        elif rule_type == "has_upper":
            if not any(ch.isupper() for ch in password):
                errors.append(message)

    return (len(errors) == 0, errors)


def calculate_shannon_entropy(password: str) -> float:
    """Return Shannon entropy estimate in bits for a password."""
    if not password:
        return 0.0

    counts: dict[str, int] = {}
    for char in password:
        counts[char] = counts.get(char, 0) + 1

    entropy_per_char = 0.0
    length = len(password)
    for count in counts.values():
        probability = count / length
        entropy_per_char -= probability * math.log2(probability)

    return entropy_per_char * length


def classify_password_strength(password: str) -> str:
    """Map entropy score to Faible/Moyen/Fort."""
    entropy = calculate_shannon_entropy(password)
    if entropy < 35:
        return "Faible"
    if entropy < 60:
        return "Moyen"
    return "Fort"


def _md5_hash_b64(password: str) -> str:
    digest = hashlib.md5(password.encode("utf-8")).digest()
    return _encode_b64(digest)


def _make_bcrypt_record(username: str, password: str, cost: int) -> AuthRecord:
    salt = os.urandom(DEFAULT_SALT_BYTES)
    prepared_password = salt + password.encode("utf-8")
    bcrypt_hash = bcrypt.hashpw(prepared_password, bcrypt.gensalt(rounds=cost))
    return AuthRecord(
        username=username,
        algo=MODERN_ALGO,
        cost=cost,
        salt_b64=_encode_b64(salt),
        hash_b64=_encode_b64(bcrypt_hash),
    )


def _parse_record(raw_line: str) -> AuthRecord | None:
    line = raw_line.strip()
    if not line or ":" not in line:
        return None

    parts = line.split(":")

    if len(parts) == 2:
        username, hash_b64 = parts
        if not username or not hash_b64:
            return None
        return AuthRecord(username=username, algo=LEGACY_ALGO, cost=0, salt_b64="", hash_b64=hash_b64)

    if len(parts) == 5:
        username, algo, cost_str, salt_b64, hash_b64 = parts
        if not username or not algo or not cost_str or not salt_b64 or not hash_b64:
            return None
        try:
            cost = int(cost_str)
        except ValueError:
            return None
        return AuthRecord(username=username, algo=algo, cost=cost, salt_b64=salt_b64, hash_b64=hash_b64)

    return None


def _serialize_record(record: AuthRecord) -> str:
    if record.is_legacy_md5:
        return f"{record.username}:{record.hash_b64}"
    return f"{record.username}:{record.algo}:{record.cost}:{record.salt_b64}:{record.hash_b64}"


class AuthManager:
    """Load rules, manage accounts, verify passwords, and migrate MD5 records."""

    def __init__(
        self,
        db_path: str = DEFAULT_PASSWORD_DB,
        rules_path: str = DEFAULT_RULES_FILE,
        bcrypt_cost: int = DEFAULT_BCRYPT_COST,
    ) -> None:
        self.db_path = Path(db_path)
        self.rules_path = Path(rules_path)
        self.bcrypt_cost = bcrypt_cost
        self.rules = _load_rules(self.rules_path)
        self.records: dict[str, AuthRecord] = {}
        self._load_records()

    def _load_records(self) -> None:
        self.records = {}
        if not self.db_path.exists():
            self.db_path.touch()
            return

        for raw_line in self.db_path.read_text(encoding="utf-8").splitlines():
            record = _parse_record(raw_line)
            if record is not None:
                self.records[record.username] = record

    def _persist_records(self) -> None:
        lines = [_serialize_record(record) for record in self.records.values()]
        payload = "\n".join(lines)
        if payload:
            payload += "\n"
        self.db_path.write_text(payload, encoding="utf-8")

    def user_exists(self, username: str) -> bool:
        """Return True if a username already exists in the password database."""
        return username in self.records

    def register_user(self, username: str, password: str, password_confirm: str) -> tuple[bool, str, str | None]:
        """Register a user and return (success, message, entropy_label)."""
        if not username or ":" in username:
            return False, "Invalid username.", None

        if self.user_exists(username):
            return False, "Username already exists.", None

        if password != password_confirm:
            return False, "Password confirmation does not match.", None

        valid, errors = validate_password(password, self.rules)
        if not valid:
            return False, "Password policy failed: " + "; ".join(errors), None

        entropy_label = classify_password_strength(password)

        new_record = _make_bcrypt_record(username=username, password=password, cost=self.bcrypt_cost)
        self.records[username] = new_record
        self._persist_records()
        return True, "Account created.", entropy_label

    def _verify_bcrypt_record(self, record: AuthRecord, password: str) -> bool:
        try:
            salt = _decode_b64(record.salt_b64)
            stored_hash = _decode_b64(record.hash_b64)
        except (ValueError, binascii.Error):
            return False

        candidate_hash = bcrypt.hashpw(salt + password.encode("utf-8"), stored_hash)
        return hmac.compare_digest(candidate_hash, stored_hash)

    def _verify_legacy_md5(self, record: AuthRecord, password: str) -> bool:
        candidate = _md5_hash_b64(password)
        return hmac.compare_digest(candidate, record.hash_b64)

    def _migrate_legacy_record(self, username: str, password: str) -> None:
        migrated = _make_bcrypt_record(username=username, password=password, cost=self.bcrypt_cost)
        self.records[username] = migrated
        self._persist_records()

    def authenticate_user(self, username: str, password: str) -> tuple[bool, str]:
        """Validate a login. Legacy MD5 records are migrated on successful login."""
        record = self.records.get(username)
        if record is None:
            return False, "Unknown username."

        if record.is_legacy_md5:
            if self._verify_legacy_md5(record, password):
                self._migrate_legacy_record(username, password)
                return True, "Login successful. Legacy hash migrated to bcrypt."
            return False, "Invalid password."

        if record.algo != MODERN_ALGO:
            return False, f"Unsupported algorithm: {record.algo}."

        if self._verify_bcrypt_record(record, password):
            return True, "Login successful."

        return False, "Invalid password."

    def create_legacy_md5_user_for_tests(self, username: str, password: str) -> None:
        """Create a legacy MD5 user record. Intended for controlled test setup only."""
        self.records[username] = AuthRecord(
            username=username,
            algo=LEGACY_ALGO,
            cost=0,
            salt_b64="",
            hash_b64=_md5_hash_b64(password),
        )
        self._persist_records()
