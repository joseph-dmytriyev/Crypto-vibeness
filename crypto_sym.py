"""Symmetric crypto helpers: PBKDF2 key derivation + AES-GCM encryption."""

from __future__ import annotations

import base64
import binascii
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_SERVER_KEY_DB = "logs/user_keys_do_not_steal_plz.txt"
DEFAULT_CLIENT_USERS_DIR = "users"
DEFAULT_KDF_ALGO = "pbkdf2"
DEFAULT_KDF_COST = 200_000
DEFAULT_SALT_BYTES = 12
DEFAULT_KEY_SIZE = 32
DEFAULT_NONCE_BYTES = 12


@dataclass
class KeyRecord:
    """Represents one persisted KDF output."""

    username: str
    kdf_algo: str
    cost: int
    salt_b64: str
    key_b64: str


def _encode_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def derive_key_pbkdf2(
    secret: str,
    salt: bytes | None = None,
    iterations: int = DEFAULT_KDF_COST,
    key_size: int = DEFAULT_KEY_SIZE,
) -> tuple[bytes, bytes, int]:
    """Derive a key from a user-provided secret using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(DEFAULT_SALT_BYTES)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(secret.encode("utf-8"))
    return key, salt, iterations


def _parse_record_line(line: str) -> KeyRecord | None:
    parts = line.strip().split(":")
    if len(parts) != 5:
        return None

    username, kdf_algo, cost_str, salt_b64, key_b64 = parts
    if not username or not kdf_algo or not cost_str or not salt_b64 or not key_b64:
        return None

    try:
        cost = int(cost_str)
    except ValueError:
        return None

    return KeyRecord(
        username=username,
        kdf_algo=kdf_algo,
        cost=cost,
        salt_b64=salt_b64,
        key_b64=key_b64,
    )


def _serialize_record(record: KeyRecord) -> str:
    return (
        f"{record.username}:{record.kdf_algo}:{record.cost}:"
        f"{record.salt_b64}:{record.key_b64}"
    )


def _load_server_records(db_path: Path) -> dict[str, KeyRecord]:
    records: dict[str, KeyRecord] = {}
    if not db_path.exists():
        db_path.touch()
        return records

    for raw_line in db_path.read_text(encoding="utf-8").splitlines():
        record = _parse_record_line(raw_line)
        if record is not None:
            records[record.username] = record
    return records


def _persist_server_records(db_path: Path, records: dict[str, KeyRecord]) -> None:
    content = "\n".join(_serialize_record(record) for record in records.values())
    if content:
        content += "\n"
    db_path.write_text(content, encoding="utf-8")


def get_or_create_server_key(
    username: str,
    secret: str,
    db_path: str = DEFAULT_SERVER_KEY_DB,
    iterations: int = DEFAULT_KDF_COST,
) -> bytes:
    """Return user key from server storage, or create one from secret if missing."""
    key_db_path = Path(db_path)
    records = _load_server_records(key_db_path)

    existing = records.get(username)
    if existing is not None:
        try:
            salt = _decode_b64(existing.salt_b64)
            stored_key = _decode_b64(existing.key_b64)
        except (ValueError, binascii.Error):
            raise ValueError("Corrupted key record") from None

        derived_key, _, _ = derive_key_pbkdf2(secret=secret, salt=salt, iterations=existing.cost)
        if not hmac.compare_digest(derived_key, stored_key):
            raise ValueError("Invalid encryption secret")
        return stored_key

    new_key, new_salt, used_iterations = derive_key_pbkdf2(secret=secret, iterations=iterations)
    records[username] = KeyRecord(
        username=username,
        kdf_algo=DEFAULT_KDF_ALGO,
        cost=used_iterations,
        salt_b64=_encode_b64(new_salt),
        key_b64=_encode_b64(new_key),
    )
    _persist_server_records(key_db_path, records)
    return new_key


def get_server_key_config(
    username: str,
    db_path: str = DEFAULT_SERVER_KEY_DB,
) -> tuple[int, bytes]:
    """
    Return persisted PBKDF2 configuration for a server-side user key.

    Returns:
        tuple[int, bytes]: (iterations, salt_bytes)
    """
    key_db_path = Path(db_path)
    records = _load_server_records(key_db_path)
    record = records.get(username)
    if record is None:
        raise ValueError("Missing key record")
    try:
        salt = _decode_b64(record.salt_b64)
    except (ValueError, binascii.Error):
        raise ValueError("Corrupted key record") from None
    return record.cost, salt


def _client_key_path(username: str, users_dir: str = DEFAULT_CLIENT_USERS_DIR) -> Path:
    return Path(users_dir) / username / "key.txt"


def get_or_create_client_key(
    username: str,
    secret: str,
    users_dir: str = DEFAULT_CLIENT_USERS_DIR,
    iterations: int = DEFAULT_KDF_COST,
) -> bytes:
    """Return user key from local client storage, or create one if missing."""
    key_path = _client_key_path(username, users_dir=users_dir)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        raw = key_path.read_text(encoding="utf-8").strip()
        parts = raw.split(":")
        if len(parts) != 4:
            raise ValueError("Invalid local key format")

        kdf_algo, cost_str, salt_b64, key_b64 = parts
        if kdf_algo != DEFAULT_KDF_ALGO:
            raise ValueError("Unsupported local key algorithm")

        try:
            cost = int(cost_str)
            salt = _decode_b64(salt_b64)
            stored_key = _decode_b64(key_b64)
        except (ValueError, binascii.Error):
            raise ValueError("Corrupted local key file") from None

        derived_key, _, _ = derive_key_pbkdf2(secret=secret, salt=salt, iterations=cost)
        if not hmac.compare_digest(derived_key, stored_key):
            raise ValueError("Invalid encryption secret")
        return stored_key

    key, salt, used_iterations = derive_key_pbkdf2(secret=secret, iterations=iterations)
    key_path.write_text(
        f"{DEFAULT_KDF_ALGO}:{used_iterations}:{_encode_b64(salt)}:{_encode_b64(key)}\n",
        encoding="utf-8",
    )
    return key


def encrypt_message(plaintext: str, key: bytes) -> str:
    """Encrypt UTF-8 plaintext and return a base64 payload (nonce + ciphertext)."""
    if len(key) < 16:
        raise ValueError("AES key must be at least 16 bytes")

    aesgcm = AESGCM(key)
    nonce = os.urandom(DEFAULT_NONCE_BYTES)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return _encode_b64(nonce + ciphertext)


def decrypt_message(payload_b64: str, key: bytes) -> str:
    """Decrypt a base64 payload (nonce + ciphertext) back to UTF-8 text."""
    if len(key) < 16:
        raise ValueError("AES key must be at least 16 bytes")

    try:
        blob = _decode_b64(payload_b64)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid encrypted payload") from None

    if len(blob) <= DEFAULT_NONCE_BYTES:
        raise ValueError("Encrypted payload is too short")

    nonce = blob[:DEFAULT_NONCE_BYTES]
    ciphertext = blob[DEFAULT_NONCE_BYTES:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


# =============================================================================
# SymmetricEncryption class (Dev 3 E2EE integration)
# =============================================================================

from typing import Tuple


class SymmetricEncryption:
    """
    Handles symmetric AES-GCM encryption and decryption for E2EE.
    
    Each message is encrypted with a random nonce (IV) to prevent
    pattern analysis. The nonce is prepended to the ciphertext.
    
    This class provides a higher-level interface for E2EE module compatibility.
    """
    
    ALGORITHM = "AES-256-GCM"
    KEY_SIZE = 32  # 256-bit key
    NONCE_SIZE = 12  # 96-bit nonce (12 bytes) for GCM
    TAG_SIZE = 16  # 128-bit authentication tag
    KDF_ITERATIONS = 100000
    
    def __init__(self):
        """Initialize symmetric encryption handler."""
        pass
    
    @staticmethod
    def generate_session_key() -> bytes:
        """
        Generate a random session key for AES-256-GCM.
        
        Returns:
            bytes: 32-byte (256-bit) random key
        """
        return os.urandom(SymmetricEncryption.KEY_SIZE)
    
    def encrypt_message(self, plaintext: str, key: bytes) -> str:
        """
        Encrypt a plaintext message using AES-256-GCM.
        
        The output format is: base64(nonce || ciphertext || tag)
        
        Args:
            plaintext: Message to encrypt (str)
            key: Session key (32 bytes for AES-256)
        
        Returns:
            str: Base64-encoded encrypted message (nonce + ciphertext + tag)
        """
        if len(key) != SymmetricEncryption.KEY_SIZE:
            raise ValueError(f"Key must be {SymmetricEncryption.KEY_SIZE} bytes, got {len(key)}")
        
        # Generate a random nonce for this message
        nonce = os.urandom(SymmetricEncryption.NONCE_SIZE)
        
        # Create cipher object and encrypt
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Combine nonce + ciphertext (tag is already appended by AESGCM)
        payload = nonce + ciphertext
        
        # Return base64-encoded payload
        return base64.b64encode(payload).decode('utf-8')
    
    def decrypt_message(self, payload_b64: str, key: bytes) -> str:
        """
        Decrypt a message encrypted with encrypt_message.
        
        Args:
            payload_b64: Base64-encoded encrypted message
            key: Session key (32 bytes for AES-256)
        
        Returns:
            str: Decrypted plaintext message
        """
        if len(key) != SymmetricEncryption.KEY_SIZE:
            raise ValueError(f"Key must be {SymmetricEncryption.KEY_SIZE} bytes, got {len(key)}")
        
        try:
            # Decode from base64
            payload = base64.b64decode(payload_b64.encode('utf-8'))
            
            # Extract nonce and ciphertext
            nonce = payload[:SymmetricEncryption.NONCE_SIZE]
            ciphertext = payload[SymmetricEncryption.NONCE_SIZE:]
            
            # Create cipher object and decrypt
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def derive_key_from_password(
        self, password: str, salt: bytes = None
    ) -> Tuple[bytes, bytes]:
        """
        Derive an AES-256 key from a password using PBKDF2.
        
        Args:
            password: Password string
            salt: Optional salt (if None, generates random 32-byte salt)
        
        Returns:
            Tuple[bytes, bytes]: (derived_key, salt) both 32 bytes
        """
        if salt is None:
            salt = os.urandom(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=SymmetricEncryption.KEY_SIZE,
            salt=salt,
            iterations=SymmetricEncryption.KDF_ITERATIONS,
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
