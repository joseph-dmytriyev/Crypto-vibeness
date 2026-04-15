"""Unit tests for crypto_sym.py."""

import os
import tempfile
import unittest
from pathlib import Path

from crypto_sym import (
    decrypt_message,
    derive_key_pbkdf2,
    encrypt_message,
    get_or_create_client_key,
    get_or_create_server_key,
)


class CryptoSymTests(unittest.TestCase):
    def test_pbkdf2_is_deterministic_with_same_salt(self) -> None:
        salt = b"123456789012"
        key1, _, _ = derive_key_pbkdf2("Secret123!", salt=salt, iterations=150000)
        key2, _, _ = derive_key_pbkdf2("Secret123!", salt=salt, iterations=150000)
        self.assertEqual(key1, key2)

    def test_aes_gcm_roundtrip_and_random_nonce(self) -> None:
        key = os.urandom(32)
        encrypted_one = encrypt_message("hello world", key)
        encrypted_two = encrypt_message("hello world", key)

        self.assertNotEqual(encrypted_one, encrypted_two)
        self.assertEqual(decrypt_message(encrypted_one, key), "hello world")
        self.assertEqual(decrypt_message(encrypted_two, key), "hello world")

    def test_server_key_storage_and_secret_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "user_keys_do_not_steal_plz.txt"

            key1 = get_or_create_server_key("alice", "UltraSecret1", db_path=str(db_path), iterations=120000)
            key2 = get_or_create_server_key("alice", "UltraSecret1", db_path=str(db_path), iterations=120000)
            self.assertEqual(key1, key2)

            with self.assertRaises(ValueError):
                get_or_create_server_key("alice", "WrongSecret", db_path=str(db_path), iterations=120000)

    def test_client_key_storage_and_secret_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            users_dir = Path(tmp_dir) / "users"

            key1 = get_or_create_client_key("bob", "TopSecret9", users_dir=str(users_dir), iterations=130000)
            key2 = get_or_create_client_key("bob", "TopSecret9", users_dir=str(users_dir), iterations=130000)
            self.assertEqual(key1, key2)

            with self.assertRaises(ValueError):
                get_or_create_client_key("bob", "WrongSecret", users_dir=str(users_dir), iterations=130000)


if __name__ == "__main__":
    unittest.main()
