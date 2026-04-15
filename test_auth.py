"""Unit tests for auth.py."""

import json
import tempfile
import unittest
from pathlib import Path

from auth import AuthManager


class AuthManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "this_is_safe.txt"
        self.rules_path = self.base_path / "password_rules.json"
        self.rules_path.write_text(
            json.dumps(
                {
                    "rules": [
                        {"type": "min_length", "value": 8, "message": "At least 8 characters"},
                        {"type": "has_digit", "message": "At least 1 digit"},
                        {"type": "has_upper", "message": "At least 1 uppercase letter"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.manager = AuthManager(
            db_path=str(self.db_path),
            rules_path=str(self.rules_path),
            bcrypt_cost=12,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_register_and_login_with_policy(self) -> None:
        ok, message, _ = self.manager.register_user("alice", "weakpass", "weakpass")
        self.assertFalse(ok)
        self.assertIn("Password policy failed", message)

        ok, _, strength = self.manager.register_user("alice", "StrongPwd1", "StrongPwd1")
        self.assertTrue(ok)
        self.assertIn(strength, {"Faible", "Moyen", "Fort"})

        storage_content = self.db_path.read_text(encoding="utf-8")
        self.assertNotIn("StrongPwd1", storage_content)

        ok, _ = self.manager.authenticate_user("alice", "wrong-password")
        self.assertFalse(ok)

        ok, _ = self.manager.authenticate_user("alice", "StrongPwd1")
        self.assertTrue(ok)

    def test_same_password_generates_different_hashes(self) -> None:
        self.manager.register_user("alice", "SharedPwd1", "SharedPwd1")
        self.manager.register_user("bob", "SharedPwd1", "SharedPwd1")

        line_by_user = {}
        for raw in self.db_path.read_text(encoding="utf-8").splitlines():
            username, algo, cost, salt_b64, hash_b64 = raw.split(":")
            self.assertEqual(algo, "bcrypt")
            self.assertEqual(cost, "12")
            line_by_user[username] = (salt_b64, hash_b64)

        self.assertNotEqual(line_by_user["alice"], line_by_user["bob"])

    def test_legacy_md5_is_migrated_after_successful_login(self) -> None:
        self.manager.create_legacy_md5_user_for_tests("legacy", "LegacyPwd1")

        before = self.db_path.read_text(encoding="utf-8").strip()
        self.assertEqual(len(before.split(":")), 2)

        ok, _ = self.manager.authenticate_user("legacy", "LegacyPwd1")
        self.assertTrue(ok)

        after = self.db_path.read_text(encoding="utf-8").strip()
        self.assertEqual(len(after.split(":")), 5)
        self.assertIn(":bcrypt:12:", after)


if __name__ == "__main__":
    unittest.main()
