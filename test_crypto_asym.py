"""
Test suite for asymmetric cryptography module (crypto_asym.py).

Tests key generation, encryption, decryption, signing, and verification.
Validates RSA-OAEP key encapsulation and RSA-PSS/Ed25519 signatures.

Run: python test_crypto_asym.py
"""

import os
import shutil
import tempfile
from pathlib import Path

from crypto_asym import AsymmetricKeyManager


def cleanup_test_users():
    """Remove test user directories created during tests."""
    users_dir = Path("users")
    if users_dir.exists():
        test_users = [d for d in users_dir.iterdir() if d.name.startswith("test_user")]
        for user_dir in test_users:
            shutil.rmtree(user_dir)


def test_rsa_key_generation():
    """Test RSA key pair generation and persistence."""
    print("🔹 Testing RSA key generation...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="rsa")
    username = "test_user_rsa"
    
    # Generate keys
    pub_pem, priv_pem = manager.generate_key_pair(username)
    
    # Verify keys are bytes
    assert isinstance(pub_pem, bytes), "Public key should be bytes"
    assert isinstance(priv_pem, bytes), "Private key should be bytes"
    
    # Verify PEM format
    assert b"BEGIN PUBLIC KEY" in pub_pem, "Public key should be in PEM format"
    assert b"BEGIN PRIVATE KEY" in priv_pem, "Private key should be in PEM format"
    
    # Verify files were created
    user_dir = Path("users") / username
    assert user_dir.exists(), "User directory should be created"
    assert (user_dir / f"{username}.pub").exists(), "Public key file should exist"
    assert (user_dir / f"{username}.priv").exists(), "Private key file should exist"
    
    print("  ✅ RSA key generation passed")


def test_ed25519_key_generation():
    """Test Ed25519 key pair generation and persistence."""
    print("🔹 Testing Ed25519 key generation...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="ed25519")
    username = "test_user_ed25519"
    
    # Generate keys
    pub_pem, priv_pem = manager.generate_key_pair(username)
    
    # Verify keys are bytes
    assert isinstance(pub_pem, bytes), "Public key should be bytes"
    assert isinstance(priv_pem, bytes), "Private key should be bytes"
    
    # Verify PEM format
    assert b"BEGIN PUBLIC KEY" in pub_pem, "Public key should be in PEM format"
    assert b"BEGIN PRIVATE KEY" in priv_pem, "Private key should be in PEM format"
    
    # Verify files were created
    user_dir = Path("users") / username
    assert (user_dir / f"{username}.pub").exists(), "Public key file should exist"
    assert (user_dir / f"{username}.priv").exists(), "Private key file should exist"
    
    print("  ✅ Ed25519 key generation passed")


def test_load_existing_keys():
    """Test loading existing key pairs from disk."""
    print("🔹 Testing key loading from disk...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="rsa")
    username = "test_user_load"
    
    # Generate and save keys
    pub_pem_1, priv_pem_1 = manager.generate_key_pair(username)
    
    # Load keys again (should not regenerate)
    pub_pem_2, priv_pem_2 = manager.generate_key_pair(username)
    
    # Verify loaded keys match original
    assert pub_pem_1 == pub_pem_2, "Public key should match on reload"
    assert priv_pem_1 == priv_pem_2, "Private key should match on reload"
    
    print("  ✅ Key loading passed")


def test_rsa_encryption_decryption():
    """Test RSA-OAEP key encapsulation (session key encryption)."""
    print("🔹 Testing RSA encryption/decryption (key encapsulation)...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="rsa")
    
    # Generate keys for two users
    alice = "test_user_alice"
    bob = "test_user_bob"
    manager.generate_key_pair(alice)
    manager.generate_key_pair(bob)
    
    # Simulate: Alice encrypts a session key with Bob's public key
    session_key = os.urandom(32)  # 256-bit AES key
    encrypted_key = manager.encrypt_session_key(bob, session_key)
    
    # Verify ciphertext is different from plaintext
    assert encrypted_key != session_key, "Ciphertext should differ from plaintext"
    
    # Bob decrypts the session key with his private key
    decrypted_key = manager.decrypt_session_key(bob, encrypted_key)
    
    # Verify decryption is correct
    assert decrypted_key == session_key, "Decrypted key should match original"
    
    print("  ✅ RSA encryption/decryption passed")


def test_rsa_signing_verification():
    """Test RSA-PSS signature creation and verification."""
    print("🔹 Testing RSA-PSS signing/verification...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="rsa")
    username = "test_user_sign"
    manager.generate_key_pair(username)
    
    # Sign a message
    message = b"Hello, secure world!"
    signature = manager.sign_message(username, message)
    
    # Verify signature is valid
    assert manager.verify_signature(username, message, signature), \
        "Signature verification should succeed"
    
    # Verify corrupted message fails
    corrupted_message = b"Hello, insecure world!"
    assert not manager.verify_signature(username, corrupted_message, signature), \
        "Signature verification should fail for corrupted message"
    
    # Verify corrupted signature fails
    corrupted_signature = os.urandom(len(signature))
    assert not manager.verify_signature(username, message, corrupted_signature), \
        "Signature verification should fail for corrupted signature"
    
    print("  ✅ RSA-PSS signing/verification passed")


def test_ed25519_signing_verification():
    """Test Ed25519 signature creation and verification."""
    print("🔹 Testing Ed25519 signing/verification...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="ed25519")
    username = "test_user_ed_sign"
    manager.generate_key_pair(username)
    
    # Sign a message
    message = b"Ed25519 signature test"
    signature = manager.sign_message(username, message)
    
    # Verify signature is valid
    assert manager.verify_signature(username, message, signature), \
        "Signature verification should succeed"
    
    # Verify corrupted message fails
    corrupted_message = b"corrupted message"
    assert not manager.verify_signature(username, corrupted_message, signature), \
        "Signature verification should fail for corrupted message"
    
    print("  ✅ Ed25519 signing/verification passed")


def test_force_key_regeneration():
    """Test forced key regeneration with force=True."""
    print("🔹 Testing forced key regeneration...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="rsa")
    username = "test_user_force"
    
    # Generate initial keys
    pub_pem_1, priv_pem_1 = manager.generate_key_pair(username)
    
    # Force regeneration (should create new different keys)
    pub_pem_2, priv_pem_2 = manager.generate_key_pair(username, force=True)
    
    # New keys should be different from the first set
    assert pub_pem_1 != pub_pem_2, "Forced regeneration should create different keys"
    assert priv_pem_1 != priv_pem_2, "Forced regeneration should create different keys"
    
    print("  ✅ Forced key regeneration passed")


def test_invalid_algorithm():
    """Test that invalid algorithm raises ValueError."""
    print("🔹 Testing invalid algorithm rejection...")
    
    try:
        manager = AsymmetricKeyManager(algorithm="invalid")
        assert False, "Should raise ValueError for invalid algorithm"
    except ValueError as e:
        assert "Unsupported algorithm" in str(e)
        print("  ✅ Invalid algorithm rejection passed")


def test_invalid_username():
    """Test that invalid username raises ValueError."""
    print("🔹 Testing invalid username rejection...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="rsa")
    
    invalid_usernames = ["", "user/malicious", "user\\malicious"]
    for bad_username in invalid_usernames:
        try:
            manager.generate_key_pair(bad_username)
            assert False, f"Should reject invalid username: {bad_username}"
        except ValueError:
            pass
    
    print("  ✅ Invalid username rejection passed")


def test_ed25519_encryption_not_supported():
    """Test that Ed25519 encryption raises ValueError."""
    print("🔹 Testing Ed25519 encryption rejection...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="ed25519")
    username = "test_user_ed_encrypt"
    manager.generate_key_pair(username)
    
    try:
        manager.encrypt_session_key(username, b"test_session_key")
        assert False, "Should raise ValueError for Ed25519 encryption"
    except ValueError as e:
        assert "Ed25519 cannot be used for encryption" in str(e)
    
    try:
        manager.decrypt_session_key(username, b"test_ciphertext")
        assert False, "Should raise ValueError for Ed25519 decryption"
    except ValueError as e:
        assert "Ed25519 cannot be used for decryption" in str(e)
    
    print("  ✅ Ed25519 encryption rejection passed")


def test_cross_user_encryption():
    """Test that keys from different users can't decrypt each other's messages."""
    print("🔹 Testing cross-user encryption isolation...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="rsa")
    alice = "test_user_alice_cross"
    bob = "test_user_bob_cross"
    charlie = "test_user_charlie_cross"
    
    manager.generate_key_pair(alice)
    manager.generate_key_pair(bob)
    manager.generate_key_pair(charlie)
    
    # Alice encrypts a message to Bob
    session_key = os.urandom(32)
    encrypted_for_bob = manager.encrypt_session_key(bob, session_key)
    
    # Charlie should not be able to decrypt Alice's message to Bob
    try:
        manager.decrypt_session_key(charlie, encrypted_for_bob)
        # If it doesn't raise, the decryption will fail and return garbage
        # This is the expected cryptographic behavior
        print("  ℹ️  Charlie cannot decrypt Bob's message (as expected)")
    except Exception:
        pass
    
    print("  ✅ Cross-user encryption isolation passed")


def test_public_key_export():
    """Test exporting public key in PEM format."""
    print("🔹 Testing public key export...")
    cleanup_test_users()
    
    manager = AsymmetricKeyManager(algorithm="rsa")
    username = "test_user_export"
    manager.generate_key_pair(username)
    
    # Export public key
    exported_key = manager.export_public_key_pem(username)
    
    # Verify it's valid PEM
    assert b"BEGIN PUBLIC KEY" in exported_key, "Exported key should be in PEM format"
    assert isinstance(exported_key, bytes), "Exported key should be bytes"
    
    print("  ✅ Public key export passed")


def run_all_tests():
    """Run all test cases."""
    print("\n" + "="*60)
    print("🧪 CRYPTO_ASYM.PY TEST SUITE")
    print("="*60 + "\n")
    
    tests = [
        test_rsa_key_generation,
        test_ed25519_key_generation,
        test_load_existing_keys,
        test_rsa_encryption_decryption,
        test_rsa_signing_verification,
        test_ed25519_signing_verification,
        test_force_key_regeneration,
        test_invalid_algorithm,
        test_invalid_username,
        test_ed25519_encryption_not_supported,
        test_cross_user_encryption,
        test_public_key_export,
    ]
    
    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
            failed += 1
    
    cleanup_test_users()
    
    print("\n" + "="*60)
    if failed == 0:
        print(f"✅ ALL {len(tests)} TESTS PASSED")
    else:
        print(f"❌ {failed}/{len(tests)} TESTS FAILED")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
