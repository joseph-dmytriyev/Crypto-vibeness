"""
Asymmetric cryptography module using RSA and Ed25519.

This module provides key generation, encryption, decryption, signing, and verification
capabilities for end-to-end encrypted communication. Keys are persisted locally in
`users/<username>/` directory.

Author: Dev 3
Algorithms:
  - Key generation: RSA 2048-bit or Ed25519
  - Encryption: RSA-OAEP with SHA-256 (for session key encapsulation)
  - Signatures: RSA-PSS with SHA-256 or Ed25519
  - Hash function: SHA-256 for all operations
"""

import os
from pathlib import Path
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.hazmat.backends import default_backend


class AsymmetricKeyManager:
    """
    Manages asymmetric key pairs (RSA or Ed25519) for users.
    
    Generates, stores, and retrieves cryptographic key pairs from persistent storage.
    Provides encryption/decryption and signing/verification interfaces.
    """

    KEY_ALGORITHM = "rsa"  # "rsa" or "ed25519"
    USERS_DIR = Path("users")
    RSA_KEY_SIZE = 2048
    
    def __init__(self, algorithm: str = "rsa"):
        """
        Initialize the key manager.
        
        Args:
            algorithm: Cryptographic algorithm - "rsa" (default) or "ed25519"
        """
        if algorithm not in ("rsa", "ed25519"):
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'rsa' or 'ed25519'.")
        self.algorithm = algorithm
        self.backend = default_backend()

    def generate_key_pair(self, username: str, force: bool = False) -> Tuple[bytes, bytes]:
        """
        Generate an asymmetric key pair (public, private) for a user.
        
        Keys are automatically saved to users/<username>/<username>.pub and .priv.
        If keys already exist, skip generation unless force=True.
        
        Args:
            username: User identifier (used for directory and file naming)
            force: If True, regenerate keys even if they exist (overwrites existing keys)
        
        Returns:
            Tuple[bytes, bytes]: (public_key_pem, private_key_pem)
        
        Raises:
            ValueError: If username is invalid
        """
        if not username or "/" in username or "\\" in username:
            raise ValueError(f"Invalid username: {username}")

        user_dir = self.USERS_DIR / username
        priv_file = user_dir / f"{username}.priv"
        pub_file = user_dir / f"{username}.pub"

        # If keys exist and force is False, load and return them
        if priv_file.exists() and pub_file.exists() and not force:
            return self._load_key_pair(username)

        # Create user directory if it doesn't exist
        user_dir.mkdir(parents=True, exist_ok=True)

        # Generate keys based on algorithm
        if self.algorithm == "rsa":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.RSA_KEY_SIZE,
                backend=self.backend,
            )
        else:  # ed25519
            private_key = ed25519.Ed25519PrivateKey.generate()

        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Save keys to disk
        with open(priv_file, "wb") as f:
            f.write(private_pem)
        # Restrict private key permissions to owner only (0600)
        os.chmod(priv_file, 0o600)
        
        with open(pub_file, "wb") as f:
            f.write(public_pem)

        return public_pem, private_pem

    def _load_key_pair(self, username: str) -> Tuple[bytes, bytes]:
        """
        Load an existing key pair from disk.
        
        Args:
            username: User identifier
        
        Returns:
            Tuple[bytes, bytes]: (public_key_pem, private_key_pem)
        
        Raises:
            FileNotFoundError: If key files don't exist
        """
        user_dir = self.USERS_DIR / username
        priv_file = user_dir / f"{username}.priv"
        pub_file = user_dir / f"{username}.pub"

        if not priv_file.exists() or not pub_file.exists():
            raise FileNotFoundError(f"Key files for user '{username}' not found in {user_dir}")

        with open(priv_file, "rb") as f:
            private_pem = f.read()
        with open(pub_file, "rb") as f:
            public_pem = f.read()

        return public_pem, private_pem

    def load_private_key(self, username: str):
        """
        Load a private key object from disk.
        
        Args:
            username: User identifier
        
        Returns:
            RSAPrivateKey or Ed25519PrivateKey
        """
        _, private_pem = self._load_key_pair(username)
        return serialization.load_pem_private_key(
            private_pem, password=None, backend=self.backend
        )

    def load_public_key(self, username: str):
        """
        Load a public key object from disk.
        
        Args:
            username: User identifier
        
        Returns:
            RSAPublicKey or Ed25519PublicKey
        """
        public_pem, _ = self._load_key_pair(username)
        return serialization.load_pem_public_key(public_pem, backend=self.backend)

    def encrypt_session_key(self, recipient_username: str, session_key: bytes) -> bytes:
        """
        Encrypt a session key using the recipient's public key (RSA-OAEP only).
        
        This method is used for key encapsulation: Alice generates an AES session key,
        encrypts it with Bob's public RSA key, and sends it to Bob via the server.
        
        Note: Ed25519 is only for signatures; RSA is required for encryption.
        
        Args:
            recipient_username: Username of the recipient
            session_key: The session key to encrypt (typically 32 bytes for AES-256)
        
        Returns:
            bytes: Encrypted session key (ciphertext)
        
        Raises:
            ValueError: If algorithm is Ed25519 (not supported for encryption)
        """
        if self.algorithm == "ed25519":
            raise ValueError("Ed25519 cannot be used for encryption. Use RSA for key encapsulation.")

        public_key = self.load_public_key(recipient_username)

        encrypted_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return encrypted_key

    def decrypt_session_key(self, username: str, encrypted_session_key: bytes) -> bytes:
        """
        Decrypt an encrypted session key using the user's private key (RSA-OAEP only).
        
        Args:
            username: Username of the recipient
            encrypted_session_key: The encrypted session key
        
        Returns:
            bytes: Decrypted session key
        
        Raises:
            ValueError: If algorithm is Ed25519
        """
        if self.algorithm == "ed25519":
            raise ValueError("Ed25519 cannot be used for decryption. Use RSA for key encapsulation.")

        private_key = self.load_private_key(username)

        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return session_key

    def sign_message(self, username: str, message: bytes) -> bytes:
        """
        Sign a message using the user's private key.
        
        Uses RSA-PSS with SHA-256 or Ed25519 signature depending on algorithm.
        
        Args:
            username: User identifier
            message: Message to sign (bytes)
        
        Returns:
            bytes: Signature
        """
        private_key = self.load_private_key(username)

        if self.algorithm == "rsa":
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:  # ed25519
            signature = private_key.sign(message)

        return signature

    def verify_signature(self, sender_username: str, message: bytes, signature: bytes) -> bool:
        """
        Verify a message signature using the sender's public key.
        
        Args:
            sender_username: Username of the message sender
            message: Original message (bytes)
            signature: Signature to verify (bytes)
        
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            public_key = self.load_public_key(sender_username)

            if self.algorithm == "rsa":
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            else:  # ed25519
                public_key.verify(signature, message)

            return True
        except Exception:
            return False

    def export_public_key_pem(self, username: str) -> bytes:
        """
        Export a user's public key in PEM format.
        
        Useful for distributing public keys to other users or the server.
        
        Args:
            username: User identifier
        
        Returns:
            bytes: Public key in PEM format
        """
        public_pem, _ = self._load_key_pair(username)
        return public_pem
