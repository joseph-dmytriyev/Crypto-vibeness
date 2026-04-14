"""
Symmetric cryptography module for AES encryption/decryption.

This module provides AES-GCM encryption and decryption capabilities for
end-to-end encrypted communication. It uses PyCA/cryptography library
for secure symmetric encryption with authenticated encryption.

Author: Dev 2 (adapted for Dev 3 E2EE integration)
Algorithm: AES-256-GCM with random nonce per message
"""

import os
import base64
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class SymmetricEncryption:
    """
    Handles symmetric AES-GCM encryption and decryption.
    
    Each message is encrypted with a random nonce (IV) to prevent
    pattern analysis. The nonce is prepended to the ciphertext.
    """
    
    ALGORITHM = "AES-256-GCM"
    KEY_SIZE = 32  # 256-bit key
    NONCE_SIZE = 12  # 96-bit nonce (12 bytes) for GCM
    TAG_SIZE = 16  # 128-bit authentication tag
    KDF_ITERATIONS = 100000
    
    def __init__(self):
        """Initialize symmetric encryption handler."""
        self.backend = default_backend()
    
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
        where || denotes concatenation.
        
        Args:
            plaintext: Message to encrypt (str)
            key: Session key (32 bytes for AES-256)
        
        Returns:
            str: Base64-encoded encrypted message (nonce + ciphertext + tag)
        
        Raises:
            ValueError: If key size is incorrect
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        
        # Generate a random nonce for this message
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Create cipher object
        cipher = AESGCM(key)
        
        # Encrypt plaintext
        ciphertext = cipher.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Combine nonce + ciphertext (tag is already appended by AESGCM)
        payload = nonce + ciphertext
        
        # Return base64-encoded payload
        return base64.b64encode(payload).decode('utf-8')
    
    def decrypt_message(self, payload_b64: str, key: bytes) -> str:
        """
        Decrypt a message encrypted with encrypt_message.
        
        Args:
            payload_b64: Base64-encoded encrypted message from encrypt_message
            key: Session key (32 bytes for AES-256)
        
        Returns:
            str: Decrypted plaintext message
        
        Raises:
            ValueError: If key size is incorrect or decryption fails
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        
        try:
            # Decode from base64
            payload = base64.b64decode(payload_b64.encode('utf-8'))
            
            # Extract nonce and ciphertext
            nonce = payload[:self.NONCE_SIZE]
            ciphertext = payload[self.NONCE_SIZE:]
            
            # Create cipher object
            cipher = AESGCM(key)
            
            # Decrypt ciphertext (AESGCM.decrypt validates the tag)
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def derive_key_from_password(
        self, password: str, salt: bytes = None
    ) -> Tuple[bytes, bytes]:
        """
        Derive an AES-256 key from a password using PBKDF2.
        
        Useful for deriving shared keys in pre-shared scenarios.
        
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
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
            backend=self.backend,
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
