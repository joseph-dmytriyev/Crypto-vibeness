"""
End-to-End Encryption (E2EE) module for secure 1-to-1 messaging.

This module implements the complete E2EE protocol:
1. Key Exchange: Generate session keys using RSA-OAEP encapsulation
2. Message Encryption: Sign + encrypt all 1-to-1 messages
3. Message Verification: Verify signatures before decryption
4. Key Registry: Maintain public key directory for all users

The server is "honest-but-curious": it routes messages faithfully but
cannot read 1-to-1 encrypted content.

Author: Dev 3
Architecture:
  - Asymmetric: RSA/Ed25519 for key exchange and signatures (crypto_asym.py)
  - Symmetric: AES-256-GCM for message encryption (crypto_sym.py)
  - Protocol: Signature first (guarantees sender identity), then encryption
"""

import os
import base64
import json
from pathlib import Path
from typing import Optional, Dict, Tuple
from datetime import datetime

from crypto_asym import AsymmetricKeyManager
from crypto_sym import SymmetricEncryption


class E2EEMessage:
    """
    Represents an end-to-end encrypted message ready for transmission.
    
    Format (JSON):
    {
        "type": "e2ee_message",
        "sender": "alice",
        "recipient": "bob",
        "encrypted_session_key": "<base64 RSA-OAEP encrypted AES key>",
        "encrypted_message": "<base64 AES-GCM encrypted message>",
        "signature": "<base64 RSA-PSS signature>",
        "algorithm": "rsa",
        "timestamp": "2026-04-14T12:00:00Z"
    }
    """
    
    def __init__(
        self,
        sender: str,
        recipient: str,
        encrypted_session_key: bytes,
        encrypted_message: str,
        signature: bytes,
        algorithm: str = "rsa",
    ):
        """
        Initialize an E2EE message.
        
        Args:
            sender: Username of message sender
            recipient: Username of message recipient
            encrypted_session_key: AES key encrypted with recipient's public RSA key
            encrypted_message: Message encrypted with session key (base64)
            signature: Signature of plaintext message with sender's private key
            algorithm: Asymmetric algorithm ("rsa" or "ed25519")
        """
        self.sender = sender
        self.recipient = recipient
        self.encrypted_session_key = encrypted_session_key
        self.encrypted_message = encrypted_message
        self.signature = signature
        self.algorithm = algorithm
        self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    def to_json(self) -> str:
        """
        Serialize message to JSON format for transmission.
        
        Returns:
            str: JSON-encoded E2EE message
        """
        return json.dumps({
            "type": "e2ee_message",
            "sender": self.sender,
            "recipient": self.recipient,
            "encrypted_session_key": base64.b64encode(
                self.encrypted_session_key
            ).decode('utf-8'),
            "encrypted_message": self.encrypted_message,
            "signature": base64.b64encode(self.signature).decode('utf-8'),
            "algorithm": self.algorithm,
            "timestamp": self.timestamp,
        })
    
    @staticmethod
    def from_json(json_str: str) -> "E2EEMessage":
        """
        Deserialize message from JSON format.
        
        Args:
            json_str: JSON-encoded E2EE message
        
        Returns:
            E2EEMessage: Deserialized message object
        """
        data = json.loads(json_str)
        return E2EEMessage(
            sender=data["sender"],
            recipient=data["recipient"],
            encrypted_session_key=base64.b64decode(
                data["encrypted_session_key"]
            ),
            encrypted_message=data["encrypted_message"],
            signature=base64.b64decode(data["signature"]),
            algorithm=data.get("algorithm", "rsa"),
        )


class E2EEKeyRegistry:
    """
    Maintains a registry of public keys for all connected users.
    
    The server distributes this registry to all clients, allowing them
    to encrypt messages to any known user.
    """
    
    def __init__(self):
        """Initialize empty public key registry."""
        self.registry: Dict[str, bytes] = {}
    
    def register_user(self, username: str, public_key_pem: bytes) -> None:
        """
        Register a user's public key in the registry.
        
        Args:
            username: Username
            public_key_pem: Public key in PEM format (bytes)
        """
        self.registry[username] = public_key_pem
    
    def get_public_key(self, username: str) -> Optional[bytes]:
        """
        Retrieve a user's public key.
        
        Args:
            username: Username
        
        Returns:
            bytes: Public key in PEM format, or None if not found
        """
        return self.registry.get(username)
    
    def user_exists(self, username: str) -> bool:
        """Check if user is registered in the key registry."""
        return username in self.registry
    
    def list_users(self) -> list:
        """Get list of all registered usernames."""
        return list(self.registry.keys())
    
    def to_dict(self) -> Dict[str, str]:
        """
        Export registry as dict with base64-encoded keys.
        
        Useful for serializing to JSON for distribution.
        
        Returns:
            Dict[str, str]: {username: base64_public_key}
        """
        return {
            username: base64.b64encode(key).decode('utf-8')
            for username, key in self.registry.items()
        }
    
    def from_dict(self, registry_dict: Dict[str, str]) -> None:
        """
        Import registry from dict with base64-encoded keys.
        
        Args:
            registry_dict: {username: base64_public_key}
        """
        self.registry = {
            username: base64.b64decode(key_b64)
            for username, key_b64 in registry_dict.items()
        }


class E2EEManager:
    """
    Complete E2EE message manager combining asymmetric and symmetric crypto.
    
    Handles:
    1. Key Exchange: Generate and encrypt session keys
    2. Message Preparation: Sign and encrypt messages
    3. Message Reception: Verify signatures and decrypt
    4. Public Key Management: Maintain user registry
    """
    
    def __init__(self, username: str, algorithm: str = "rsa"):
        """
        Initialize E2EE manager for a specific user.
        
        Args:
            username: User identifier
            algorithm: Asymmetric algorithm ("rsa" or "ed25519")
        """
        self.username = username
        self.algorithm = algorithm
        self.asym_manager = AsymmetricKeyManager(algorithm=algorithm)
        self.sym_encryption = SymmetricEncryption()
        self.key_registry = E2EEKeyRegistry()
        
        # Generate user's key pair if not exists
        pub_pem, priv_pem = self.asym_manager.generate_key_pair(username)
        self.public_key_pem = pub_pem
    
    def register_recipient_public_key(self, recipient: str) -> None:
        """
        Register a recipient's public key from disk.
        
        Loads the public key from users/<recipient>/<recipient>.pub
        and adds it to the registry.
        
        Args:
            recipient: Recipient username
        
        Raises:
            FileNotFoundError: If recipient's public key file doesn't exist
        """
        pub_pem = self.asym_manager.export_public_key_pem(recipient)
        self.key_registry.register_user(recipient, pub_pem)
    
    def create_session_key_exchange(self, recipient: str) -> Tuple[bytes, bytes]:
        """
        Create a session key exchange for a recipient.
        
        This simulates Alice wanting to send a 1-to-1 message to Bob:
        1. Alice generates a random AES-256 session key
        2. Alice encrypts this key with Bob's public RSA key (RSA-OAEP)
        3. The encrypted key can be transmitted via the server
        4. Bob decrypts with his private key to get the session key
        
        Args:
            recipient: Recipient username
        
        Returns:
            Tuple[bytes, bytes]: (session_key, encrypted_session_key)
                - session_key: Raw AES-256 key (32 bytes)
                - encrypted_session_key: RSA-OAEP encrypted key
        
        Raises:
            ValueError: If recipient not in registry
        """
        if not self.key_registry.user_exists(recipient):
            raise ValueError(
                f"Recipient '{recipient}' not in key registry. "
                f"Register their public key first."
            )
        
        # Generate random session key
        session_key = self.sym_encryption.generate_session_key()
        
        # Encrypt session key with recipient's public key (RSA-OAEP)
        encrypted_session_key = self.asym_manager.encrypt_session_key(
            recipient, session_key
        )
        
        return session_key, encrypted_session_key
    
    def prepare_e2ee_message(
        self, recipient: str, plaintext: str, session_key: bytes
    ) -> E2EEMessage:
        """
        Prepare a complete E2EE message ready for transmission.
        
        Process:
        1. Sign the plaintext with sender's private key (guarantees authenticity)
        2. Encrypt plaintext with session key (AES-256-GCM)
        3. Encrypt session key with recipient's public key (RSA-OAEP)
        4. Bundle everything into E2EEMessage
        
        Args:
            recipient: Recipient username
            plaintext: Message text to send
            session_key: Session key for this conversation (32 bytes)
        
        Returns:
            E2EEMessage: Complete encrypted message ready to send
        
        Raises:
            ValueError: If recipient not in registry or crypto fails
        """
        if not self.key_registry.user_exists(recipient):
            raise ValueError(
                f"Recipient '{recipient}' not in key registry"
            )
        
        # Step 1: Sign the plaintext message with sender's private key
        signature = self.asym_manager.sign_message(
            self.username, plaintext.encode('utf-8')
        )
        
        # Step 2: Encrypt plaintext with session key
        encrypted_message = self.sym_encryption.encrypt_message(
            plaintext, session_key
        )
        
        # Step 3: Encrypt session key with recipient's public key
        encrypted_session_key = self.asym_manager.encrypt_session_key(
            recipient, session_key
        )
        
        # Step 4: Create E2EE message object
        message = E2EEMessage(
            sender=self.username,
            recipient=recipient,
            encrypted_session_key=encrypted_session_key,
            encrypted_message=encrypted_message,
            signature=signature,
            algorithm=self.algorithm,
        )
        
        return message
    
    def receive_e2ee_message(
        self, e2ee_message: E2EEMessage, session_key: bytes
    ) -> str:
        """
        Receive and verify an E2EE message.
        
        Process:
        1. Decrypt session key with receiver's private key (RSA-OAEP)
        2. Decrypt message with session key (AES-256-GCM)
        3. Verify signature with sender's public key
        4. If signature invalid, reject message
        
        Args:
            e2ee_message: E2EEMessage object received
            session_key: Session key for this conversation (32 bytes)
                        (normally obtained by decrypting encrypted_session_key)
        
        Returns:
            str: Plaintext message if verification succeeds
        
        Raises:
            ValueError: If signature verification fails
        """
        # Step 1: Decrypt message with session key
        try:
            plaintext = self.sym_encryption.decrypt_message(
                e2ee_message.encrypted_message, session_key
            )
        except Exception as e:
            raise ValueError(f"Message decryption failed: {str(e)}")
        
        # Step 2: Verify signature with sender's public key
        plaintext_bytes = plaintext.encode('utf-8')
        signature_valid = self.asym_manager.verify_signature(
            e2ee_message.sender, plaintext_bytes, e2ee_message.signature
        )
        
        if not signature_valid:
            raise ValueError(
                f"Signature verification failed for message from '{e2ee_message.sender}'. "
                f"Message rejected (possible tampering detected)."
            )
        
        return plaintext
    
    def decrypt_session_key(self, encrypted_session_key: bytes) -> bytes:
        """
        Decrypt a session key encrypted with this user's public key.
        
        This is used when receiving a message: the sender encrypted the
        session key with our public key, and we decrypt it with our
        private key to read the message.
        
        Args:
            encrypted_session_key: Session key encrypted with RSA-OAEP
        
        Returns:
            bytes: Decrypted session key (32 bytes for AES-256)
        
        Raises:
            ValueError: If decryption fails
        """
        return self.asym_manager.decrypt_session_key(
            self.username, encrypted_session_key
        )
    
    def serialize_public_key(self) -> str:
        """
        Export this user's public key as base64 for distribution.
        
        Returns:
            str: Base64-encoded public key
        """
        return base64.b64encode(self.public_key_pem).decode('utf-8')


# Convenience function for server-side key registry
def create_registry_from_users(user_list: list) -> E2EEKeyRegistry:
    """
    Create a key registry by loading public keys for a list of users.
    
    Used server-side to build and distribute the public key directory.
    
    Args:
        user_list: List of usernames to include in registry
    
    Returns:
        E2EEKeyRegistry: Populated registry
    """
    registry = E2EEKeyRegistry()
    asym_manager = AsymmetricKeyManager()
    
    for username in user_list:
        try:
            pub_pem = asym_manager.export_public_key_pem(username)
            registry.register_user(username, pub_pem)
        except FileNotFoundError:
            # User's keys don't exist yet, skip
            pass
    
    return registry
