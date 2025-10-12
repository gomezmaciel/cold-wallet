"""
Secure key storage and management.
Handles keypair generation, encryption, and persistence.
"""
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Hash import keccak
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple


# Security parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_PARALLELISM = 2
SALT_LENGTH = 16
NONCE_LENGTH = 12


class KeyStore:
    """Manages cryptographic keys with secure encrypted storage."""
    
    def __init__(self, keystore_dir: Path = Path("keystores")):
        """Initialize KeyStore with storage directory."""
        self.keystore_dir = keystore_dir
        self.keystore_dir.mkdir(exist_ok=True)
    
    @staticmethod
    def create(passphrase: str, scheme: str = "Ed25519") -> Tuple[str, str]:
        """
        Create new encrypted keystore with keypair.
        
        Args:
            passphrase: User passphrase for encryption
            scheme: Signature scheme (Ed25519 or ECDSA)
        
        Returns:
            (address, public_key_b64)
        
        Raises:
            ValueError: If passphrase is too weak or scheme unsupported
        """
        # Validate passphrase
        if len(passphrase) < 12:
            raise ValueError("Passphrase must be at least 12 characters")
        
        if scheme != "Ed25519":
            raise ValueError(f"Scheme {scheme} not supported yet. Use Ed25519.")
        
        # 1. Generate Ed25519 keypair
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        
        # 2. Derive address from public key
        address = KeyStore._derive_address(verify_key.encode())
        
        # 3. Derive encryption key from passphrase using Argon2id
        salt = os.urandom(SALT_LENGTH)
        kdf = Argon2id(
            salt=salt,
            length=32,  # 256 bits for AES-256
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
        )
        encryption_key = kdf.derive(passphrase.encode('utf-8'))
        
        # 4. Encrypt private key with AES-256-GCM
        nonce = os.urandom(NONCE_LENGTH)
        aesgcm = AESGCM(encryption_key)
        
        # Private key bytes
        private_key_bytes = bytes(signing_key)
        
        # Encrypt (returns ciphertext with authentication tag appended)
        ciphertext_with_tag = aesgcm.encrypt(nonce, private_key_bytes, None)
        
        # Split ciphertext and tag (last 16 bytes is tag)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        # 5. Create keystore JSON
        keystore_data = {
            "version": "1.0",
            "address": address,
            "pubkey_b64": Base64Encoder.encode(verify_key.encode()).decode('utf-8'),
            "scheme": scheme,
            "created": datetime.utcnow().isoformat() + "Z",
            "kdf": "Argon2id",
            "kdf_params": {
                "salt_b64": Base64Encoder.encode(salt).decode('utf-8'),
                "t_cost": ARGON2_TIME_COST,
                "m_cost": ARGON2_MEMORY_COST,
                "p": ARGON2_PARALLELISM,
                "output_length": 32
            },
            "cipher": "AES-256-GCM",
            "cipher_params": {
                "nonce_b64": Base64Encoder.encode(nonce).decode('utf-8')
            },
            "ciphertext_b64": Base64Encoder.encode(ciphertext).decode('utf-8'),
            "tag_b64": Base64Encoder.encode(tag).decode('utf-8')
        }
        
        # 6. Save to file
        filename = f"wallet_{address[:10]}.json"
        filepath = Path("keystores") / filename
        
        with open(filepath, 'w') as f:
            json.dump(keystore_data, f, indent=2)
        
        # 7. Return address and public key
        pubkey_b64 = Base64Encoder.encode(verify_key.encode()).decode('utf-8')
        return address, pubkey_b64
    
    @staticmethod
    def _derive_address(pubkey_bytes: bytes) -> str:
        """
        Derive Ethereum-style address from public key using KECCAK-256.
        
        Args:
            pubkey_bytes: Ed25519 public key (32 bytes)
        
        Returns:
            Address string with 0x prefix
        """
        # Hash public key with KECCAK-256
        k = keccak.new(digest_bits=256)
        k.update(pubkey_bytes)
        hash_bytes = k.digest()
        
        # Take last 20 bytes
        address_bytes = hash_bytes[12:]
        
        # Format as hex with 0x prefix
        return "0x" + address_bytes.hex()
    
    @staticmethod
    def load(keystore_path: Path, passphrase: str) -> SigningKey:
        """
        Load and decrypt private key from keystore.
        
        Args:
            keystore_path: Path to keystore JSON file
            passphrase: User passphrase for decryption
        
        Returns:
            Decrypted SigningKey
        
        Raises:
            FileNotFoundError: If keystore doesn't exist
            ValueError: If passphrase is incorrect or keystore is corrupted
        """
        # Load keystore
        with open(keystore_path, 'r') as f:
            keystore_data = json.load(f)
        
        # Extract parameters
        salt = Base64Encoder.decode(keystore_data['kdf_params']['salt_b64'])
        nonce = Base64Encoder.decode(keystore_data['cipher_params']['nonce_b64'])
        ciphertext = Base64Encoder.decode(keystore_data['ciphertext_b64'])
        tag = Base64Encoder.decode(keystore_data['tag_b64'])
        
        # Derive encryption key from passphrase
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=keystore_data['kdf_params']['t_cost'],
            lanes=keystore_data['kdf_params']['p'],
            memory_cost=keystore_data['kdf_params']['m_cost'],
        )
        
        try:
            encryption_key = kdf.derive(passphrase.encode('utf-8'))
        except Exception as e:
            raise ValueError("Failed to derive key from passphrase") from e
        
        # Decrypt private key
        aesgcm = AESGCM(encryption_key)
        
        try:
            # Combine ciphertext and tag for decryption
            ciphertext_with_tag = ciphertext + tag
            private_key_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        except Exception as e:
            raise ValueError("Incorrect passphrase or corrupted keystore") from e
        
        # Create SigningKey from decrypted bytes
        signing_key = SigningKey(private_key_bytes)
        
        return signing_key
