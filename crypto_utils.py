"""
Módulo de utilidades criptográficas para Cold Wallet
"""

import os
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type


def generate_keypair():
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_bytes, public_bytes


def derive_address(public_key_bytes):
    hash_obj = hashlib.sha3_256(public_key_bytes)
    hash_bytes = hash_obj.digest()
    address_bytes = hash_bytes[-20:]
    address = '0x' + address_bytes.hex()
    return address


def encrypt_keystore(private_key_bytes, password):
    salt = os.urandom(16)
    key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)
    keystore = {
        'version': 1,
        'crypto': {
            'cipher': 'aes-256-gcm',
            'ciphertext': ciphertext.hex(),
            'nonce': nonce.hex(),
            'kdf': 'argon2id',
            'kdfparams': {
                'salt': salt.hex(),
                'time_cost': 3,
                'memory_cost': 65536,
                'parallelism': 4,
                'hash_length': 32
            }
        }
    }
    return keystore


def decrypt_keystore(keystore, password):
    crypto = keystore['crypto']
    kdfparams = crypto['kdfparams']
    salt = bytes.fromhex(kdfparams['salt'])
    key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=kdfparams['time_cost'],
        memory_cost=kdfparams['memory_cost'],
        parallelism=kdfparams['parallelism'],
        hash_len=kdfparams['hash_length'],
        type=Type.ID
    )
    nonce = bytes.fromhex(crypto['nonce'])
    ciphertext = bytes.fromhex(crypto['ciphertext'])
    aesgcm = AESGCM(key)
    private_key_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return private_key_bytes


def canonicalize_transaction(tx_data):
    canonical = json.dumps(tx_data, sort_keys=True, separators=(',', ':'))
    return canonical.encode('utf-8')


def sign_transaction(private_key_bytes, tx_data):
    message = canonicalize_transaction(tx_data)
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = private_key.sign(message)
    return signature.hex()


def verify_signature(public_key_bytes, tx_data, signature_hex):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        message = canonicalize_transaction(tx_data)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        signature = bytes.fromhex(signature_hex)
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error en verificación: {e}")
        return False
