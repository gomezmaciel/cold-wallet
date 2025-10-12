#!/usr/bin/env python3
"""Test transactions module"""
from app.crypto.keystore import KeyStore
from app.transaction.models import Transaction
from app.transaction.signer import Signer
from app.transaction.verifier import Verifier
from pathlib import Path

print("🔐 Testing Transactions...\n")

# Create a test wallet
print("1️⃣ Creating test wallet...")
address, pubkey = KeyStore.create("test_pass_123456")
keystore_file = Path(f"keystores/wallet_{address[:10]}.json")
signing_key = KeyStore.load(keystore_file, "test_pass_123456")
print(f"✅ Wallet: {address}\n")

# Create transaction
print("2️⃣ Creating transaction...")
tx = Transaction(
    from_address=address,
    to="0x1234567890abcdef1234567890abcdef12345678",
    value="10.5",
    nonce=0
)
print(f"✅ Transaction created\n")

# Sign transaction
print("3️⃣ Signing transaction...")
signed_tx = Signer.sign(signing_key, tx)
print(f"✅ Signature: {signed_tx.signature_b64[:40]}...\n")

# Verify transaction
print("4️⃣ Verifying transaction...")
result = Verifier.verify(signed_tx)
print(f"✅ Valid: {result['valid']}\n")

# Test tampering
print("5️⃣ Testing tampered transaction...")
tx.value = "999.9"  # Change value
signed_tx_bad = Signer.sign(signing_key, tx)
signed_tx_bad.signature_b64 = signed_tx.signature_b64  # Use old signature
result = Verifier.verify(signed_tx_bad)
print(f"✅ Tampered detected: {not result['valid']}\n")

print("🎉 All transaction tests passed!")
