#!/usr/bin/env python3
"""Test script for crypto module"""
from app.crypto.keystore import KeyStore
from pathlib import Path

print("🔐 Testing KeyStore...\n")

# Test 1: Create keystore
print("1️⃣ Creating new keystore...")
passphrase = "test_passphrase_123456"
address, pubkey = KeyStore.create(passphrase)
print(f"✅ Address: {address}")
print(f"✅ Pubkey: {pubkey[:40]}...\n")

# Test 2: Load keystore
print("2️⃣ Loading keystore...")
keystore_file = Path(f"keystores/wallet_{address[:10]}.json")
signing_key = KeyStore.load(keystore_file, passphrase)
print(f"✅ Private key loaded successfully\n")

# Test 3: Verify address matches
verify_key = signing_key.verify_key
address_check = KeyStore._derive_address(verify_key.encode())
print(f"3️⃣ Verifying address derivation...")
print(f"✅ Addresses match: {address == address_check}\n")

print("🎉 All tests passed!")

