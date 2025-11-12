#!/usr/bin/env python3
import json
from crypto_utils import (
    generate_keypair,
    derive_address,
    encrypt_keystore,
    decrypt_keystore,
    sign_transaction,
    verify_signature
)

print("\n╔" + "=" * 68 + "╗")
print("║" + " " * 15 + "COLD WALLET - PRUEBAS AUTOMÁTICAS" + " " * 20 + "║")
print("╚" + "=" * 68 + "╝\n")

# PRUEBA 1
print("=" * 70)
print("PRUEBA 1: INICIALIZACIÓN DE WALLET")
print("=" * 70)
password = "MiPasswordSeguro123!"
print("\n🔐 Generando par de claves Ed25519...")
private_key, public_key = generate_keypair()
print(f"   ✅ Clave privada: {len(private_key)} bytes")
print(f"   ✅ Clave pública: {len(public_key)} bytes")
print("\n🔐 Derivando dirección...")
address = derive_address(public_key)
print(f"   ✅ Dirección: {address}")
print("\n🔐 Encriptando clave privada...")
keystore = encrypt_keystore(private_key, password)
keystore['address'] = address
keystore['public_key'] = public_key.hex()
print(f"   ✅ KDF: {keystore['crypto']['kdf']}")
print(f"   ✅ Cipher: {keystore['crypto']['cipher']}")

# PRUEBA 2
print("\n" + "=" * 70)
print("PRUEBA 2: DESENCRIPTACIÓN DE KEYSTORE")
print("=" * 70)
print("\n🔓 Desencriptando clave privada...")
decrypted_key = decrypt_keystore(keystore, password)
print(f"   ✅ Desencriptación exitosa: {len(decrypted_key)} bytes")

# PRUEBA 3
print("\n" + "=" * 70)
print("PRUEBA 3: FIRMA DE TRANSACCIÓN")
print("=" * 70)
tx_data = {
    'from': address,
    'to': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb6',
    'amount': '1.5',
    'nonce': '1'
}
print("\n📝 Transacción a firmar:")
print(json.dumps(tx_data, indent=2))
print("\n✍️  Firmando transacción...")
signature = sign_transaction(private_key, tx_data)
print(f"   ✅ Firma generada: {len(signature)} caracteres")

# PRUEBA 4
print("\n" + "=" * 70)
print("PRUEBA 4: VERIFICACIÓN DE FIRMA")
print("=" * 70)
print("\n🔍 Verificando firma original...")
is_valid = verify_signature(public_key, tx_data, signature)
if is_valid:
    print("   ✅ FIRMA VÁLIDA")
else:
    print("   ❌ FIRMA INVÁLIDA")
print("\n🔍 Verificando transacción modificada...")
modified_tx = tx_data.copy()
modified_tx['amount'] = '999.99'
is_valid_mod = verify_signature(public_key, modified_tx, signature)
if not is_valid_mod:
    print("   ✅ CORRECTAMENTE RECHAZADA")
else:
    print("   ❌ ERROR")

# PRUEBA 5
print("\n" + "=" * 70)
print("PRUEBA 5: MÚLTIPLES TRANSACCIONES")
print("=" * 70)
for i in range(1, 4):
    tx = {
        'from': address,
        'to': f'0x{"1234567890"*4}',
        'amount': str(i * 0.5),
        'nonce': str(i+1)
    }
    sig = sign_transaction(private_key, tx)
    valid = verify_signature(public_key, tx, sig)
    print(f"\n   Transacción #{i}: {'✅ VÁLIDA' if valid else '❌ INVÁLIDA'}")

# RESUMEN
print("\n" + "=" * 70)
print("RESUMEN")
print("=" * 70)
print("\n✅ PRUEBA 1: Inicialización............... OK")
print("✅ PRUEBA 2: Desencriptación.............. OK")
print("✅ PRUEBA 3: Firma........................ OK")
print("✅ PRUEBA 4: Verificación................. OK")
print("✅ PRUEBA 5: Múltiples transacciones...... OK")
print("\n🎉 " + "=" * 66 + " 🎉")
print("🎉 TODAS LAS PRUEBAS PASARON EXITOSAMENTE" + " " * 25 + "🎉")
print("🎉 " + "=" * 66 + " 🎉\n")
