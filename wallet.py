#!/usr/bin/env python3
import sys
import json
import getpass
from pathlib import Path
from crypto_utils import (
    generate_keypair,
    derive_address,
    encrypt_keystore,
    decrypt_keystore,
    sign_transaction,
    verify_signature
)

def init_wallet(keystore_path='keystore.json'):
    print("=== Inicializar Nueva Wallet ===\n")
    while True:
        password = getpass.getpass("Ingresa una contraseña segura: ")
        confirm = getpass.getpass("Confirma la contraseña: ")
        if password == confirm:
            if len(password) < 8:
                print("⚠️  La contraseña debe tener al menos 8 caracteres\n")
                continue
            break
        else:
            print("⚠️  Las contraseñas no coinciden. Intenta de nuevo.\n")
    print("\n🔐 Generando par de claves...")
    private_key, public_key = generate_keypair()
    print("🔐 Derivando dirección...")
    address = derive_address(public_key)
    print("🔐 Encriptando clave privada...")
    keystore = encrypt_keystore(private_key, password)
    keystore['address'] = address
    keystore['public_key'] = public_key.hex()
    with open(keystore_path, 'w') as f:
        json.dump(keystore, f, indent=2)
    print("\n✅ Wallet creada exitosamente!")
    print(f"📁 Keystore guardado en: {keystore_path}")
    print(f"📍 Dirección: {address}")
    print(f"🔑 Clave pública: {public_key.hex()}")
    print("\n⚠️  IMPORTANTE: Guarda tu contraseña de forma segura.")

def sign_tx(keystore_path='keystore.json'):
    print("=== Firmar Transacción ===\n")
    if not Path(keystore_path).exists():
        print(f"❌ Error: No se encontró el keystore en {keystore_path}")
        print("   Ejecuta 'python3 wallet.py init' primero")
        return
    with open(keystore_path, 'r') as f:
        keystore = json.load(f)
    print(f"📍 Dirección de la wallet: {keystore['address']}\n")
    print("Ingresa los datos de la transacción:")
    to_address = input("  Dirección destino: ").strip()
    amount = input("  Cantidad: ").strip()
    nonce = input("  Nonce (número único): ").strip()
    tx_data = {
        'from': keystore['address'],
        'to': to_address,
        'amount': amount,
        'nonce': nonce
    }
    print("\n📝 Transacción a firmar:")
    print(json.dumps(tx_data, indent=2))
    password = getpass.getpass("\nIngresa la contraseña de la wallet: ")
    try:
        print("\n🔓 Desencriptando clave privada...")
        private_key = decrypt_keystore(keystore, password)
        print("✍️  Firmando transacción...")
        signature = sign_transaction(private_key, tx_data)
        signed_tx = {
            'transaction': tx_data,
            'signature': signature,
            'public_key': keystore['public_key']
        }
        tx_filename = f"signed_tx_{nonce}.json"
        with open(tx_filename, 'w') as f:
            json.dump(signed_tx, f, indent=2)
        print("\n✅ Transacción firmada exitosamente!")
        print(f"📁 Guardada en: {tx_filename}")
        print(f"✍️  Firma: {signature[:32]}...{signature[-32:]}")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("   Verifica que la contraseña sea correcta")

def verify_tx(tx_file):
    print("=== Verificar Transacción ===\n")
    if not Path(tx_file).exists():
        print(f"❌ Error: No se encontró el archivo {tx_file}")
        return
    with open(tx_file, 'r') as f:
        signed_tx = json.load(f)
    tx_data = signed_tx['transaction']
    signature = signed_tx['signature']
    public_key_hex = signed_tx['public_key']
    print("📝 Transacción:")
    print(json.dumps(tx_data, indent=2))
    print(f"\n✍️  Firma: {signature[:32]}...{signature[-32:]}")
    print(f"🔑 Clave pública: {public_key_hex[:32]}...{public_key_hex[-32:]}")
    public_key_bytes = bytes.fromhex(public_key_hex)
    print("\n🔍 Verificando firma...")
    is_valid = verify_signature(public_key_bytes, tx_data, signature)
    if is_valid:
        print("✅ FIRMA VÁLIDA")
        print("   La transacción fue firmada correctamente")
    else:
        print("❌ FIRMA INVÁLIDA")
        print("   La transacción puede haber sido modificada")

def show_help():
    help_text = """
╔═══════════════════════════════════════════════════════════════╗
║              Cold Wallet - Billetera Fría                     ║
╚═══════════════════════════════════════════════════════════════╝

COMANDOS:
  init                    Inicializar nueva wallet
  sign                    Firmar una transacción
  verify <archivo>        Verificar una transacción firmada
  help                    Mostrar esta ayuda

EJEMPLOS:
  python3 wallet.py init
  python3 wallet.py sign
  python3 wallet.py verify signed_tx_1.json
"""
    print(help_text)

def main():
    if len(sys.argv) < 2:
        show_help()
        return
    command = sys.argv[1].lower()
    if command == 'init':
        init_wallet()
    elif command == 'sign':
        sign_tx()
    elif command == 'verify':
        if len(sys.argv) < 3:
            print("❌ Error: Debes especificar el archivo")
        else:
            verify_tx(sys.argv[2])
    elif command == 'help':
        show_help()
    else:
        print(f"❌ Comando desconocido: {command}")

if __name__ == '__main__':
    main()
