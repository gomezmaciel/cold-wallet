# 🔐 Cold Wallet - Billetera Fría de Criptomonedas

Proyecto de Criptografía 2026-1 - Sistema de gestión segura de claves y firma de transacciones.

## 🔒 Características de Seguridad

- **Ed25519** para firmas digitales
- **Argon2id** para derivación de claves (KDF)
- **AES-256-GCM** para encriptación autenticada
- **SHA3-256** para derivación de direcciones estilo Ethereum

## 📦 Requisitos

- Python 3.8 o superior
- pip (gestor de paquetes de Python)

## 🚀 Instalación

### En Mac/Linux:
```bash
# Clonar el repositorio
git clone https://github.com/gomezmaciel/cold-wallet.git
cd cold-wallet

# Instalar dependencias
pip3 install -r requirements.txt
```

### En Windows:
```bash
# Clonar el repositorio
git clone https://github.com/gomezmaciel/cold-wallet.git
cd cold-wallet

# Instalar dependencias
pip install -r requirements.txt
```

## 🎯 Uso

### Ver ayuda:

**Mac/Linux:**
```bash
python3 wallet.py help
```

**Windows:**
```bash
python wallet.py help
```

### Inicializar nueva wallet:

**Mac/Linux:**
```bash
python3 wallet.py init
```

**Windows:**
```bash
python wallet.py init
```

### Firmar transacción:

**Mac/Linux:**
```bash
python3 wallet.py sign
```

**Windows:**
```bash
python wallet.py sign
```

### Verificar transacción firmada:

**Mac/Linux:**
```bash
python3 wallet.py verify signed_tx_1.json
```

**Windows:**
```bash
python wallet.py verify signed_tx_1.json
```

## 🧪 Ejecutar Pruebas Automáticas

Ejecuta la suite completa de pruebas:

**Mac/Linux:**
```bash
python3 test_wallet.py
```

**Windows:**
```bash
python test_wallet.py
```

Esto ejecutará 5 pruebas:
1. ✅ Inicialización de Wallet
2. ✅ Desencriptación de Keystore
3. ✅ Firma de Transacción
4. ✅ Verificación de Firma
5. ✅ Múltiples Transacciones

## 📁 Estructura del Proyecto
```
cold-wallet/
├── crypto_utils.py          # Funciones criptográficas
├── wallet.py                # Interfaz CLI
├── test_wallet.py           # Suite de pruebas
├── requirements.txt         # Dependencias
├── README.md               # Documentación
├── keystore.json           # Wallet encriptada (generada localmente)
└── signed_tx_*.json        # Transacciones firmadas (generadas localmente)
```

## 🔐 Funcionalidades

### 1. Generación de Claves
- Genera par de claves Ed25519 (32 bytes cada una)
- Deriva dirección estilo Ethereum usando SHA3-256

### 2. Almacenamiento Seguro (Keystore)
- Encripta clave privada con Argon2id + AES-256-GCM
- Parámetros Argon2id: time_cost=3, memory=64MB, parallelism=4
- Almacena dirección y clave pública

### 3. Firma de Transacciones
- Firma transacciones con Ed25519
- Canonicalización JSON para consistencia
- Genera firma de 64 bytes (128 caracteres hex)

### 4. Verificación de Firmas
- Verifica autenticidad de transacciones
- Detecta cualquier modificación en los datos
- Protección contra fraude

## 🛡️ Arquitectura de Seguridad
```
┌─────────────────────────────────────────────┐
│         Generación de Claves                │
│     Ed25519 (32 bytes privada/pública)      │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│      Derivación de Dirección                │
│     SHA3-256 → últimos 20 bytes → 0x...     │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│       Almacenamiento (Keystore)             │
│  Password → Argon2id → AES-256-GCM          │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│      Firma de Transacciones                 │
│  JSON Canonicalizado → Ed25519 Sign         │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│      Verificación de Firmas                 │
│  Detecta modificaciones / Valida origen     │
└─────────────────────────────────────────────┘
```

## ⚠️ Importante

- **Guarda tu contraseña de forma segura** - No hay forma de recuperarla
- **Haz backup de tu keystore.json** - Contiene tu wallet encriptada
- **No subas tu keystore a Git** - Ya está en .gitignore por seguridad
- **Este proyecto es educativo** - No usar con dinero real

## 📚 Tecnologías Utilizadas

- **Python 3.8+**
- **cryptography** - Implementación de Ed25519 y AES-GCM
- **argon2-cffi** - Derivación de claves con Argon2id

## 👥 Equipo

- **García Gonzales Alejandro**
- **Gómez Maciel Viridiana** 
- **Pérez del Angel Joaquín Eduardo**
- **Romero Pizano Christian Gustavo**

## 📄 Licencia

Proyecto académico - Criptografía 2026-1  
Universidad Nacional Autónoma de México
