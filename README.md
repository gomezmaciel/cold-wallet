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

# Si pip no funciona, usar:
python -m pip install -r requirements.txt
```

## 🎯 Uso Rápido

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
4. ✅ Verificación de Firma (incluye detección de fraude)
5. ✅ Múltiples Transacciones

## 📁 Estructura del Proyecto
```
cold-wallet/
├── crypto_utils.py          # Funciones criptográficas principales
├── wallet.py                # Interfaz CLI (comandos: init, sign, verify)
├── test_wallet.py           # Suite de pruebas automatizadas
├── requirements.txt         # Dependencias del proyecto
├── README.md               # Esta documentación
├── .gitignore              # Archivos ignorados por Git
│
├── app/                    # Implementación modular (Fase 1)
│   ├── crypto/            # Módulos de criptografía
│   ├── transaction/       # Manejo de transacciones
│   ├── ui/                # Interfaz de usuario
│   └── main.py            # Punto de entrada
│
├── docs/                   # Documentación técnica
│   └── technical_report.md
│
├── tests/                  # Pruebas unitarias adicionales
│
└── [Archivos generados localmente, no en Git]
    ├── keystore.json          # Tu wallet encriptada
    └── signed_tx_*.json       # Transacciones firmadas
```

## 🔄 Evolución del Proyecto

Este proyecto se desarrolló en dos fases:

### Fase 1: Arquitectura Modular
- Estructura de carpetas separadas (`app/crypto/`, `app/transaction/`, `app/ui/`)
- Sistema completo de transacciones con CLI
- Implementación inicial del sistema de keystores

### Fase 2: Versión Simplificada (Actual)
- Consolidación en 3 archivos principales
- Interfaz CLI mejorada y más intuitiva
- Suite completa de pruebas automatizadas
- Documentación compatible Windows/Mac

**Ambas versiones están disponibles en el repositorio para referencia.**

## 🔐 Funcionalidades Detalladas

### 1. Generación de Claves
- Genera par de claves Ed25519 (32 bytes cada una)
- Deriva dirección estilo Ethereum usando SHA3-256
- Almacena clave pública y dirección en el keystore

### 2. Almacenamiento Seguro (Keystore)
- Encripta clave privada con Argon2id + AES-256-GCM
- Parámetros Argon2id:
  - Time cost: 3 iteraciones
  - Memory: 64MB (65536 KB)
  - Parallelism: 4 hilos
  - Output: 32 bytes
- Nonce aleatorio de 12 bytes para AES-GCM
- Tag de autenticación incluido (AEAD)

### 3. Firma de Transacciones
- Canonicalización JSON (claves ordenadas alfabéticamente)
- Firma Ed25519 de 64 bytes (128 caracteres hexadecimales)
- Almacena transacción + firma + clave pública

### 4. Verificación de Firmas
- Verifica autenticidad usando la clave pública
- Detecta cualquier modificación en los datos de la transacción
- Protección contra:
  - Modificación de montos
  - Cambio de direcciones
  - Alteración de cualquier campo

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

## 🎓 Demostración de Seguridad

Para demostrar la detección de fraude:

1. Firma una transacción:
```bash
   python3 wallet.py sign
```

2. Modifica manualmente el archivo `signed_tx_X.json` (cambia el monto)

3. Intenta verificarla:
```bash
   python3 wallet.py verify signed_tx_X.json
```

4. El sistema detectará la modificación: ❌ **FIRMA INVÁLIDA**

## ⚠️ Importante

- **Guarda tu contraseña de forma segura** - No hay forma de recuperarla
- **Haz backup de tu keystore.json** - Contiene tu wallet encriptada
- **No subas tu keystore a Git** - Ya está en .gitignore por seguridad
- **Este proyecto es educativo** - No usar con dinero real en producción

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

## 📖 Documentación Adicional

Para más detalles técnicos, consulta:
- `docs/technical_report.md` - Reporte técnico completo del proyecto
