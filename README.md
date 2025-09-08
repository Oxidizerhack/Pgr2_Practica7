# 🔐 CTFUtils

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![GitHub](https://img.shields.io/badge/GitHub-Oxidizerhack%2Fctfutils-blue)](https://github.com/Oxidizerhack/ctfutils)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](https://github.com/Oxidizerhack/ctfutils)

**Una librería completa de Python para competencias CTF y ciberseguridad**

*Herramientas poderosas y fáciles de usar para criptografía, esteganografía, análisis forense y más*

[🚀 Instalación](#-instalación) • [📖 Guía Rápida](#-guía-rápida) • [🎯 Módulos](#-módulos) • [💡 Ejemplos](#-ejemplos) • [📚 Documentación](#-documentación)

</div>

---

## ✨ Características Principales

🔐 **Criptografía Avanzada** - Caesar, Vigenère, XOR, Base64, hashing y más  
🖼️ **Esteganografía Múltiple** - Texto, imágenes, whitespace y zero-width  
🔍 **Análisis Forense** - Archivos, memoria, red y extracción de metadatos  
🔧 **Utilidades Diversas** - Encodings, conversores y herramientas matemáticas  
⚡ **Fácil de Usar** - API intuitiva y documentación completa  
🧪 **Totalmente Testeado** - Cobertura de tests ~85%

## 🚀 Instalación

### Instalación Rápida

```bash
# Clonar e instalar para desarrollo
git clone https://github.com/Oxidizerhack/ctfutils.git
cd ctfutils
pip install -e .
```

### Requisitos del Sistema
- **Python**: 3.8 o superior
- **SO**: Windows, Linux, macOS
- **Dependencias**: Pillow, cryptography, requests

<details>
<summary>📦 Ver dependencias completas</summary>

**Principales:**
- `Pillow >= 8.0.0` - Procesamiento de imágenes
- `cryptography >= 3.0.0` - Algoritmos criptográficos
- `requests >= 2.25.0` - Operaciones de red

**Desarrollo:**
- `pytest >= 6.0.0` - Testing framework
- `black >= 21.0.0` - Formateador de código
- `flake8 >= 3.8.0` - Linter de código

</details>

## 📖 Guía Rápida

```python
from ctfutils.crypto.classical import caesar_encrypt, caesar_decrypt
from ctfutils.crypto.modern import base64_encode, xor_encrypt
from ctfutils.stego.text import hide_text_whitespace
from ctfutils.forensics.files import extract_strings

# Cifrado Caesar
encrypted = caesar_encrypt("HELLO", 3)  # "KHOOR"
decrypted = caesar_decrypt(encrypted, 3)  # "HELLO"

# Base64 y XOR
b64 = base64_encode("Secret message")
xor_result = xor_encrypt("FLAG{test}", "key")

# Esteganografía
hidden_msg = hide_text_whitespace("Normal text", "Hidden data")

# Análisis forense
strings = extract_strings("binary_file.exe")
```

## 🎯 Módulos

<table>
<tr>
<th width="25%">🔐 Crypto</th>
<th width="25%">🖼️ Stego</th>
<th width="25%">🔍 Forensics</th>
<th width="25%">🔧 Misc</th>
</tr>
<tr>
<td valign="top">

**Criptografía clásica y moderna**
- Caesar & Vigenère
- Base64, Hex, Binary
- XOR encryption
- MD5, SHA1, SHA256
- Hash identification

</td>
<td valign="top">

**Esteganografía avanzada**
- Whitespace hiding
- Zero-width characters  
- LSB en imágenes PNG
- Análisis de entropía
- Text pattern detection

</td>
<td valign="top">

**Análisis forense digital**
- String extraction
- File signatures
- Metadata analysis
- Memory dumps
- Network log parsing

</td>
<td valign="top">

**Utilidades y conversores**
- Multiple encodings
- ASCII/Hex/Binary
- Morse code
- Mathematical utils
- Pattern generation

</td>
</tr>
</table>
## 💡 Ejemplos

### 🔐 Criptografía

<details>
<summary><strong>Cifrados Clásicos</strong></summary>

```python
from ctfutils.crypto.classical import caesar_encrypt, vigenere_encrypt

# Caesar cipher
encrypted = caesar_encrypt("ATTACK AT DAWN", 13)  # ROT13
print(encrypted)  # "NGGNPX NG QNJA"

# Vigenère cipher  
secret = vigenere_encrypt("SECRET", "KEY")
print(secret)  # "CIAVED"
```

</details>

<details>
<summary><strong>Hashing y Análisis</strong></summary>

```python
from ctfutils.crypto.hashing import sha256_hash, identify_hash

# Generar hash
hash_result = sha256_hash("password123")

# Identificar tipo de hash automáticamente
hash_type = identify_hash("5d41402abc4b2a76b9719d911017c592")
print(hash_type)  # "MD5"
```

</details>

### 🖼️ Esteganografía

<details>
<summary><strong>Texto y Whitespace</strong></summary>

```python
from ctfutils.stego.text import hide_text_whitespace, zero_width_encode

# Ocultar en espacios y tabs
cover_text = "Este es un texto normal."
hidden = hide_text_whitespace(cover_text, "FLAG{hidden}")

# Caracteres zero-width
invisible = zero_width_encode("secret")
public_text = f"Texto público{invisible} continúa aquí."
```

</details>

### 🔍 Análisis Forense

<details>
<summary><strong>Análisis de Archivos</strong></summary>

```python
from ctfutils.forensics.files import extract_strings, file_signature

# Extraer strings de binarios
strings = extract_strings("suspicious.exe", min_length=6)
flags = [s for s in strings if "FLAG{" in s]

# Identificar tipo de archivo
info = file_signature("mystery_file")
print(f"Tipo: {info['type']}, Tamaño: {info['size']} bytes")
```

</details>

### 🔧 Utilidades

<details>
<summary><strong>Encodings y Conversores</strong></summary>

```python
from ctfutils.misc.encodings import hex_encode, morse_encode
from ctfutils.misc.converters import ascii_to_hex

# Múltiples encodings
hex_result = hex_encode("Hello World")
morse_result = morse_encode("SOS")

# Conversiones ASCII
ascii_values = ascii_to_hex("ABC", separator=" ")  # "41 42 43"
```

</details>
## 📚 Documentación

### 🧪 Testing y Desarrollo

```bash
# Ejecutar todos los tests
pytest tests/ -v

# Tests con cobertura
pytest --cov=ctfutils tests/

# Test específico por módulo
pytest tests/test_crypto.py -v
```

### 🛠️ Estructura del Proyecto

```
ctfutils/
├── crypto/          # Módulo de criptografía
│   ├── classical.py    # Caesar, Vigenère, etc.
│   ├── modern.py       # Base64, XOR, etc.
│   └── hashing.py      # MD5, SHA*, etc.
├── stego/           # Módulo de esteganografía  
│   ├── text.py         # Whitespace, zero-width
│   └── image.py        # LSB en imágenes
├── forensics/       # Módulo forense
│   ├── files.py        # Análisis de archivos
│   ├── network.py      # Logs y red
│   └── memory.py       # Dumps de memoria
└── misc/            # Utilidades
    ├── encodings.py    # Múltiples encodings
    ├── converters.py   # Conversores
    └── utils.py        # Matemáticas y más
```

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Este proyecto está en desarrollo activo.

### 📋 Guidelines

✅ **Tests**: Asegúrate de que todos los tests pasen  
✅ **Código**: Sigue PEP 8 y añade docstrings  
✅ **Documentación**: Actualiza README si es necesario  
✅ **Funcionalidades**: Añade tests para nuevas características  

### 🚀 Ideas Futuras

- 🎵 **Audio Steganography**: LSB en archivos WAV
- 📡 **PCAP Analysis**: Integración completa con Scapy  
- 🔒 **Advanced Crypto**: RSA, ECC, algoritmos modernos
- 🕸️ **Web Utils**: SQL injection helpers, XSS payloads
- 🤖 **ML Integration**: Detección automática de cifrados

## 📊 Estado del Proyecto

<div align="center">

| Métrica | Valor |
|---------|-------|
| 📅 **Versión** | 0.1.0 |
| 📈 **Estado** | En desarrollo activo |
| 🧪 **Tests** | ~85% cobertura |
| 📚 **Funciones** | 80+ implementadas |
| 🐍 **Python** | 3.8+ compatible |

</div>

## 📝 Licencia

Este proyecto está licenciado bajo la **Licencia MIT** - ver el archivo [LICENSE](LICENSE) para detalles.

```
MIT License - Libre para usar, modificar y distribuir
```

## ⚠️ Disclaimer Legal

**Esta herramienta está diseñada exclusivamente para:**

✅ Propósitos educativos y de investigación  
✅ Competencias CTF legítimas  
✅ Investigación de seguridad autorizada  
✅ Análisis forense legal  

Los usuarios son completamente responsables de asegurar que tienen la autorización adecuada antes de usar estas herramientas en cualquier sistema o dato.

---

<div align="center">

### 🚀 Desarrollado con ❤️ para la comunidad CTF

**[📂 Repositorio](https://github.com/Oxidizerhack/ctfutils)** • **[🐛 Issues](https://github.com/Oxidizerhack/ctfutils/issues)** • **[💬 Discusiones](https://github.com/Oxidizerhack/ctfutils/discussions)**

</div>