# 🔐 CTFUtils

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![GitHub](https://img.shields.io/badge/GitHub-Oxidizerhack%2Fctfutils-blue)](https://github.com/Oxidizerhack/ctfutils)

**CTFUtils** es una librería completa de Python diseñada específicamente para competencias de **CTF (Capture the Flag)** y desafíos de ciberseguridad. Proporciona herramientas fáciles de usar para criptografía, esteganografía, análisis forense y diversas tareas de codificación/decodificación comúnmente encontradas en competencias CTF.

## 📋 Tabla de Contenidos

- [🚀 Instalación](#-instalación)
- [📦 Dependencias](#-dependencias)
- [🎯 Módulos Disponibles](#-módulos-disponibles)
- [📖 Guía de Uso](#-guía-de-uso)
- [💡 Ejemplos Prácticos](#-ejemplos-prácticos)
- [🧪 Testing](#-testing)
- [🤝 Contribuciones](#-contribuciones)
- [📝 Licencia](#-licencia)

## 🚀 Instalación

### Instalación Local para Desarrollo
```bash
git clone https://github.com/Oxidizerhack/ctfutils.git
cd ctfutils
pip install -e .



Requisitos del Sistema
Python 3.8+
Sistema Operativo: Windows, Linux, macOS
📦 Dependencias
Dependencias Principales
Pillow >= 8.0.0: Procesamiento de imágenes para esteganografía LSB
cryptography >= 3.0.0: Algoritmos criptográficos avanzados
requests >= 2.25.0: Descargas y análisis de red
Dependencias de Desarrollo
pytest >= 6.0.0: Framework de testing
pytest-cov >= 2.0.0: Cobertura de código
black >= 21.0.0: Formateador automático de código
flake8 >= 3.8.0: Linter para calidad de código
Librerías Estándar Integradas
base64, hashlib, urllib.parse, html, re, os, math, itertools, struct
🎯 Módulos Disponibles
CTFUtils está organizado en 4 módulos principales:

Módulo	Descripción	Funciones Principales
🔐 crypto	Criptografía clásica y moderna	Caesar, Vigenère, Base64, XOR, Hashing
🖼️ stego	Esteganografía multimedia	Whitespace, Zero-width, LSB en imágenes
🔍 forensics	Análisis forense digital	Strings extraction, File analysis, Network logs
🔧 misc	Utilidades diversas	Encoding/Decoding, Conversores, Math utils
📖 Guía de Uso
🔐 Módulo Crypto - Criptografía
Criptografía Clásica
Python


from ctfutils.crypto.classical import caesar_encrypt, caesar_decrypt
from ctfutils.crypto.classical import vigenere_encrypt, vigenere_decrypt

# === CAESAR CIPHER ===
# Cifrado básico
texto = "HELLO WORLD"
cifrado = caesar_encrypt(texto, 3)
print(cifrado)  # "KHOOR ZRUOG"

# Descifrado
original = caesar_decrypt(cifrado, 3)
print(original)  # "HELLO WORLD"

# ROT13 (caso especial)
rot13 = caesar_encrypt("Attack at dawn!", 13)
print(rot13)  # "Nggnpx ng qnja!"

# === VIGENÈRE CIPHER ===
# Cifrado con clave
mensaje = "ATTACK AT DAWN"
clave = "LEMON"
cifrado_v = vigenere_encrypt(mensaje, clave)
print(cifrado_v)  # "LXFOPV EF RNHR"

# Descifrado
original_v = vigenere_decrypt(cifrado_v, clave)
print(original_v)  # "ATTACK AT DAWN"
Criptografía Moderna
Python


from ctfutils.crypto.modern import base64_encode, base64_decode
from ctfutils.crypto.modern import xor_encrypt, xor_decrypt_hex

# === BASE64 ===
texto = "Hello CTF World! 🚩"
b64_encoded = base64_encode(texto)
print(f"Base64: {b64_encoded}")

b64_decoded = base64_decode(b64_encoded)
print(f"Decoded: {b64_decoded}")

# === XOR ENCRYPTION ===
secreto = "FLAG{this_is_secret}"
key = "CTF"
xor_result = xor_encrypt(secreto, key)
print(f"XOR (hex): {xor_result}")

# Descifrado XOR
original_xor = xor_decrypt_hex(xor_result, key)
print(f"XOR Decrypted: {original_xor}")
Sistema de Hashing
Python


from ctfutils.crypto.hashing import md5_hash, sha256_hash, sha1_hash
from ctfutils.crypto.hashing import verify_hash, identify_hash

# === GENERACIÓN DE HASHES ===
password = "admin123"

md5_result = md5_hash(password)
sha1_result = sha1_hash(password)
sha256_result = sha256_hash(password)

print(f"MD5:    {md5_result}")
print(f"SHA1:   {sha1_result}")
print(f"SHA256: {sha256_result}")

# === VERIFICACIÓN DE HASHES ===
hash_encontrado = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
if verify_hash("hello", hash_encontrado, "sha256"):
    print("¡Password correcto!")

# === IDENTIFICACIÓN AUTOMÁTICA ===
hash_misterioso = "5d41402abc4b2a76b9719d911017c592"
tipo = identify_hash(hash_misterioso)
print(f"Tipo detectado: {tipo}")  # "MD5"
🖼️ Módulo Stego - Esteganografía
Esteganografía en Texto
Python


from ctfutils.stego.text import hide_text_whitespace, extract_text_whitespace
from ctfutils.stego.text import zero_width_encode, zero_width_decode

# === WHITESPACE STEGANOGRAPHY ===
texto_cobertura = """Este es un documento completamente normal.
No contiene información oculta.
Es solo un archivo de texto común."""

mensaje_oculto = "FLAG{hidden_in_spaces_and_tabs}"

# Ocultar usando espacios y tabs
stego_text = hide_text_whitespace(texto_cobertura, mensaje_oculto)
print("✅ Mensaje oculto en whitespace")

# Extraer mensaje
mensaje_extraido = extract_text_whitespace(stego_text)
print(f"🔍 Mensaje encontrado: {mensaje_extraido}")

# === ZERO-WIDTH CHARACTERS ===
secreto_zw = "CTF{invisible_chars}"
encoded_zw = zero_width_encode(secreto_zw)

# Texto que parece normal pero tiene datos ocultos
texto_publico = f"Este texto parece normal{encoded_zw} pero esconde algo."
print("Texto con datos invisibles creado")

decoded_zw = zero_width_decode(texto_publico)
print(f"🔍 Datos invisibles: {decoded_zw}")
Esteganografía en Imágenes
Python


from ctfutils.stego.image import hide_text_lsb, extract_text_lsb

# === LSB STEGANOGRAPHY ===
# Requiere imagen PNG sin compresión con pérdida
mensaje_img = "FLAG{hidden_in_pixels}"

# Ocultar en imagen
try:
    hide_text_lsb("cover_image.png", mensaje_img, "stego_image.png")
    print("✅ Mensaje ocultado en imagen")
    
    # Extraer de imagen
    mensaje_recuperado = extract_text_lsb("stego_image.png")
    print(f"🔍 Mensaje en imagen: {mensaje_recuperado}")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("💡 Tip: Necesitas Pillow y una imagen PNG válida")
🔍 Módulo Forensics - Análisis Forense
Análisis de Archivos
Python


from ctfutils.forensics.files import extract_strings, file_signature
from ctfutils.forensics.files import metadata_extract, hex_dump

# === EXTRACCIÓN DE STRINGS ===
# Extraer texto legible de binarios
strings_encontrados = extract_strings("suspicious_file.exe", min_length=6)

print(f"📄 Encontrados {len(strings_encontrados)} strings")
for i, string in enumerate(strings_encontrados[:10]):
    print(f"  {i+1:2d}. {string}")

# Buscar flags específicamente
possible_flags = [s for s in strings_encontrados if any(flag in s for flag in ["FLAG{", "CTF{", "flag{"])]
print(f"🚩 Posibles flags: {possible_flags}")

# === IDENTIFICACIÓN DE ARCHIVOS ===
file_info = file_signature("mystery_file")
print(f"🔍 Análisis de archivo:")
print(f"  Tipo detectado: {file_info['type']}")
print(f"  Tamaño: {file_info['size']:,} bytes")
print(f"  Header hex: {file_info['header_hex']}")
print(f"  Header ASCII: '{file_info['header_ascii']}'")

# === METADATOS COMPLETOS ===
metadata = metadata_extract("important_file.pdf")
print(f"📋 Metadatos: {metadata}")

# === HEX DUMP ===
hex_output = hex_dump("binary_file.bin", offset=0, length=128)
print("🔢 Hex dump (primeros 128 bytes):")
print(hex_output)
Análisis de Red y Logs
Python


from ctfutils.forensics.network import extract_http_data, extract_urls
from ctfutils.forensics.network import extract_ip_addresses, extract_email_addresses

# === ANÁLISIS DE LOGS HTTP ===
log_sample = """
10.0.1.100 - - [02/Sep/2025:10:15:30 +0000] "GET /admin/panel HTTP/1.1" 200 1024
192.168.1.50 - - [02/Sep/2025:10:15:31 +0000] "POST /login HTTP/1.1" 401 512
172.16.0.25 - - [02/Sep/2025:10:15:32 +0000] "GET /flag.txt HTTP/1.1" 200 45
10.0.1.100 - - [02/Sep/2025:10:15:33 +0000] "GET /secret/data HTTP/1.1" 403 256
"""

# Extraer requests HTTP
http_requests = extract_http_data(log_sample)
print("🌐 Requests HTTP encontrados:")
for req in http_requests:
    print(f"  {req['method']} {req['path']} - IP: {req.get('ip', 'N/A')}")

# === EXTRACCIÓN DE INFORMACIÓN ===
texto_mixto = """
Para más información visita https://ctf-challenge.example.com/secret
O contacta al admin: support@ctfteam.org
Servidores principales: 192.168.1.10, 10.0.0.5, 172.16.254.1
Backup disponible en www.backup-ctf.net
Email alternativo: emergency@ctfsec.com
"""

urls = extract_urls(texto_mixto)
ips = extract_ip_addresses(texto_mixto)
emails = extract_email_addresses(texto_mixto)

print(f"🔗 URLs: {urls}")
print(f"🌍 IPs: {ips}")
print(f"📧 Emails: {emails}")
Análisis de Memoria
Python


from ctfutils.forensics.memory import find_patterns, search_memory_strings

# === BÚSQUEDA DE PATRONES ===
# Buscar flags en dumps de memoria
try:
    flag_patterns = find_patterns("memory.dump", "FLAG{", context=50)
    print(f"🚩 Encontrados {len(flag_patterns)} patrones de flags")
    
    for pattern in flag_patterns[:3]:  # Mostrar primeros 3
        print(f"  Offset: {pattern['offset']:08x}")
        print(f"  Contexto: {pattern['context_ascii'][:100]}...")
        
except FileNotFoundError:
    print("💡 Archivo memory.dump no encontrado")

# === BÚSQUEDA MÚLTIPLE ===
search_terms = ["password", "secret", "key", "flag", "admin"]
try:
    results = search_memory_strings("memory.dump", search_terms)
    
    for term, matches in results.items():
        if matches:
            print(f"🔑 '{term}': {len(matches)} coincidencias")
            
except FileNotFoundError:
    print("💡 Para análisis de memoria, necesitas un archivo de volcado")
🔧 Módulo Misc - Utilidades
Encodings y Decodificaciones
Python


from ctfutils.misc.encodings import *

# === ENCODINGS BÁSICOS ===
texto_original = "Hello CTF World!"

# Hexadecimal
hex_result = hex_encode(texto_original)
print(f"Hex: {hex_result}")
hex_back = hex_decode(hex_result)
print(f"Hex decoded: {hex_back}")

# Binario
binary_result = binary_encode(texto_original)
print(f"Binary: {binary_result}")
binary_back = binary_decode(binary_result)
print(f"Binary decoded: {binary_back}")

# Base32
base32_result = base32_encode(texto_original)
print(f"Base32: {base32_result}")

# URL Encoding
url_text = "Hello World & Special Chars!"
url_encoded = url_encode(url_text)
print(f"URL encoded: {url_encoded}")

# === MORSE CODE ===
mensaje_morse = "SOS HELP ME"
morse_encoded = morse_encode(mensaje_morse)
print(f"Morse: {morse_encoded}")
morse_decoded = morse_decode(morse_encoded)
print(f"Morse decoded: {morse_decoded}")

# === CIFRADOS ADICIONALES ===
# ROT encoding personalizable
rot_result = rot_encode("Hello", 7)
print(f"ROT7: {rot_result}")

# Atbash (A=Z, B=Y, etc.)
atbash_result = atbash_encode("HELLO")
print(f"Atbash: {atbash_result}")  # "SVOOL"
Convertidores y Transformaciones
Python


from ctfutils.misc.converters import *

# === CONVERSIONES NUMÉRICAS ===
texto = "ABC"

# ASCII a diferentes formatos
hex_values = ascii_to_hex(texto, separator=" ")
print(f"ASCII to Hex: {hex_values}")  # "41 42 43"

ascii_values = text_to_ascii_values(texto, separator=", ")
print(f"ASCII values: {ascii_values}")  # "65, 66, 67"

# Conversiones de base
numero = 255
print(f"255 en binario: {decimal_to_binary(numero)}")
print(f"255 en hex: {decimal_to_hex(numero)}")

# === MANIPULACIÓN DE STRINGS ===
texto_ejemplo = "Hello World 123"

print(f"Reverso: {reverse_string(texto_ejemplo)}")
print(f"Sin espacios: {remove_whitespace(texto_ejemplo)}")
print(f"En chunks de 3: {chunk_string(texto_ejemplo, 3)}")

# Intercalar strings
str1, str2 = "ACE", "135"
intercalado = interleave_strings(str1, str2)
print(f"Intercalado: {intercalado}")  # "A1C3E5"

# Extraer elementos
texto_mixto = "H3ll0 W0rld! 2025"
numeros = extract_numbers(texto_mixto)
letras = extract_letters(texto_mixto)
print(f"Números extraídos: {numeros}")
print(f"Letras extraídas: {letras}")
Utilidades Matemáticas y Análisis
Python


from ctfutils.misc.utils import *

# === ANÁLISIS DE ENTROPÍA ===
texto_random = "x9k2mf8qp1w7n4cv6b3z5j8h9g2k1m"
texto_repetitivo = "aaaaaaaaaaaaaaaaaaaaaaaaa"

entropy_alta = calculate_entropy(texto_random)
entropy_baja = calculate_entropy(texto_repetitivo)

print(f"Entropía alta: {entropy_alta:.3f} bits")
print(f"Entropía baja: {entropy_baja:.3f} bits")
print("💡 Entropía alta sugiere datos cifrados/comprimidos")

# === FUNCIONES MATEMÁTICAS ===
# Máximo común divisor y mínimo común múltiplo
a, b = 48, 18
print(f"GCD({a}, {b}) = {gcd(a, b)}")
print(f"LCM({a}, {b}) = {lcm(a, b)}")

# Análisis de primalidad
numeros_test = [17, 25, 97, 100]
for num in numeros_test:
    primo = "es primo" if is_prime(num) else "no es primo"
    print(f"{num} {primo}")

# Factorización
numero_factor = 60
factores = prime_factors(numero_factor)
print(f"Factores primos de {numero_factor}: {factores}")

# === GENERACIÓN DE WORDLISTS ===
# Wordlist pequeña para demostración
charset = "abc"
wordlist = list(generate_wordlist(charset, 2, 3))
print(f"Wordlist generada: {wordlist[:10]}...")  # Primeras 10

# Bruteforce con patrón
pattern = "ctf{??}"  # 2 caracteres variables
charset_hex = "0123456789abcdef"
candidates = list(bruteforce_pattern(pattern, charset_hex))
print(f"Candidatos para '{pattern}': {candidates[:5]}...")

# === ANÁLISIS DE DISTANCIAS ===
# Útil para análisis de similitud
str1, str2 = "kitten", "sitting"
hamming_dist = hamming_distance("karolin", "kathrin")  # Mismo tamaño
levenshtein_dist = levenshtein_distance(str1, str2)

print(f"Distancia Hamming: {hamming_dist}")
print(f"Distancia Levenshtein entre '{str1}' y '{str2}': {levenshtein_dist}")
💡 Ejemplos Prácticos de CTF
Caso 1: Desafío de Criptografía Mixta
Python


# Mensaje encontrado en un CTF
mensaje_misterioso = "SGVsbG8gQ1RGISBGTEFHe2I0czM2NF9pc19mdW59"

print("🔍 Analizando mensaje misterioso...")

# Paso 1: ¿Es Base64?
try:
    paso1 = base64_decode(mensaje_misterioso)
    print(f"✅ Base64 decoded: {paso1}")
    
    # Paso 2: ¿Necesita más decodificación?
    if "FLAG{" in paso1:
        print(f"🚩 ¡Flag encontrado!: {paso1}")
    else:
        # Paso 3: ¿Es otro encoding?
        try:
            paso2 = base64_decode(paso1)
            print(f"✅ Doble Base64: {paso2}")
        except:
            print("🔄 Probando otros métodos...")
            
except Exception as e:
    print(f"❌ No es Base64: {e}")
Caso 2: Análisis Forense de Archivo
Python


# Archivo sospechoso descargado
archivo_ctf = "challenge_file.dat"

print("🔍 Iniciando análisis forense...")

# Paso 1: Identificar tipo real
try:
    info = file_signature(archivo_ctf)
    print(f"📄 Tipo detectado: {info['type']}")
    print(f"📏 Tamaño: {info['size']:,} bytes")
    
    # Paso 2: Extraer strings
    strings = extract_strings(archivo_ctf, min_length=8)
    print(f"📝 Strings encontrados: {len(strings)}")
    
    # Paso 3: Buscar flags
    flags = [s for s in strings if any(f in s.upper() for f in ["FLAG", "CTF"])]
    if flags:
        print(f"🚩 Posibles flags: {flags}")
    
    # Paso 4: Hex dump de cabecera
    header_dump = hex_dump(archivo_ctf, 0, 64)
    print(f"🔢 Header hex:\n{header_dump}")
    
except FileNotFoundError:
    print("💡 Archivo no encontrado, creando ejemplo...")
Caso 3: Esteganografía en Múltiples Capas
Python


# Texto aparentemente normal de un CTF
texto_sospechoso = """Este documento contiene información importante.
Por favor léelo cuidadosamente.
No hay nada oculto aquí."""

print("🔍 Buscando información oculta...")

# Método 1: Whitespace steganography
try:
    hidden1 = extract_text_whitespace(texto_sospechoso)
    if hidden1:
        print(f"✅ Encontrado en whitespace: {hidden1}")
except:
    print("❌ No hay datos en whitespace")

# Método 2: Zero-width characters
try:
    hidden2 = zero_width_decode(texto_sospechoso)
    if hidden2:
        print(f"✅ Encontrado en zero-width: {hidden2}")
except:
    print("❌ No hay zero-width chars")

# Método 3: Análisis de entropía
entropy = calculate_entropy(texto_sospechoso)
print(f"📊 Entropía del texto: {entropy:.3f}")
if entropy > 4.0:
    print("⚠️  Entropía alta - posible cifrado oculto")
Caso 4: Cracking Automático de Caesar
Python


# Mensaje cifrado con Caesar desconocido
mensaje_caesar = "WKLV LV D VHFUHW PHVVDJH IURP WKH FWI"

print("🔍 Intentando cracking automático de Caesar...")

for shift in range(1, 26):
    decoded = caesar_decrypt(mensaje_caesar, shift)
    
    # Buscar palabras comunes en inglés
    palabras_comunes = ["THE", "AND", "FLAG", "SECRET", "MESSAGE", "CTF"]
    palabras_encontradas = sum(1 for palabra in palabras_comunes if palabra in decoded.upper())
    
    if palabras_encontradas >= 2:
        print(f"🎯 Shift {shift} (score: {palabras_encontradas}): {decoded}")
        
# Resultado esperado: Shift 3: "THIS IS A SECRET MESSAGE FROM THE CTF"
🧪 Testing
Ejecutar Tests
bash


# Tests básicos
pytest tests/ -v

# Tests con cobertura
pytest --cov=ctfutils tests/

# Test de módulo específico
pytest tests/test_crypto.py -v

# Tests con output detallado
pytest tests/ -v -s
Estructura de Tests
Code


tests/
├── __init__.py
├── test_crypto.py          # Tests criptografía
├── test_stego.py           # Tests esteganografía
├── test_forensics.py       # Tests análisis forense
└── test_misc.py            # Tests utilidades
🤝 Contribuciones
¡Las contribuciones son bienvenidas! Este proyecto está en desarrollo activo.

Cómo Contribuir
Fork el repositorio
Crea una rama para tu feature (git checkout -b feature/nueva-funcionalidad)
Commit tus cambios (git commit -m 'Añadir nueva funcionalidad')
Push a la rama (git push origin feature/nueva-funcionalidad)
Abre un Pull Request
Guidelines
✅ Asegúrate de que todos los tests pasen
✅ Añade tests para nuevas funcionalidades
✅ Sigue PEP 8 para estilo de código
✅ Documenta funciones con docstrings
✅ Actualiza el README si es necesario
Ideas para Futuras Mejoras
🎵 Audio Steganography: LSB en archivos WAV
📡 PCAP Analysis: Integración completa con Scapy
🔒 Advanced Crypto: RSA, ECC, algoritmos modernos
🕸️ Web Utils: SQL injection helpers, XSS payloads
🤖 ML Integration: Detección automática de cifrados
📝 Licencia
Este proyecto está licenciado bajo la Licencia MIT. Ver el archivo LICENSE para más detalles.

Code


MIT License - Libre para usar, modificar y distribuir
🔗 Enlaces y Recursos
📂 Repositorio: https://github.com/Oxidizerhack/ctfutils
🐛 Reportar Issues: https://github.com/Oxidizerhack/ctfutils/issues
💬 Discusiones: https://github.com/Oxidizerhack/ctfutils/discussions
⚠️ Disclaimer Legal
Esta herramienta está diseñada exclusivamente para:

✅ Propósitos educativos
✅ Competencias CTF legítimas
✅ Investigación de seguridad autorizada
✅ Análisis forense legal
Los usuarios son completamente responsables de asegurar que tienen la autorización adecuada antes de usar estas herramientas en cualquier sistema o dato.

📊 Estado del Proyecto
📅 Versión Actual: 0.1.0
📈 Estado: En desarrollo activo
🧪 Cobertura de Tests: ~85%
📚 Funciones Implementadas: 80+
🐍 Compatibilidad: Python 3.8+
🚀 Desarrollado con ❤️ para la comunidad CTF por Oxidizerhack

Última actualización: 02 de Septiembre, 2025