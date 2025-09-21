# CTFUtils - Ejemplos Prácticos

Esta carpeta contiene ejemplos prácticos de uso de la librería CTFUtils en competencias CTF reales.

## 📚 Ejemplos Disponibles

### 🔐 [crypto_examples.py](crypto_examples.py)
**Módulo de Criptografía**
- ✅ Caesar Cipher con brute force
- ✅ Vigenère Cipher con clave conocida
- ✅ Análisis de hashes MD5/SHA
- ✅ Cadenas de encoding complejas
- 🎯 **Casos de uso**: Challenges de crypto clásica, análisis de hashes, decodificación múltiple

### 🔍 [forensics_examples.py](forensics_examples.py)
**Módulo de Análisis Forense**
- ✅ Análisis de archivos binarios
- ✅ Extracción de strings y firmas
- ✅ Análisis de logs de red
- ✅ Análisis de memoria y procesos
- 🎯 **Casos de uso**: File analysis, network forensics, memory dumps

### 📝 [steganography_examples.py](steganography_examples.py)
**Módulo de Esteganografía**
- ✅ Ocultación en espacios de texto
- ✅ Caracteres de ancho cero
- ✅ LSB steganography en imágenes
- ✅ Detección de esteganografía
- 🎯 **Casos de uso**: Mensajes ocultos, análisis de texto/imagen

### 🔧 [misc_examples.py](misc_examples.py)
**Módulo de Utilidades**
- ✅ Conversiones numéricas (bin/hex/oct)
- ✅ Transformaciones de texto
- ✅ Manipulación de strings (ROT13, reverse)
- ✅ Encoding/decoding múltiple
- 🎯 **Casos de uso**: Conversiones rápidas, transformaciones de datos

## 🚀 Cómo Usar los Ejemplos

### Ejecutar un ejemplo específico:
```bash
cd docs/examples/
python crypto_examples.py
python forensics_examples.py
python steganography_examples.py
python misc_examples.py
```

### Importar funciones en tus scripts:
```python
# Importar desde los ejemplos
import sys
sys.path.append('docs/examples')

from crypto_examples import ejemplo_caesar_cipher
from forensics_examples import ejemplo_file_analysis

# Usar en tu código
ejemplo_caesar_cipher()
```

## 📖 Estructura de cada ejemplo

Cada archivo sigue la misma estructura:
1. **Función específica**: Ejemplos enfocados en una técnica
2. **Datos de prueba**: Casos reales de CTF
3. **Proceso paso a paso**: Explicación detallada
4. **Resultados esperados**: Validación de salida
5. **Flujo completo**: Ejemplo de challenge real

## 🎯 Casos de Uso por Módulo

| Módulo | Casos CTF Comunes | Ejemplos Incluidos |
|--------|-------------------|-------------------|
| **crypto** | Caesar, Vigenère, Hash cracking | Brute force, hash analysis, multi-encoding |
| **forensics** | File analysis, Network logs, Memory dumps | Binary analysis, IP extraction, process analysis |
| **stego** | Hidden messages, LSB, Zero-width | Text hiding, image analysis, detection |
| **misc** | Number conversion, Text transform | Base conversion, string manipulation, complex decoding |

## 💡 Tips para CTFs

### 🔍 **Análisis Inicial**
1. Identifica el tipo de challenge (crypto, forensics, stego, misc)
2. Busca pistas en la descripción o archivos
3. Usa los ejemplos como plantilla

### 🛠️ **Flujo de Trabajo**
```python
# 1. Importar módulo necesario
from ctfutils.crypto.classical import CaesarCipher

# 2. Crear instancia
cipher = CaesarCipher()

# 3. Aplicar técnica
result = cipher.brute_force(encrypted_text)

# 4. Buscar flags
for shift, text in result.items():
    if 'CTF{' in text:
        print(f"FLAG encontrada: {text}")
```

### 🎯 **Patrones Comunes**
- **FLAGS**: `CTF{...}`, `FLAG{...}`, `flag{...}`
- **Encoding chains**: Base64 → ASCII → ROT13
- **Multiple layers**: Stego → Crypto → Encoding
- **Hidden data**: Strings, metadata, LSB

## 🔗 Referencias Adicionales

- [CTFUtils Documentation](../../README.md)
- [Testing Guide](../../tests/)
- [API Reference](../../ctfutils/)

---

💻 **Desarrollado para**: PRÁCTICA 7 - Desarrollo de Librería CTF  
🎓 **Curso**: Programación 2 - TECBA  
👨‍💻 **Autor**: Oxidizerhack
