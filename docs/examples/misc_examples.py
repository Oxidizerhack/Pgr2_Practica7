#!/usr/bin/env python3
"""
CTFUtils - Ejemplos Prácticos del Módulo Misc
============================================

Ejemplos de utilidades misceláneas para CTFs
"""

from ctfutils.misc.converters import NumberConverter, TextConverter
from ctfutils.misc.utils import StringManipulator
from ctfutils.misc.encodings import base64_encode, base64_decode, url_encode, url_decode

def ejemplo_number_conversions():
    """Ejemplo: Conversiones numéricas típicas en CTF"""
    print("🔢 EJEMPLO: Conversiones Numéricas")
    print("="*40)
    
    converter = NumberConverter()
    
    # Número encontrado en un CTF
    numero_decimal = 1847618633
    print(f"Número encontrado: {numero_decimal}")
    print()
    
    # Probar diferentes bases
    print("🔄 Conversiones a diferentes bases:")
    
    # Binario
    binario = converter.decimal_to_binary(numero_decimal)
    print(f"   Binario: {binario}")
    
    # Hexadecimal
    hexadecimal = converter.decimal_to_hex(numero_decimal)
    print(f"   Hexadecimal: {hexadecimal}")
    
    # Octal
    octal = converter.decimal_to_octal(numero_decimal)
    print(f"   Octal: {octal}")
    
    # Base36
    base36 = converter.decimal_to_base(numero_decimal, 36)
    print(f"   Base36: {base36}")
    
    print(f"\n💡 Pista: ¿Podrían estos representar ASCII?")
    
    # Intentar interpretar como ASCII
    # Dividir en chunks de 8 bits
    print(f"\n🔍 Interpretando binario como ASCII:")
    for i in range(0, len(binario), 8):
        byte_chunk = binario[i:i+8]
        if len(byte_chunk) == 8:
            ascii_val = int(byte_chunk, 2)
            if 32 <= ascii_val <= 126:  # ASCII imprimible
                char = chr(ascii_val)
                print(f"   {byte_chunk} -> {ascii_val} -> '{char}'")
    
    # Hex como bytes
    print(f"\n🔍 Interpretando hex como bytes:")
    try:
        hex_clean = hexadecimal.replace('0x', '')
        if len(hex_clean) % 2 == 0:
            bytes_data = bytes.fromhex(hex_clean)
            ascii_text = bytes_data.decode('ascii', errors='ignore')
            print(f"   Hex: {hex_clean}")
            print(f"   Como ASCII: '{ascii_text}'")
    except:
        print("   No es ASCII válido")
    
    print()

def ejemplo_text_conversions():
    """Ejemplo: Conversiones de texto"""
    print("📝 EJEMPLO: Conversiones de Texto")
    print("="*40)
    
    converter = TextConverter()
    
    # Texto encontrado en CTF
    texto_original = "Hello CTF World!"
    print(f"Texto original: '{texto_original}'")
    print()
    
    # Diferentes conversiones
    print("🔄 Aplicando transformaciones:")
    
    # ASCII a números
    ascii_nums = converter.text_to_ascii(texto_original)
    print(f"   ASCII numbers: {ascii_nums}")
    
    # Binario
    binario = converter.text_to_binary(texto_original)
    print(f"   Binario: {binario}")
    
    # Hexadecimal
    hexadecimal = converter.text_to_hex(texto_original)
    print(f"   Hexadecimal: {hexadecimal}")
    
    # Proceso inverso
    print(f"\n🔄 Conversiones inversas:")
    
    # De ASCII numbers de vuelta a texto
    texto_desde_ascii = converter.ascii_to_text(ascii_nums)
    print(f"   Desde ASCII: '{texto_desde_ascii}'")
    
    # De binario de vuelta a texto
    texto_desde_bin = converter.binary_to_text(binario)
    print(f"   Desde binario: '{texto_desde_bin}'")
    
    # De hex de vuelta a texto
    texto_desde_hex = converter.hex_to_text(hexadecimal)
    print(f"   Desde hex: '{texto_desde_hex}'")
    
    # Verificar integridad
    if texto_desde_ascii == texto_desde_bin == texto_desde_hex == texto_original:
        print(f"✅ ¡Todas las conversiones son correctas!")
    
    print()

def ejemplo_string_manipulation():
    """Ejemplo: Manipulación de strings"""
    print("🔧 EJEMPLO: Manipulación de Strings")
    print("="*40)
    
    manipulator = StringManipulator()
    
    # String codificado encontrado en CTF
    string_codificado = "SVOOL_PGS_JBEYQ"
    print(f"String encontrado: '{string_codificado}'")
    print()
    
    print("🔄 Probando diferentes manipulaciones:")
    
    # Reverso
    reverso = manipulator.reverse_string(string_codificado)
    print(f"   Reverso: '{reverso}'")
    
    # ROT13
    rot13 = manipulator.rot13(string_codificado)
    print(f"   ROT13: '{rot13}'")
    
    # Mayúsculas/minúsculas
    minusculas = manipulator.to_lowercase(string_codificado)
    print(f"   Minúsculas: '{minusculas}'")
    
    # Intercambio de case
    case_swap = manipulator.swap_case(string_codificado.lower())
    print(f"   Case swap: '{case_swap}'")
    
    # Quitar caracteres
    sin_underscores = manipulator.remove_chars(string_codificado, "_")
    print(f"   Sin underscores: '{sin_underscores}'")
    
    # Reemplazar caracteres
    con_espacios = manipulator.replace_chars(string_codificado, "_", " ")
    print(f"   Underscores->espacios: '{con_espacios}'")
    
    # Combinaciones
    print(f"\n🎯 Probando combinaciones:")
    combinacion1 = manipulator.rot13(manipulator.reverse_string(string_codificado))
    print(f"   Reverso + ROT13: '{combinacion1}'")
    
    combinacion2 = manipulator.reverse_string(manipulator.rot13(string_codificado))
    print(f"   ROT13 + Reverso: '{combinacion2}'")
    
    print()

def ejemplo_encoding_decoding():
    """Ejemplo: Codificación y decodificación"""
    print("🔐 EJEMPLO: Encoding/Decoding")
    print("="*40)
    
    # Mensaje original
    mensaje = "CTF{encoding_challenge_solved}"
    print(f"Mensaje original: '{mensaje}'")
    print()
    
    print("🔄 Aplicando diferentes encodings:")
    
    # Base64
    b64_encoded = base64_encode(mensaje)
    print(f"   Base64: {b64_encoded}")
    
    # URL encoding
    url_encoded = url_encode(mensaje)
    print(f"   URL encoded: {url_encoded}")
    
    # Proceso de decodificación
    print(f"\n🔄 Decodificando:")
    
    # Base64 decode
    b64_decoded = base64_decode(b64_encoded)
    print(f"   Base64 decoded: '{b64_decoded}'")
    
    # URL decode
    url_decoded = url_decode(url_encoded)
    print(f"   URL decoded: '{url_decoded}'")
    
    # Verificación
    if b64_decoded == url_decoded == mensaje:
        print(f"✅ ¡Todas las decodificaciones correctas!")
    
    print()

def ejemplo_ctf_challenge():
    """Ejemplo: Challenge CTF completo"""
    print("🎯 EJEMPLO: CTF Challenge Completo")
    print("="*40)
    
    print("📋 Challenge: 'Multiple Layers'")
    print("   Descripción: Decodifica el mensaje oculto")
    print("   Pista: 'Los números no mienten, pero a veces se disfrazan'")
    print()
    
    # El challenge (múltiples capas de encoding)
    challenge_input = "NTQgNjggNjkgNzMgMjAgNjkgNzMgMjAgNjEgMjAgNzMgNjUgNjMgNzIgNjUgNzQgMjAgNjYgNmMgNjEgNjc="
    print(f"📥 Input del challenge: {challenge_input}")
    print()
    
    print("🔍 Proceso de solución:")
    
    # Paso 1: Parece Base64
    print("1️⃣ Detectando Base64...")
    step1 = base64_decode(challenge_input)
    print(f"   Decodificado: '{step1}'")
    
    # Paso 2: Ahora tenemos números separados por espacios
    print(f"\n2️⃣ Analizando números...")
    numeros = step1.split()
    print(f"   Números encontrados: {numeros}")
    
    # Paso 3: Convertir números a ASCII
    print(f"\n3️⃣ Convirtiendo a ASCII...")
    converter = TextConverter()
    ascii_chars = []
    
    for num in numeros:
        ascii_val = int(num)
        char = chr(ascii_val)
        ascii_chars.append(char)
        print(f"   {num} -> '{char}'")
    
    mensaje_final = ''.join(ascii_chars)
    print(f"\n🎯 Mensaje final: '{mensaje_final}'")
    
    # Paso 4: ¿Hay más capas?
    print(f"\n4️⃣ ¿Hay más transformaciones?")
    
    # Probar ROT13
    manipulator = StringManipulator()
    rot13_result = manipulator.rot13(mensaje_final)
    print(f"   ROT13: '{rot13_result}'")
    
    # Probar reverso
    reverse_result = manipulator.reverse_string(mensaje_final)
    print(f"   Reverso: '{reverse_result}'")
    
    # Buscar patrones de flag
    import re
    flag_patterns = [r'CTF\{[^}]+\}', r'FLAG\{[^}]+\}', r'flag\{[^}]+\}']
    
    textos_a_revisar = [mensaje_final, rot13_result, reverse_result]
    
    print(f"\n🔍 Buscando patterns de flag...")
    for i, texto in enumerate(textos_a_revisar, 1):
        for pattern in flag_patterns:
            matches = re.findall(pattern, texto, re.IGNORECASE)
            if matches:
                print(f"   ✅ FLAG encontrada en transformación {i}: {matches[0]}")
                break
    
    print(f"\n📊 RESUMEN:")
    print(f"   Base64 -> Números ASCII -> Texto plano")
    print(f"   Técnicas usadas: Base64 decode, ASCII conversion")
    print(f"   🏆 Challenge resuelto!")
    
    print()

if __name__ == "__main__":
    print("🚩 CTFUtils - Ejemplos Prácticos de Utilidades Misc")
    print("="*55)
    print()
    
    ejemplo_number_conversions()
    ejemplo_text_conversions()
    ejemplo_string_manipulation()
    ejemplo_encoding_decoding()
    ejemplo_ctf_challenge()
    
    print("🎯 ¡Utilidades misc completadas! Usa estas herramientas para resolver challenges.")
