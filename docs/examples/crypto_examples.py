#!/usr/bin/env python3
"""
CTFUtils - Ejemplos Prácticos del Módulo Crypto
===============================================

Ejemplos completos de uso para competencias CTF
"""

from ctfutils.crypto.classical import CaesarCipher, VigenereCipher
from ctfutils.crypto.hashing import HashAnalyzer
from ctfutils.crypto.modern import base64_encode, base64_decode, xor_encrypt

def ejemplo_caesar_cipher():
    """Ejemplo: Descifrar un mensaje Caesar en CTF"""
    print("🔐 EJEMPLO: Caesar Cipher en CTF")
    print("="*40)
    
    # Mensaje cifrado encontrado en un CTF
    mensaje_cifrado = "WKLV LV D VHFUHW IODJJ"
    print(f"Mensaje cifrado: {mensaje_cifrado}")
    
    # Crear instancia del cipher
    caesar = CaesarCipher()
    
    # Probar diferentes llaves (brute force)
    print("\n🔍 Brute force attack:")
    resultados = caesar.brute_force(mensaje_cifrado)
    
    for shift, texto in resultados.items():
        if "FLAG" in texto or "SECRET" in texto:
            print(f"✅ POSIBLE FLAG - Shift {shift}: {texto}")
        elif shift <= 5:  # Mostrar solo primeros 5
            print(f"   Shift {shift}: {texto}")
    
    print()

def ejemplo_vigenere_cipher():
    """Ejemplo: Descifrar Vigenère con clave conocida"""
    print("🔐 EJEMPLO: Vigenère Cipher en CTF")
    print("="*40)
    
    # Escenario típico de CTF
    mensaje_cifrado = "LXFOPV EF RNHR"
    clave_encontrada = "LEMON"  # Encontrada en otra pista
    
    print(f"Mensaje cifrado: {mensaje_cifrado}")
    print(f"Clave encontrada: {clave_encontrada}")
    
    # Descifrar
    vigenere = VigenereCipher()
    mensaje_original = vigenere.decrypt(mensaje_cifrado, clave_encontrada)
    
    print(f"✅ Mensaje descifrado: {mensaje_original}")
    print()

def ejemplo_hash_analysis():
    """Ejemplo: Análisis de hashes en CTF"""
    print("🔐 EJEMPLO: Análisis de Hashes")
    print("="*40)
    
    # Hash encontrado en un CTF
    hash_misterioso = "5d41402abc4b2a76b9719d911017c592"
    print(f"Hash encontrado: {hash_misterioso}")
    
    # Analizar el hash
    analyzer = HashAnalyzer()
    tipo_hash = analyzer.identify_hash(hash_misterioso)
    
    print(f"📋 Tipo identificado: {tipo_hash}")
    
    # Lista de palabras comunes para CTF
    wordlist = ["hello", "flag", "password", "admin", "ctf", "secret"]
    
    print("\n🔍 Probando wordlist...")
    for palabra in wordlist:
        hash_calculado = analyzer.md5_hash(palabra)
        if hash_calculado == hash_misterioso:
            print(f"✅ MATCH ENCONTRADO: '{palabra}' -> {hash_calculado}")
            break
        else:
            print(f"   '{palabra}' -> {hash_calculado} (no match)")
    
    print()

def ejemplo_encoding_chain():
    """Ejemplo: Cadena de encodings típica en CTF"""
    print("🔐 EJEMPLO: Cadena de Encodings")
    print("="*40)
    
    # Mensaje original
    flag_original = "CTF{this_is_the_flag}"
    print(f"Flag original: {flag_original}")
    
    # Aplicar múltiples encodings (típico en CTF)
    print("\n🔗 Aplicando cadena de encodings:")
    
    # 1. XOR
    xor_result = xor_encrypt(flag_original.encode(), b'KEY')
    print(f"1. XOR con 'KEY': {xor_result.hex()}")
    
    # 2. Base64
    b64_result = base64_encode(xor_result.hex())
    print(f"2. Base64: {b64_result}")
    
    # 3. Caesar Cipher
    caesar = CaesarCipher()
    final_result = caesar.encrypt(b64_result, 13)
    print(f"3. Caesar +13: {final_result}")
    
    print(f"\n📤 Resultado final codificado: {final_result}")
    
    # Proceso inverso
    print("\n🔄 Proceso de decodificación:")
    step1 = caesar.decrypt(final_result, 13)
    print(f"1. Caesar -13: {step1}")
    
    step2_bytes = bytes.fromhex(base64_decode(step1))
    print(f"2. Base64 decode: {step2_bytes.hex()}")
    
    step3 = xor_encrypt(step2_bytes, b'KEY')
    print(f"3. XOR con 'KEY': {step3.decode()}")
    
    print(f"✅ Flag recuperada: {step3.decode()}")
    print()

if __name__ == "__main__":
    print("🚩 CTFUtils - Ejemplos Prácticos de Criptografía")
    print("="*50)
    print()
    
    ejemplo_caesar_cipher()
    ejemplo_vigenere_cipher() 
    ejemplo_hash_analysis()
    ejemplo_encoding_chain()
    
    print("🎯 ¡Ejemplos completados! Úsalos como referencia en CTFs.")
