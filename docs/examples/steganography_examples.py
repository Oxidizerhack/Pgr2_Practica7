#!/usr/bin/env python3
"""
CTFUtils - Ejemplos Prácticos de Steganografía
=============================================

Ejemplos completos de uso del módulo stego para CTFs
"""

from ctfutils.stego.text import TextSteganography, ZeroWidthSteganography
from ctfutils.stego.image import ImageSteganography
import base64
from io import BytesIO

def ejemplo_text_steganography():
    """Ejemplo: Esteganografía en texto"""
    print("📝 EJEMPLO: Esteganografía en Texto")
    print("="*40)
    
    # Mensaje público y mensaje secreto
    texto_publico = "Este es un mensaje completamente normal que no contiene nada sospechoso."
    mensaje_secreto = "FLAG{hidden_in_plain_text}"
    
    print(f"📄 Texto público: {texto_publico}")
    print(f"🤫 Mensaje secreto: {mensaje_secreto}")
    
    # Crear instancia de steganografía
    text_stego = TextSteganography()
    
    # Ocultar mensaje usando LSB en espacios
    texto_con_secreto = text_stego.hide_in_whitespace(texto_publico, mensaje_secreto)
    print(f"\n📝 Texto con mensaje oculto:")
    print(f"'{texto_con_secreto}'")
    print(f"(Visualmente idéntico, pero con espacios modificados)")
    
    # Extraer mensaje secreto
    mensaje_extraido = text_stego.extract_from_whitespace(texto_con_secreto)
    print(f"\n🔍 Mensaje extraído: {mensaje_extraido}")
    
    if mensaje_extraido == mensaje_secreto:
        print("✅ ¡Esteganografía exitosa!")
    else:
        print("❌ Error en la extracción")
    
    print()

def ejemplo_zero_width_steganography():
    """Ejemplo: Esteganografía con caracteres de ancho cero"""
    print("👻 EJEMPLO: Caracteres de Ancho Cero")
    print("="*40)
    
    # Texto normal
    texto_normal = "Bienvenido al CTF"
    mensaje_oculto = "SECRET"
    
    print(f"📄 Texto original: '{texto_normal}'")
    print(f"🤫 Mensaje a ocultar: '{mensaje_oculto}'")
    
    # Esteganografía con caracteres invisibles
    zw_stego = ZeroWidthSteganography()
    
    # Ocultar usando caracteres de ancho cero
    texto_steganografico = zw_stego.hide_message(texto_normal, mensaje_oculto)
    
    print(f"\n📝 Texto con mensaje oculto:")
    print(f"'{texto_steganografico}'")
    print("(¡Parece idéntico pero contiene caracteres invisibles!)")
    
    # Mostrar los caracteres ocultos
    print(f"\n🔍 Análisis de caracteres:")
    for i, char in enumerate(texto_steganografico):
        if ord(char) > 127:  # Caracteres no-ASCII
            print(f"   Posición {i}: Carácter invisible (Unicode: {ord(char)})")
    
    # Extraer mensaje
    mensaje_recuperado = zw_stego.extract_message(texto_steganografico)
    print(f"\n🎯 Mensaje extraído: '{mensaje_recuperado}'")
    
    if mensaje_recuperado == mensaje_oculto:
        print("✅ ¡Esteganografía con caracteres invisibles exitosa!")
    
    print()

def ejemplo_image_steganography():
    """Ejemplo: Esteganografía en imágenes (simulado)"""
    print("🖼️ EJEMPLO: Esteganografía en Imágenes")
    print("="*40)
    
    # Simulamos datos de imagen
    print("📷 Simulando imagen RGB de 10x10 pixels...")
    
    # Crear datos de imagen simple (RGB)
    width, height = 10, 10
    image_data = []
    
    # Generar datos RGB básicos
    for y in range(height):
        row = []
        for x in range(width):
            # Colores básicos
            r = (x * 25) % 256
            g = (y * 25) % 256  
            b = ((x + y) * 15) % 256
            row.append((r, g, b))
        image_data.append(row)
    
    mensaje_secreto = "CTF{image_stego}"
    print(f"🤫 Mensaje a ocultar: '{mensaje_secreto}'")
    
    # Simulación de LSB steganography
    img_stego = ImageSteganography()
    
    # Convertir mensaje a binario
    mensaje_binario = ''.join(format(ord(char), '08b') for char in mensaje_secreto)
    print(f"🔢 Mensaje en binario: {mensaje_binario[:50]}...")
    
    # Simular ocultación en LSB
    print("\n🔧 Aplicando LSB steganography...")
    print("   - Modificando bit menos significativo de cada pixel")
    print("   - Distribuyendo mensaje a través de la imagen")
    
    # Estadísticas
    pixels_necesarios = len(mensaje_binario)
    pixels_disponibles = width * height * 3  # RGB
    
    print(f"\n📊 Estadísticas:")
    print(f"   Pixels necesarios: {pixels_necesarios}")
    print(f"   Pixels disponibles: {pixels_disponibles}")
    print(f"   Capacidad utilizada: {(pixels_necesarios/pixels_disponibles)*100:.2f}%")
    
    if pixels_necesarios <= pixels_disponibles:
        print("✅ ¡Suficiente capacidad para ocultar el mensaje!")
        print("🔍 El mensaje quedaría invisible al ojo humano")
        print("📈 Cambios mínimos en valores de color (±1)")
    else:
        print("❌ Imagen demasiado pequeña para el mensaje")
    
    print()

def ejemplo_steganography_detection():
    """Ejemplo: Detección de esteganografía"""
    print("🕵️ EJEMPLO: Detección de Esteganografía")
    print("="*40)
    
    # Textos de ejemplo
    textos_prueba = [
        "Este es un texto normal sin nada oculto",
        "Este texto tiene\u200b\u200c\u200d caracteres invisibles",
        "Texto con    espacios    sospechosos",
        "Normal text without any hidden content"
    ]
    
    print("🔍 Analizando textos en busca de esteganografía...")
    print("-" * 50)
    
    text_stego = TextSteganography()
    zw_stego = ZeroWidthSteganography()
    
    for i, texto in enumerate(textos_prueba, 1):
        print(f"\n{i}. Texto: '{texto}'")
        
        # Detectar caracteres sospechosos
        chars_invisibles = 0
        espacios_multiples = 0
        
        for char in texto:
            if ord(char) > 127 and char.isspace():
                chars_invisibles += 1
        
        # Contar espacios múltiples
        import re
        espacios_multiples = len(re.findall(r'  +', texto))
        
        # Evaluación
        sospechoso = False
        razones = []
        
        if chars_invisibles > 0:
            sospechoso = True
            razones.append(f"{chars_invisibles} caracteres invisibles")
        
        if espacios_multiples > 0:
            sospechoso = True
            razones.append(f"{espacios_multiples} grupos de espacios múltiples")
        
        if sospechoso:
            print(f"   🚨 SOSPECHOSO: {', '.join(razones)}")
            # Intentar extraer mensaje
            try:
                msg_extraido = zw_stego.extract_message(texto)
                if msg_extraido:
                    print(f"   🎯 Mensaje oculto encontrado: '{msg_extraido}'")
            except:
                print("   🔍 No se pudo extraer mensaje con método actual")
        else:
            print("   ✅ Texto aparenta ser limpio")
    
    print()

def ejemplo_steganography_workflow():
    """Ejemplo: Flujo completo de esteganografía en CTF"""
    print("🎯 EJEMPLO: Flujo Completo de Stego CTF")
    print("="*40)
    
    print("📋 Escenario CTF: 'Hidden Messages Challenge'")
    print("   - Archivo de texto sospechoso encontrado")
    print("   - Posible información oculta")
    print("   - Múltiples capas de ocultación")
    print()
    
    # Capa 1: Mensaje con espacios modificados
    mensaje_capa1 = "Welcome  to  our  CTF  challenge!  Good  luck  finding  the  hidden  messages."
    print("1️⃣ CAPA 1: Análisis de espacios")
    print(f"   Texto: '{mensaje_capa1}'")
    
    text_stego = TextSteganography()
    try:
        oculto1 = text_stego.extract_from_whitespace(mensaje_capa1)
        print(f"   🎯 Extraído: '{oculto1}'")
    except:
        print("   ✅ Pista: Contar espacios entre palabras")
        # Contar espacios como código binario
        espacios = []
        palabras = mensaje_capa1.split()
        for i in range(len(palabras)-1):
            espacio_entre = mensaje_capa1.find(palabras[i+1]) - (mensaje_capa1.find(palabras[i]) + len(palabras[i]))
            espacios.append('1' if espacio_entre > 1 else '0')
        
        binario = ''.join(espacios)
        print(f"   🔢 Espacios como binario: {binario}")
        
        # Convertir a ASCII
        if len(binario) % 8 == 0:
            ascii_chars = []
            for i in range(0, len(binario), 8):
                byte = binario[i:i+8]
                ascii_chars.append(chr(int(byte, 2)))
            resultado = ''.join(ascii_chars)
            print(f"   🎯 Mensaje decodificado: '{resultado}'")
    
    # Capa 2: Caracteres invisibles
    print("\n2️⃣ CAPA 2: Caracteres invisibles")
    mensaje_capa2 = "This looks normal\u200bCTF{stego_master}\u200cbut has hidden content"
    print(f"   Texto: '{mensaje_capa2}' (aparenta normal)")
    
    zw_stego = ZeroWidthSteganography()
    try:
        oculto2 = zw_stego.extract_message(mensaje_capa2)
        print(f"   🎯 FLAG encontrada: '{oculto2}'")
    except:
        # Búsqueda manual
        import re
        matches = re.findall(r'CTF\{[^}]+\}', mensaje_capa2)
        if matches:
            print(f"   🎯 FLAG encontrada: '{matches[0]}'")
    
    # Resumen
    print("\n📊 RESUMEN DEL CHALLENGE:")
    print("   ✅ Capa 1: Decodificación de espacios")
    print("   ✅ Capa 2: Extracción de caracteres invisibles") 
    print("   🏆 FLAGS TOTAL: 1 flag principal encontrada")
    print("   💡 Técnicas: LSB en texto, Zero-width chars")
    
    print()

if __name__ == "__main__":
    print("🚩 CTFUtils - Ejemplos Prácticos de Esteganografía")
    print("="*55)
    print()
    
    ejemplo_text_steganography()
    ejemplo_zero_width_steganography()
    ejemplo_image_steganography()
    ejemplo_steganography_detection()
    ejemplo_steganography_workflow()
    
    print("🎯 ¡Esteganografía completada! Usa estas técnicas para encontrar mensajes ocultos.")
