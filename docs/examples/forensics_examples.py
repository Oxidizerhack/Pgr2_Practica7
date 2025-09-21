#!/usr/bin/env python3
"""
CTFUtils - Ejemplos Prácticos de Análisis Forense
================================================

Ejemplos de uso del módulo forensics en competencias CTF
"""

from ctfutils.forensics.files import FileAnalyzer
from ctfutils.forensics.network import NetworkAnalyzer
from ctfutils.forensics.memory import MemoryAnalyzer

def ejemplo_file_analysis():
    """Ejemplo: Análisis de archivos sospechosos"""
    print("🔍 EJEMPLO: Análisis de Archivos")
    print("="*40)
    
    # Crear datos de ejemplo
    datos_binarios = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00hello_world_secret'
    
    analyzer = FileAnalyzer()
    
    # Identificar tipo de archivo
    signature = analyzer.get_file_signature(datos_binarios)
    print(f"📄 Signature detectada: {signature}")
    
    # Extraer strings
    strings = analyzer.extract_strings(datos_binarios)
    print(f"🔤 Strings encontrados: {strings}")
    
    # Crear hex dump
    hex_dump = analyzer.create_hex_dump(datos_binarios[:50])
    print(f"\n📋 Hex dump:")
    print(hex_dump)
    
    # Calcular entropy
    entropy = analyzer.calculate_entropy(datos_binarios)
    print(f"\n📊 Entropía: {entropy:.4f}")
    
    if entropy > 7.5:
        print("⚠️  Alta entropía - posible archivo comprimido/cifrado")
    else:
        print("✅ Entropía normal - archivo no comprimido")
    
    print()

def ejemplo_network_analysis():
    """Ejemplo: Análisis de logs de red"""
    print("🌐 EJEMPLO: Análisis de Red")
    print("="*40)
    
    # Datos de ejemplo de un log de red
    log_entries = [
        "2024-01-15 10:30:15 192.168.1.100 -> 10.0.0.5:80 GET /flag.txt HTTP/1.1",
        "2024-01-15 10:30:16 10.0.0.5 -> 192.168.1.100 HTTP/1.1 200 OK",
        "2024-01-15 10:30:17 192.168.1.100 -> 8.8.8.8:53 DNS query for malicious.com",
        "2024-01-15 10:30:18 192.168.1.100 -> 192.168.1.50:22 SSH connection attempt",
        "2024-01-15 10:30:19 192.168.1.100 -> 192.168.1.50:22 SSH authentication failed"
    ]
    
    analyzer = NetworkAnalyzer()
    
    print("📊 Análisis de logs de red:")
    print("-" * 30)
    
    # Extraer IPs
    for i, log in enumerate(log_entries, 1):
        ips = analyzer.extract_ips(log)
        print(f"{i}. Log: {log[:50]}...")
        print(f"   IPs encontradas: {ips}")
    
    # Análizar un log específico
    log_sospechoso = log_entries[2]  # DNS query
    print(f"\n🔍 Análisis detallado del log sospechoso:")
    print(f"Log: {log_sospechoso}")
    
    # Extraer información
    ips = analyzer.extract_ips(log_sospechoso)
    if 'malicious' in log_sospechoso:
        print("⚠️  ALERTA: Dominio sospechoso detectado!")
        print("🚨 Posible actividad maliciosa")
    
    print()

def ejemplo_memory_analysis():
    """Ejemplo: Análisis de memoria"""
    print("🧠 EJEMPLO: Análisis de Memoria")
    print("="*40)
    
    # Simulación de dump de memoria con datos ocultos
    memory_data = b"""
    Process: notepad.exe
    PID: 1234
    Memory dump contains:
    FLAG{hidden_in_memory_12345}
    Some other process data...
    Password: supersecret123
    More memory content...
    Another flag: CTF{memory_forensics}
    """
    
    analyzer = MemoryAnalyzer()
    
    # Buscar strings en memoria
    strings_found = analyzer.extract_strings(memory_data)
    print(f"🔤 Strings extraídos de memoria:")
    for string in strings_found:
        print(f"   - {string}")
    
    print()
    
    # Buscar patrones específicos
    patterns = [r'FLAG\{[^}]+\}', r'CTF\{[^}]+\}', r'Password:\s*(\w+)']
    
    print("🎯 Búsqueda de patrones específicos:")
    for pattern in patterns:
        matches = analyzer.search_pattern(memory_data.decode('utf-8', errors='ignore'), pattern)
        if matches:
            print(f"   Pattern '{pattern}': {matches}")
    
    # Analizar procesos (simulado)
    process_info = {
        'name': 'notepad.exe',
        'pid': 1234,
        'memory_size': len(memory_data),
        'suspicious_strings': []
    }
    
    # Buscar strings sospechosos
    for string in strings_found:
        if any(keyword in string.lower() for keyword in ['flag', 'ctf', 'password']):
            process_info['suspicious_strings'].append(string)
    
    print(f"\n📋 Resumen del proceso:")
    print(f"   Nombre: {process_info['name']}")
    print(f"   PID: {process_info['pid']}")
    print(f"   Tamaño memoria: {process_info['memory_size']} bytes")
    print(f"   Strings sospechosos: {len(process_info['suspicious_strings'])}")
    
    if process_info['suspicious_strings']:
        print("🚨 ALERTA: Contenido sospechoso encontrado!")
        for sus_string in process_info['suspicious_strings']:
            print(f"      - {sus_string}")
    
    print()

def ejemplo_forensics_workflow():
    """Ejemplo: Flujo completo de análisis forense"""
    print("🕵️ EJEMPLO: Flujo Forense Completo")
    print("="*40)
    
    print("📋 Escenario: Análisis de incidente de seguridad")
    print("   - Archivo sospechoso encontrado")
    print("   - Logs de red anómalos") 
    print("   - Dump de memoria del sistema")
    print()
    
    # 1. Análisis de archivo
    print("1️⃣ FASE: Análisis de Archivo")
    file_data = b"PK\x03\x04hidden_payload_flag{file_analysis_complete}"
    file_analyzer = FileAnalyzer()
    
    signature = file_analyzer.get_file_signature(file_data)
    strings = file_analyzer.extract_strings(file_data) 
    
    print(f"   ✅ Tipo: {signature}")
    print(f"   ✅ Strings: {strings}")
    
    # 2. Análisis de red
    print("\n2️⃣ FASE: Análisis de Red")
    network_log = "192.168.1.10 -> 203.0.113.5:4444 TCP connection established"
    net_analyzer = NetworkAnalyzer()
    
    ips = net_analyzer.extract_ips(network_log)
    print(f"   ✅ IPs comunicándose: {ips}")
    
    # 3. Análisis de memoria
    print("\n3️⃣ FASE: Análisis de Memoria")
    memory_dump = b"Process memory: malware.exe FLAG{memory_artifact_found}"
    mem_analyzer = MemoryAnalyzer()
    
    mem_strings = mem_analyzer.extract_strings(memory_dump)
    print(f"   ✅ Evidencias en memoria: {mem_strings}")
    
    # Conclusiones
    print("\n📊 CONCLUSIONES DEL ANÁLISIS:")
    print("   🔍 Archivo: Posible ZIP con payload oculto")
    print("   🌐 Red: Conexión a IP externa sospechosa") 
    print("   🧠 Memoria: Proceso malicioso identificado")
    print("   🚩 FLAGS ENCONTRADAS: 2 flags de CTF recuperadas")
    
    print()

if __name__ == "__main__":
    print("🚩 CTFUtils - Ejemplos Prácticos de Análisis Forense")
    print("="*55)
    print()
    
    ejemplo_file_analysis()
    ejemplo_network_analysis()
    ejemplo_memory_analysis()
    ejemplo_forensics_workflow()
    
    print("🎯 ¡Análisis forense completado! Usa estas técnicas en CTFs.")
