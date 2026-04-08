import dns.resolver
import requests
import re
import csv
import os
from urllib.parse import urlparse

# --- CONFIGURACIÓN ---
OPENPHISH_URL = "https://openphish.com/feed.txt"
DATASET_FILE = 'shadow_auditor_dataset.csv'

SCAM_SIGNATURES = {
    'Crypto-Fraud': ['/finance/usdt_recharge', '/user/bind_bank_info', 'vip_level', 'profit', 'usdt'],
    'Brand-Impersonation': ['official-mall', 'verify-account', 'login-secure', 'claim-bonus', 'update-payment'],
    'Common-Phish': ['account-locked', 'secure-login', 'billing-update', 'verification-needed']
}

# --- MÓDULO 1: INTELIGENCIA DE AMENAZAS ---
def descargar_feed_global():
    print(f"[*] Sincronizando con OpenPhish (Threat Intelligence)...")
    try:
        r = requests.get(OPENPHISH_URL, timeout=10)
        return r.text.splitlines() if r.status_code == 200 else []
    except:
        return []

# --- MÓDULO 2: GENERACIÓN DE VARIACIONES (TYPOSQUATTING) ---
def generar_variaciones(marca):
    sustituciones = {'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '4', 's': '5'}
    variaciones = {marca}
    
    # Aplicar Leet Speak
    for char, sub in sustituciones.items():
        if char in marca:
            variaciones.add(marca.replace(char, sub))
    
    extensiones = ['.net', '.online', '.cc', '.app', '.art', '.biz', '.xyz']
    sufijos = ['-login', '-support', '-verify', '-mall']
    
    lista_final = []
    for v in variaciones:
        for ext in extensiones:
            lista_final.append(v + ext)
        for s in sufijos:
            lista_final.append(f"{v}{s}.com")
            lista_final.append(f"{v}{s}.online")
            
    return list(set(lista_final))

# --- MÓDULO 3: ANÁLISIS FORENSE Y EXTRACCIÓN DE FEATURES ---
def analizar_y_extraer(dominio):
    features = {
        'dominio': dominio,
        'longitud': len(dominio),
        'puntos': dominio.count('.'),
        'guiones': dominio.count('-'),
        'digitos': sum(c.isdigit() for c in dominio),
        'resultado': 'Limpio',
        'es_phishing': 0
    }
    
    try:
        url = f"http://{dominio}"
        headers = {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X)'}
        r = requests.get(url, timeout=5, headers=headers)
        
        if r.status_code == 403:
            features['resultado'] = 'Proteccion_403'
            features['es_phishing'] = 1 # Los 403 en dominios sospechosos son señales de alerta
            return features, ["Protección WAF (403)"]
        
        html = r.text.lower()
        hallazgos = []
        for kit, patterns in SCAM_SIGNATURES.items():
            for p in patterns:
                if p in html:
                    hallazgos.append(f"{p} ({kit})")
        
        if re.search(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', html):
            hallazgos.append("Crypto_Wallet_Detected")

        if hallazgos:
            features['resultado'] = 'Evidencia_Encontrada'
            features['es_phishing'] = 1
            
        return features, hallazgos
    except:
        return features, []

# --- MÓDULO 4: PERSISTENCIA (DATASET) ---
def guardar_dataset(data):
    file_exists = os.path.isfile(DATASET_FILE)
    with open(DATASET_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

# --- BLOQUE PRINCIPAL ---
if __name__ == "__main__":
    print("\n" + "═"*45)
    print("      SHADOW AUDITOR v5.0 | THE DATA FACTORY")
    print("═"*45)

    marca = input("\n[?] Marca a auditar (ej: bancoestado, netflix): ").lower().strip()
    feed_global = descargar_feed_global()
    
    # Cruce con el Feed Real
    print(f"[*] Buscando '{marca}' en el feed global...")
    matches = [u for u in feed_global if marca in u]
    if matches:
        print(f"[!] ALERTA: {len(matches)} amenazas detectadas hoy en la red.")
        for m in matches[:3]: print(f"    -> {m}")

    # Escaneo y Generación de Datos
    dominios = generar_variaciones(marca)
    print(f"\n[*] Analizando {len(dominios)} variaciones y guardando en '{DATASET_FILE}'...")

    for dom in dominios:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1
            resolver.lifetime = 1
            respuesta = resolver.resolve(dom, 'A')
            ip = str(respuesta[0])
            
            # Analizar y obtener datos para el ML
            features, hallazgos = analizar_y_extraer(dom)
            guardar_dataset(features)
            
            print(f"\n[!] ACTIVO: {dom} | IP: {ip}")
            if hallazgos:
                for h in hallazgos: print(f"    -> {h}")
            else:
                print("    [-] Sin firmas detectadas.")
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            print(".", end="", flush=True)
        except Exception as e:
            continue

    print(f"\n\n[*] Proceso terminado. Revisa '{DATASET_FILE}' para entrenar tu modelo.")