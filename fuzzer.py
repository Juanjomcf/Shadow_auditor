import dns.resolver
import requests
import re
import csv
import os
import math
import ssl
import socket
import concurrent.futures
import joblib
import datetime
from Levenshtein import distance as levenshtein_distance
from urllib.parse import urlparse

# --- CONFIGURACIÓN ---
OPENPHISH_URL = "https://openphish.com/feed.txt"
DATASET_FILE = 'shadow_auditor_dataset.csv'
MODEL_FILE = 'modelo_ia.pkl'
MAX_WORKERS = 25  # Hilos simultáneos

# --- CARGA DEL CEREBRO (IA) ---
def cargar_modelo():
    if os.path.exists(MODEL_FILE):
        return joblib.load(MODEL_FILE)
    return None

IA_MODEL = cargar_modelo()

SCAM_SIGNATURES = {
    'Crypto-Fraud': ['/finance/usdt_recharge', '/user/bind_bank_info', 'vip_level', 'profit', 'usdt'],
    'Brand-Impersonation': ['official-mall', 'verify-account', 'login-secure', 'claim-bonus', 'update-payment'],
    'Common-Phish': ['account-locked', 'secure-login', 'billing-update', 'verification-needed'],
    'Cybersquatting-Parked': ['is for sale', 'buy this domain', 'make offer', 'domain transfer'] # Detección de venta
}

# --- MÓDULO 1: INTELIGENCIA DE AMENAZAS (OpenPhish) ---
def descargar_feed_global():
    try:
        r = requests.get(OPENPHISH_URL, timeout=10)
        return r.text.splitlines() if r.status_code == 200 else []
    except:
        return []

# --- MÓDULO 2: MATEMÁTICAS FORENSES ---
def calcular_entropia(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analizar_ssl(dominio):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                return 1
    except:
        return 0

# --- MÓDULO 3: CUMPLIMIENTO LEGAL (LEY 21.663) ---
def generar_alerta_temprana(features, hallazgos):
    """Genera borrador para el CSIRT Nacional ante incidentes críticos."""
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dom = features['dominio']
    reporte = f"""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║       REPORTE DE ALERTA TEMPRANA - LEY N° 21.663 (ART. 9)            ║
    ╚══════════════════════════════════════════════════════════════════════╝
    FECHA/HORA DETECCIÓN: {ahora}
    DOMINIO MALICIOSO: {dom}
    DISTANCIA VISUAL: {features.get('distancia_visual', 'N/A')}
    ENTROPÍA: {features.get('entropia', 'N/A')}
    HALLAZGOS TÉCNICOS: {', '.join(hallazgos) if hallazgos else "Evasión/WAF detectado"}
    
    RIESGO: Alta probabilidad de suplantación de activos críticos.
    Se recomienda bloqueo perimetral y solicitud de take-down.
    """
    if not os.path.exists('alertas_ley'): os.makedirs('alertas_ley')
    with open(f"alertas_ley/reporte_{dom.replace('.', '_')}.txt", "w", encoding='utf-8') as f:
        f.write(reporte)

# --- MÓDULO 4: GENERACIÓN DE VARIACIONES ---
def generar_variaciones(marca):
    sustituciones = {'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '4', 's': '5'}
    variaciones = {marca}
    for char, sub in sustituciones.items():
        if char in marca:
            variaciones.add(marca.replace(char, sub))
    
    extensiones = ['.net', '.online', '.cc', '.app', '.xyz']
    sufijos = ['-login', '-support', '-verify']
    
    lista_final = []
    for v in variaciones:
        for ext in extensiones: lista_final.append(v + ext)
        for s in sufijos:
            lista_final.append(f"{v}{s}.com")
            lista_final.append(f"{v}{s}.online")
    return list(set(lista_final))

# --- MÓDULO 5: ANÁLISIS FORENSE Y EXTRACCIÓN ---
def analizar_y_extraer(dominio, marca_original):
    # Ajuste: Si marca_original es "global", la distancia visual no aplica directamente, la dejamos en 0.
    dist_visual = 0 if marca_original == "global" else levenshtein_distance(dominio.split('.')[0], marca_original)
    
    features = {
        'dominio': dominio,
        'longitud': len(dominio),
        'puntos': dominio.count('.'),
        'guiones': dominio.count('-'),
        'digitos': sum(c.isdigit() for c in dominio),
        'entropia': round(calcular_entropia(dominio), 4),
        'distancia_visual': dist_visual,
        'tiene_ssl': analizar_ssl(dominio),
        'resultado': 'Limpio',
        'es_phishing': 0
    }
    
    try:
        url = f"http://{dominio}"
        headers = {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X)'}
        
        r = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
        
        # Redirección Defensiva (Solo aplica si estamos buscando una marca específica)
        if r.history and marca_original != "global":
            dominio_final = urlparse(r.url).netloc
            if marca_original in dominio_final and any(tld in dominio_final for tld in ['.com', '.cl']):
                features['resultado'] = 'Redireccion_Defensiva'
                features['es_phishing'] = 0
                return features, [f"Safe Redirect -> {dominio_final}"]

        # Errores Críticos de Servidor
        if r.status_code >= 500:
            features['resultado'] = 'Error_Servidor_Sospechoso'
            features['es_phishing'] = 1
            return features, [f"Error HTTP {r.status_code} (Posible PhishKit)"]

        if r.status_code == 403:
            features['resultado'] = 'Proteccion_403'
            features['es_phishing'] = 1
            return features, ["WAF Activo (403)"]
        
        # Análisis de Contenido
        html = r.text.lower()
        hallazgos = []
        for kit, patterns in SCAM_SIGNATURES.items():
            for p in patterns:
                if p in html: hallazgos.append(f"{p} ({kit})")
        
        if re.search(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', html):
            hallazgos.append("Crypto_Wallet")

        if hallazgos:
            features['resultado'] = 'Evidencia_Phishing'
            features['es_phishing'] = 1
            
        return features, hallazgos
    except Exception:
        features['resultado'] = 'Error_Conexion'
        return features, []

def guardar_dataset(data):
    file_exists = os.path.isfile(DATASET_FILE)
    with open(DATASET_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

# --- MOTOR DE PROCESAMIENTO ---
def worker(dom, marca_original):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout, resolver.lifetime = 1, 1
        respuesta = resolver.resolve(dom, 'A')
        ip = str(respuesta[0])
        
        features, hallazgos = analizar_y_extraer(dom, marca_original)
        
        # Predicción de la IA en tiempo real
        pred_ia = "N/A"
        if IA_MODEL and features['resultado'] != 'Redireccion_Defensiva':
            X = [[features['longitud'], features['puntos'], features['guiones'], 
                  features['digitos'], features['entropia'], features['distancia_visual'], features['tiene_ssl']]]
            prob = IA_MODEL.predict_proba(X)[0][1]
            pred_ia = f"{round(prob * 100, 2)}%"
            
            # Generar alerta legal si es muy sospechoso o tiene firmas evidentes
            if prob > 0.85 or features['es_phishing'] == 1:
                generar_alerta_temprana(features, hallazgos)

        guardar_dataset(features)
        
        status = f"[!] ACTIVO: {dom} | IP: {ip} | IA Phish: {pred_ia}"
        if hallazgos:
            status += f"\n    -> DETALLE: {', '.join(hallazgos)}"
        return status
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return None
    except Exception:
        return None

# --- BLOQUE PRINCIPAL ACTUALIZADO ---
if __name__ == "__main__":
    print("\n" + "═"*60)
    print("      SHADOW AUDITOR v7.2 | MASSIVE HUNTER")
    print("═"*60)

    print("[1] Modo Typosquatting (Inventar variaciones para 1 marca)")
    print("[2] Modo Cacería Global (Analizar base de datos OpenPhish)")
    
    opcion = input("\n[?] Elige el modo de escaneo (1 o 2): ").strip()
    
    dominios_a_escanear = []
    marca_referencia = "global"

    if opcion == "1":
        marca_referencia = input("\n[?] Marca a auditar (ej: bancoestado): ").lower().strip()
        dominios_a_escanear = generar_variaciones(marca_referencia)
        print(f"[*] Generadas {len(dominios_a_escanear)} variaciones por fuerza bruta.")
        
    elif opcion == "2":
        print("\n[*] Descargando lista de amenazas activas desde Inteligencia Global...")
        feed_global = descargar_feed_global()
        
        # Extraemos solo la raíz del dominio de cada URL maliciosa
        dominios_brutos = [urlparse(url).netloc for url in feed_global]
        
        # Limpiamos duplicados y quitamos puertos (ej: dominio.com:80 -> dominio.com)
        dominios_limpios = list(set([d.split(':')[0] for d in dominios_brutos if d]))
        
        # Tomamos una muestra de los primeros 100 para no saturar la red local
        dominios_a_escanear = dominios_limpios[:100] 
        print(f"[*] Cargados {len(dominios_a_escanear)} dominios vivos confirmados.")
        
    else:
        print("[!] Opción inválida.")
        exit()

    # Verificación de IA
    if IA_MODEL:
        print("[✔] Cerebro de IA cargado. Predicción en tiempo real ACTIVADA.")
    else:
        print("[!] IA no detectada. Las predicciones dirán N/A.")

    print(f"[*] Disparando {MAX_WORKERS} hilos simultáneos...")

    # Procesamiento Concurrente
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(worker, dom, marca_referencia) for dom in dominios_a_escanear]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res: print(res)
            else: print(".", end="", flush=True)

    print(f"\n\n[*] Auditoría terminada. Revisa tu archivo '{DATASET_FILE}'")