import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os

# --- CONFIGURACIÓN ---
DATASET_FILE = 'shadow_auditor_dataset.csv'
MODEL_FILE = 'modelo_ia.pkl'

def entrenar_shadow_ia():
    print("\n" + "═"*60)
    print("      SHADOW AUDITOR | TRAINING FACILITY v2.0 (IA)")
    print("═"*60)

    # 1. Verificar existencia del dataset
    if not os.path.exists(DATASET_FILE):
        print(f"[!] ERROR: No se encontró el archivo '{DATASET_FILE}'.")
        return

    print(f"[*] Cargando dataset forense desde '{DATASET_FILE}'...")
    try:
        # Leemos el CSV de forma estándar
        df = pd.read_csv(DATASET_FILE)
    except Exception as e:
        print(f"[!] ERROR AL LEER CSV: {e}")
        return

    # --- ESCUDO DE INGENIERÍA DE DATOS (COERCIÓN) ---
    print("[*] Aplicando limpieza y coerción de datos...")
    
    # Columnas que deben ser números sí o sí
    cols_numericas = [
        'longitud', 'puntos', 'guiones', 'digitos', 
        'entropia', 'distancia_visual', 'tiene_ssl', 'es_phishing'
    ]
    
    # Forzamos conversión: si hay texto donde debe haber números, se convierte en NaN
    for col in cols_numericas:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # Eliminamos cualquier fila que tenga NaN en las columnas críticas
    filas_antes = len(df)
    df = df.dropna(subset=cols_numericas)
    filas_despues = len(df)
    
    if filas_antes > filas_despues:
        print(f"[!] Limpieza: Se eliminaron {filas_antes - filas_despues} filas corruptas.")

    # Aseguramos que la etiqueta objetivo sea entero (0 o 1)
    df['es_phishing'] = df['es_phishing'].astype(int)

    # Limpieza de duplicados
    df = df.drop_duplicates()
    print(f"[*] Dataset listo para entrenamiento. Total muestras válidas: {len(df)}")

    # 2. Separar Características (X) y Objetivo (y)
    X = df[['longitud', 'puntos', 'guiones', 'digitos', 'entropia', 'distancia_visual', 'tiene_ssl']]
    y = df['es_phishing']

    if len(y.unique()) < 2:
        print("\n[!] ERROR: No hay suficiente variedad (Phishing vs Limpio) para entrenar.")
        return

    # 3. División de datos
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 4. Entrenar Random Forest
    print("[*] Entrenando red neuronal con Random Forest...")
    model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    model.fit(X_train, y_train)

    # 5. Reporte de Rendimiento
    y_pred = model.predict(X_test)
    print("\n[📊] REPORTE DE RENDIMIENTO DEL MODELO:")
    print("═"*40)
    print(classification_report(y_test, y_pred, zero_division=0))

    # 6. Exportar Modelo
    joblib.dump(model, MODEL_FILE)
    print(f"\n[✔] ÉXITO MÁXIMO: Cerebro actualizado en '{MODEL_FILE}'.")

if __name__ == "__main__":
    entrenar_shadow_ia()