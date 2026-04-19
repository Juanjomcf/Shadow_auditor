# Shadow Auditor v7.2.4 🛡️🤖
### Framework de Detección de Infraestructura Maliciosa e Inteligencia de Amenazas

Shadow Auditor es una herramienta avanzada de ciberseguridad diseñada para la identificación proactiva de ataques de **Phishing**, **Typosquatting** y **Fraude Digital**. El sistema utiliza una combinación de heurísticas forenses, firmas de comportamiento y un modelo de **Inteligencia Artificial (Random Forest)** para clasificar dominios maliciosos en tiempo real.

---

## 🚀 Características Principales

- **Massive Hunter (Fuzzer):** Motor de escaneo concurrente (Multi-threading) optimizado para procesar grandes volúmenes de dominios simultáneamente.
- **Typosquatting Engine:** Algoritmos de generación táctica basados en sustitución de caracteres y métricas de **Distancia de Levenshtein**.
- **Global Threat Intelligence:** Integración con feeds globales (OpenPhish) para el rastreo de amenazas activas en la red.
- **Análisis Forense Multidimensional:** Evaluación de entropía de Shannon, validación de certificados SSL y escaneo profundo de firmas de PhishKits.
- **Predictive IA:** Clasificación automatizada mediante un modelo entrenado en Python, asignando niveles de riesgo probabilísticos.

---

## ⚖️ Cumplimiento Legal (Ley N° 21.663)

Este proyecto integra un módulo de **Alerta Temprana** alineado con el **Artículo 9 de la Ley Marco de Ciberseguridad en Chile**. El sistema automatiza la generación de reportes técnicos detallados para facilitar la entrega de información al **CSIRT Nacional** ante incidentes que afecten la seguridad de activos críticos.

> **Nota:** Por razones de OPSEC (Operations Security) y cumplimiento ético, los reportes detallados y los datasets de entrenamiento masivos están excluidos del repositorio público.

---

## 🛠️ Tecnologías Utilizadas

- **Lenguaje:** Python 3.13
- **IA/ML:** Scikit-Learn (Random Forest) & Joblib
- **Redes/Forense:** DNS Python, Requests & Socket Programming
- **Entorno:** Desarrollado y optimizado para **CachyOS (Linux Kernel 6.x)**

---

## 📦 Instalación y Uso

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/Juanjomcf/Shadow_auditor.git](https://github.com/Juanjomcf/Shadow_auditor.git)
   cd Shadow_auditor
