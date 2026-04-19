# Shadow Auditor 🔍 

> **Status:** 🛠️ Work in Progress - Refactoring for Serverless Architecture

## Project Overview
Shadow Auditor es una herramienta de reconocimiento (Recon) y enumeración de subdominios diseñada para agilizar las fases iniciales de una auditoría de seguridad. A diferencia de los fuzzers genéricos, este proyecto se enfoca en la integración de datasets de **Threat Intelligence** para identificar activos expuestos con mayor precisión.

Este proyecto forma parte de mi portafolio profesional como **Junior Cloud & Security Engineer**, demostrando la capacidad de automatizar tareas críticas de ciberseguridad mediante código eficiente.

## 🛠️ Tech Stack & Tools
- **Language:** Python 3.13
- **Environment:** Linux (CachyOS / Arch Based)
- **Cloud (Roadmap):** AWS Lambda & DynamoDB
- **Automation:** Git for version control

## 📁 Project Structure
- `fuzzer.py`: El núcleo del motor de búsqueda y lógica de peticiones.
- `requirements.txt`: Dependencias necesarias para el despliegue del entorno.
- `shadow_auditor_dataset.csv`: Dataset local utilizado para el entrenamiento y pruebas de fuzzing.
- `.gitignore`: Configuración de exclusión para entornos virtuales y archivos sensibles.

## 🚀 Roadmap (The "E-Corp" Path)
Actualmente, el proyecto se encuentra en una transición hacia una arquitectura **Cloud Native** para permitir auditorías a gran escala sin dependencia de hardware local:
- [x] Motor básico de fuzzing en Python.
- [ ] Implementación de lógica asíncrona para mejorar el rendimiento.
- [ ] Despliegue en **AWS Lambda** para ejecución serverless.
- [ ] Almacenamiento de hallazgos en **Amazon DynamoDB**.

## 💻 Setup & Usage
Para ejecutar el auditor localmente, se recomienda el uso de un entorno virtual:

```bash
# Clonar el repositorio
git clone [https://github.com/Juanjomcf/Shadow_auditor.git](https://github.com/Juanjomcf/Shadow_auditor.git)
cd Shadow_auditor

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar el fuzzer
python fuzzer.py
