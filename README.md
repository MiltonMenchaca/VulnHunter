# VulnHunter

VulnHunter es una herramienta avanzada de análisis de vulnerabilidades web con interfaz gráfica moderna, diseñada para profesionales de seguridad y pentesters.

## Características

- **Módulos de Escaneo**:
  - LFI/RFI Scanner con detección avanzada (`lfi_rfi_integration.py`)
  - XXE Scanner (`xxe_integration.py`)
  - SSRF Scanner (`ssrf_integration.py`)
  - SQL Injection Scanner (`sql_injection.py` / `sqlmap_integration.py`)
  - WFuzz Integration (`wfuzz_integration.py`)
  - XSS Integration (`xss_integration.py`)
  - WhatWeb Integration (`whatweb.py`)
  - **Scanner Combinado** con análisis heurístico (`combined_scanner.py`)

- **Características Avanzadas**:
  - Detección y bypass de WAF
  - Análisis heurístico de respuestas
  - Generación de reportes detallados (HTML/PDF) mediante `report_generator.py`
  - Compresión y ofuscación de payloads
  - Shells polimórficos (memory shell, fileless shell)

## Instalación

```bash
# 1. Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o
.\venv\Scripts\activate   # Windows

# 2. Instalar dependencias
pip install -r requirements.txt

# (Opcional) Instalar en modo editable
pip install -e .
