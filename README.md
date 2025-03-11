# VulnHunter

![VulnHunter Logo](src/ui/assets/logo.png)

**VulnHunter** is an advanced web vulnerability analysis tool with a modern graphical interface, designed for security professionals and pentesters.

## Features

- **Scanning Modules**:
  - LFI/RFI Scanner with advanced detection (`lfi_rfi_integration.py`)
  - XXE Scanner (`xxe_integration.py`)
  - SSRF Scanner (`ssrf_integration.py`)
  - SQL Injection Scanner (`sql_injection.py` / `sqlmap_integration.py`)
  - WFuzz Integration (`wfuzz_integration.py`)
  - XSS Integration (`xss_integration.py`)
  - WhatWeb Integration (`whatweb.py`)
  - **Combined Scanner** with heuristic analysis (`combined_scanner.py`)

- **Advanced Capabilities**:
  - WAF detection and bypass
  - Heuristic response analysis
  - Detailed report generation (HTML/PDF) via `report_generator.py`
  - Payload compression and obfuscation
  - Polymorphic shells (memory shell, fileless shell)

## Installation

```bash
# 1. Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate   # Windows

# 2. Install dependencies
pip install -r requirements.txt

# (Optional) Install in editable mode
pip install -e .
```

## Usage

```bash
# Direct execution:
python main.py
```

## Project Structure

```
VulnHunter/
├── config/
│   └── settings.py
├── data/
│   └── payloads/
├── logs/
├── reports/
├── src/
│   ├── core/
│   │   ├── cms/
│   │   ├── exploit/
│   │   ├── metasploit/
│   │   ├── network/
│   │   ├── utils/
│   │   │   ├── export.py
│   │   │   ├── test_connection.py
│   │   │   ├── tooltip.py
│   │   │   ├── utils.py
│   │   │   └── validation.py
│   │   └── web/
│   │       ├── combined_scanner.py
│   │       ├── lfi_rfi_integration.py
│   │       ├── report_generator.py
│   │       ├── sql_injection.py
│   │       ├── sqlmap_integration.py
│   │       ├── ssrf_integration.py
│   │       ├── wfuzz_integration.py
│   │       ├── whatweb.py
│   │       ├── xss_integration.py
│   │       ├── xxe_integration.py
│   │       └── templates/
│   │           ├── __init__.py
│   │           └── report.html
│   ├── templates/
│   │   └── reports/
│   └── ui/
│       ├── main_window.py
│       ├── theme/
│       ├── utils/
│       └── windows/
│           ├── lfi_rfi_window.py
│           ├── xxe_window.py
│           ├── ssrf_window.py
│           ├── ...
│           └── ...
├── tests/
├── venv/
├── main.py
├── requirements.txt
├── setup.py
└── README.md
```

### Configuration

You can modify tool settings in `config/settings.py`, which may include:

- Timeouts and connection limits
- Paths for custom payloads
- Report configuration
- WAF options
- Logging parameters
