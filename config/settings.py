"""
Configuración global para VulnHunter
"""

import os

# Rutas base
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOADS_DIR = os.path.join(BASE_DIR, 'data', 'payloads')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'src', 'templates')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

# Configuración de conexión
TIMEOUT = 30
MAX_RETRIES = 3
VERIFY_SSL = False

# Configuración de escaneo
MAX_THREADS = 10
PORT_SCAN_TIMEOUT = 5
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Configuración de payloads
PAYLOAD_TYPES = {
    'lfi': {
        'basic': os.path.join(PAYLOADS_DIR, 'lfi_basic.txt'),
        'advanced': os.path.join(PAYLOADS_DIR, 'lfi_advanced.txt'),
        'shells': os.path.join(PAYLOADS_DIR, 'lfi_shells.txt')
    },
    'rfi': {
        'basic': os.path.join(PAYLOADS_DIR, 'rfi_basic.txt'),
        'advanced': os.path.join(PAYLOADS_DIR, 'rfi_advanced.txt'),
        'shells': os.path.join(PAYLOADS_DIR, 'rfi_shells.txt')
    },
    'xxe': {
        'basic': os.path.join(PAYLOADS_DIR, 'xxe_basic.txt'),
        'advanced': os.path.join(PAYLOADS_DIR, 'xxe_advanced.txt'),
        'oob': os.path.join(PAYLOADS_DIR, 'xxe_oob.txt')
    },
    'ssrf': {
        'basic': os.path.join(PAYLOADS_DIR, 'ssrf_basic.txt'),
        'blind': os.path.join(PAYLOADS_DIR, 'ssrf_blind.txt'),
        'protocols': os.path.join(PAYLOADS_DIR, 'ssrf_protocols.txt')
    }
}

# Configuración de WAF
WAF_EVASION = {
    'cloudflare': ['hex_encoding', 'double_encoding', 'null_byte_injection'],
    'akamai': ['unicode_bypass', 'null_byte', 'double_url_encode'],
    'imperva': ['comment_injection', 'space_substitution', 'character_rotation'],
    'f5': ['path_manipulation', 'special_characters', 'cookie_manipulation']
}

# Configuración de reportes
REPORT_TEMPLATES = {
    'html': os.path.join(TEMPLATES_DIR, 'reports', 'base.html'),
    'vulnerability': os.path.join(TEMPLATES_DIR, 'reports', 'vulnerability.html')
}

# Configuración de logging
LOG_FILE = os.path.join(BASE_DIR, 'vulnhunter.log')
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Configuración de UI
UI_THEME = 'dark'
UI_SCALING = 1.0
UI_DEFAULT_SIZE = (1024, 768)

# Configuración de análisis heurístico
HEURISTIC_WEIGHTS = {
    'response_code': 0.3,
    'content_length': 0.2,
    'error_patterns': 0.25,
    'sensitive_data': 0.25
}

# Configuración de compresión
COMPRESSION_METHODS = ['gzip', 'deflate', 'bzip2']
MAX_COMPRESSION_SIZE = 1024 * 1024  # 1MB

# Configuración de shells
SHELL_TYPES = {
    'memory': {
        'enabled': True,
        'max_size': 512 * 1024  # 512KB
    },
    'fileless': {
        'enabled': True,
        'timeout': 300  # 5 minutos
    }
}
