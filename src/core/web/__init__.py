"""
Core web modules for vulnerability scanning.
"""

# Importar módulos principales para facilitar las importaciones
from .lfi_rfi_integration import LFIRFIScanner
from .xxe_integration import XXEScanner
from .combined_scanner import CombinedScanner, WAFDetector
from .report_generator import ReportGenerator