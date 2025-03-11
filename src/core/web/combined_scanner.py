from typing import Dict, Any, Optional, List
import requests
from .lfi_rfi_integration import LFIRFIScanner
from .xxe_integration import XXEScanner
from datetime import datetime
import jinja2
import os
import logging

# Verificar si existe el módulo report_generator
try:
    from .report_generator import ReportGenerator
except ImportError:
    # Si no existe, creamos una clase básica
    class ReportGenerator:
        def generate_report(self, results, format='html'):
            return f"<html><body><h1>Vulnerability Report</h1><pre>{str(results)}</pre></body></html>"

class CombinedScanner:
    """Combined scanner for LFI/RFI and XXE."""
    def __init__(self):
        self.lfi_scanner = LFIRFIScanner()
        self.xxe_scanner = XXEScanner()
        self.waf_detector = WAFDetector()
        self.report_generator = ReportGenerator()
        self.logger = logging.getLogger(__name__)
        
    def chain_attack(self, url: str) -> Dict[str, Any]:
        """Performs a chained attack combining LFI/RFI and XXE."""
        results = {}
        
        try:
            # Detect WAF
            response = requests.head(url, timeout=10)
            waf_type = self.waf_detector.detect_waf(response)
            if waf_type:
                bypass_techniques = self.waf_detector.get_bypass_technique(waf_type)
                results['waf'] = {
                    'type': waf_type,
                    'bypass_techniques': bypass_techniques
                }
            
            # First, attempt XXE
            xxe_results = self.xxe_scanner.scan(url)
            if xxe_results:
                results['xxe'] = xxe_results
                # If XXE is successful, attempt LFI via XXE
                lfi_via_xxe = self.lfi_scanner.scan_via_xxe(url, xxe_results)
                results['lfi_via_xxe'] = lfi_via_xxe
            else:
                # Otherwise, attempt normal LFI/RFI
                results['lfi_rfi'] = self.lfi_scanner.scan_url(url)
        except Exception as e:
            self.logger.error(f"Error in chain attack: {str(e)}")
            results['error'] = str(e)
            
        return results

class WAFDetector:
    """WAF detection and bypass."""
    def __init__(self):
        self.waf_signatures = {
            'cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'akamai': ['akamai-gtm', 'aka-cdn'],
            'imperva': ['incap_ses', '_incap_', 'visid_incap'],
            'f5': ['TS01', 'F5-TrafficShield'],
            'fortinet': ['FORTIWAFSID'],
            'barracuda': ['barra_counter_session'],
            'citrix': ['ns_af=', 'citrix_ns_id'],
            'aws': ['x-amz-cf-id', 'awselb']
        }
        
        self.waf_bypass = {
            'cloudflare': [
                'hex_encoding',
                'double_encoding',
                'null_byte_injection'
            ],
            'akamai': [
                'unicode_bypass',
                'null_byte',
                'double_url_encode'
            ],
            'imperva': [
                'comment_injection',
                'space_substitution',
                'character_rotation'
            ],
            'f5': [
                'path_manipulation',
                'special_characters',
                'cookie_manipulation'
            ],
            'default': [
                'base64_encode',
                'url_encode',
                'hex_encode'
            ]
        }
        
    def detect_waf(self, response: requests.Response) -> Optional[str]:
        """Detects if a WAF is present and its type."""
        headers = response.headers
        cookies = response.cookies
        
        # Check headers
        for waf, signatures in self.waf_signatures.items():
            for sig in signatures:
                if any(sig.lower() in h.lower() for h in headers.values()):
                    return waf
                    
        # Check cookies
        for waf, signatures in self.waf_signatures.items():
            for sig in signatures:
                if any(sig.lower() in c.lower() for c in cookies.keys()):
                    return waf
                    
        return None
        
    def get_bypass_technique(self, waf_type: str) -> List[str]:
        """Returns bypass techniques specific to the WAF."""
        return self.waf_bypass.get(waf_type, self.waf_bypass['default'])
