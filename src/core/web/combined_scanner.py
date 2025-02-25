from typing import Dict, Any, Optional, List
import requests
from .lfi_rfi_integration import LFIRFIScanner
from .xxe_integration import XXEScanner
from datetime import datetime
import jinja2
import os

class CombinedScanner:
    """Combined scanner for LFI/RFI and XXE."""
    def __init__(self):
        self.lfi_scanner = LFIRFIScanner()
        self.xxe_scanner = XXEScanner()
        self.waf_detector = WAFDetector()
        self.report_generator = VulnerabilityReport()
        
    def chain_attack(self, url: str) -> Dict[str, Any]:
        """Performs a chained attack combining LFI/RFI and XXE."""
        results = {}
        
        # Detect WAF
        response = requests.head(url)
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

class VulnerabilityReport:
    """Vulnerability report generator."""
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.template_loader = jinja2.FileSystemLoader(self.template_dir)
        self.template_env = jinja2.Environment(loader=self.template_loader)
        
    def generate_report(self, results: Dict[str, Any], format: str = 'html') -> str:
        """Generates a report in the specified format."""
        template_name = f'report.{format}'
        template = self.template_env.get_template(template_name)
        
        report_data = {
            'results': results,
            'timestamp': datetime.now(),
            'risk_level': self._calculate_risk(results),
            'summary': self._generate_summary(results)
        }
        
        return template.render(**report_data)
        
    def _calculate_risk(self, results: Dict[str, Any]) -> str:
        """Calculates the risk level based on the results."""
        score = 0
        
        # Calculate score based on found vulnerabilities
        if results.get('xxe'):
            score += 8  # XXE is considered high risk
        if results.get('lfi_via_xxe'):
            score += 9  # LFI via XXE is very dangerous
        if results.get('lfi_rfi'):
            score += 7  # Direct LFI/RFI is medium-high risk
            
        # Adjust for WAF presence
        if results.get('waf'):
            score -= 2  # WAF presence reduces risk
        
        # Determine risk level
        if score >= 15:
            return 'CRITICAL'
        elif score >= 10:
            return 'HIGH'
        elif score >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a summary of the results."""
        summary = {
            'total_vulnerabilities': 0,
            'types': [],
            'waf_present': bool(results.get('waf')),
            'critical_findings': []
        }
        
        if results.get('xxe'):
            summary['total_vulnerabilities'] += len(results['xxe'])
            summary['types'].append('XXE')
            
        if results.get('lfi_via_xxe'):
            summary['total_vulnerabilities'] += len(results['lfi_via_xxe'])
            summary['types'].append('LFI via XXE')
            summary['critical_findings'].append('LFI executed via XXE')
            
        if results.get('lfi_rfi'):
            summary['total_vulnerabilities'] += len(results['lfi_rfi'])
            summary['types'].append('LFI/RFI')
            
        return summary
