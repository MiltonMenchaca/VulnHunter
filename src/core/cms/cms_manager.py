import subprocess
import json
import logging
from typing import Dict, List, Optional

class CMSManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def detect_cms(self, target_url: str) -> Dict:
        """Detects the CMS used on a target URL using multiple methods."""
        results = {}
        try:
            # 1. Detection with WhatWeb
            whatweb = subprocess.run(['whatweb', '-j', target_url], 
                                       capture_output=True, text=True)
            if whatweb.returncode == 0:
                results['whatweb'] = json.loads(whatweb.stdout)

            # 2. Detection with curl and header analysis
            headers = subprocess.run(['curl', '-I', '-L', target_url],
                                     capture_output=True, text=True)
            if headers.returncode == 0:
                results['headers'] = self._parse_headers(headers.stdout)

            # 3. Detection of common files
            common_files = {
                'wordpress': ['/wp-login.php', '/wp-admin', '/wp-content'],
                'joomla': ['/administrator', '/components', '/modules'],
                'drupal': ['/user/login', '/node/add', '/admin']
            }
            results['file_detection'] = self._check_common_files(target_url, common_files)

            # 4. Version fingerprinting
            results['version'] = self._detect_version(target_url, results)

            return results

        except Exception as e:
            self.logger.error(f"Error detecting CMS: {e}")
            return results

    def _parse_headers(self, headers_str: str) -> Dict:
        """Parses the HTTP headers in search of CMS indicators."""
        headers = {}
        for line in headers_str.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers

    def _check_common_files(self, url: str, files_dict: Dict) -> Dict:
        """Checks for the existence of common files for each CMS."""
        results = {}
        for cms, paths in files_dict.items():
            results[cms] = []
            for path in paths:
                try:
                    response = subprocess.run(
                        ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                         f"{url.rstrip('/')}{path}"],
                        capture_output=True, text=True
                    )
                    if response.stdout.strip() != '404':
                        results[cms].append(path)
                except Exception as e:
                    self.logger.error(f"Error checking {path}: {e}")
        return results

    def _detect_version(self, url: str, previous_results: Dict) -> Dict:
        """Detects the CMS version using multiple methods."""
        version_info = {}
        
        # Analyze previous WhatWeb results
        if 'whatweb' in previous_results:
            version_info['whatweb_version'] = self._extract_version_from_whatweb(
                previous_results['whatweb']
            )

        # Search in specific version files
        version_files = {
            'wordpress': ['/readme.html', '/wp-includes/version.php'],
            'joomla': ['/administrator/manifests/files/joomla.xml'],
            'drupal': ['/CHANGELOG.txt']
        }

        for cms, files in version_files.items():
            for file in files:
                try:
                    response = subprocess.run(
                        ['curl', '-s', f"{url.rstrip('/')}{file}"],
                        capture_output=True, text=True
                    )
                    if response.returncode == 0:
                        version_info[f"{cms}_{file}"] = self._extract_version_from_content(
                            cms, response.stdout
                        )
                except Exception as e:
                    self.logger.error(f"Error checking version file {file}: {e}")

        return version_info

    def _extract_version_from_whatweb(self, whatweb_results: Dict) -> str:
        """Extracts the version from the WhatWeb results."""
        try:
            # Implement specific logic to extract version from WhatWeb output
            return whatweb_results.get('version', 'unknown')
        except Exception:
            return 'unknown'

    def _extract_version_from_content(self, cms: str, content: str) -> str:
        """Extracts the version from the content of specific files."""
        version_patterns = {
            'wordpress': r'Version\s+([\d.]+)',
            'joomla': r'<version>([\d.]+)</version>',
            'drupal': r'Drupal\s+([\d.]+)'
        }
        
        try:
            import re
            pattern = version_patterns.get(cms)
            if pattern:
                match = re.search(pattern, content)
                if match:
                    return match.group(1)
        except Exception as e:
            self.logger.error(f"Error extracting version: {e}")
        
        return 'unknown'

    def scan_wordpress(self, target_url: str, aggressive: bool = False) -> Dict:
        """Scans a WordPress site using wpscan with advanced options."""
        try:
            # Configure scan options
            scan_options = [
                '--url', target_url,
                '--format', 'json',
                '--detection-mode', 'aggressive' if aggressive else 'passive',
                '--enumerate', 'vp,vt,tt,cb,dbe,u,m',  # Plugins, themes, timthumbs, config backups, db exports, users, media
                '--plugins-detection', 'aggressive' if aggressive else 'passive',
                '--plugins-version-detection', 'aggressive' if aggressive else 'mixed',
                '--random-user-agent',  # Avoid blocking
                '--disable-tls-checks'  # Handle self-signed certificates
            ]

            # Add options for aggressive scanning
            if aggressive:
                scan_options.extend([
                    '--wp-content-dir',
                    '--wp-plugins-dir',
                    '--force'
                ])

            result = subprocess.run(['wpscan'] + scan_options, capture_output=True, text=True)
            
            if result.returncode == 0:
                scan_results = json.loads(result.stdout)
                
                # Enrich results with additional information
                scan_results['additional_checks'] = {
                    'security_headers': self._check_security_headers(target_url),
                    'exposed_files': self._check_exposed_sensitive_files(target_url),
                    'backup_files': self._find_backup_files(target_url),
                    'debug_mode': self._check_debug_mode(target_url)
                }
                
                return scan_results
            return {'error': 'Scan failed', 'output': result.stderr}
            
        except Exception as e:
            self.logger.error(f"Error scanning WordPress: {e}")
            return {'error': str(e)}

    def _check_security_headers(self, url: str) -> Dict:
        """Checks security headers."""
        try:
            headers = subprocess.run(['curl', '-I', '-L', url],
                                       capture_output=True, text=True)
            if headers.returncode == 0:
                security_headers = {
                    'X-Frame-Options': False,
                    'X-XSS-Protection': False,
                    'X-Content-Type-Options': False,
                    'Strict-Transport-Security': False,
                    'Content-Security-Policy': False
                }
                
                for line in headers.stdout.split('\n'):
                    for header in security_headers:
                        if header in line:
                            security_headers[header] = True
                            
                return security_headers
        except Exception as e:
            self.logger.error(f"Error checking security headers: {e}")
        return {}

    def _check_exposed_sensitive_files(self, url: str) -> List[str]:
        """Searches for exposed sensitive files."""
        sensitive_files = [
            'wp-config.php.bak',
            'wp-config.php~',
            '.wp-config.php.swp',
            'wp-config.php.save',
            'wp-config.php.orig',
            'wp-config.php.old'
        ]
        
        exposed = []
        for file in sensitive_files:
            try:
                response = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                     f"{url.rstrip('/')}/{file}"],
                    capture_output=True, text=True
                )
                if response.stdout.strip() != '404':
                    exposed.append(file)
            except Exception as e:
                self.logger.error(f"Error checking {file}: {e}")
        return exposed

    def _find_backup_files(self, url: str) -> List[str]:
        """Searches for backup files."""
        backup_patterns = [
            '*.sql',
            '*.zip',
            '*.tar.gz',
            '*.bak',
            'backup*',
            'dump*'
        ]
        
        found_backups = []
        for pattern in backup_patterns:
            try:
                response = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                     f"{url.rstrip('/')}/wp-content/{pattern}"],
                    capture_output=True, text=True
                )
                if response.stdout.strip() != '404':
                    found_backups.append(f"wp-content/{pattern}")
            except Exception as e:
                self.logger.error(f"Error checking backup {pattern}: {e}")
        return found_backups

    def _check_debug_mode(self, url: str) -> bool:
        """Checks if debug mode is enabled."""
        try:
            response = subprocess.run(
                ['curl', '-s', url],
                capture_output=True, text=True
            )
            return 'WP_DEBUG' in response.stdout
        except Exception as e:
            self.logger.error(f"Error checking debug mode: {e}")
            return False

    def scan_joomla(self, target_url: str) -> Dict:
        """Scans a Joomla site using joomscan."""
        try:
            result = subprocess.run(['joomscan', '--url', target_url],
                                      capture_output=True, text=True)
            if result.returncode == 0:
                return {'raw_output': result.stdout}
            return {}
        except Exception as e:
            self.logger.error(f"Error scanning Joomla: {e}")
            return {}

    def scan_drupal(self, target_url: str) -> Dict:
        """Scans a Drupal site using droopescan."""
        try:
            result = subprocess.run(['droopescan', 'scan', 'drupal', '-u', target_url],
                                      capture_output=True, text=True)
            if result.returncode == 0:
                return {'raw_output': result.stdout}
            return {}
        except Exception as e:
            self.logger.error(f"Error scanning Drupal: {e}")
            return {}

    def get_vulnerabilities(self, cms_type: str, version: str) -> List[Dict]:
        """Searches for known vulnerabilities for a specific CMS."""
        try:
            # Use searchsploit to find exploits
            result = subprocess.run(['searchsploit', '-j', f"{cms_type} {version}"],
                                      capture_output=True, text=True)
            if result.returncode == 0:
                return json.loads(result.stdout).get('RESULTS', [])
            return []
        except Exception as e:
            self.logger.error(f"Error searching for vulnerabilities: {e}")
            return []
