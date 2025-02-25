"""
Vulnerability Report Generator
"""

import os
import jinja2
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    """Class for generating vulnerability reports."""
    
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'templates', 'reports')
        self.template_loader = jinja2.FileSystemLoader(self.template_dir)
        self.template_env = jinja2.Environment(loader=self.template_loader)
        
    def generate_report(self, results: Dict[str, Any], format: str = 'html') -> str:
        """Generates a report in the specified format."""
        if format == 'html':
            return self._generate_html_report(results)
        elif format == 'pdf':
            return self._generate_pdf_report(results)
        else:
            raise ValueError(f"Unsupported format: {format}")
            
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generates a report in HTML format."""
        try:
            template = self.template_env.get_template('base.html')
            
            report_data = {
                'results': results,
                'timestamp': datetime.now(),
                'risk_level': self._calculate_risk(results),
                'summary': self._generate_summary(results)
            }
            
            return template.render(**report_data)
            
        except Exception as e:
            raise Exception(f"Error generating HTML report: {str(e)}")
            
    def _generate_pdf_report(self, results: Dict[str, Any]) -> bytes:
        """Generates a report in PDF format."""
        try:
            import pdfkit
            
            # First generate HTML
            html_content = self._generate_html_report(results)
            
            # Convert to PDF
            pdf_content = pdfkit.from_string(html_content, False)
            
            return pdf_content
            
        except Exception as e:
            raise Exception(f"Error generating PDF report: {str(e)}")
            
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
            
        # Adjust for WAF
        if results.get('waf'):
            score -= 2  # The presence of a WAF reduces the risk
            
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
