"""
Report generator module for vulnerability scanning results.
"""

from typing import Dict, Any, List
from datetime import datetime
import os
import jinja2
import logging

class ReportGenerator:
    """Vulnerability report generator."""
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        
        # Asegurar que el directorio de templates existe
        os.makedirs(self.template_dir, exist_ok=True)
        
        # Crear un template básico si no existe
        self._ensure_template_exists()
        
        self.template_loader = jinja2.FileSystemLoader(self.template_dir)
        self.template_env = jinja2.Environment(loader=self.template_loader)
        self.logger = logging.getLogger(__name__)
        
    def _ensure_template_exists(self):
        """Ensures that the basic report template exists."""
        template_path = os.path.join(self.template_dir, 'report.html')
        if not os.path.exists(template_path):
            basic_template = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f39c12; }
        .low { color: #27ae60; }
        .section { margin-bottom: 20px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .vuln-item { margin-bottom: 10px; padding: 10px; background-color: #f8f9fa; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <div class="section">
        <h2>Summary</h2>
        <p>Scan completed at: {{ timestamp }}</p>
        <p>Overall Risk Level: <span class="{{ risk_level.lower() }}">{{ risk_level }}</span></p>
        <p>Total Vulnerabilities: {{ summary.total_vulnerabilities }}</p>
        <p>Vulnerability Types: {{ summary.types|join(', ') }}</p>
        {% if summary.waf_present %}
        <p>WAF Detected: Yes</p>
        {% else %}
        <p>WAF Detected: No</p>
        {% endif %}
        
        {% if summary.critical_findings %}
        <div class="critical">
            <h3>Critical Findings:</h3>
            <ul>
            {% for finding in summary.critical_findings %}
                <li>{{ finding }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endif %}
    </div>
    
    {% if results.waf %}
    <div class="section">
        <h2>WAF Detection</h2>
        <p>Type: {{ results.waf.type }}</p>
        <h3>Bypass Techniques:</h3>
        <ul>
        {% for technique in results.waf.bypass_techniques %}
            <li>{{ technique }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}
    
    {% if results.xxe %}
    <div class="section">
        <h2>XXE Vulnerabilities</h2>
        {% for vuln in results.xxe %}
        <div class="vuln-item">
            <h3>XXE in {{ vuln.parameter }}</h3>
            <p>URL: {{ vuln.url }}</p>
            <p>Severity: <span class="{{ vuln.severity.lower() }}">{{ vuln.severity }}</span></p>
            <p>Payload: <code>{{ vuln.payload }}</code></p>
            <h4>Recommendations:</h4>
            <ul>
            {% for rec in vuln.recommendations %}
                <li>{{ rec }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </div>
    {% endif %}
    
    {% if results.lfi_via_xxe %}
    <div class="section">
        <h2>LFI via XXE Vulnerabilities</h2>
        {% for vuln in results.lfi_via_xxe %}
        <div class="vuln-item">
            <h3>LFI via XXE in {{ vuln.parameter }}</h3>
            <p>URL: {{ vuln.url }}</p>
            <p>Severity: <span class="{{ vuln.severity.lower() }}">{{ vuln.severity }}</span></p>
            <p>Payload: <code>{{ vuln.payload }}</code></p>
            <h4>Recommendations:</h4>
            <ul>
            {% for rec in vuln.recommendations %}
                <li>{{ rec }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </div>
    {% endif %}
    
    {% if results.lfi_rfi %}
    <div class="section">
        <h2>LFI/RFI Vulnerabilities</h2>
        {% for vuln in results.lfi_rfi %}
        <div class="vuln-item">
            <h3>{{ vuln.vulnerability_type }} in {{ vuln.parameter }}</h3>
            <p>URL: {{ vuln.url }}</p>
            <p>Severity: <span class="{{ vuln.severity.lower() }}">{{ vuln.severity }}</span></p>
            <p>Payload: <code>{{ vuln.payload }}</code></p>
            <h4>Recommendations:</h4>
            <ul>
            {% for rec in vuln.recommendations %}
                <li>{{ rec }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </div>
    {% endif %}
    
    <div class="section">
        <h2>Disclaimer</h2>
        <p>This report was generated automatically by VulnHunter. The results should be verified manually before taking action.</p>
    </div>
</body>
</html>"""
            with open(template_path, 'w') as f:
                f.write(basic_template)
        
    def generate_report(self, results: Dict[str, Any], format: str = 'html') -> str:
        """Generates a report in the specified format."""
        try:
            if format == 'html':
                template_name = 'report.html'
                template = self.template_env.get_template(template_name)
                
                report_data = {
                    'results': results,
                    'timestamp': datetime.now(),
                    'risk_level': self._calculate_risk(results),
                    'summary': self._generate_summary(results)
                }
                
                return template.render(**report_data)
            elif format == 'pdf':
                # Generate HTML first
                html_content = self.generate_report(results, format='html')
                
                try:
                    import pdfkit
                    pdf_content = pdfkit.from_string(html_content, False)
                    return pdf_content
                except Exception as e:
                    self.logger.error(f"Error converting to PDF: {str(e)}")
                    # Fallback - return HTML content with error message
                    error_html = f"<html><body><h1>PDF Generation Error</h1><p>{str(e)}</p><hr>{html_content}</body></html>"
                    return error_html
            else:
                raise ValueError(f"Unsupported report format: {format}")
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            # Fallback to a simple report
            return f"<html><body><h1>Vulnerability Report</h1><pre>{str(results)}</pre></body></html>"
        
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