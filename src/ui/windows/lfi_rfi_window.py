import tkinter as tk
from tkinter import ttk, filedialog
import customtkinter as ctk
from ..base_window import BaseWindow
from ...core.web.lfi_rfi_integration import LFIRFIScanner
from ...core.web.combined_scanner import CombinedScanner
from src.core.web.report_generator import ReportGenerator
import json
import os

class ToolTip:
    """Class to create tooltips for widgets"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show)
        self.widget.bind("<Leave>", self.hide)
    
    def show(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        label = ttk.Label(self.tooltip, text=self.text, justify='left',
                         background="#ffffe0", relief='solid', borderwidth=1)
        label.pack()
    
    def hide(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class LFIRFIWindow(BaseWindow):
    def __init__(self, parent):
        self.scanner = LFIRFIScanner(callback=self._on_result)
        self.combined_scanner = CombinedScanner()
        self.combined_scanner.report_generator = ReportGenerator()
        super().__init__(parent)
        self._create_ui()
        
    def _create_ui(self):
        """Create the UI widgets"""
        # Main frame with two columns
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left frame for options
        self.left_frame = ttk.LabelFrame(self.main_frame, text="Scan Options")
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # URL and parameters
        url_label = ttk.Label(self.left_frame, text="Target URL:")
        url_label.pack(pady=5)
        self.url_entry = ttk.Entry(self.left_frame)
        self.url_entry.pack(fill=tk.X, padx=5, pady=5)
        ToolTip(self.url_entry, "Enter the full target URL\nEx: http://example.com/index.php")
        
        params_label = ttk.Label(self.left_frame, text="Parameters (JSON):")
        params_label.pack(pady=5)
        self.params_entry = ttk.Entry(self.left_frame)
        self.params_entry.pack(fill=tk.X, padx=5, pady=5)
        ToolTip(self.params_entry, "Enter the parameters in JSON format\nEx: {\"file\": \"index.php\"}")
        
        # Scan mode
        scan_mode_frame = ttk.LabelFrame(self.left_frame, text="Scan Mode")
        scan_mode_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.scan_mode = tk.StringVar(value="lfi_rfi")
        modes = [
            ("LFI/RFI Only", "lfi_rfi"),
            ("Combined (LFI/RFI + XXE)", "combined")
        ]
        for text, mode in modes:
            rb = ttk.Radiobutton(scan_mode_frame, text=text, value=mode, variable=self.scan_mode)
            rb.pack(anchor=tk.W)
            ToolTip(rb, f"Use scan mode: {text}")

        # Payload Generation Section
        payload_frame = ttk.LabelFrame(self.left_frame, text="Payload Generator")
        payload_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Shell type
        shell_label = ttk.Label(payload_frame, text="Shell Type:")
        shell_label.pack(pady=2)
        self.template_var = tk.StringVar(value="basic_cmd")
        templates = ["basic_cmd", "stealth_eval", "memory_shell", "fileless_shell", "image_shell", "multipart_shell"]
        self.template_combo = ttk.Combobox(payload_frame, values=templates, textvariable=self.template_var)
        self.template_combo.pack(fill=tk.X, padx=5, pady=2)
        ToolTip(self.template_combo, 
            "Select the shell type:\n" +
            "- basic_cmd: Basic command shell\n" +
            "- stealth_eval: Obfuscated shell using eval\n" +
            "- memory_shell: In-memory shell\n" +
            "- fileless_shell: Fileless shell\n" +
            "- image_shell: Shell hidden in image\n" +
            "- multipart_shell: Polymorphic shell"
        )
        
        # Evasion Techniques
        evasion_frame = ttk.LabelFrame(payload_frame, text="Evasion Techniques")
        evasion_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.evasion_vars = {}
        evasion_techniques = [
            ("comment_injection", "Comment Injection"),
            ("space_substitution", "Space Substitution"),
            ("string_concat", "String Concatenation"),
            ("hex_encode", "Hexadecimal Encoding")
        ]
        
        for tech_id, tech_name in evasion_techniques:
            self.evasion_vars[tech_id] = tk.BooleanVar(value=False)
            cb = ttk.Checkbutton(evasion_frame, text=tech_name, variable=self.evasion_vars[tech_id])
            cb.pack(anchor=tk.W)
            ToolTip(cb, f"Use evasion technique: {tech_name}")
        
        # Compression
        compression_frame = ttk.LabelFrame(payload_frame, text="Compression")
        compression_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.compression_var = tk.StringVar(value="gzip")
        compressions = ["gzip", "deflate", "bzip2"]
        for comp in compressions:
            rb = ttk.Radiobutton(compression_frame, text=comp, value=comp, variable=self.compression_var)
            rb.pack(anchor=tk.W)
            ToolTip(rb, f"Use {comp} compression")
        
        # Action buttons
        self.generate_btn = ttk.Button(payload_frame, text="Generate Payload", command=self._generate_payload)
        self.generate_btn.pack(pady=5)
        ToolTip(self.generate_btn, "Generate a new payload with the selected options")
        
        self.scan_btn = ttk.Button(self.left_frame, text="Start Scan", command=self._start_scan)
        self.scan_btn.pack(pady=10)
        ToolTip(self.scan_btn, "Start the scan with the current configuration")
        
        self.save_btn = ttk.Button(self.left_frame, text="Save Payload", command=self._save_payload)
        self.save_btn.pack(pady=5)
        ToolTip(self.save_btn, "Save the last generated payload")
        
        # Report Options
        report_frame = ttk.LabelFrame(self.left_frame, text="Report Options")
        report_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.report_format = tk.StringVar(value="html")
        formats = [
            ("HTML", "html"),
            ("PDF", "pdf")
        ]
        for text, fmt in formats:
            rb = ttk.Radiobutton(report_frame, text=text, value=fmt, variable=self.report_format)
            rb.pack(side=tk.LEFT, padx=5)
            ToolTip(rb, f"Generate report in {text} format")
            
        self.report_btn = ttk.Button(report_frame, text="Generate Report", command=self._generate_report)
        self.report_btn.pack(pady=5)
        ToolTip(self.report_btn, "Generate a detailed report of the vulnerabilities found")

        # Right frame for results
        self.right_frame = ttk.LabelFrame(self.main_frame, text="Results")
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Results area
        self.results_text = tk.Text(self.right_frame, wrap=tk.WORD, width=50)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar for results
        scrollbar = ttk.Scrollbar(self.right_frame, command=self.results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.config(yscrollcommand=scrollbar.set)
        
    def _generate_payload(self):
        """Generates a new polymorphic payload"""
        try:
            template_type = self.template_var.get()
            
            # Get selected evasion techniques
            evasion_techniques = [
                tech_id for tech_id, var in self.evasion_vars.items()
                if var.get()
            ]
            
            # Generate payload
            payload = self.scanner.generate_polymorphic_payload(
                template_type,
                evasion_techniques=evasion_techniques
            )
            
            # Display payload information
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "=== Generated Payload ===\n\n")
            self.results_text.insert(tk.END, f"Type: {template_type}\n")
            self.results_text.insert(tk.END, f"Evasion Techniques: {', '.join(payload['evasion_applied'])}\n")
            self.results_text.insert(tk.END, f"Compression: {payload['compression']}\n\n")
            self.results_text.insert(tk.END, "Original Content:\n")
            self.results_text.insert(tk.END, payload['original'][:200] + "...\n\n")
            self.results_text.insert(tk.END, "Processed Content (preview):\n")
            self.results_text.insert(tk.END, str(payload['content'][:100]) + "...\n")
            
            # Save the current payload
            self.current_payload = payload
            
        except Exception as e:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Error generating payload: {str(e)}")
            
    def _save_payload(self):
        """Saves the generated payload"""
        if not hasattr(self, 'current_payload'):
            self.results_text.insert(tk.END, "\nError: No generated payload to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".php",
            filetypes=[
                ("PHP Files", "*.php"),
                ("All Files", "*.*")
            ]
        )
        
        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    f.write(self.current_payload['content'])
                self.results_text.insert(tk.END, f"\nPayload saved at: {file_path}")
            except Exception as e:
                self.results_text.insert(tk.END, f"\nError saving payload: {str(e)}")
                
    def _start_scan(self):
        """Starts the LFI/RFI scan"""
        url = self.url_entry.get()
        params_str = self.params_entry.get()
        
        try:
            params = json.loads(params_str) if params_str else {}
        except json.JSONDecodeError:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "Error: Invalid JSON parameters")
            return
            
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting scan on {url}...\n")
        
        try:
            if self.scan_mode.get() == "combined":
                results = self.combined_scanner.chain_attack(url)
                self.current_results = results  # Save for report
                
                # Display WAF results if available
                if 'waf' in results:
                    self.results_text.insert(tk.END, f"\nWAF Detected: {results['waf']['type']}\n")
                    self.results_text.insert(tk.END, "Recommended Bypass Techniques:\n")
                    for technique in results['waf']['bypass_techniques']:
                        self.results_text.insert(tk.END, f"- {technique}\n")
                
                # Display XXE results
                if 'xxe' in results:
                    self.results_text.insert(tk.END, f"\nXXE vulnerabilities found: {len(results['xxe'])}\n")
                    
                # Display LFI via XXE results
                if 'lfi_via_xxe' in results:
                    self.results_text.insert(tk.END, f"\nLFI via XXE found: {len(results['lfi_via_xxe'])}\n")
                    
                # Display LFI/RFI results
                if 'lfi_rfi' in results:
                    self.results_text.insert(tk.END, f"\nLFI/RFI vulnerabilities: {len(results['lfi_rfi'])}\n")
            else:
                results = self.scanner.scan_url(url, params)
                self.current_results = {'lfi_rfi': results}  # Save for report
                
                self.results_text.insert(tk.END, f"\nFound {len(results)} vulnerabilities\n")
                
                for result in results:
                    self.results_text.insert(tk.END, f"\n{'-'*50}\n")
                    self.results_text.insert(tk.END, f"Type: {result['vuln_type']}\n")
                    self.results_text.insert(tk.END, f"Parameter: {result['param']}\n")
                    self.results_text.insert(tk.END, f"Payload: {result['payload']}\n")
                    
                    # Display heuristic analysis
                    analysis = self.scanner._analyze_response(result['response'])
                    self.results_text.insert(tk.END, f"\nHeuristic Analysis:\n")
                    self.results_text.insert(tk.END, f"Score: {analysis['score']}\n")
                    self.results_text.insert(tk.END, f"Confidence: {analysis['confidence']}%\n")
                    if analysis['evidence']:
                        self.results_text.insert(tk.END, "Evidence found:\n")
                        for ev in analysis['evidence']:
                            self.results_text.insert(tk.END, f"- {ev}\n")
                    
        except Exception as e:
            self.results_text.insert(tk.END, f"\nError during scan: {str(e)}")
            
    def _generate_report(self):
        """Generates a report of the vulnerabilities found"""
        if not hasattr(self, 'current_results'):
            self.results_text.insert(tk.END, "\nError: No results to generate a report")
            return
            
        try:
            format = self.report_format.get()
            report = self.combined_scanner.report_generator.generate_report(
                self.current_results,
                format=format
            )
            
            # Save report
            file_types = {
                'html': ('HTML files', '*.html'),
                'pdf': ('PDF files', '*.pdf')
            }
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=f".{format}",
                filetypes=[file_types[format], ("All files", "*.*")]
            )
            
            if file_path:
                with open(file_path, 'w' if format == 'html' else 'wb') as f:
                    f.write(report)
                self.results_text.insert(tk.END, f"\nReport saved at: {file_path}")
                
        except Exception as e:
            self.results_text.insert(tk.END, f"\nError generating report: {str(e)}")
            
    def _on_result(self, result):
        """Callback for real-time results"""
        self.results_text.insert(tk.END, f"\nNew vulnerability found!\n")
        self.results_text.insert(tk.END, f"Type: {result['vuln_type']}\n")
        self.results_text.insert(tk.END, f"Parameter: {result['param']}\n")
        self.results_text.insert(tk.END, f"Payload: {result['payload']}\n")
        
        # Display real-time heuristic analysis
        if 'response' in result:
            analysis = self.scanner._analyze_response(result['response'])
            self.results_text.insert(tk.END, f"\nHeuristic Analysis:\n")
            self.results_text.insert(tk.END, f"Score: {analysis['score']}\n")
            self.results_text.insert(tk.END, f"Confidence: {analysis['confidence']}%\n")
            if analysis['evidence']:
                self.results_text.insert(tk.END, "Evidence found:\n")
                for ev in analysis['evidence']:
                    self.results_text.insert(tk.END, f"- {ev}\n")
