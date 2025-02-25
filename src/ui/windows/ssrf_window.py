"""
Window for the SSRF scanner
"""

import tkinter as tk
from tkinter import ttk, filedialog
import json
import customtkinter as ctk
from ..base_window import BaseWindow
from ...core.web.ssrf_integration import SSRFScanner
from ...core.utils.tooltip import ToolTip

class SSRFWindow(BaseWindow):
    def __init__(self, parent):
        self.scanner = SSRFScanner(callback=self._on_result)
        super().__init__(parent)
        self._create_ui()
        
    def _create_ui(self):
        """Creates the user interface."""
        # Main frame with two columns
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left frame for scan options
        self.left_frame = ttk.LabelFrame(self.main_frame, text="Scan Options")
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # URL and parameters
        self.url_entry = self.create_labeled_entry(
            self.left_frame,
            "Target URL:",
            "Enter the URL to scan"
        )
        
        self.params_entry = self.create_labeled_entry(
            self.left_frame,
            "Parameters (JSON):",
            "Enter parameters in JSON format\nEx: {\"url\": \"http://example.com\"}"
        )
        
        # Scan options
        scan_options_frame = ttk.LabelFrame(self.left_frame, text="Scan Options")
        scan_options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Types of scans
        self.scan_types = {
            'basic': tk.BooleanVar(value=True),
            'blind': tk.BooleanVar(value=True),
            'ports': tk.BooleanVar(value=True),
            'protocols': tk.BooleanVar(value=True)
        }
        
        for scan_type, var in self.scan_types.items():
            cb = ttk.Checkbutton(
                scan_options_frame,
                text=scan_type.capitalize(),
                variable=var
            )
            cb.pack(anchor=tk.W)
            ToolTip(cb, f"Enable {scan_type} scan")
            
        # Custom ports
        ports_frame = ttk.Frame(scan_options_frame)
        ports_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ports_frame, text="Ports:").pack(side=tk.LEFT)
        self.ports_entry = ttk.Entry(ports_frame)
        self.ports_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ports_entry.insert(0, "80,443,8080,8443")
        ToolTip(self.ports_entry, "Comma-separated list of ports")
        
        # Custom protocols
        protocols_frame = ttk.Frame(scan_options_frame)
        protocols_frame.pack(fill=tk.X, pady=5)
        
        self.protocols = ttk.Combobox(
            protocols_frame,
            values=['http', 'https', 'file', 'dict', 'gopher', 'ftp', 'ldap']
        )
        self.protocols.set('http')
        self.protocols.pack(fill=tk.X)
        ToolTip(self.protocols, "Select the protocol to test")
        
        # Buttons
        buttons_frame = ttk.Frame(self.left_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        self.scan_btn = ttk.Button(
            buttons_frame,
            text="Start Scan",
            command=self._start_scan
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(self.scan_btn, "Start the SSRF scan")
        
        self.stop_btn = ttk.Button(
            buttons_frame,
            text="Stop",
            command=self._stop_scan
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(self.stop_btn, "Stop the current scan")
        
        self.clear_btn = ttk.Button(
            buttons_frame,
            text="Clear",
            command=self._clear_results
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(self.clear_btn, "Clear the results")
        
        # Right frame for results
        self.right_frame = ttk.LabelFrame(self.main_frame, text="Results")
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Results area
        self.results_text = ctk.CTkTextbox(self.right_frame)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def _start_scan(self):
        """Starts the SSRF scan."""
        url = self.url_entry.get()
        params_str = self.params_entry.get()
        
        try:
            params = json.loads(params_str) if params_str else {}
        except json.JSONDecodeError:
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert(tk.END, "Error: Invalid JSON parameters")
            return
            
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, f"Starting scan on {url}...\n")
        
        try:
            results = self.scanner.scan_url(url, params)
            
            self.results_text.insert(tk.END, f"\nFound {len(results)} vulnerabilities\n")
            
            for result in results:
                self.results_text.insert(tk.END, f"\n{'-'*50}\n")
                self.results_text.insert(tk.END, f"Type: {result['type']}\n")
                self.results_text.insert(tk.END, f"Parameter: {result['param']}\n")
                self.results_text.insert(tk.END, f"Payload: {result['payload']}\n")
                self.results_text.insert(tk.END, f"Evidence: {result['evidence']}\n")
                
        except Exception as e:
            self.results_text.insert(tk.END, f"\nError during scan: {str(e)}")
            
    def _stop_scan(self):
        """Stops the current scan."""
        # Implement logic to stop the scan
        self.results_text.insert(tk.END, "\nStop requested...")
        
    def _clear_results(self):
        """Clears the results."""
        self.results_text.delete("1.0", tk.END)
        
    def _on_result(self, result):
        """Callback for real-time results."""
        self.results_text.insert(tk.END, "\nNew vulnerability found!\n")
        self.results_text.insert(tk.END, f"Type: {result['type']}\n")
        self.results_text.insert(tk.END, f"Parameter: {result['param']}\n")
        self.results_text.insert(tk.END, f"Payload: {result['payload']}\n")
        self.results_text.insert(tk.END, f"Evidence: {result['evidence']}\n")
