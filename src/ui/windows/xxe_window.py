import customtkinter as ctk
import tkinter.messagebox as messagebox
from threading import Thread
import json
from typing import Optional, Dict, Any
from datetime import datetime

from src.ui.base_window import BaseWindow
from src.core.web.xxe_integration import (
    XXEScanner,
    validate_xml_endpoint,
    export_results
)

class XXEWindow(BaseWindow):
    """
    Frame for XXE (XML External Entity) testing, which includes:
      - Target URL configuration
      - Payload selection/editing
      - Results visualization
      - Results export
    """
    
    def __init__(self, parent):
        # Control variables
        self.scan_types = ['file_read', 'ssrf', 'dos', 'oob', 'error_based', 'parameter_entities']
        self.scanner = XXEScanner(callback=self._on_result)
        self.running = False
        self.results = []
        
        super().__init__(parent)
        
        self._create_ui()
        
    def _create_ui(self):
        """Creates the user interface."""
        # ----- Top Frame for URL -----
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(padx=10, pady=10, fill="x")
        
        ctk.CTkLabel(
            top_frame,
            text="Target URL:",
            font=("Arial", 12)
        ).pack(side="left", padx=5)
        
        self.url_entry = ctk.CTkEntry(
            top_frame,
            width=400,
            placeholder_text="http://example.com/api/xml"
        )
        self.url_entry.pack(side="left", padx=5, expand=True, fill="x")
        
        # Validate Endpoint button
        self.validate_btn = ctk.CTkButton(
            top_frame,
            text="Validate Endpoint",
            command=self._validate_endpoint
        )
        self.validate_btn.pack(side="right", padx=5)
        
        # ----- Main Frame -----
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        # Left frame for scan configuration
        left_frame = ctk.CTkFrame(main_frame)
        left_frame.pack(side="left", padx=5, pady=5, fill="both", expand=True)
        
        ctk.CTkLabel(
            left_frame,
            text="Scan Configuration",
            font=("Arial", 12, "bold")
        ).pack(pady=5)
        
        # Checkboxes for scan types
        self.scan_type_vars = {}
        for scan_type in self.scan_types:
            var = ctk.BooleanVar(value=True)
            self.scan_type_vars[scan_type] = var
            ctk.CTkCheckBox(
                left_frame,
                text=scan_type.replace('_', ' ').title(),
                variable=var
            ).pack(padx=5, pady=2, anchor="w")
        
        # Advanced options
        ctk.CTkLabel(
            left_frame,
            text="Advanced Options",
            font=("Arial", 10, "bold")
        ).pack(pady=(10, 5))
        
        # Thorough Mode
        self.thorough_mode_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            left_frame,
            text="Thorough Mode",
            variable=self.thorough_mode_var,
            command=self._update_scanner_config
        ).pack(padx=5, pady=2, anchor="w")
        
        # Right frame for results
        right_frame = ctk.CTkFrame(main_frame)
        right_frame.pack(side="right", padx=5, pady=5, fill="both", expand=True)
        
        ctk.CTkLabel(
            right_frame,
            text="Results",
            font=("Arial", 12, "bold")
        ).pack(pady=5)
        
        self.results_text = ctk.CTkTextbox(
            right_frame,
            width=300,
            height=200
        )
        self.results_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        # ----- Bottom Frame for Buttons -----
        bottom_frame = ctk.CTkFrame(self)
        bottom_frame.pack(padx=10, pady=5, fill="x")
        
        # Start/Stop scan button
        self.start_btn = ctk.CTkButton(
            bottom_frame,
            text="Start Scan",
            command=self._toggle_scan
        )
        self.start_btn.pack(side="left", padx=5)
        
        # Export results button
        self.export_btn = ctk.CTkButton(
            bottom_frame,
            text="Export Results",
            command=self._export_results
        )
        self.export_btn.pack(side="right", padx=5)
        
    def _update_scanner_config(self):
        """Updates the scanner configuration."""
        self.scanner.configure(
            thorough_mode=self.thorough_mode_var.get()
        )
    
    def _validate_endpoint(self):
        """Validates if the endpoint accepts XML."""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
            
        def validate():
            try:
                if validate_xml_endpoint(url):
                    messagebox.showinfo(
                        "Success",
                        "The endpoint accepts XML. You can proceed with the scan."
                    )
                else:
                    messagebox.showwarning(
                        "Warning",
                        "The endpoint does not appear to accept XML. The scan may fail."
                    )
            except Exception as e:
                messagebox.showerror("Error", f"Error validating endpoint: {str(e)}")
        
        Thread(target=validate).start()
    
    def _toggle_scan(self):
        """Starts or stops the scan."""
        if not self.running:
            url = self.url_entry.get().strip()
            
            if not url:
                messagebox.showerror(
                    "Error",
                    "Please enter a URL"
                )
                return
            
            # Get selected scan types
            selected_types = [
                scan_type for scan_type, var in self.scan_type_vars.items()
                if var.get()
            ]
            
            if not selected_types:
                messagebox.showerror(
                    "Error",
                    "Please select at least one scan type"
                )
                return
            
            self.running = True
            self.start_btn.configure(text="Stop Scan")
            self.results_text.delete("0.0", "end")
            self.results = []
            
            def run_scan():
                try:
                    self.scanner.scan_async(url, scan_types=selected_types)
                except Exception as e:
                    messagebox.showerror("Error", f"Scan error: {str(e)}")
                finally:
                    self.running = False
                    self.start_btn.configure(text="Start Scan")
            
            Thread(target=run_scan).start()
        else:
            self.running = False
            self.start_btn.configure(text="Start Scan")
    
    def _on_result(self, result: Dict[str, Any]):
        """Callback to process scan results."""
        self.results.append(result)
        
        # Format result for display
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "VULNERABLE" if result.get('vulnerable') else "NOT VULNERABLE"
        severity = result.get('severity', 'UNKNOWN')
        scan_type = result.get('scan_type', 'Unknown')
        
        result_text = (
            f"[{timestamp}] - {status} ({severity})\n"
            f"Type: {scan_type}\n"
            f"URL: {result['url']}\n"
            f"Code: {result.get('response_code', 'N/A')}\n"
        )
        
        if result.get('evidence'):
            result_text += "Evidence:\n"
            for evidence in result['evidence']:
                result_text += f"  - {evidence}\n"
        
        if result.get('recommendations'):
            result_text += "Recommendations:\n"
            for rec in result['recommendations']:
                result_text += f"  - {rec}\n"
        
        if 'error' in result:
            result_text += f"Error: {result['error']}\n"
        
        result_text += f"{'-' * 50}\n"
        
        # Update UI
        self.results_text.insert("end", result_text)
        self.results_text.see("end")
    
    def _export_results(self):
        """Exports the results to a JSON file."""
        if not self.results:
            messagebox.showinfo(
                "Info",
                "No results to export"
            )
            return
            
        try:
            filename = f"xxe_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            if export_results(self.results, filename):
                messagebox.showinfo(
                    "Success",
                    f"Results exported to {filename}"
                )
            else:
                messagebox.showerror(
                    "Error",
                    "Error exporting results"
                )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error exporting results: {str(e)}"
            )
