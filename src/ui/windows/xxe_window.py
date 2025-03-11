"""
XXE (XML External Entity) Scanner window implementation.
"""

import customtkinter as ctk
import tkinter as tk
from ..base_window import BaseWindow
from ...core.web.xxe_integration import XXEScanner

class XXEWindow(BaseWindow):
    def __init__(self, parent):
        super().__init__(parent)
        self.scanner = XXEScanner()
        self._create_ui()

    def _create_ui(self):
        """Create the user interface elements."""
        # Left side - Controls
        control_frame = ctk.CTkFrame(self.left_frame)
        control_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        control_frame.grid_columnconfigure(0, weight=1)

        # URL Input
        url_label = ctk.CTkLabel(control_frame, text="Target URL:")
        url_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        self.url_entry = ctk.CTkEntry(control_frame, width=300)
        self.url_entry.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        # Parameter Input
        param_label = ctk.CTkLabel(control_frame, text="Parameter to test:")
        param_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
        
        self.param_entry = ctk.CTkEntry(control_frame, width=300)
        self.param_entry.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
        
        # Method Selection
        method_label = ctk.CTkLabel(control_frame, text="HTTP Method:")
        method_label.grid(row=4, column=0, sticky="w", padx=5, pady=5)
        
        self.method_var = tk.StringVar(value="POST")
        methods = ["GET", "POST"]
        method_frame = ctk.CTkFrame(control_frame)
        method_frame.grid(row=5, column=0, sticky="ew", padx=5, pady=5)
        
        for i, method in enumerate(methods):
            rb = ctk.CTkRadioButton(
                method_frame,
                text=method,
                variable=self.method_var,
                value=method
            )
            rb.grid(row=0, column=i, padx=10)
        
        # Custom Headers
        headers_label = ctk.CTkLabel(control_frame, text="Custom Headers (JSON):")
        headers_label.grid(row=6, column=0, sticky="w", padx=5, pady=5)
        
        self.headers_text = ctk.CTkTextbox(control_frame, height=100)
        self.headers_text.grid(row=7, column=0, sticky="ew", padx=5, pady=5)
        self.headers_text.insert("1.0", '{\n    "Content-Type": "application/xml"\n}')
        
        # Scan Options
        options_frame = ctk.CTkFrame(control_frame)
        options_frame.grid(row=8, column=0, sticky="ew", padx=5, pady=10)
        options_frame.grid_columnconfigure(0, weight=1)
        
        self.dtd_var = tk.BooleanVar(value=True)
        dtd_check = ctk.CTkCheckBox(
            options_frame,
            text="Include DTD attacks",
            variable=self.dtd_var
        )
        dtd_check.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        self.entity_var = tk.BooleanVar(value=True)
        entity_check = ctk.CTkCheckBox(
            options_frame,
            text="Test entity expansion",
            variable=self.entity_var
        )
        entity_check.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        
        self.oob_var = tk.BooleanVar(value=True)
        oob_check = ctk.CTkCheckBox(
            options_frame,
            text="Out-of-band testing",
            variable=self.oob_var
        )
        oob_check.grid(row=2, column=0, sticky="w", padx=5, pady=2)
        
        # Buttons
        button_frame = ctk.CTkFrame(control_frame)
        button_frame.grid(row=9, column=0, sticky="ew", padx=5, pady=10)
        button_frame.grid_columnconfigure((0,1), weight=1)
        
        scan_button = ctk.CTkButton(
            button_frame,
            text="Start Scan",
            command=self._start_scan
        )
        scan_button.grid(row=0, column=0, padx=5, pady=5)
        
        clear_button = ctk.CTkButton(
            button_frame,
            text="Clear",
            command=self._clear_fields
        )
        clear_button.grid(row=0, column=1, padx=5, pady=5)
        
        # Right side - Results
        results_label = ctk.CTkLabel(self.right_frame, text="Scan Results:")
        results_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        self.results_text = ctk.CTkTextbox(self.right_frame, width=400, height=500)
        self.results_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configure grid weights for right frame
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(1, weight=1)

    def _start_scan(self):
        """Start the XXE scan with the configured parameters."""
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()
        method = self.method_var.get()
        
        if not url or not param:
            self.show_error("URL and parameter are required!")
            return
        
        try:
            headers = eval(self.headers_text.get("1.0", tk.END).strip())
        except Exception as e:
            self.show_error(f"Invalid headers format: {str(e)}")
            return
        
        options = {
            "dtd_attacks": self.dtd_var.get(),
            "entity_expansion": self.entity_var.get(),
            "oob_testing": self.oob_var.get()
        }
        
        # Clear previous results
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, "Starting scan...\n\n")
        self.update()
        
        try:
            results = self.scanner.scan(
                url=url,
                param=param,
                method=method,
                headers=headers,
                **options
            )
            
            self.results_text.insert(tk.END, "Scan completed!\n\n")
            self.results_text.insert(tk.END, "Findings:\n")
            self.results_text.insert(tk.END, "-" * 50 + "\n")
            
            if isinstance(results, list):
                for finding in results:
                    self.results_text.insert(tk.END, f"• {finding}\n")
            else:
                self.results_text.insert(tk.END, str(results))
                
        except Exception as e:
            self.show_error(f"Error during scan: {str(e)}")
            self.results_text.insert(tk.END, f"Error: {str(e)}\n")

    def _clear_fields(self):
        """Clear all input fields."""
        self.url_entry.delete(0, tk.END)
        self.param_entry.delete(0, tk.END)
        self.method_var.set("POST")
        self.headers_text.delete("1.0", tk.END)
        self.headers_text.insert("1.0", '{\n    "Content-Type": "application/xml"\n}')
        self.dtd_var.set(True)
        self.entity_var.set(True)
        self.oob_var.set(True)
        self.results_text.delete("1.0", tk.END)