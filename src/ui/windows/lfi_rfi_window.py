"""
LFI/RFI (Local/Remote File Inclusion) Scanner window implementation.
"""

import customtkinter as ctk
import tkinter as tk
from ..base_window import BaseWindow
from ...core.web.lfi_rfi_integration import LFIRFIScanner

class LFIRFIWindow(BaseWindow):
    def __init__(self, parent):
        super().__init__(parent)
        self.scanner = LFIRFIScanner()
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
        
        self.method_var = tk.StringVar(value="GET")
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
        
        # Scan Type Selection
        type_label = ctk.CTkLabel(control_frame, text="Scan Type:")
        type_label.grid(row=6, column=0, sticky="w", padx=5, pady=5)
        
        type_frame = ctk.CTkFrame(control_frame)
        type_frame.grid(row=7, column=0, sticky="ew", padx=5, pady=5)
        
        self.lfi_var = tk.BooleanVar(value=True)
        lfi_check = ctk.CTkCheckBox(
            type_frame,
            text="LFI (Local File Inclusion)",
            variable=self.lfi_var
        )
        lfi_check.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        self.rfi_var = tk.BooleanVar(value=True)
        rfi_check = ctk.CTkCheckBox(
            type_frame,
            text="RFI (Remote File Inclusion)",
            variable=self.rfi_var
        )
        rfi_check.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        
        # Advanced Options
        options_frame = ctk.CTkFrame(control_frame)
        options_frame.grid(row=8, column=0, sticky="ew", padx=5, pady=10)
        
        self.null_byte_var = tk.BooleanVar(value=True)
        null_byte_check = ctk.CTkCheckBox(
            options_frame,
            text="Try NULL byte injection",
            variable=self.null_byte_var
        )
        null_byte_check.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        self.path_traversal_var = tk.BooleanVar(value=True)
        path_traversal_check = ctk.CTkCheckBox(
            options_frame,
            text="Test path traversal variants",
            variable=self.path_traversal_var
        )
        path_traversal_check.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        
        self.filter_bypass_var = tk.BooleanVar(value=True)
        filter_bypass_check = ctk.CTkCheckBox(
            options_frame,
            text="Try filter bypass techniques",
            variable=self.filter_bypass_var
        )
        filter_bypass_check.grid(row=2, column=0, sticky="w", padx=5, pady=2)
        
        # Custom Files to Check
        files_label = ctk.CTkLabel(control_frame, text="Custom files to check (one per line):")
        files_label.grid(row=9, column=0, sticky="w", padx=5, pady=5)
        
        self.files_text = ctk.CTkTextbox(control_frame, height=100)
        self.files_text.grid(row=10, column=0, sticky="ew", padx=5, pady=5)
        self.files_text.insert("1.0", "/etc/passwd\n/etc/shadow\n/proc/self/environ")
        
        # Buttons
        button_frame = ctk.CTkFrame(control_frame)
        button_frame.grid(row=11, column=0, sticky="ew", padx=5, pady=10)
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
        """Start the LFI/RFI scan with the configured parameters."""
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()
        method = self.method_var.get()
        
        if not url or not param:
            self.show_error("URL and parameter are required!")
            return
        
        custom_files = self.files_text.get("1.0", tk.END).strip().split("\n")
        
        options = {
            "lfi": self.lfi_var.get(),
            "rfi": self.rfi_var.get(),
            "null_byte": self.null_byte_var.get(),
            "path_traversal": self.path_traversal_var.get(),
            "filter_bypass": self.filter_bypass_var.get(),
            "custom_files": custom_files
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
        self.method_var.set("GET")
        self.lfi_var.set(True)
        self.rfi_var.set(True)
        self.null_byte_var.set(True)
        self.path_traversal_var.set(True)
        self.filter_bypass_var.set(True)
        self.files_text.delete("1.0", tk.END)
        self.files_text.insert("1.0", "/etc/passwd\n/etc/shadow\n/proc/self/environ")
        self.results_text.delete("1.0", tk.END)