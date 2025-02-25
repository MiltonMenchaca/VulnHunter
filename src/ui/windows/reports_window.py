# windows/reports_window.py

import customtkinter as ctk
from tkinter import filedialog, messagebox
import json
import os
from datetime import datetime

class ReportsWindow(ctk.CTkFrame):
    """
    Window to generate and view reports.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True, padx=10, pady=10)
        self._create_ui()

    def _create_ui(self):
        # Report Title
        report_title = ctk.CTkLabel(
            self,
            text="Generate Report",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        report_title.pack(pady=20)

        # Select which tools to include in the report
        ctk.CTkLabel(self, text="Select the tools to include:").pack(pady=(10, 5))

        tools = [
            "OSINT",
            "ARP Scan",
            "Sniffer",
            "MacChanger",
            "SQL Injection",
            "Advanced Scanner",
            "Hydra",
            "Wfuzz"
            # Add more tools as needed
        ]

        self.tool_vars = {}
        for tool in tools:
            var = ctk.StringVar(value="Off")
            cb = ctk.CTkCheckBox(
                self,
                text=tool,
                variable=var,
                onvalue="On",
                offvalue="Off"
            )
            cb.pack(anchor="w", padx=20)
            self.tool_vars[tool] = var

        # Button to generate the report
        def generate_report():
            selected_tools = [tool for tool, var in self.tool_vars.items() if var.get() == "On"]
            if not selected_tools:
                messagebox.showwarning("Warning", "Please select at least one tool for the report.")
                return

            # Ask where to save the report
            save_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
            )
            if not save_path:
                return

            # Get the current date
            current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Generate the report (basic example)
            report = {
                "title": "Pentesting Report - Vuln Hunter",
                "included_tools": selected_tools,
                "date": current_date,
                "results": {}  # Here you can add the actual tool results
            }

            try:
                with open(save_path, 'w') as f:
                    json.dump(report, f, indent=4)
                messagebox.showinfo("Success", f"Report successfully generated at {save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not generate the report: {e}")

        generate_button = ctk.CTkButton(
            self,
            text="Generate Report",
            command=generate_report
        )
        generate_button.pack(pady=20)
