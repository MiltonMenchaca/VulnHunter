import tkinter as tk
import customtkinter as ctk
from ..base_window import BaseWindow

class BaseScannerWindow(BaseWindow):
    """Base class for all scanner windows."""

    def __init__(self, parent):
        super().__init__(parent)
        self._create_ui()

    def _create_ui(self):
        """
        Uses the frames already created in BaseWindow:
         - self.left_frame
         - self.right_frame
        This avoids mixing ttk with ctk so that the theme is applied properly.
        """
        # "Scan Options" label on the left panel
        left_label = ctk.CTkLabel(
            self.left_frame,
            text="Scan Options",
            font=ctk.CTkFont(weight="bold", size=14)
        )
        left_label.pack(pady=5)

        # Here you could create your option widgets (buttons, entries, etc.)
        # Example button:
        self.scan_button = ctk.CTkButton(
            self.left_frame,
            text="Start Scan",
            command=self._on_scan_start
        )
        self.scan_button.pack(pady=5)

        # "Results" label on the right panel
        right_label = ctk.CTkLabel(
            self.right_frame,
            text="Results",
            font=ctk.CTkFont(weight="bold", size=14)
        )
        right_label.pack(pady=5)

        # Text area to display results
        self.results_text = ctk.CTkTextbox(self.right_frame)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _on_scan_start(self):
        """Example method to handle the start of the scan."""
        self._on_result("Starting scan...")

    def _on_result(self, result: str):
        """Inserts a scan result into the textbox."""
        self.results_text.insert("end", str(result) + "\n")
        self.results_text.see("end")
