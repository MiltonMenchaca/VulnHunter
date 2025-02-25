"""
Base class for all application windows
"""

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

class BaseWindow(ctk.CTkFrame):
    """Base class for all application windows."""

    def __init__(self, parent):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        """Basic UI setup: main_frame with left_frame and right_frame."""
        # Main frame that will contain both panels
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Left panel for options/controls
        self.left_frame = ctk.CTkFrame(self.main_frame)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Right panel for results or additional content
        self.right_frame = ctk.CTkFrame(self.main_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    def show_error(self, message: str):
        """Shows an error message in a MessageBox."""
        messagebox.showerror("Error", message)

    def show_info(self, message: str):
        """Shows an informational message in a MessageBox."""
        messagebox.showinfo("Information", message)

    def show_warning(self, message: str):
        """Shows a warning message in a MessageBox."""
        messagebox.showwarning("Warning", message)
