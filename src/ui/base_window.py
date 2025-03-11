"""
Base window class that provides common functionality for all tool windows.
"""

import customtkinter as ctk
from tkinter import messagebox
from src.ui.theme import COLORS

class BaseWindow(ctk.CTkFrame):
    """Base class for all tool windows."""

    def __init__(self, parent):
        """Initialize the base window with common elements."""
        super().__init__(parent)
        
        # Store reference to parent
        self.parent = parent
        
        # Store theme colors
        self.colors = COLORS
        
        # Configure the main frame (self)
        self.configure(fg_color=self.colors["background"])
        
        # Create the basic layout
        self._create_base_layout()

    def _create_base_layout(self):
        """Creates the basic two-column layout used by all tools."""
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create left frame (for controls)
        self.left_frame = ctk.CTkFrame(
            self,
            fg_color=self.colors["secondary_bg"]
        )
        self.left_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create right frame (for output/results)
        self.right_frame = ctk.CTkFrame(
            self,
            fg_color=self.colors["secondary_bg"]
        )
        self.right_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        # Pack the main frame
        self.pack(fill="both", expand=True)

    def show_error(self, message: str):
        """Shows an error message dialog."""
        messagebox.showerror("Error", message)

    def show_warning(self, message: str):
        """Shows a warning message dialog."""
        messagebox.showwarning("Warning", message)

    def show_info(self, message: str):
        """Shows an information message dialog."""
        messagebox.showinfo("Information", message)

    def show_confirmation(self, message: str) -> bool:
        """Shows a confirmation dialog and returns True if user confirms."""
        return messagebox.askyesno("Confirm", message)