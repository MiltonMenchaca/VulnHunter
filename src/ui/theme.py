"""
Theme configuration for the application.
Defines colors and theme application functions.
"""

import customtkinter as ctk

COLORS = {
    "background": "#1a1a1a",        # Dark background
    "secondary_bg": "#2d2d2d",      # Slightly lighter background for contrast
    "accent": "#00b894",            # Green accent color (mint)
    "text": "#ffffff",              # White text
    "text_secondary": "#b3b3b3",    # Gray text for less important elements
    "button": "#00b894",            # Green button background
    "button_hover": "#00d6a4",      # Lighter green for hover
    "success": "#00b894",           # Green for success messages
    "warning": "#ffc107",           # Yellow for warnings
    "error": "#dc3545",             # Red for errors
    "info": "#00d6a4",             # Light green for information
}

def apply_theme():
    """
    Applies the custom dark theme to the entire CustomTkinter application.
    This function sets global appearance and color settings.
    """
    # Set the default color theme to dark
    ctk.set_appearance_mode("dark")
    
    # Set the default color theme
    ctk.set_default_color_theme("green")
    
    return COLORS