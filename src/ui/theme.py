"""
Global theme configuration for the application
"""

COLORS = {
    "background": "#1a1a1a",      # Main dark background
    "secondary_bg": "#2d2d2d",    # Secondary background
    "accent": "#00ff00",          # Bright green for accents
    "button": "#1e5128",          # Dark green for buttons
    "button_hover": "#2e7c3c",    # Lighter green for hover
    "text": "#ffffff",            # White text
    "text_secondary": "#b3b3b3"   # Gray secondary text
}

def apply_theme():
    """Applies the custom theme to CustomTkinter."""
    import customtkinter as ctk

    # Ensure we use dark mode (optional but recommended)
    ctk.set_appearance_mode("dark")
    # Set the base color theme
    ctk.set_default_color_theme("dark-blue")

    # Adjust scaling (optional)
    ctk.set_widget_scaling(1.0)

    # Override base theme colors with your own values
    theme_overrides = {
        "CTk": {
            "fg_color": COLORS["background"]
        },
        "CTkFrame": {
            "fg_color": COLORS["secondary_bg"],
            "top_fg_color": COLORS["secondary_bg"]
        },
        "CTkButton": {
            "fg_color": COLORS["button"],
            "hover_color": COLORS["button_hover"],
            "text_color": COLORS["text"],
            "border_color": COLORS["button"]
        },
        "CTkLabel": {
            "text_color": COLORS["text"]
        },
        "CTkEntry": {
            "fg_color": COLORS["background"],
            "border_color": COLORS["button"],
            "text_color": COLORS["text"]
        },
        "CTkCheckBox": {
            "fg_color": COLORS["button"],
            "hover_color": COLORS["button_hover"],
            "text_color": COLORS["text"],
            "checkmark_color": COLORS["text"]
        },
        "CTkTextbox": {
            "fg_color": COLORS["background"],
            "text_color": COLORS["text"]
        },
        "CTkTabview": {
            "fg_color": COLORS["secondary_bg"],
            "segmented_button_fg_color": COLORS["button"],
            "segmented_button_selected_color": COLORS["button_hover"],
            "segmented_button_selected_hover_color": COLORS["button_hover"],
            "text_color": COLORS["text"]
        },
        "CTkProgressBar": {
            "fg_color": COLORS["background"],
            "progress_color": COLORS["button"]
        }
    }

    # Apply overrides to the current theme
    for widget, color_dict in theme_overrides.items():
        # Check if the widget section exists in the theme
        if widget not in ctk.ThemeManager.theme:
            continue
        for color_key, color_value in color_dict.items():
            # If the color key exists in the widget section, override it
            if color_key in ctk.ThemeManager.theme[widget]:
                ctk.ThemeManager.theme[widget][color_key] = color_value
