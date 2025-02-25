import os
import logging
import customtkinter as ctk
from PIL import Image
from pathlib import Path
import sys

# Configure logging
logging.basicConfig(
    filename='logs/vulnhunter.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Ensure the project's root directory is in PYTHONPATH
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Import and apply global theme
from src.ui.theme import COLORS, apply_theme
apply_theme()

# Import tool windows
from src.ui.windows.metasploit import MetasploitWindow
from src.ui.windows.osint_window import OSINTWindow
from src.ui.windows.arp_window import ARPWindow
from src.ui.windows.sniffer_window import SnifferWindow
from src.ui.windows.macchanger_window import MacChangerWindow
from src.ui.windows.scanner_window import ScannerWindow
from src.ui.windows.sql_injection_window import SQLInjectionWindow
from src.ui.windows.sqlmap_window import SQLMapWindow
from src.ui.windows.xss_window import XSSWindow
from src.ui.windows.hydra_window import HydraWindow
from src.ui.windows.wfuzz_window import WFuzzWindow
from src.ui.windows.reports_window import ReportsWindow
from src.ui.windows.cms_window import create_cms_frame
from src.ui.windows.xxe_window import XXEWindow
from src.ui.windows.lfi_rfi_window import LFIRFIWindow

class VulnHunterApp(ctk.CTk):
    """Main application window for VulnHunter."""

    def __init__(self):
        super().__init__()
        
        # Configure dark background color from the theme
        self.configure(fg_color=COLORS["background"])
        
        # Keep a reference to theme colors
        self.colors = COLORS
        
        # Main window setup
        self.title("VulnHunter")
        self._setup_window()
        
        # Control variables
        self.current_frame = None
        self.tool_frames = {}
        self.subframes = {}
        
        # Build the UI
        self._create_ui()
        
        # Display the default screen ("Home")
        self.show_subframe("Home")

    def _setup_window(self):
        """Sets up window size and position."""
        window_width = 1200
        window_height = 800
        
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        pos_top = int((screen_height / 2) - (window_height / 2))
        pos_right = int((screen_width / 2) - (window_width / 2))
        
        # Apply geometry
        self.geometry(f"{window_width}x{window_height}+{pos_right}+{pos_top}")
        
        # Configure main grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)  # Sidebar
        self.grid_columnconfigure(1, weight=1)  # Content area

    def _create_ui(self):
        """Creates the main user interface."""
        # Sidebar
        self.sidebar = self._create_sidebar()
        
        # Content area (right panel)
        self.content_frame = ctk.CTkFrame(
            self,
            fg_color=self.colors["secondary_bg"]
        )
        self.content_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        # Load the logo (displayed on the sidebar)
        self._load_logo()
        
        # (Optional) Create a tools menu
        self._create_tools_menu()

    def _create_sidebar(self) -> ctk.CTkScrollableFrame:
        """Creates the scrollable sidebar with phases and tool buttons."""
        sidebar = ctk.CTkScrollableFrame(
            self,
            width=200,
            fg_color=self.colors["secondary_bg"]
        )
        sidebar.grid(row=0, column=0, padx=20, pady=20, sticky="ns")
        
        # Phases and tool buttons
        self.phases = [
            ("PHASE 1: RECONNAISSANCE", [("OSINT", "OSINT"), ("ARP Scan", "ARP")]),
            ("PHASE 2: ENUMERATION", [("Sniffer", "Sniffer"), ("MacChanger", "MacChanger"), ("CMS", "CMS")]),
            ("PHASE 3: VULNERABILITY SEARCH & ANALYSIS", [("Advanced Scanner", "Scanner")]),
            ("PHASE 4: EXPLOITATION", [
                ("SQL Injection", "SQLi"), ("SQLmap", "SQLmap"), ("XSS", "XSS"),
                ("XXE", "XXE"), ("LFI/RFI", "LFIRFI"), ("Metasploit", "Metasploit")
            ]),
            ("PHASE 5: POST-EXPLOITATION", [("Hydra", "Hydra"), ("Wfuzz", "Wfuzz")]),
            ("PHASE 6: REPORTING", [("Generate Report", "Reportes")]),
        ]
        
        # Create phase labels and tool buttons
        for phase_title, tools in self.phases:
            ctk.CTkLabel(
                sidebar,
                text=phase_title,
                font=ctk.CTkFont(weight="bold", size=16),
                text_color=self.colors["accent"]
            ).pack(pady=(20, 10))
            
            for tool_text, tool_name in tools:
                ctk.CTkButton(
                    sidebar,
                    text=tool_text,
                    width=180,
                    height=40,
                    command=lambda name=tool_name: self.show_subframe(name),
                    fg_color=self.colors["button"],
                    hover_color=self.colors["button_hover"],
                    text_color=self.colors["text"]
                ).pack(pady=5)
        
        return sidebar

    def _load_logo(self):
        """Loads and displays the application logo from 'src/ui/assets/logo.png'."""
        try:
            # Build the path: 'src/ui/assets/logo.png'
            logo_path = Path(__file__).parent / "assets" / "logo.png"
            
            if logo_path.exists():
                logo_image = Image.open(logo_path)
                logo_photo = ctk.CTkImage(logo_image, size=(180, 180))
                logo_label = ctk.CTkLabel(self.sidebar, image=logo_photo, text="")
                logo_label.pack(pady=20)
            else:
                logging.warning(f"Logo not found at {logo_path}")
        except Exception as e:
            logging.warning(f"Could not load the logo: {e}")

    def _create_tools_menu(self):
        """Creates a tools menu (optional)."""
        pass  # Not needed because the buttons are created in _create_sidebar

    def show_subframe(self, name: str):
        """
        Hides the current frame and displays the selected sub-window.
        :param name: The name of the tool or sub-window to show.
        """
        if self.current_frame:
            self.current_frame.pack_forget()
        
        # Create a new frame based on the selected tool
        if name == "Metasploit":
            self.current_frame = MetasploitWindow(self.content_frame)
        elif name == "Home":
            self.current_frame = self.create_home_frame(self.content_frame)
        elif name == "OSINT":
            self.current_frame = OSINTWindow(self.content_frame)
        elif name == "ARP":
            self.current_frame = ARPWindow(self.content_frame)
        elif name == "Sniffer":
            self.current_frame = SnifferWindow(self.content_frame)
        elif name == "MacChanger":
            self.current_frame = MacChangerWindow(self.content_frame)
        elif name == "Scanner":
            self.current_frame = ScannerWindow(self.content_frame)
        elif name == "SQLi":
            self.current_frame = SQLInjectionWindow(self.content_frame)
        elif name == "CMS":
            self.current_frame = create_cms_frame(self.content_frame)
        elif name == "SQLmap":
            self.current_frame = SQLMapWindow(self.content_frame)
        elif name == "XSS":
            self.current_frame = XSSWindow(self.content_frame)
        elif name == "XXE":
            self.current_frame = XXEWindow(self.content_frame)
        elif name == "LFIRFI":
            self.current_frame = LFIRFIWindow(self.content_frame)
        elif name == "Hydra":
            self.current_frame = HydraWindow(self.content_frame)
        elif name == "Wfuzz":
            self.current_frame = WFuzzWindow(self.content_frame)
        elif name == "Reportes":
            self.current_frame = ReportsWindow(self.content_frame)
        else:
            # Generic frame for unimplemented tools
            self.current_frame = self.create_generic_frame(self.content_frame, name)
        
        # Show the new frame
        self.current_frame.pack(fill="both", expand=True)

    def create_home_frame(self, parent) -> ctk.CTkFrame:
        """
        Home screen displayed by default.
        :param parent: The parent container where this frame is placed.
        :return: A CTkFrame containing welcome text and optional logo.
        """
        frame = ctk.CTkFrame(parent)
        
        welcome_label = ctk.CTkLabel(
            frame,
            text="Welcome to VulnHunter",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        welcome_label.pack(pady=20)
        
        description = """
        VulnHunter is a comprehensive tool for penetration testing and security analysis.
        
        Select a tool from the side menu to get started.
        """
        
        desc_label = ctk.CTkLabel(
            frame,
            text=description,
            font=ctk.CTkFont(size=16),
            wraplength=600
        )
        desc_label.pack(pady=20)
        
        # Optional: Additional logo below the text
        try:
            # If you want a second file, e.g. 'logo_home.png'
            # Or you can reuse 'logo.png' if you prefer
            extra_logo_path = Path(__file__).parent / "assets" / "logo_home.png"
            if extra_logo_path.exists():
                extra_img = Image.open(extra_logo_path)
                ctk_img = ctk.CTkImage(extra_img, size=(200, 200))
                extra_label = ctk.CTkLabel(frame, image=ctk_img, text="")
                extra_label.pack(pady=20)
            else:
                logging.warning(f"Home logo not found at {extra_logo_path}")
        except Exception as e:
            logging.warning(f"Could not load the home logo: {e}")
        
        return frame

    def create_generic_frame(self, parent, name: str) -> ctk.CTkFrame:
        """
        Creates a generic frame for tools not yet implemented.
        :param parent: The parent container.
        :param name: The name of the unimplemented tool.
        :return: A CTkFrame with a placeholder message.
        """
        frame = ctk.CTkFrame(parent)
        
        label = ctk.CTkLabel(
            frame,
            text=f"Tool: {name}",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        label.pack(pady=20)
        
        message = ctk.CTkLabel(
            frame,
            text="This tool is under development...",
            font=ctk.CTkFont(size=16)
        )
        message.pack(pady=20)
        
        return frame

if __name__ == "__main__":
    # Start the application if this file is run directly
    app = VulnHunterApp()
    app.mainloop()
