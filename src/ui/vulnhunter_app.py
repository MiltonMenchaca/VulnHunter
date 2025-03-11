import os
import logging
import customtkinter as ctk
import tkinter as tk
from PIL import Image
from pathlib import Path
import sys

# Ensure the project's root directory is in PYTHONPATH
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Import theme colors
from src.ui.theme import COLORS

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
        # Configurar el tamaño mínimo de la ventana
        self.minsize(800, 600)
        
        # Tamaño preferido
        window_width = 1200
        window_height = 800
        
        # Centrar en la pantalla
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        pos_top = int((screen_height / 2) - (window_height / 2))
        pos_right = int((screen_width / 2) - (window_width / 2))
        
        # Apply geometry
        self.geometry(f"{window_width}x{window_height}+{pos_right}+{pos_top}")
        
        # Configurar el título con un icono si está disponible
        self.title("VulnHunter - Advanced Web Vulnerability Scanner")
        
        try:
            icon_path = Path(__file__).parent / "assets" / "icon.ico"
            if icon_path.exists():
                self.iconbitmap(icon_path)
        except Exception as e:
            logging.warning(f"Could not load icon: {e}")
        
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
        
        # Create menu
        self._create_menu()

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
        
        # Crear un botón para la pantalla de inicio
        home_button = ctk.CTkButton(
            sidebar,
            text="Home",
            width=180,
            height=40,
            command=lambda: self.show_subframe("Home"),
            fg_color=self.colors["accent"],
            hover_color=self.colors["button_hover"],
            text_color=self.colors["background"]
        )
        home_button.pack(pady=(0, 15))
        
        # Create phase labels and tool buttons
        for phase_title, tools in self.phases:
            phase_frame = ctk.CTkFrame(
                sidebar,
                fg_color="transparent"
            )
            phase_frame.pack(fill="x", pady=(10, 5))
            
            phase_label = ctk.CTkLabel(
                phase_frame,
                text=phase_title,
                font=ctk.CTkFont(weight="bold", size=16),
                text_color=self.colors["accent"]
            )
            phase_label.pack(pady=(5, 10), anchor="w")
            
            for tool_text, tool_name in tools:
                tool_button = ctk.CTkButton(
                    sidebar,
                    text=tool_text,
                    width=180,
                    height=40,
                    command=lambda name=tool_name: self.show_subframe(name),
                    fg_color=self.colors["button"],
                    hover_color=self.colors["button_hover"],
                    text_color=self.colors["text"]
                )
                tool_button.pack(pady=5)
        
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
                # Si no existe el logo, crear un texto como alternativa
                logging.warning(f"Logo not found at {logo_path}")
                logo_text = ctk.CTkLabel(
                    self.sidebar,
                    text="VulnHunter",
                    font=ctk.CTkFont(size=24, weight="bold"),
                    text_color=self.colors["accent"]
                )
                logo_text.pack(pady=20)
                
                # Crear un marco con el color de acento como alternativa visual
                logo_frame = ctk.CTkFrame(
                    self.sidebar,
                    width=150,
                    height=150,
                    fg_color=self.colors["accent"]
                )
                logo_frame.pack(pady=10)
                
                # Añadir texto dentro del marco
                logo_inner_text = ctk.CTkLabel(
                    logo_frame,
                    text="VH",
                    font=ctk.CTkFont(size=60, weight="bold"),
                    text_color=self.colors["background"]
                )
                logo_inner_text.place(relx=0.5, rely=0.5, anchor="center")
        except Exception as e:
            logging.warning(f"Could not load the logo: {e}")
            # Crear un texto como alternativa
            logo_text = ctk.CTkLabel(
                self.sidebar,
                text="VulnHunter",
                font=ctk.CTkFont(size=24, weight="bold"),
                text_color=self.colors["accent"]
            )
            logo_text.pack(pady=20)

    def _create_menu(self):
        """Creates a menu bar with options."""
        menu_bar = tk.Menu(self)
        
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Home", command=lambda: self.show_subframe("Home"))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_closing)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        
        # Añadir herramientas por fase
        for phase_title, tools in self.phases:
            phase_menu = tk.Menu(tools_menu, tearoff=0)
            for tool_text, tool_name in tools:
                phase_menu.add_command(
                    label=tool_text,
                    command=lambda name=tool_name: self.show_subframe(name)
                )
            tools_menu.add_cascade(label=phase_title.split(":")[1].strip(), menu=phase_menu)
        
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self._show_documentation)
        help_menu.add_command(label="About", command=self._show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        # Configurar el menú
        self.configure(menu=menu_bar)
    
    def _show_documentation(self):
        """Muestra la documentación de la aplicación."""
        # Crear una ventana emergente para la documentación
        doc_window = ctk.CTkToplevel(self)
        doc_window.title("VulnHunter Documentation")
        doc_window.geometry("600x400")
        doc_window.grab_set()  # Hacer modal
        
        # Contenido de la documentación
        doc_frame = ctk.CTkScrollableFrame(doc_window)
        doc_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        title = ctk.CTkLabel(
            doc_frame,
            text="VulnHunter Documentation",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=10)
        
        doc_text = """
        VulnHunter is a comprehensive tool for penetration testing and security analysis.
        
        This application provides various tools for different phases of penetration testing:
        
        1. RECONNAISSANCE: Gather information about the target.
        2. ENUMERATION: Identify and list system information.
        3. VULNERABILITY SEARCH & ANALYSIS: Find potential vulnerabilities.
        4. EXPLOITATION: Exploit discovered vulnerabilities.
        5. POST-EXPLOITATION: Actions after successful exploitation.
        6. REPORTING: Generate reports of findings.
        
        Each tool has specific functionality and options. Select a tool from the sidebar to get started.
        """
        
        doc_label = ctk.CTkLabel(
            doc_frame,
            text=doc_text,
            font=ctk.CTkFont(size=14),
            wraplength=550,
            justify="left"
        )
        doc_label.pack(pady=10)
        
        # Botón para cerrar
        close_button = ctk.CTkButton(
            doc_window,
            text="Close",
            command=doc_window.destroy,
            width=100
        )
        close_button.pack(pady=10)
    
    def _show_about(self):
        """Muestra información sobre la aplicación."""
        # Crear una ventana emergente para la información
        about_window = ctk.CTkToplevel(self)
        about_window.title("About VulnHunter")
        about_window.geometry("400x300")
        about_window.grab_set()  # Hacer modal
        
        # Contenido de la información
        about_frame = ctk.CTkFrame(about_window)
        about_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        title = ctk.CTkLabel(
            about_frame,
            text="VulnHunter",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.pack(pady=10)
        
        version = ctk.CTkLabel(
            about_frame,
            text="Version 1.0",
            font=ctk.CTkFont(size=16)
        )
        version.pack(pady=5)
        
        about_text = """
        An advanced web vulnerability scanner and penetration testing tool.
        
        Developed for educational and security testing purposes.
        
        © 2023 VulnHunter Team
        """
        
        about_label = ctk.CTkLabel(
            about_frame,
            text=about_text,
            font=ctk.CTkFont(size=14),
            wraplength=350
        )
        about_label.pack(pady=10)
        
        # Botón para cerrar
        close_button = ctk.CTkButton(
            about_window,
            text="Close",
            command=about_window.destroy,
            width=100
        )
        close_button.pack(pady=10)
    
    def _on_closing(self):
        """Maneja el cierre de la aplicación."""
        # Aquí podrías añadir confirmación o guardar configuración
        self.quit()
        self.destroy()

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
                # Si no existe logo_home.png, intentar usar logo.png
                logo_path = Path(__file__).parent / "assets" / "logo.png"
                if logo_path.exists():
                    logo_img = Image.open(logo_path)
                    ctk_img = ctk.CTkImage(logo_img, size=(200, 200))
                    extra_label = ctk.CTkLabel(frame, image=ctk_img, text="")
                    extra_label.pack(pady=20)
                else:
                    logging.warning(f"No logo found for home screen")
        except Exception as e:
            logging.warning(f"Could not load the home logo: {e}")
        
        # Añadir botones de acceso rápido
        quick_access_frame = ctk.CTkFrame(frame)
        quick_access_frame.pack(pady=20, fill=tk.X)
        
        quick_access_label = ctk.CTkLabel(
            quick_access_frame,
            text="Quick Access",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        quick_access_label.pack(pady=10)
        
        # Crear una cuadrícula de botones
        button_frame = ctk.CTkFrame(quick_access_frame)
        button_frame.pack(pady=10)
        
        quick_tools = [
            ("LFI/RFI Scanner", "LFIRFI"),
            ("SQL Injection", "SQLi"),
            ("XSS Scanner", "XSS"),
            ("Metasploit", "Metasploit")
        ]
        
        for i, (text, tool) in enumerate(quick_tools):
            row = i // 2
            col = i % 2
            
            button = ctk.CTkButton(
                button_frame,
                text=text,
                command=lambda t=tool: self.show_subframe(t),
                width=180,
                height=40,
                fg_color=self.colors["button"],
                hover_color=self.colors["button_hover"]
            )
            button.grid(row=row, column=col, padx=10, pady=10)
        
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
        
        # Añadir una imagen de "en construcción"
        try:
            construction_path = Path(__file__).parent / "assets" / "under_construction.png"
            if construction_path.exists():
                construction_img = Image.open(construction_path)
                ctk_img = ctk.CTkImage(construction_img, size=(200, 200))
                img_label = ctk.CTkLabel(frame, image=ctk_img, text="")
                img_label.pack(pady=20)
        except Exception as e:
            logging.warning(f"Could not load the construction image: {e}")
        
        # Botón para volver a la pantalla de inicio
        back_button = ctk.CTkButton(
            frame,
            text="Back to Home",
            command=lambda: self.show_subframe("Home"),
            fg_color=self.colors["button"],
            hover_color=self.colors["button_hover"]
        )
        back_button.pack(pady=20)
        
        return frame

if __name__ == "__main__":
    # Start the application if this file is run directly
    app = VulnHunterApp()
    app.mainloop()
