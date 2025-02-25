"""
Main VulnHunter window
"""

import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from .windows import (
    MetasploitWindow, ARPWindow, SnifferWindow, MacChangerWindow,
    ScannerWindow, SQLInjectionWindow, SQLMapWindow, XSSWindow,
    HydraWindow, WFuzzWindow, ReportsWindow, OSINTWindow,
    ReverseShellWindow, CMSFrame, XXEWindow, LFIRFIWindow,
    SSRFWindow
)

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.current_window = None
        self._create_ui()
        
    def _create_ui(self):
        """Creates the main user interface."""
        # Main frame
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top frame for the menu
        self.menu_frame = ctk.CTkFrame(self.main_frame)
        self.menu_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Menu buttons
        buttons = [
            ("Metasploit", "metasploit"),
            ("ARP", "arp"),
            ("Sniffer", "sniffer"),
            ("MAC Changer", "macchanger"),
            ("Scanner", "scanner"),
            ("SQL Injection", "sqlinjection"),
            ("SQLMap", "sqlmap"),
            ("XSS", "xss"),
            ("LFI/RFI", "lfi_rfi"),
            ("XXE", "xxe"),
            ("SSRF", "ssrf"),
            ("Hydra", "hydra"),
            ("WFuzz", "wfuzz"),
            ("OSINT", "osint"),
            ("Reverse Shell", "revshell"),
            ("CMS", "cms"),
            ("Reports", "reports")
        ]
        
        # Create frame for horizontal scrollbar
        scroll_frame = ttk.Frame(self.menu_frame)
        scroll_frame.pack(fill=tk.X, expand=True)
        
        # Create canvas and scrollbar
        canvas = tk.Canvas(scroll_frame, height=40)
        scrollbar = ttk.Scrollbar(scroll_frame, orient="horizontal", command=canvas.xview)
        canvas.configure(xscrollcommand=scrollbar.set)
        
        # Internal frame for buttons
        buttons_frame = ttk.Frame(canvas)
        
        # Create buttons
        for text, cmd in buttons:
            btn = ctk.CTkButton(
                buttons_frame,
                text=text,
                command=lambda x=cmd: self._show_window(x)
            )
            btn.pack(side=tk.LEFT, padx=5)
            
        # Configure canvas
        canvas.create_window((0, 0), window=buttons_frame, anchor="nw")
        buttons_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"), width=self.root.winfo_width())
        
        # Pack widgets
        canvas.pack(side=tk.TOP, fill=tk.X)
        scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Frame for the content area
        self.content_frame = ctk.CTkFrame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Show the initial window
        self._show_window("lfi_rfi")
        
    def _show_window(self, window_type):
        """Shows the selected window."""
        # Clear the current window
        if self.current_window:
            self.current_window.destroy()
            
        # Create a new window
        window_map = {
            "metasploit": MetasploitWindow,
            "arp": ARPWindow,
            "sniffer": SnifferWindow,
            "macchanger": MacChangerWindow,
            "scanner": ScannerWindow,
            "sqlinjection": SQLInjectionWindow,
            "sqlmap": SQLMapWindow,
            "xss": XSSWindow,
            "lfi_rfi": LFIRFIWindow,
            "xxe": XXEWindow,
            "ssrf": SSRFWindow,
            "hydra": HydraWindow,
            "wfuzz": WFuzzWindow,
            "reports": ReportsWindow,
            "osint": OSINTWindow,
            "revshell": ReverseShellWindow,
            "cms": CMSFrame
        }
        
        window_class = window_map.get(window_type)
        if window_class:
            self.current_window = window_class(self.content_frame)
            
        self.current_window.pack(fill=tk.BOTH, expand=True)
