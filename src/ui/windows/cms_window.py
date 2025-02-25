import customtkinter as ctk 
from src.core.cms.cms_manager import CMSManager
from src.ui.theme import COLORS
import json
from typing import Optional, Dict
import threading
import time

def create_cms_frame(parent):
    """Creates and returns a frame for CMS enumeration"""
    return CMSFrame(parent)

class CMSFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.cms_manager = CMSManager()
        self.current_scan = None
        self.setup_ui()
        
    def _create_labeled_entry(self, parent, label_text: str, row: int, column: int,
                             columnspan: int = 2) -> ctk.CTkEntry:
        """Helper to create labeled entry widgets"""
        label = ctk.CTkLabel(parent, text=label_text)
        label.grid(row=row, column=column, padx=5, pady=5)
        
        entry = ctk.CTkEntry(parent, width=300)
        entry.grid(row=row, column=column + 1, columnspan=columnspan, padx=5, pady=5)
        
        return entry

    def setup_ui(self):
        # Main frame divided into two columns
        self.left_frame = ctk.CTkFrame(self)
        self.left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        self.right_frame = ctk.CTkFrame(self)
        self.right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Left panel - Controls
        self._setup_control_panel()
        
        # Right panel - Results
        self._setup_results_panel()
        
    def _setup_control_panel(self):
        """Configures the left control panel"""
        # URL Input
        self.url_entry = self._create_labeled_entry(
            self.left_frame, "Target URL:", 0, 0
        )
        
        # Scan options
        options_frame = ctk.CTkFrame(self.left_frame)
        options_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        
        self.aggressive_var = ctk.BooleanVar(value=False)
        self.aggressive_check = ctk.CTkCheckBox(
            options_frame,
            text="Aggressive Mode",
            variable=self.aggressive_var
        )
        self.aggressive_check.grid(row=0, column=0, padx=5, pady=5)
        
        self.follow_redirects_var = ctk.BooleanVar(value=True)
        self.follow_redirects_check = ctk.CTkCheckBox(
            options_frame,
            text="Follow Redirects",
            variable=self.follow_redirects_var
        )
        self.follow_redirects_check.grid(row=0, column=1, padx=5, pady=5)
        
        # Action buttons in a separate frame
        actions_frame = ctk.CTkFrame(self.left_frame)
        actions_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        
        # First row of buttons
        self.detect_button = ctk.CTkButton(
            actions_frame,
            text="Detect CMS",
            command=self._start_detection
        )
        self.detect_button.grid(row=0, column=0, padx=5, pady=5)
        
        self.scan_all_button = ctk.CTkButton(
            actions_frame,
            text="Full Scan",
            command=self._start_full_scan
        )
        self.scan_all_button.grid(row=0, column=1, padx=5, pady=5)
        
        # Second row of buttons
        cms_buttons_frame = ctk.CTkFrame(actions_frame)
        cms_buttons_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        self.scan_wp_button = ctk.CTkButton(
            cms_buttons_frame,
            text="WordPress",
            command=lambda: self._start_cms_scan('wordpress')
        )
        self.scan_wp_button.grid(row=0, column=0, padx=5, pady=5)
        
        self.scan_joomla_button = ctk.CTkButton(
            cms_buttons_frame,
            text="Joomla",
            command=lambda: self._start_cms_scan('joomla')
        )
        self.scan_joomla_button.grid(row=0, column=1, padx=5, pady=5)
        
        self.scan_drupal_button = ctk.CTkButton(
            cms_buttons_frame,
            text="Drupal",
            command=lambda: self._start_cms_scan('drupal')
        )
        self.scan_drupal_button.grid(row=0, column=2, padx=5, pady=5)
        
        # Progress bar
        self.progress_var = ctk.DoubleVar()
        self.progress_bar = ctk.CTkProgressBar(self.left_frame)
        self.progress_bar.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        self.progress_bar.set(0)
        
        # Current status
        self.status_label = ctk.CTkLabel(self.left_frame, text="Ready")
        self.status_label.grid(row=4, column=0, columnspan=3, padx=5, pady=5)
        
    def _setup_results_panel(self):
        """Configures the right results panel"""
        # Tabs for different types of results
        self.tabview = ctk.CTkTabview(self.right_frame)
        self.tabview.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        # Configure tabs
        self.tabview.add("Detection")
        self.tabview.add("Vulnerabilities")
        self.tabview.add("Files")
        self.tabview.add("Configuration")
        
        # Text areas for each tab
        self.detection_text = ctk.CTkTextbox(self.tabview.tab("Detection"))
        self.detection_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.vulns_text = ctk.CTkTextbox(self.tabview.tab("Vulnerabilities"))
        self.vulns_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.files_text = ctk.CTkTextbox(self.tabview.tab("Files"))
        self.files_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.config_text = ctk.CTkTextbox(self.tabview.tab("Configuration"))
        self.config_text.pack(fill="both", expand=True, padx=5, pady=5)

    def _start_detection(self):
        """Starts the CMS detection process"""
        url = self.url_entry.get()
        if not url:
            self._show_error("Please enter a URL")
            return
            
        self._update_status("Detecting CMS...")
        self.progress_bar.set(0)
        
        def detection_thread():
            try:
                results = self.cms_manager.detect_cms(url)
                self._update_results(results)
                self._update_status("Detection completed")
                self.progress_bar.set(1)
            except Exception as e:
                self._show_error(f"Detection error: {str(e)}")
                
        threading.Thread(target=detection_thread).start()

    def _start_full_scan(self):
        """Starts a full scan of the target"""
        url = self.url_entry.get()
        if not url:
            self._show_error("Please enter a URL")
            return
            
        self._update_status("Starting full scan...")
        self.progress_bar.set(0)
        
        def full_scan_thread():
            try:
                # Initial detection
                self._update_status("Phase 1/4: CMS Detection")
                detection_results = self.cms_manager.detect_cms(url)
                self.progress_bar.set(0.25)
                
                # Determine CMS and scan
                cms_type = self._determine_cms_type(detection_results)
                self._update_status(f"Phase 2/4: Scanning {cms_type}")
                scan_results = self._scan_specific_cms(cms_type, url)
                self.progress_bar.set(0.5)
                
                # Search for vulnerabilities
                self._update_status("Phase 3/4: Searching for vulnerabilities")
                vuln_results = self.cms_manager.get_vulnerabilities(cms_type, scan_results.get('version', 'latest'))
                self.progress_bar.set(0.75)
                
                # File analysis
                self._update_status("Phase 4/4: Analyzing files")
                file_results = self._analyze_files(url, cms_type)
                self.progress_bar.set(1)
                
                # Display results
                self._show_full_scan_results({
                    'detection': detection_results,
                    'scan': scan_results,
                    'vulnerabilities': vuln_results,
                    'files': file_results
                })
                
                self._update_status("Full scan completed")
                
            except Exception as e:
                self._show_error(f"Scan error: {str(e)}")
                
        threading.Thread(target=full_scan_thread).start()

    def _start_cms_scan(self, cms_type: str):
        """Starts a scan specific to a CMS type"""
        url = self.url_entry.get()
        if not url:
            self._show_error("Please enter a URL")
            return
            
        self._update_status(f"Scanning {cms_type}...")
        self.progress_bar.set(0)
        
        def scan_thread():
            try:
                if cms_type == 'wordpress':
                    results = self.cms_manager.scan_wordpress(
                        url, 
                        aggressive=self.aggressive_var.get()
                    )
                elif cms_type == 'joomla':
                    results = self.cms_manager.scan_joomla(url)
                elif cms_type == 'drupal':
                    results = self.cms_manager.scan_drupal(url)
                else:
                    raise ValueError(f"Unsupported CMS type: {cms_type}")
                    
                self._update_results(results)
                self._update_status(f"{cms_type.capitalize()} scan completed")
                self.progress_bar.set(1)
                
            except Exception as e:
                self._show_error(f"Scan error: {str(e)}")
                
        threading.Thread(target=scan_thread).start()

    def _determine_cms_type(self, detection_results: Dict) -> str:
        """Determines the CMS type based on detection results"""
        # Implement detection logic based on the results
        return detection_results.get('cms_type', 'wordpress')

    def _scan_specific_cms(self, cms_type: str, url: str) -> Dict:
        """Performs a scan specific to the CMS type"""
        if cms_type == 'wordpress':
            return self.cms_manager.scan_wordpress(url, self.aggressive_var.get())
        elif cms_type == 'joomla':
            return self.cms_manager.scan_joomla(url)
        elif cms_type == 'drupal':
            return self.cms_manager.scan_drupal(url)
        return {}

    def _analyze_files(self, url: str, cms_type: str) -> Dict:
        """Analyzes files and directories of the CMS"""
        # Implement CMS-specific file analysis
        return {}

    def _update_status(self, message: str):
        """Updates the status message"""
        self.status_label.configure(text=message)
        self.update_idletasks()

    def _show_error(self, message: str):
        """Displays an error message"""
        self.status_label.configure(text=f"Error: {message}")
        self.progress_bar.set(0)
        self._update_results({'error': message})

    def _update_results(self, results: Dict):
        """Updates the results in the corresponding tabs"""
        # Detection
        if 'detection' in results:
            self.detection_text.delete("1.0", ctk.END)
            self.detection_text.insert("1.0", json.dumps(results['detection'], indent=2))
            
        # Vulnerabilities
        if 'vulnerabilities' in results:
            self.vulns_text.delete("1.0", ctk.END)
            self.vulns_text.insert("1.0", json.dumps(results['vulnerabilities'], indent=2))
            
        # Files
        if 'files' in results:
            self.files_text.delete("1.0", ctk.END)
            self.files_text.insert("1.0", json.dumps(results['files'], indent=2))
            
        # Configuration
        if 'configuration' in results:
            self.config_text.delete("1.0", ctk.END)
            self.config_text.insert("1.0", json.dumps(results['configuration'], indent=2))

    def _show_full_scan_results(self, results: Dict):
        """Displays the full scan results"""
        self._update_results({
            'detection': results.get('detection', {}),
            'vulnerabilities': results.get('vulnerabilities', []),
            'files': results.get('files', {}),
            'configuration': results.get('scan', {})
        })
