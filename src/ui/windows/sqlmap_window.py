import customtkinter as ctk
from src.core.web.sqlmap_integration import run_sqlmap  # Ensure the file is in the correct directory and accessible
import tkinter.messagebox as messagebox
from threading import Thread

class SQLMapWindow(ctk.CTkFrame):
    """
    Frame for SQLmap, including:
      - Input for the target URL
      - Configuration of level and risk
      - Selection of techniques
      - Custom headers and cookies
      - Results area
      - Control buttons
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        
        # Control variables
        self.running = False
        self.sqlmap_process = None
        
        self._create_ui()
        
    def _create_ui(self):
        """Creates the user interface."""
        # Module title
        ctk.CTkLabel(
            self,
            text="SQLmap: SQL Injection Testing",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=10)

        # Target URL input
        ctk.CTkLabel(
            self, 
            text="Target URL:", 
            anchor="w"
        ).pack(pady=(10, 0), padx=20, fill="x")
        
        self.url_entry = ctk.CTkEntry(
            self, 
            placeholder_text="http://example.com/vulnerable"
        )
        self.url_entry.pack(pady=(0, 10), padx=20, fill="x")

        # Level
        ctk.CTkLabel(
            self, 
            text="Level (--level):", 
            anchor="w"
        ).pack(pady=(10, 0), padx=20, fill="x")
        
        self.level_slider = ctk.CTkSlider(
            self, 
            from_=1, 
            to=5, 
            number_of_steps=4
        )
        self.level_slider.set(1)
        self.level_slider.pack(pady=(0, 10), padx=20, fill="x")

        # Risk
        ctk.CTkLabel(
            self, 
            text="Risk (--risk):", 
            anchor="w"
        ).pack(pady=(10, 0), padx=20, fill="x")
        
        self.risk_slider = ctk.CTkSlider(
            self, 
            from_=1, 
            to=3, 
            number_of_steps=2
        )
        self.risk_slider.set(1)
        self.risk_slider.pack(pady=(0, 10), padx=20, fill="x")

        # Specific techniques
        ctk.CTkLabel(
            self, 
            text="Techniques (--technique):", 
            anchor="w"
        ).pack(pady=(10, 0), padx=20, fill="x")
        
        self.technique_entry = ctk.CTkEntry(
            self, 
            placeholder_text="Ex: BEUSTQ (optional)"
        )
        self.technique_entry.pack(pady=(0, 10), padx=20, fill="x")

        # Custom HTTP headers
        ctk.CTkLabel(
            self, 
            text="HTTP Headers (optional):", 
            anchor="w"
        ).pack(pady=(10, 0), padx=20, fill="x")
        
        self.headers_entry = ctk.CTkEntry(
            self, 
            placeholder_text="Ex: User-Agent: Mozilla/5.0"
        )
        self.headers_entry.pack(pady=(0, 10), padx=20, fill="x")

        # Cookies
        ctk.CTkLabel(
            self, 
            text="Cookies (optional):", 
            anchor="w"
        ).pack(pady=(10, 0), padx=20, fill="x")
        
        self.cookies_entry = ctk.CTkEntry(
            self, 
            placeholder_text="Ex: PHPSESSID=abc123"
        )
        self.cookies_entry.pack(pady=(0, 10), padx=20, fill="x")

        # Results area
        ctk.CTkLabel(
            self, 
            text="Results:", 
            anchor="w"
        ).pack(pady=(10, 0), padx=20, fill="x")
        
        self.results_text = ctk.CTkTextbox(
            self, 
            height=200
        )
        self.results_text.pack(pady=(0, 10), padx=20, fill="both", expand=True)

        # Button frame
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(pady=10, padx=20, fill="x")

        # Start button
        self.start_button = ctk.CTkButton(
            button_frame,
            text="Start SQLmap",
            command=self._start_sqlmap
        )
        self.start_button.pack(side="left", padx=5)

        # Stop button
        self.stop_button = ctk.CTkButton(
            button_frame,
            text="Stop",
            command=self._stop_sqlmap,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        # Clear results button
        self.clear_button = ctk.CTkButton(
            button_frame,
            text="Clear Results",
            command=self._clear_results
        )
        self.clear_button.pack(side="left", padx=5)
        
    def _start_sqlmap(self):
        """Starts SQLmap with the configured parameters."""
        # Validate URL
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror(
                "Error",
                "You must specify a target URL"
            )
            return
            
        # Gather parameters
        params = {
            "url": url,
            "level": int(self.level_slider.get()),
            "risk": int(self.risk_slider.get()),
            "technique": self.technique_entry.get().strip(),
            "headers": self.headers_entry.get().strip(),
            "cookies": self.cookies_entry.get().strip()
        }
        
        # Clear previous results
        self.results_text.delete("1.0", "end")
        
        # Update UI
        self.running = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        
        # Start SQLmap in a separate thread
        Thread(target=self._sqlmap_thread, args=(params,), daemon=True).start()
        
    def _sqlmap_thread(self, params):
        """Runs SQLmap in a separate thread."""
        try:
            # Start SQLmap
            self.results_text.insert("end", "Starting SQLmap...\n")
            for output in run_sqlmap(**params):
                if not self.running:
                    break
                    
                # Show output
                self.results_text.insert("end", output + "\n")
                self.results_text.see("end")
                
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error while running SQLmap: {str(e)}"
            )
            
        finally:
            self._stop_sqlmap()
            
    def _stop_sqlmap(self):
        """Stops SQLmap execution."""
        self.running = False
        if self.sqlmap_process:
            self.sqlmap_process.terminate()
            
        # Update UI
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.results_text.insert("end", "\nSQLmap stopped.\n")
        
    def _clear_results(self):
        """Clears the results area."""
        self.results_text.delete("1.0", "end")
