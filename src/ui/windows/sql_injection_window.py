import customtkinter as ctk
import tkinter.messagebox as messagebox
from threading import Thread

# Attempt to import pyperclip and handle the error if it's not installed
try:
    import pyperclip
except ImportError:
    pyperclip = None

# Import SQL Injection logic
from src.core.web.sql_injection import SQLInjection, get_sql_injection_commands
from src.core.utils.export import export_sql_to_csv, export_sql_to_json, export_sql_to_pdf

class SQLInjectionWindow(ctk.CTkFrame):
    """
    Frame for SQL Injection that includes:
      - Input for the target URL.
      - Button to start the attack.
      - TextBox to display results.
      - Buttons to export results.
      - TextBox with common SQL Injection payloads.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        
        # Control variables
        self.attacking = False
        self.sql_injection = None
        self.results = []
        
        self._create_ui()
        
    def _create_ui(self):
        """Creates the user interface."""
        # ----- Top Frame for URL and Attack Button -----
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(padx=10, pady=10, fill="x")

        # Label and Entry for URL
        ctk.CTkLabel(
            top_frame, 
            text="Target URL:"
        ).grid(row=0, column=0, padx=5, pady=5, sticky="e")

        self.url_entry = ctk.CTkEntry(
            top_frame, width=400,
            placeholder_text="Ex: http://example.com/login.php"
        )
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Attack Button
        self.attack_button = ctk.CTkButton(
            top_frame,
            text="Start Attack",
            command=self._start_attack
        )
        self.attack_button.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        # ----- Middle Frame for Results -----
        results_frame = ctk.CTkFrame(self)
        results_frame.pack(padx=10, pady=5, fill="both", expand=True)

        # Results TextBox
        self.results_text = ctk.CTkTextbox(
            results_frame,
            width=600,
            height=200
        )
        self.results_text.pack(padx=5, pady=5, fill="both", expand=True)

        # ----- Bottom Frame for Payloads -----
        payloads_frame = ctk.CTkFrame(self)
        payloads_frame.pack(padx=10, pady=10, fill="x")

        # Payloads Label
        ctk.CTkLabel(
            payloads_frame,
            text="Common Payloads:"
        ).pack(padx=5, pady=5)

        # Payloads TextBox
        self.payloads_text = ctk.CTkTextbox(
            payloads_frame,
            width=600,
            height=100
        )
        self.payloads_text.pack(padx=5, pady=5, fill="x")

        # Load common payloads
        payloads = get_sql_injection_commands()
        self.payloads_text.insert("1.0", "\n".join(payloads))
        self.payloads_text.configure(state="disabled")

        # ----- Frame for Export Buttons -----
        export_frame = ctk.CTkFrame(self)
        export_frame.pack(padx=10, pady=5, fill="x")

        # Export Buttons
        self.export_csv_button = ctk.CTkButton(
            export_frame,
            text="Export CSV",
            command=self._export_csv,
            state="disabled"
        )
        self.export_csv_button.pack(side="left", padx=5)

        self.export_json_button = ctk.CTkButton(
            export_frame,
            text="Export JSON",
            command=self._export_json,
            state="disabled"
        )
        self.export_json_button.pack(side="left", padx=5)

        self.export_pdf_button = ctk.CTkButton(
            export_frame,
            text="Export PDF",
            command=self._export_pdf,
            state="disabled"
        )
        self.export_pdf_button.pack(side="left", padx=5)

        # Button to Copy Results
        if pyperclip:
            self.copy_button = ctk.CTkButton(
                export_frame,
                text="Copy Results",
                command=self._copy_results,
                state="disabled"
            )
            self.copy_button.pack(side="left", padx=5)
            
    def _start_attack(self):
        """Starts the SQL Injection attack."""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror(
                "Error",
                "You must specify a target URL"
            )
            return
            
        # Clear previous results
        self.results_text.delete("1.0", "end")
        self.results = []
        
        # Update UI
        self.attacking = True
        self.attack_button.configure(state="disabled")
        self._update_export_buttons("disabled")
        
        # Start attack in a separate thread
        Thread(target=self._attack_thread, args=(url,), daemon=True).start()
        
    def _attack_thread(self, url):
        """Runs the attack in a separate thread."""
        try:
            # Create SQLInjection object
            self.sql_injection = SQLInjection(url)
            
            # Execute attack
            self.results_text.insert("end", "Starting attack...\n")
            for result in self.sql_injection.attack():
                if not self.attacking:
                    break
                    
                # Save and show result
                self.results.append(result)
                self._update_results(result)
                
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error during the attack: {str(e)}"
            )
            
        finally:
            self._stop_attack()
            
    def _stop_attack(self):
        """Stops the attack."""
        self.attacking = False
        self.attack_button.configure(state="normal")
        self._update_export_buttons("normal" if self.results else "disabled")
        self.results_text.insert("end", "\nAttack finished.\n")
        
    def _update_results(self, result):
        """Updates the results area with a new result."""
        self.results_text.insert("end", str(result) + "\n")
        self.results_text.see("end")
        
    def _update_export_buttons(self, state):
        """Updates the state of the export buttons."""
        self.export_csv_button.configure(state=state)
        self.export_json_button.configure(state=state)
        self.export_pdf_button.configure(state=state)
        if hasattr(self, 'copy_button'):
            self.copy_button.configure(state=state)
            
    def _export_csv(self):
        """Exports the results to CSV."""
        try:
            export_sql_to_csv(self.results)
            messagebox.showinfo(
                "Success",
                "Results exported to CSV"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error exporting to CSV: {str(e)}"
            )
            
    def _export_json(self):
        """Exports the results to JSON."""
        try:
            export_sql_to_json(self.results)
            messagebox.showinfo(
                "Success",
                "Results exported to JSON"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error exporting to JSON: {str(e)}"
            )
            
    def _export_pdf(self):
        """Exports the results to PDF."""
        try:
            export_sql_to_pdf(self.results)
            messagebox.showinfo(
                "Success",
                "Results exported to PDF"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error exporting to PDF: {str(e)}"
            )
            
    def _copy_results(self):
        """Copies the results to the clipboard."""
        if not pyperclip:
            messagebox.showerror(
                "Error",
                "pyperclip is not installed"
            )
            return
            
        try:
            results_text = self.results_text.get("1.0", "end-1c")
            pyperclip.copy(results_text)
            messagebox.showinfo(
                "Success",
                "Results copied to clipboard"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error copying results: {str(e)}"
            )
