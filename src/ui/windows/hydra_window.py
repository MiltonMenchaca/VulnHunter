import customtkinter as ctk
import tkinter.messagebox as messagebox
from tkinter import filedialog
from threading import Thread
from src.core.exploit.hydra_integration import HydraIntegration
import logging
import os

class HydraWindow(ctk.CTkFrame):
    """
    Frame for Hydra integration which includes:
      - Input fields for target, service, username, and password file.
      - Optionally, port and additional options.
      - A button to start the attack.
      - A TextBox to display results.
      - A button to select the password file.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        
        # Logger configuration
        self.logger = logging.getLogger(__name__)
        
        # Control variables
        self.running = False
        self.hydra_process = None
        
        self._create_ui()
        
    def _create_ui(self):
        """Creates the user interface"""
        # ----- Inputs for Hydra Configuration -----
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(padx=10, pady=10, fill="x")

        # Target
        ctk.CTkLabel(
            top_frame, 
            text="Target (IP/Domain):"
        ).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        
        self.target_entry = ctk.CTkEntry(
            top_frame, 
            width=400, 
            placeholder_text="Ex: 192.168.1.100 or example.com"
        )
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Service
        ctk.CTkLabel(
            top_frame, 
            text="Service:"
        ).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        
        self.service_entry = ctk.CTkEntry(
            top_frame, 
            width=400, 
            placeholder_text="Ex: ssh, ftp, http"
        )
        self.service_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Username
        ctk.CTkLabel(
            top_frame, 
            text="Username:"
        ).grid(row=2, column=0, padx=5, pady=5, sticky="e")
        
        self.username_entry = ctk.CTkEntry(
            top_frame, 
            width=400, 
            placeholder_text="Ex: admin"
        )
        self.username_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        # Password File
        ctk.CTkLabel(
            top_frame, 
            text="Password File:"
        ).grid(row=3, column=0, padx=5, pady=5, sticky="e")
        
        self.password_file_entry = ctk.CTkEntry(
            top_frame, 
            width=300, 
            placeholder_text="Path to password file"
        )
        self.password_file_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        # Button to Browse for Password File
        browse_button = ctk.CTkButton(
            top_frame,
            text="Browse",
            command=self._browse_password_file,
            width=80
        )
        browse_button.grid(row=3, column=2, padx=5, pady=5)

        # Port (optional)
        ctk.CTkLabel(
            top_frame, 
            text="Port (optional):"
        ).grid(row=4, column=0, padx=5, pady=5, sticky="e")
        
        self.port_entry = ctk.CTkEntry(
            top_frame, 
            width=400, 
            placeholder_text="Ex: 22 (optional)"
        )
        self.port_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        # Additional options
        ctk.CTkLabel(
            top_frame, 
            text="Additional Options:"
        ).grid(row=5, column=0, padx=5, pady=5, sticky="e")
        
        self.options_entry = ctk.CTkEntry(
            top_frame, 
            width=400, 
            placeholder_text="Ex: -s 21 -t 4 (optional)"
        )
        self.options_entry.grid(row=5, column=1, padx=5, pady=5, sticky="w")

        # ----- TextBox for Results -----
        self.results_text = ctk.CTkTextbox(
            self, 
            height=200, 
            wrap="word"
        )
        self.results_text.pack(padx=10, pady=(0, 10), fill="both", expand=True)

        # ----- Frame for Buttons -----
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(pady=10)

        # Button to Start Attack
        self.start_button = ctk.CTkButton(
            button_frame,
            text="Start Attack",
            command=self._start_attack
        )
        self.start_button.pack(side="left", padx=5)

        # Button to Stop Attack
        self.stop_button = ctk.CTkButton(
            button_frame,
            text="Stop",
            command=self._stop_attack,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        # Button to Clear Results
        self.clear_button = ctk.CTkButton(
            button_frame,
            text="Clear Results",
            command=self._clear_results
        )
        self.clear_button.pack(side="left", padx=5)
        
    def _browse_password_file(self):
        """Opens a dialog to select the password file"""
        filename = filedialog.askopenfilename(
            title="Select password file",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.password_file_entry.delete(0, "end")
            self.password_file_entry.insert(0, filename)
            
    def _start_attack(self):
        """Starts the Hydra attack"""
        # Validate inputs
        target = self.target_entry.get().strip()
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password_file = self.password_file_entry.get().strip()
        port = self.port_entry.get().strip()
        options = self.options_entry.get().strip()
        
        # Validations
        if not target:
            messagebox.showerror(
                "Error",
                "You must specify a target"
            )
            return
            
        if not service:
            messagebox.showerror(
                "Error",
                "You must specify a service"
            )
            return
            
        if not username:
            messagebox.showerror(
                "Error",
                "You must specify a username"
            )
            return
            
        if not password_file:
            messagebox.showerror(
                "Error",
                "You must specify a password file"
            )
            return
            
        if not os.path.isfile(password_file):
            messagebox.showerror(
                "Error",
                "The password file does not exist"
            )
            return
            
        # Clear previous results
        self.results_text.delete("1.0", "end")
        
        # Update UI
        self.running = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        
        # Start the attack in a separate thread
        Thread(target=self._attack_thread, args=(
            target, service, username, password_file, port, options
        ), daemon=True).start()
        
    def _attack_thread(self, target, service, username, password_file, port, options):
        """Executes the attack in a separate thread"""
        try:
            # Create HydraIntegration object
            self.hydra_process = HydraIntegration()
            
            # Execute attack
            self.results_text.insert("end", "Starting Hydra attack...\n")
            for output in self.hydra_process.run_attack(
                target=target,
                service=service,
                username=username,
                password_file=password_file,
                port=port,
                options=options
            ):
                if not self.running:
                    break
                    
                # Display output
                self._update_results(output)
                
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error during attack: {str(e)}"
            )
            self.logger.error(f"Error in Hydra attack: {str(e)}")
            
        finally:
            self._stop_attack()
            
    def _stop_attack(self):
        """Stops the attack"""
        self.running = False
        if self.hydra_process:
            self.hydra_process.stop()
            
        # Update UI
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.results_text.insert("end", "\nAttack stopped.\n")
        
    def _update_results(self, output):
        """Updates the results area with new output"""
        self.results_text.insert("end", str(output) + "\n")
        self.results_text.see("end")
        
    def _clear_results(self):
        """Clears the results area"""
        self.results_text.delete("1.0", "end")
