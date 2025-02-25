# reverse_shell_window.py

import json
import os
import customtkinter as ctk
from tkinter import messagebox, filedialog, Toplevel
from src.core.exploit.reverse_shell_integration import ReverseShellGenerator
import logging
import threading
import time

class ReverseShellWindow(ctk.CTkFrame):
    """
    Window for a Reverse Shell Generator with enhanced usability and functionality:
    1. Shell type selection (Combobox).
    2. Visual IP/port validation.
    3. Automatic encoding options.
    4. Dynamic template management (add/save).
    5. Quick verification or testing.
    6. Copy/export command.
    7. Debug mode with detailed logs.
    8. Organized sections for a better user experience.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Initialize the reverse shell generator
        self.shell_generator = ReverseShellGenerator(debug=False, log_file="reverse_shell_window.log")
        
        # Control variables
        self.ip_var = ctk.StringVar(value="192.168.1.10")
        self.port_var = ctk.StringVar(value="4444")
        self.shell_type_var = ctk.StringVar(value="")
        self.encode_var = ctk.BooleanVar(value=False)
        self.debug_var = ctk.BooleanVar(value=False)
        
        # Configure logging
        self.logger = logging.getLogger("ReverseShellWindow")
        self.logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler("reverse_shell_window.log")
        file_formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                                           datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Load previous configurations
        self.loaded_config = {}
        config_file = "reverse_shell_config.json"
        if os.path.isfile(config_file):
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    self.loaded_config = json.load(f)
                self.logger.info("Previous configurations loaded successfully.")
            except Exception as e:
                self.logger.error(f"Error loading configurations: {e}")
                self.loaded_config = {}
        else:
            self.logger.info("No previous configuration file found. Using default values.")
        
        # Create the interface
        self._create_ui()
        
    def _create_ui(self):
        """Create the user interface."""
        # Title
        title_label = ctk.CTkLabel(self, text="Reverse Shell Generator", 
                                   font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        # Main frame with two columns
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Left column: configuration
        left_frame = ctk.CTkFrame(main_frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # Frame for IP and Port
        ip_port_frame = ctk.CTkFrame(left_frame)
        ip_port_frame.pack(fill="x", padx=5, pady=5)
        
        # IP
        ip_label = ctk.CTkLabel(ip_port_frame, text="IP:")
        ip_label.pack(side="left", padx=5)
        
        ip_entry = ctk.CTkEntry(ip_port_frame, textvariable=self.ip_var)
        ip_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # Port
        port_label = ctk.CTkLabel(ip_port_frame, text="Port:")
        port_label.pack(side="left", padx=5)
        
        port_entry = ctk.CTkEntry(ip_port_frame, textvariable=self.port_var)
        port_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # Shell type
        shell_frame = ctk.CTkFrame(left_frame)
        shell_frame.pack(fill="x", padx=5, pady=5)
        
        shell_label = ctk.CTkLabel(shell_frame, text="Shell Type:")
        shell_label.pack(side="left", padx=5)
        
        shell_types = self.shell_generator.list_shell_types()
        shell_combo = ctk.CTkComboBox(shell_frame, values=shell_types,
                                      variable=self.shell_type_var)
        shell_combo.pack(side="left", fill="x", expand=True, padx=5)
        
        # Options
        options_frame = ctk.CTkFrame(left_frame)
        options_frame.pack(fill="x", padx=5, pady=5)
        
        encode_check = ctk.CTkCheckBox(options_frame, text="Encode command",
                                       variable=self.encode_var)
        encode_check.pack(side="left", padx=5)
        
        debug_check = ctk.CTkCheckBox(options_frame, text="Debug mode",
                                      variable=self.debug_var, command=self._toggle_debug)
        debug_check.pack(side="left", padx=5)
        
        # Buttons
        buttons_frame = ctk.CTkFrame(left_frame)
        buttons_frame.pack(fill="x", padx=5, pady=5)
        
        generate_btn = ctk.CTkButton(buttons_frame, text="Generate",
                                     command=self._generate_shell)
        generate_btn.pack(side="left", padx=5)
        
        copy_btn = ctk.CTkButton(buttons_frame, text="Copy",
                                 command=self._copy_command)
        copy_btn.pack(side="left", padx=5)
        
        save_btn = ctk.CTkButton(buttons_frame, text="Save",
                                 command=self._save_command)
        save_btn.pack(side="left", padx=5)
        
        test_btn = ctk.CTkButton(buttons_frame, text="Test",
                                 command=self._test_shell)
        test_btn.pack(side="left", padx=5)
        
        # Right column: result and logs
        right_frame = ctk.CTkFrame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # Result
        result_label = ctk.CTkLabel(right_frame, text="Generated command:")
        result_label.pack(pady=5)
        
        self.result_text = ctk.CTkTextbox(right_frame, height=100)
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Logs
        logs_label = ctk.CTkLabel(right_frame, text="Logs:")
        logs_label.pack(pady=5)
        
        self.logs_text = ctk.CTkTextbox(right_frame, height=150)
        self.logs_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Load previous configurations
        self._load_config()
        
    def _load_config(self):
        """Load previous configurations."""
        if self.loaded_config:
            self.ip_var.set(self.loaded_config.get("ip", "192.168.1.10"))
            self.port_var.set(self.loaded_config.get("port", "4444"))
            self.shell_type_var.set(self.loaded_config.get("shell_type", ""))
            self.encode_var.set(self.loaded_config.get("encode", False))
            self.debug_var.set(self.loaded_config.get("debug_mode", False))
        
    def _toggle_debug(self):
        """Enable or disable debug mode."""
        if self.debug_var.get():
            self.logger.setLevel(logging.DEBUG)
            self.shell_generator.debug = True
        else:
            self.logger.setLevel(logging.INFO)
            self.shell_generator.debug = False
        
    def _generate_shell(self):
        """Generate the reverse shell command."""
        try:
            # Get values
            ip = self.ip_var.get().strip()
            port = self.port_var.get().strip()
            shell_type = self.shell_type_var.get()
            encode = self.encode_var.get()
            debug = self.debug_var.get()
            
            # Validate input
            if not ip or not port or not shell_type:
                messagebox.showerror("Error", "All fields are required")
                return
            
            # Generate command
            command = self.shell_generator.generate_shell(
                shell_type, ip, port, encode=encode, debug=debug
            )
            
            # Show result
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", command)
            
            # Log
            self._log(f"Command successfully generated for {shell_type}")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self._log(f"Error generating command: {str(e)}")
    
    def _copy_command(self):
        """Copy the command to clipboard."""
        command = self.result_text.get("1.0", "end").strip()
        if command:
            self.clipboard_clear()
            self.clipboard_append(command)
            messagebox.showinfo("Success", "Command copied to clipboard")
            self._log("Command copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No command to copy")
    
    def _save_command(self):
        """Save the command to a file."""
        command = self.result_text.get("1.0", "end").strip()
        if not command:
            messagebox.showwarning("Warning", "No command to save")
            return
            
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(command)
                messagebox.showinfo("Success", "Command saved successfully")
                self._log(f"Command saved to {file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error saving: {str(e)}")
            self._log(f"Error saving: {str(e)}")
    
    def _test_shell(self):
        """Test the reverse shell."""
        command = self.result_text.get("1.0", "end").strip()
        if not command:
            messagebox.showwarning("Warning", "No command to test")
            return
            
        try:
            # Start the listener in a separate thread
            thread = threading.Thread(
                target=self._start_listener,
                args=(self.ip_var.get(), self.port_var.get())
            )
            thread.daemon = True
            thread.start()
            
            # Show instructions
            messagebox.showinfo(
                "Test",
                "Listener started. Execute the command on the target machine."
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Error starting test: {str(e)}")
            self._log(f"Error starting test: {str(e)}")
    
    def _start_listener(self, ip, port):
        """Start a listener for testing."""
        try:
            self._log(f"Starting listener on {ip}:{port}")
            self.shell_generator.start_listener(ip, port)
        except Exception as e:
            self._log(f"Error in listener: {str(e)}")
    
    def _log(self, message):
        """Add a message to the log."""
        if self.debug_var.get():
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] {message}\n"
            self.logs_text.insert("end", log_message)
            self.logs_text.see("end")
            self.logger.debug(message)
    
    def _save_config(self):
        """Save the current configuration."""
        config = {
            "ip": self.ip_var.get(),
            "port": self.port_var.get(),
            "shell_type": self.shell_type_var.get(),
            "encode": self.encode_var.get(),
            "debug_mode": self.debug_var.get()
        }
        
        try:
            with open("reverse_shell_config.json", "w") as f:
                json.dump(config, f, indent=4)
            messagebox.showinfo("Success", "Configuration saved successfully")
            self.logger.info("Configuration saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving configuration: {str(e)}")
            self.logger.error(f"Error saving configuration: {str(e)}")
