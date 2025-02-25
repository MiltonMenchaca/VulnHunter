import customtkinter as ctk
import tkinter.messagebox as messagebox
from threading import Thread
import time

# Import the core logic from sniffer_logic
from src.core.network.sniffer import HTTPSniffer

class SnifferWindow(ctk.CTkFrame):
    """
    Frame for a Sniffer that includes:
      - Input for the network interface.
      - Advanced parameters (max_captures, vendor detection).
      - Buttons to start/stop the sniffer.
      - A textbox to show results.
      - Buttons to save credentials and export traffic.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        
        # Control variables
        self.sniffer = None
        self.capturing = False
        
        self._create_ui()
        
    def _create_ui(self):
        """Creates the user interface."""
        # ------------------------------------------------------
        # Label and Entry for the network interface
        # ------------------------------------------------------
        ctk.CTkLabel(
            self, 
            text="Network interface (e.g., eth0, wlan0):"
        ).pack(padx=20, pady=(10, 5))

        self.interface_entry = ctk.CTkEntry(
            self,
            placeholder_text="e.g., eth0",
            width=400
        )
        self.interface_entry.pack(padx=20, pady=5)

        # ------------------------------------------------------
        # Advanced parameters
        # ------------------------------------------------------
        params_frame = ctk.CTkFrame(self)
        params_frame.pack(padx=20, pady=5)

        # 1) Max captures in memory
        ctk.CTkLabel(params_frame, text="Max Captures:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.max_captures_entry = ctk.CTkEntry(params_frame, width=80, placeholder_text="1000")
        self.max_captures_entry.grid(row=0, column=1, padx=5, pady=5)

        # 2) Vendor detection
        self.vendor_var = ctk.BooleanVar(value=False)
        vendor_check = ctk.CTkCheckBox(
            params_frame,
            text="Detect Vendor",
            variable=self.vendor_var
        )
        vendor_check.grid(row=0, column=2, padx=10, pady=5)

        # ------------------------------------------------------
        # Action buttons
        # ------------------------------------------------------
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(padx=20, pady=10)

        self.start_button = ctk.CTkButton(
            button_frame,
            text="Start Capture",
            command=self._start_capture
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            button_frame,
            text="Stop",
            command=self._stop_capture,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        # ------------------------------------------------------
        # Results area
        # ------------------------------------------------------
        self.results_text = ctk.CTkTextbox(self, height=300)
        self.results_text.pack(padx=20, pady=10, fill="both", expand=True)

        # ------------------------------------------------------
        # Export buttons
        # ------------------------------------------------------
        export_frame = ctk.CTkFrame(self)
        export_frame.pack(padx=20, pady=10)

        self.save_creds_button = ctk.CTkButton(
            export_frame,
            text="Save Credentials",
            command=self._save_credentials,
            state="disabled"
        )
        self.save_creds_button.pack(side="left", padx=5)

        self.export_pcap_button = ctk.CTkButton(
            export_frame,
            text="Export PCAP",
            command=self._export_pcap,
            state="disabled"
        )
        self.export_pcap_button.pack(side="left", padx=5)
        
    def _start_capture(self):
        """Starts packet capture."""
        interface = self.interface_entry.get().strip()
        if not interface:
            messagebox.showerror(
                "Error",
                "You must specify a network interface"
            )
            return
            
        try:
            max_captures = int(self.max_captures_entry.get().strip())
        except ValueError:
            max_captures = 1000  # Default value
            
        # Create sniffer
        self.sniffer = HTTPSniffer(
            interface=interface,
            max_captures=max_captures,
            resolve_vendor=self.vendor_var.get()
        )
        
        # Start capture in a separate thread
        self.capturing = True
        Thread(target=self._capture_packets, daemon=True).start()
        
        # Update UI
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("end", "Starting capture...\n")
        
    def _capture_packets(self):
        """Captures packets and updates the UI."""
        try:
            for packet in self.sniffer.capture():
                if not self.capturing:
                    break
                    
                # Show packet in UI
                self.results_text.insert("end", str(packet) + "\n")
                self.results_text.see("end")
                
                # Small pause so as not to flood the UI
                time.sleep(0.01)
                
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error during capture: {str(e)}"
            )
            
        finally:
            self._stop_capture()
            
    def _stop_capture(self):
        """Stops packet capture."""
        self.capturing = False
        if self.sniffer:
            self.sniffer.stop()
            
        # Update UI
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.save_creds_button.configure(state="normal")
        self.export_pcap_button.configure(state="normal")
        self.results_text.insert("end", "\nCapture stopped.\n")
        
    def _save_credentials(self):
        """Saves captured credentials."""
        if not self.sniffer or not self.sniffer.credentials:
            messagebox.showwarning(
                "Warning",
                "No credentials to save"
            )
            return
            
        try:
            self.sniffer.save_credentials()
            messagebox.showinfo(
                "Success",
                "Credentials saved to credentials.txt"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error saving credentials: {str(e)}"
            )
            
    def _export_pcap(self):
        """Exports the capture in PCAP format."""
        if not self.sniffer or not self.sniffer.packets:
            messagebox.showwarning(
                "Warning",
                "No packets to export"
            )
            return
            
        try:
            self.sniffer.save_pcap()
            messagebox.showinfo(
                "Success",
                "Capture saved to capture.pcap"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error exporting capture: {str(e)}"
            )
