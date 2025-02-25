import customtkinter as ctk
import tkinter.messagebox as messagebox
from threading import Thread
import time

# Import the ARP logic (advanced version)
from src.core.network.arp_scanner import (
    arp_scan,
    export_arp_to_csv,
    export_arp_to_json,
    export_arp_to_pdf,
    detect_local_network
)


class ARPWindow(ctk.CTkFrame):
    """
    Frame for ARP Scan which includes:
      - Options to input (or auto-detect) the network range.
      - Advanced parameters: timeout, retry, verbose, resolve_vendor.
      - A progress bar and status label.
      - Buttons to start and stop the scan.
      - A Textbox to display results (IP, MAC, Hostname, Vendor).
      - Export buttons (CSV, JSON, PDF) that are enabled upon completion.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        
        # Control variables
        self.cancel_scan = [False]
        self.scanned_hosts = []  # Will contain dicts with "IP", "MAC", "Hostname", "Vendor"
        
        self._create_ui()
        
    def _create_ui(self):
        """Creates the user interface"""
        # ----------------------------------------------------
        # Network parameters
        # ----------------------------------------------------
        ctk.CTkLabel(
            self, 
            text="Network Range (ex: 192.168.1.0/24) or leave blank to auto-detect:"
        ).pack(padx=20, pady=(10, 5))

        self.network_entry = ctk.CTkEntry(
            self, 
            placeholder_text="Ex: 192.168.1.0/24",
            width=300
        )
        self.network_entry.pack(padx=20, pady=5)

        # Checkbox to auto-detect the local subnet
        self.autodetect_var = ctk.BooleanVar(value=False)
        autodetect_check = ctk.CTkCheckBox(
            master=self,
            text="Auto-detect local network",
            variable=self.autodetect_var
        )
        autodetect_check.pack(pady=5)

        # ----------------------------------------------------
        # Advanced parameters
        # ----------------------------------------------------
        advanced_frame = ctk.CTkFrame(self)
        advanced_frame.pack(padx=20, pady=10, fill="x")

        # Timeout
        timeout_label = ctk.CTkLabel(advanced_frame, text="Timeout (s):")
        timeout_label.grid(row=0, column=0, padx=5, pady=5)
        
        self.timeout_entry = ctk.CTkEntry(advanced_frame, width=70)
        self.timeout_entry.insert(0, "2")
        self.timeout_entry.grid(row=0, column=1, padx=5, pady=5)

        # Retry
        retry_label = ctk.CTkLabel(advanced_frame, text="Retries:")
        retry_label.grid(row=0, column=2, padx=5, pady=5)
        
        self.retry_entry = ctk.CTkEntry(advanced_frame, width=70)
        self.retry_entry.insert(0, "3")
        self.retry_entry.grid(row=0, column=3, padx=5, pady=5)

        # Verbose and Resolve Vendor
        self.verbose_var = ctk.BooleanVar(value=True)
        verbose_check = ctk.CTkCheckBox(
            advanced_frame, 
            text="Verbose", 
            variable=self.verbose_var
        )
        verbose_check.grid(row=0, column=4, padx=5, pady=5)

        self.resolve_vendor_var = ctk.BooleanVar(value=True)
        resolve_vendor_check = ctk.CTkCheckBox(
            advanced_frame, 
            text="Resolve Vendor", 
            variable=self.resolve_vendor_var
        )
        resolve_vendor_check.grid(row=0, column=5, padx=5, pady=5)

        # ----------------------------------------------------
        # Action buttons
        # ----------------------------------------------------
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(padx=20, pady=10, fill="x")

        self.scan_button = ctk.CTkButton(
            button_frame, 
            text="Start Scan", 
            command=self._start_scan
        )
        self.scan_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            button_frame, 
            text="Stop", 
            command=self._stop_scan,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        # ----------------------------------------------------
        # Progress bar and status
        # ----------------------------------------------------
        self.progress_bar = ctk.CTkProgressBar(self)
        self.progress_bar.pack(padx=20, pady=5, fill="x")
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(self, text="Ready to scan")
        self.status_label.pack(padx=20, pady=5)

        # ----------------------------------------------------
        # Results
        # ----------------------------------------------------
        self.results_text = ctk.CTkTextbox(self, height=200)
        self.results_text.pack(padx=20, pady=10, fill="both", expand=True)

        # ----------------------------------------------------
        # Export buttons
        # ----------------------------------------------------
        export_frame = ctk.CTkFrame(self)
        export_frame.pack(padx=20, pady=10, fill="x")

        self.csv_button = ctk.CTkButton(
            export_frame, 
            text="Export CSV", 
            command=lambda: self._export_results("csv"),
            state="disabled"
        )
        self.csv_button.pack(side="left", padx=5)

        self.json_button = ctk.CTkButton(
            export_frame, 
            text="Export JSON", 
            command=lambda: self._export_results("json"),
            state="disabled"
        )
        self.json_button.pack(side="left", padx=5)

        self.pdf_button = ctk.CTkButton(
            export_frame, 
            text="Export PDF", 
            command=lambda: self._export_results("pdf"),
            state="disabled"
        )
        self.pdf_button.pack(side="left", padx=5)
        
    def _start_scan(self):
        """Starts the ARP scan in a separate thread"""
        # Clear previous results
        self.results_text.delete("1.0", "end")
        self.scanned_hosts = []
        self.cancel_scan[0] = False
        
        # Get parameters
        network = self.network_entry.get().strip()
        if not network:
            if self.autodetect_var.get():
                network = detect_local_network()
            else:
                messagebox.showerror("Error", "You must enter a valid network range or enable auto-detect.")
                return

        if not network:
            messagebox.showerror(
                "Error", 
                "Could not auto-detect the network. Please enter a range manually."
            )
            return
                
        try:
            timeout = float(self.timeout_entry.get())
            retry = int(self.retry_entry.get())
        except ValueError:
            messagebox.showerror(
                "Error", 
                "The timeout and retry values must be valid numbers."
            )
            return
            
        # Update UI
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.progress_bar.set(0)
        self.status_label.configure(text="Starting scan...")
        
        # Start scan in a separate thread
        scan_thread = Thread(
            target=self._run_scan,
            args=(network, timeout, retry)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
    def _run_scan(self, network, timeout, retry):
        """Runs the ARP scan and updates the UI"""
        try:
            total_hosts = sum(1 for _ in arp_scan(
                network, 
                timeout=timeout,
                retry=retry,
                verbose=self.verbose_var.get(),
                resolve_vendor=self.resolve_vendor_var.get(),
                dry_run=True
            ))
            
            hosts_scanned = 0
            for host in arp_scan(
                network,
                timeout=timeout,
                retry=retry,
                verbose=self.verbose_var.get(),
                resolve_vendor=self.resolve_vendor_var.get()
            ):
                if self.cancel_scan[0]:
                    break
                    
                self.scanned_hosts.append(host)
                hosts_scanned += 1
                
                # Update progress
                progress = hosts_scanned / total_hosts
                self.progress_bar.set(progress)
                
                # Update results
                self.results_text.insert("end", f"IP: {host['ip']}\n")
                self.results_text.insert("end", f"MAC: {host['mac']}\n")
                if host.get('hostname'):
                    self.results_text.insert("end", f"Hostname: {host['hostname']}\n")
                if host.get('vendor'):
                    self.results_text.insert("end", f"Vendor: {host['vendor']}\n")
                self.results_text.insert("end", "-" * 50 + "\n")
                self.results_text.see("end")
                
                # Update status
                self.status_label.configure(
                    text=f"Scanning... ({hosts_scanned}/{total_hosts})"
                )
                
            # Finish
            if self.cancel_scan[0]:
                self.status_label.configure(text="Scan canceled")
            else:
                self.status_label.configure(
                    text=f"Scan completed. {hosts_scanned} hosts found."
                )
                
        except Exception as e:
            messagebox.showerror("Error", f"Error during scan: {str(e)}")
            self.status_label.configure(text="Error during scan")
            
        finally:
            # Restore UI
            self.scan_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            
            # Enable export buttons if results exist
            export_state = "normal" if self.scanned_hosts else "disabled"
            self.csv_button.configure(state=export_state)
            self.json_button.configure(state=export_state)
            self.pdf_button.configure(state=export_state)
            
    def _stop_scan(self):
        """Stops the current scan"""
        self.cancel_scan[0] = True
        self.stop_button.configure(state="disabled")
        
    def _export_results(self, format_type):
        """Exports the results in the specified format"""
        if not self.scanned_hosts:
            messagebox.showwarning(
                "Warning",
                "There are no results to export."
            )
            return
            
        try:
            if format_type == "csv":
                export_arp_to_csv(self.scanned_hosts)
                messagebox.showinfo(
                    "Success",
                    "Results exported to arp_results.csv"
                )
            elif format_type == "json":
                export_arp_to_json(self.scanned_hosts)
                messagebox.showinfo(
                    "Success",
                    "Results exported to arp_results.json"
                )
            elif format_type == "pdf":
                export_arp_to_pdf(self.scanned_hosts)
                messagebox.showinfo(
                    "Success",
                    "Results exported to arp_results.pdf"
                )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error exporting results: {str(e)}"
            )
