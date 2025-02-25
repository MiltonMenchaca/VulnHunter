import customtkinter as ctk
import tkinter.messagebox as messagebox
from tkinter import ttk
from threading import Thread
import logging

# Import the scanner logic
from src.core.network.scanner import scan_ports, NMAP_INSTALLED
# Import export functions
from src.core.utils.export import export_results, export_sql_to_pdf
# Import utility functions for validation
from src.core.utils.utils import validate_ip_addresses, validate_port_range, escape_special_characters


class ScannerWindow(ctk.CTkFrame):
    """
    Frame for the Advanced Port Scanner that includes:
      - Inputs for IP addresses and port range.
      - A button to start the scan.
      - A progress indicator with percentage.
      - A Treeview to display the results in a tabular format.
      - Buttons to export results.
    """

    def __init__(self, parent):
        super().__init__(parent)

        # Control variables
        self.scanning = False
        self.scan_results = []

        self._create_ui()

    def _create_ui(self):
        """Creates the user interface."""
        # 1) TOP FRAME (IP fields and Ports)
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(padx=10, pady=10, fill="x")

        ctk.CTkLabel(
            top_frame,
            text="IP Addresses (comma-separated or with ranges, e.g. 192.168.1.1, 192.168.1.5-10):"
        ).grid(row=0, column=0, padx=5, pady=5, sticky="e")

        self.ip_entry = ctk.CTkEntry(
            top_frame, width=300,
            placeholder_text="E.g.: 192.168.1.1, 192.168.1.5-10"
        )
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkLabel(
            top_frame,
            text="Port Range:"
        ).grid(row=1, column=0, padx=5, pady=5, sticky="e")

        self.port_range_entry = ctk.CTkEntry(
            top_frame, width=200,
            placeholder_text="E.g.: 1-1024"
        )
        self.port_range_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # 2) PROGRESS FRAME
        progress_frame = ctk.CTkFrame(self)
        progress_frame.pack(padx=10, pady=5, fill="x")

        self.progress_var = ctk.DoubleVar()
        self.progress_bar = ctk.CTkProgressBar(
            progress_frame,
            variable=self.progress_var,
            width=400
        )
        self.progress_bar.pack(side="left", padx=10)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            progress_frame,
            text="0%"
        )
        self.progress_label.pack(side="left", padx=5)

        # 3) BUTTON FRAME
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(padx=10, pady=5, fill="x")

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

        self.export_button = ctk.CTkButton(
            button_frame,
            text="Export Results",
            command=self._export_results,
            state="disabled"
        )
        self.export_button.pack(side="left", padx=5)

        # 4) TREEVIEW FOR RESULTS
        columns = ("ip", "port", "state", "service", "version")
        self.results_tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
            height=15
        )

        # Configure columns
        self.results_tree.heading("ip", text="IP")
        self.results_tree.heading("port", text="Port")
        self.results_tree.heading("state", text="State")
        self.results_tree.heading("service", text="Service")
        self.results_tree.heading("version", text="Version")

        self.results_tree.column("ip", width=120)
        self.results_tree.column("port", width=80)
        self.results_tree.column("state", width=80)
        self.results_tree.column("service", width=100)
        self.results_tree.column("version", width=200)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self,
            orient="vertical",
            command=self.results_tree.yview
        )
        self.results_tree.configure(yscrollcommand=scrollbar.set)

        # Pack Treeview and scrollbar
        self.results_tree.pack(padx=10, pady=5, fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _start_scan(self):
        """Starts the port scan."""
        # Validate IPs
        ips = self.ip_entry.get().strip()
        if not validate_ip_addresses(ips):
            messagebox.showerror(
                "Error",
                "The IP addresses are not valid"
            )
            return

        # Validate port range
        ports = self.port_range_entry.get().strip()
        if not validate_port_range(ports):
            messagebox.showerror(
                "Error",
                "The port range is not valid"
            )
            return

        # Clear previous results
        self.results_tree.delete(*self.results_tree.get_children())
        self.scan_results = []

        # Update UI
        self.scanning = True
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.export_button.configure(state="disabled")
        self.progress_var.set(0)
        self.progress_label.configure(text="0%")

        # Start scanning in a separate thread
        Thread(target=self._scan_thread, args=(ips, ports), daemon=True).start()

    def _scan_thread(self, ips, ports):
        """Performs the scan in a separate thread."""
        try:
            total_progress = 0
            for result in scan_ports(ips, ports):
                if not self.scanning:
                    break

                if isinstance(result, float):
                    # It's progress
                    total_progress = result
                    self.progress_var.set(total_progress)
                    self.progress_label.configure(text=f"{int(total_progress * 100)}%")
                else:
                    # It's a result
                    self.scan_results.append(result)
                    self._update_treeview(result)

        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error during the scan: {str(e)}"
            )

        finally:
            self._stop_scan()

    def _stop_scan(self):
        """Stops the scan."""
        self.scanning = False
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.export_button.configure(state="normal" if self.scan_results else "disabled")

    def _update_treeview(self, result):
        """Updates the Treeview with a new result."""
        self.results_tree.insert(
            "",
            "end",
            values=(
                result["ip"],
                result["port"],
                result["state"],
                result.get("service", ""),
                result.get("version", "")
            )
        )

    def _export_results(self):
        """Exports the scan results."""
        if not self.scan_results:
            messagebox.showwarning(
                "Warning",
                "No results to export"
            )
            return

        try:
            export_results(self.scan_results)
            messagebox.showinfo(
                "Success",
                "Results exported successfully"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error exporting results: {str(e)}"
            )
