# windows/osint_window.py

import customtkinter as ctk
import tkinter.messagebox as messagebox
from threading import Thread
from typing import Callable, List, Dict, Any

# Attempt to import pyperclip and handle the error if it's not installed
try:
    import pyperclip
except ImportError:
    pyperclip = None

# Import your osint.py functions (adjust paths if necessary)
from src.core.network.osint import (
    whois_lookup,
    geoip_lookup,
    dns_subdomain_lookup,
    reverse_ip_lookup,
    shodan_lookup,
    theharvester_lookup,
    sublist3r_lookup,
    export_osint_to_csv,
    export_osint_to_json,
    export_osint_to_pdf,
    get_osint_commands
)

class OSINTWindow(ctk.CTkFrame):
    """
    Window for OSINT with:
      - Inputs for each OSINT tool (WHOIS, GeoIP, Subdomains, Shodan, Reverse IP,
        theHarvester, Sublist3r).
      - Buttons to run each lookup asynchronously (in threads).
      - A textbox to display results (logs).
      - Export buttons (CSV, JSON, PDF), enabled when there are results.
      - Save functionality, and a list of copyable OSINT commands.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Initialize data structures for results
        self.whois_results: List[Dict[str, Any]] = []
        self.geoip_results: List[Dict[str, Any]] = []
        self.subdomain_results: List[Dict[str, Any]] = []
        self.shodan_results: List[Dict[str, Any]] = []
        self.reverse_ip_results: List[Any] = []
        self.theharvester_results: List[Dict[str, Any]] = []
        self.sublist3r_results: List[str] = []
        
        self._create_ui()

    def _create_ui(self):
        # Results frame
        self.results_frame = ctk.CTkFrame(self)
        self.results_frame.pack(padx=10, pady=(10, 5), fill="both", expand=True)

        self.results_text = ctk.CTkTextbox(
            master=self.results_frame,
            width=650,
            height=300,
            wrap="word",
            state="disabled"
        )
        self.results_text.pack(fill="both", expand=True)

        # Scrollable frame for options
        self.options_scrollable = ctk.CTkScrollableFrame(
            master=self,
            width=700,
            height=450,
            label_text="OSINT Module"
        )
        self.options_scrollable.pack(padx=10, pady=5, fill="both", expand=False)

        # Configure the grid in the options frame
        self.options_scrollable.grid_columnconfigure(0, weight=0)
        self.options_scrollable.grid_columnconfigure(1, weight=1)
        self.options_scrollable.grid_columnconfigure(2, weight=0)

        # Create the different sections
        self._create_whois_section()
        self._create_geoip_section()
        self._create_subdomains_section()
        self._create_shodan_section()
        self._create_reverse_ip_section()
        self._create_harvester_section()
        self._create_sublist3r_section()
        self._create_export_section()
        self._create_commands_section()

    def _run_in_thread(self, target_func: Callable, *args, **kwargs) -> None:
        """Runs target_func in a daemon thread to avoid blocking the UI."""
        def task():
            target_func(*args, **kwargs)
        Thread(target=task, daemon=True).start()

    def _append_log(self, message: str) -> None:
        """Inserts a message into the results Textbox and checks exports."""
        self.results_text.configure(state="normal")
        self.results_text.insert("end", message + "\n")
        self.results_text.configure(state="disabled")
        self.results_text.see("end")
        self._check_exports()

    def _check_exports(self) -> None:
        """Enables or disables export buttons if data is or isn't present."""
        has_data = any([
            self.whois_results, self.geoip_results, self.subdomain_results,
            self.shodan_results, self.reverse_ip_results,
            self.theharvester_results, self.sublist3r_results
        ])
        state = "normal" if has_data else "disabled"
        self.btn_csv.configure(state=state)
        self.btn_json.configure(state=state)
        self.btn_pdf.configure(state=state)
        self.save_button.configure(state=state)

    def _create_whois_section(self):
        frame = ctk.CTkFrame(self.options_scrollable)
        frame.grid(row=0, column=0, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(frame, text="Domain/IP for WHOIS:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.whois_entry = ctk.CTkEntry(
            frame, width=250, placeholder_text="Ex: example.com or 8.8.8.8"
        )
        self.whois_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkButton(
            frame,
            text="Run WHOIS",
            command=self._run_whois
        ).grid(row=0, column=2, padx=5, pady=5, sticky="w")

    def _create_geoip_section(self):
        frame = ctk.CTkFrame(self.options_scrollable)
        frame.grid(row=1, column=0, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(frame, text="IP for GeoIP:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.geoip_entry = ctk.CTkEntry(
            frame, width=250, placeholder_text="Ex: 8.8.8.8"
        )
        self.geoip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkButton(
            frame,
            text="Run GeoIP",
            command=self._run_geoip
        ).grid(row=0, column=2, padx=5, pady=5, sticky="w")

    def _create_subdomains_section(self):
        frame = ctk.CTkFrame(self.options_scrollable)
        frame.grid(row=2, column=0, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(frame, text="Domain for Subdomains:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.subdomain_entry = ctk.CTkEntry(
            frame, width=250, placeholder_text="Ex: example.com"
        )
        self.subdomain_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkButton(
            frame,
            text="Resolve Subdomains",
            command=self._run_subdomains
        ).grid(row=0, column=2, padx=5, pady=5, sticky="w")

    def _create_shodan_section(self):
        frame = ctk.CTkFrame(self.options_scrollable)
        frame.grid(row=3, column=0, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(frame, text="IP for Shodan:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.shodan_ip_entry = ctk.CTkEntry(
            frame, width=250, placeholder_text="Ex: 8.8.8.8"
        )
        self.shodan_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkLabel(frame, text="Shodan API Key:").grid(
            row=1, column=0, padx=5, pady=5, sticky="e"
        )
        self.shodan_api_entry = ctk.CTkEntry(
            frame,
            width=250,
            placeholder_text="Your Shodan API Key",
            show="*"
        )
        self.shodan_api_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkButton(
            frame,
            text="Shodan Lookup",
            command=self._run_shodan
        ).grid(row=1, column=2, padx=5, pady=5, sticky="w")

    def _create_reverse_ip_section(self):
        frame = ctk.CTkFrame(self.options_scrollable)
        frame.grid(row=4, column=0, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(frame, text="Domain/IP for Reverse IP:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.reverse_ip_entry = ctk.CTkEntry(
            frame, width=250, placeholder_text="Ex: example.com or 8.8.8.8"
        )
        self.reverse_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkButton(
            frame,
            text="Reverse IP Lookup",
            command=self._run_reverse_ip
        ).grid(row=0, column=2, padx=5, pady=5, sticky="w")

    def _create_harvester_section(self):
        frame = ctk.CTkFrame(self.options_scrollable)
        frame.grid(row=5, column=0, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(frame, text="Domain for theHarvester:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.harvester_domain_entry = ctk.CTkEntry(
            frame, width=250, placeholder_text="Ex: example.com"
        )
        self.harvester_domain_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkLabel(frame, text="Result limit:").grid(
            row=1, column=0, padx=5, pady=5, sticky="e"
        )
        self.harvester_limit_entry = ctk.CTkEntry(
            frame, width=80, placeholder_text="100"
        )
        self.harvester_limit_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.harvester_dork_var = ctk.BooleanVar(value=False)
        self.harvester_dork_check = ctk.CTkCheckBox(
            frame,
            text="Use dorks (-e)",
            variable=self.harvester_dork_var
        )
        self.harvester_dork_check.grid(row=2, column=1, sticky="w", padx=5)

        ctk.CTkLabel(frame, text="Source (-b):").grid(
            row=3, column=0, padx=5, pady=5, sticky="e"
        )
        self.harvester_source_box = ctk.CTkComboBox(
            frame,
            values=["all", "google", "bing", "crtsh"],
            state="readonly"
        )
        self.harvester_source_box.set("all")
        self.harvester_source_box.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkButton(
            frame,
            text="Run theHarvester",
            command=self._run_harvester
        ).grid(row=3, column=2, padx=5, pady=5, sticky="w")

    def _create_sublist3r_section(self):
        frame = ctk.CTkFrame(self.options_scrollable)
        frame.grid(row=6, column=0, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(frame, text="Domain for Sublist3r:").grid(
            row=0, column=0, padx=5, pady=5, sticky="e"
        )
        self.sublist3r_domain_entry = ctk.CTkEntry(
            frame, width=250, placeholder_text="Ex: example.com"
        )
        self.sublist3r_domain_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkLabel(frame, text="Threads:").grid(
            row=1, column=0, padx=5, pady=5, sticky="e"
        )
        self.sublist3r_threads_entry = ctk.CTkEntry(
            frame, width=80, placeholder_text="30"
        )
        self.sublist3r_threads_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkLabel(frame, text="Ports (optional):").grid(
            row=2, column=0, padx=5, pady=5, sticky="e"
        )
        self.sublist3r_ports_entry = ctk.CTkEntry(
            frame, width=80, placeholder_text="80,443"
        )
        self.sublist3r_ports_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        ctk.CTkButton(
            frame,
            text="Run Sublist3r",
            command=self._run_sublist3r
        ).grid(row=2, column=2, padx=5, pady=5, sticky="w")

    def _create_export_section(self):
        frame = ctk.CTkFrame(self)
        frame.pack(pady=10)

        self.btn_csv = ctk.CTkButton(
            frame,
            text="Export to CSV",
            command=lambda: self._export_results("csv"),
            state="disabled"
        )
        self.btn_json = ctk.CTkButton(
            frame,
            text="Export to JSON",
            command=lambda: self._export_results("json"),
            state="disabled"
        )
        self.btn_pdf = ctk.CTkButton(
            frame,
            text="Export to PDF",
            command=lambda: self._export_results("pdf"),
            state="disabled"
        )

        self.btn_csv.pack(side="left", padx=5)
        self.btn_json.pack(side="left", padx=5)
        self.btn_pdf.pack(side="left", padx=5)

        self.save_button = ctk.CTkButton(
            self,
            text="Save Results",
            command=self._save_results,
            state="disabled"
        )
        self.save_button.pack(pady=5)

    def _create_commands_section(self):
        ctk.CTkLabel(self, text="Common OSINT Commands").pack(pady=10)

        commands = get_osint_commands()
        commands_text = "\n".join(commands)

        self.commands_textbox = ctk.CTkTextbox(
            self,
            width=500,
            height=150,
            wrap="word"
        )
        self.commands_textbox.insert("end", commands_text)
        self.commands_textbox.configure(state="disabled")
        self.commands_textbox.pack(pady=10)

        ctk.CTkButton(
            self,
            text="Copy All Commands",
            command=self._copy_all_commands
        ).pack(pady=10)

    def _run_whois(self):
        target = self.whois_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "You must enter a domain or IP for WHOIS.")
            return

        def task():
            data = whois_lookup(target)
            if "error" in data:
                self._append_log(f"[WHOIS] Error: {data['error']}")
            else:
                self.whois_results.append(data)
                self._append_log(f"[WHOIS] Results for {target}:")
                for k, v in data.items():
                    self._append_log(f"  {k}: {v}")

        self._run_in_thread(task)

    def _run_geoip(self):
        ip = self.geoip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "You must enter an IP for GeoIP.")
            return

        def task():
            data = geoip_lookup(ip)
            if "error" in data:
                self._append_log(f"[GeoIP] Error: {data['error']}")
            else:
                self.geoip_results.append(data)
                self._append_log(f"[GeoIP] Data for {ip}:")
                for k, v in data.items():
                    self._append_log(f"  {k}: {v}")

        self._run_in_thread(task)

    def _run_subdomains(self):
        domain = self.subdomain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "You must enter a domain for Subdomains.")
            return

        def task():
            common_subdomains = ["www", "mail", "ftp", "api", "dev", "test", "ns1", "ns2"]
            found = dns_subdomain_lookup(domain, common_subdomains)
            if found:
                self.subdomain_results.extend(found)
                self._append_log(f"[Subdomains] Active in {domain}:")
                for s in found:
                    self._append_log(f"  {s['subdomain']} -> {s['ip']}")
            else:
                self._append_log(f"[Subdomains] No active subdomains found for {domain}.")

        self._run_in_thread(task)

    def _run_shodan(self):
        ip = self.shodan_ip_entry.get().strip()
        api_key = self.shodan_api_entry.get().strip()
        if not ip or not api_key:
            messagebox.showerror("Error", "You must enter the IP and Shodan API Key.")
            return

        def task():
            data = shodan_lookup(ip, api_key)
            if "error" in data:
                self._append_log(f"[Shodan] Error: {data['error']}")
            else:
                self.shodan_results.append(data)
                self._append_log(f"[Shodan] Data for {ip}:")
                for k, v in data.items():
                    self._append_log(f"  {k}: {v}")

        self._run_in_thread(task)

    def _run_reverse_ip(self):
        target = self.reverse_ip_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "You must enter a domain/IP for Reverse IP.")
            return

        def task():
            data = reverse_ip_lookup(target)
            if isinstance(data, dict) and "error" in data:
                self._append_log(f"[Reverse IP] Error: {data['error']}")
            elif isinstance(data, str):
                self.reverse_ip_results.append(data)
                self._append_log(f"[Reverse IP] Hostname of {target}: {data}")
            elif data is None:
                self._append_log(f"[Reverse IP] No data found for {target}.")
            else:
                self._append_log(f"[Reverse IP] Unexpected response for {target}: {data}")

        self._run_in_thread(task)

    def _run_harvester(self):
        domain = self.harvester_domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "You must enter a domain for theHarvester.")
            return

        try:
            limit = int(self.harvester_limit_entry.get().strip() or "100")
        except ValueError:
            limit = 100

        use_dork = self.harvester_dork_var.get()
        source = self.harvester_source_box.get()

        def task():
            data = theharvester_lookup(domain, limit=limit, use_dork=use_dork, source=source)
            if "error" in data:
                self._append_log(f"[theHarvester] Error: {data['error']}")
            else:
                self.theharvester_results.append(data)
                self._append_log(f"[theHarvester] Results for {domain}:")

                emails = data.get("emails", [])
                hosts = data.get("hosts", [])
                
                if emails:
                    self._append_log("  Emails found:")
                    for e in emails:
                        self._append_log(f"    {e}")
                if hosts:
                    self._append_log("  Hosts found:")
                    for h in hosts:
                        self._append_log(f"    {h['host']} -> {h['ip']}")
                if not emails and not hosts:
                    self._append_log("  No emails or hosts found.")

        self._run_in_thread(task)

    def _run_sublist3r(self):
        domain = self.sublist3r_domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "You must enter a domain for Sublist3r.")
            return

        try:
            threads = int(self.sublist3r_threads_entry.get().strip() or "30")
        except ValueError:
            threads = 30

        ports = self.sublist3r_ports_entry.get().strip() or None

        def task():
            data = sublist3r_lookup(domain, threads=threads, ports=ports)
            if "error" in data:
                self._append_log(f"[Sublist3r] Error: {data['error']}")
            else:
                subs = data.get("subdomains", [])
                if subs:
                    self.sublist3r_results.extend(subs)
                    self._append_log(f"[Sublist3r] Subdomains for {domain}:")
                    for sd in subs:
                        self._append_log(f"  {sd}")
                else:
                    self._append_log(f"[Sublist3r] No subdomains found for {domain}.")

        self._run_in_thread(task)

    def _get_all_results(self) -> Dict[str, Any]:
        """Combines results into a single dict for export."""
        return {
            "WHOIS": self.whois_results,
            "GeoIP": self.geoip_results,
            "Subdomains": self.subdomain_results,
            "Shodan": self.shodan_results,
            "Reverse IP": self.reverse_ip_results,
            "theHarvester": self.theharvester_results,
            "Sublist3r": self.sublist3r_results
        }

    def _export_results(self, format: str):
        """Exports the results in the specified format."""
        if not any(self._get_all_results().values()):
            messagebox.showwarning("Warning", "No results to export.")
            return

        try:
            results = self._get_all_results()
            if format == "csv":
                export_osint_to_csv("osint_results.csv", results)
            elif format == "json":
                export_osint_to_json("osint_results.json", results)
            elif format == "pdf":
                export_osint_to_pdf("osint_results.pdf", results)
            messagebox.showinfo("Success", f"Results exported to osint_results.{format}")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting results: {str(e)}")

    def _save_results(self):
        """Saves the results to a JSON file."""
        if not any(self._get_all_results().values()):
            messagebox.showwarning("Warning", "No results to save.")
            return

        try:
            export_osint_to_json("osint_results.json", self._get_all_results())
            messagebox.showinfo("Saved", "Results saved to 'osint_results.json'.")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving results: {str(e)}")

    def _copy_all_commands(self):
        """Copies all OSINT commands to the clipboard."""
        if pyperclip:
            commands = get_osint_commands()
            pyperclip.copy("\n".join(commands))
            messagebox.showinfo("Success", "All commands copied to clipboard.")
        else:
            messagebox.showerror(
                "Error",
                "pyperclip is not installed.\nInstall it using 'pip install pyperclip'."
            )
