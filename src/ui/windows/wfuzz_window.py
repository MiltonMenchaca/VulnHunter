# windows/wfuzz_window.py

import customtkinter as ctk
import tkinter.messagebox as messagebox
from tkinter import filedialog
from threading import Thread
from src.core.web.wfuzz_integration import WfuzzIntegration
import logging
import os
import json
import re
import time

class WFuzzWindow(ctk.CTkFrame):
    """
    GUI window to configure and run Wfuzz, including:
      - Target URL, wordlist file
      - Parameters to fuzz (with {FUZZ})
      - Fields to filter/hide HTTP codes (--hc, --sc)
      - Rate limit control (--rate)
      - Silent mode and debug mode
      - Retry handling
      - Additional options
      - Status/progress section and a TextBox for showing results
      - Export/load configurations in JSON
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self._create_ui()

    def _create_ui(self):
        # ------------------------------------------------------
        # Top Section with Configuration Fields
        # ------------------------------------------------------
        self.config_frame = ctk.CTkFrame(self)
        self.config_frame.pack(padx=10, pady=10, fill="x")

        # 1) Target URL
        ctk.CTkLabel(self.config_frame, text="Target URL:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.target_entry = ctk.CTkEntry(self.config_frame, width=400, placeholder_text="Ex: https://example.com/FUZZ")
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # 2) Wordlist File
        ctk.CTkLabel(self.config_frame, text="Wordlist File:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.wordlist_entry = ctk.CTkEntry(self.config_frame, width=300, placeholder_text="Path to wordlist file")
        self.wordlist_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        browse_button = ctk.CTkButton(
            self.config_frame, text="Browse", width=80, command=self._browse_wordlist_file
        )
        browse_button.grid(row=1, column=2, padx=5, pady=5, sticky="w")

        # 3) Parameters to Fuzz
        ctk.CTkLabel(self.config_frame, text="Parameters to Fuzz:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.parameters_entry = ctk.CTkEntry(self.config_frame, width=400, placeholder_text="Ex: /FUZZ, /path/FUZZ/file")
        self.parameters_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        # 4) Hide/Show HTTP Codes
        # a) Hide Codes (--hc)
        ctk.CTkLabel(self.config_frame, text="Hide Codes (--hc):").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.hide_codes_entry = ctk.CTkEntry(self.config_frame, width=400, placeholder_text="Ex: 404,403")
        self.hide_codes_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        # b) Show Codes (--sc)
        ctk.CTkLabel(self.config_frame, text="Show Codes (--sc):").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.show_codes_entry = ctk.CTkEntry(self.config_frame, width=400, placeholder_text="Ex: 200,302")
        self.show_codes_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        # 5) Rate Limit (--rate)
        ctk.CTkLabel(self.config_frame, text="Rate Limit (--rate):").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.rate_entry = ctk.CTkEntry(self.config_frame, width=100, placeholder_text="Requests/sec")
        self.rate_entry.grid(row=5, column=1, padx=5, pady=5, sticky="w")

        # 6) Silent Mode (checkbox)
        self.silent_var = ctk.BooleanVar(value=False)
        self.silent_check = ctk.CTkCheckBox(self.config_frame, text="Silent Mode (--silent)", variable=self.silent_var)
        self.silent_check.grid(row=6, column=1, padx=5, pady=5, sticky="w")

        # 7) Debug Mode (checkbox)
        self.debug_var = ctk.BooleanVar(value=False)
        self.debug_check = ctk.CTkCheckBox(self.config_frame, text="Debug Mode (more detailed log)", variable=self.debug_var)
        self.debug_check.grid(row=7, column=1, padx=5, pady=5, sticky="w")

        # 8) Retry Handling
        ctk.CTkLabel(self.config_frame, text="Retries:").grid(row=8, column=0, padx=5, pady=5, sticky="e")
        self.retries_entry = ctk.CTkEntry(self.config_frame, width=100, placeholder_text="3")
        self.retries_entry.grid(row=8, column=1, padx=5, pady=5, sticky="w")

        # 9) Additional Options
        ctk.CTkLabel(self.config_frame, text="Additional Options (--hr, --hs, etc.):").grid(row=9, column=0, padx=5, pady=5, sticky="e")
        self.additional_options_entry = ctk.CTkEntry(self.config_frame, width=400, placeholder_text="Ex: --hr '^PHPSESSID=' --hs 'login'")
        self.additional_options_entry.grid(row=9, column=1, padx=5, pady=5, sticky="w")

        # 10) Export/Import Config Buttons
        export_button = ctk.CTkButton(
            self.config_frame, text="Export Config", command=self._export_config, width=130
        )
        export_button.grid(row=10, column=1, pady=5, padx=5, sticky="w")

        import_button = ctk.CTkButton(
            self.config_frame, text="Import Config", command=self._import_config, width=130
        )
        import_button.grid(row=10, column=2, pady=5, padx=5, sticky="w")

        # ------------------------------------------------------
        # Button to Start Fuzzing Attack
        # ------------------------------------------------------
        start_button = ctk.CTkButton(
            self.config_frame, text="Start Fuzzing Attack", command=self._start_wfuzz_scan
        )
        start_button.grid(row=11, column=1, padx=5, pady=10, sticky="w")

        # ------------------------------------------------------
        # Status/Progress Section
        # ------------------------------------------------------
        self.status_label = ctk.CTkLabel(self.config_frame, text="Ready.", anchor="w")
        self.status_label.grid(row=12, column=1, padx=5, pady=5, sticky="w")

        # ------------------------------------------------------
        # TextBox to Show Results
        # ------------------------------------------------------
        self.results_text = ctk.CTkTextbox(
            self, width=800, height=300, wrap="word", state="disabled"
        )
        self.results_text.pack(padx=10, pady=(0, 10), fill="both", expand=True)

    def _export_config(self):
        """Saves the current configuration to a JSON file."""
        config_data = {
            "target": self.target_entry.get().strip(),
            "wordlist": self.wordlist_entry.get().strip(),
            "parameters": self.parameters_entry.get().strip(),
            "hide_codes": self.hide_codes_entry.get().strip(),
            "show_codes": self.show_codes_entry.get().strip(),
            "rate": self.rate_entry.get().strip(),
            "silent": self.silent_var.get(),
            "debug": self.debug_var.get(),
            "retries": self.retries_entry.get().strip(),
            "additional_options": self.additional_options_entry.get().strip()
        }
        file_path = filedialog.asksaveasfilename(
            title="Save Fuzzing Profile",
            defaultextension=".json",
            filetypes=(("JSON Files", "*.json"), ("All Files", "*.*")),
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(config_data, f, indent=4, ensure_ascii=False)
                messagebox.showinfo("Export Config", f"Configuration saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save configuration:\n{e}")

    def _import_config(self):
        """Loads configuration from a JSON file and populates the fields."""
        file_path = filedialog.askopenfilename(
            title="Load Fuzzing Profile",
            filetypes=(("JSON Files", "*.json"), ("All Files", "*.*")),
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    config_data = json.load(f)
                self.target_entry.delete(0, "end")
                self.target_entry.insert(0, config_data.get("target", ""))

                self.wordlist_entry.delete(0, "end")
                self.wordlist_entry.insert(0, config_data.get("wordlist", ""))

                self.parameters_entry.delete(0, "end")
                self.parameters_entry.insert(0, config_data.get("parameters", ""))

                self.hide_codes_entry.delete(0, "end")
                self.hide_codes_entry.insert(0, config_data.get("hide_codes", ""))

                self.show_codes_entry.delete(0, "end")
                self.show_codes_entry.insert(0, config_data.get("show_codes", ""))

                self.rate_entry.delete(0, "end")
                self.rate_entry.insert(0, config_data.get("rate", ""))

                self.silent_var.set(bool(config_data.get("silent", False)))
                self.debug_var.set(bool(config_data.get("debug", False)))

                self.retries_entry.delete(0, "end")
                self.retries_entry.insert(0, config_data.get("retries", ""))

                self.additional_options_entry.delete(0, "end")
                self.additional_options_entry.insert(0, config_data.get("additional_options", ""))

                messagebox.showinfo("Import Config", f"Configuration loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not load configuration:\n{e}")

    def _browse_wordlist_file(self):
        """Allows selection of the wordlist file."""
        file_path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if file_path:
            self.wordlist_entry.delete(0, "end")
            self.wordlist_entry.insert(0, file_path)

    def _start_wfuzz_scan(self):
        """Starts running Wfuzz in a separate thread."""
        target = self.target_entry.get().strip()
        wordlist = self.wordlist_entry.get().strip()
        parameters = self.parameters_entry.get().strip()
        hide_codes = self.hide_codes_entry.get().strip()
        show_codes = self.show_codes_entry.get().strip()
        rate_val = self.rate_entry.get().strip()
        is_silent = self.silent_var.get()
        is_debug = self.debug_var.get()
        retries_val = self.retries_entry.get().strip() or "3"
        additional_opts = self.additional_options_entry.get().strip()

        if not target or not wordlist or not parameters:
            messagebox.showerror("Error", "Please fill in the required fields (URL, Wordlist, Parameters).")
            return

        if not (target.startswith("http://") or target.startswith("https://")):
            messagebox.showwarning("Warning", "URL typically starts with http:// or https://")
        if not os.path.isfile(wordlist):
            messagebox.showerror("Error", f"Wordlist file does not exist:\n{wordlist}")
            return

        if rate_val and not rate_val.isdigit():
            messagebox.showwarning("Warning", "Rate must be a number. It will be ignored.")
            rate_val = ""

        if not re.match(r"^\d+$", retries_val):
            messagebox.showwarning("Warning", "Retries must be a number. Defaulting to 3.")
            retries_val = "3"

        options_list = []
        if hide_codes:
            options_list += ["--hc", hide_codes]
        if show_codes:
            options_list += ["--sc", show_codes]
        if rate_val:
            options_list += ["--rate", rate_val]
        if is_silent:
            options_list.append("--silent")
        if is_debug:
            options_list += ["-v", "2"]
        if additional_opts:
            extra_tokens = additional_opts.split()
            options_list += extra_tokens

        param_list = [p.strip() for p in parameters.split(",") if p.strip()]

        def wfuzz_thread():
            self.status_label.configure(text="Running Wfuzz, please wait...")
            start_time = time.time()
            attempt_counter = 0
            success = False
            max_retries = int(retries_val)

            integration = WfuzzIntegration()

            while not success and attempt_counter < max_retries:
                attempt_counter += 1
                self._log_message(f"Starting Wfuzz (attempt {attempt_counter}/{max_retries})...")

                output = integration.run_wfuzz(
                    target=target,
                    wordlist=wordlist,
                    parameters=param_list,
                    additional_options=options_list
                )

                if "Error executing Wfuzz:" in output:
                    self._log_message(f"[ERROR] Wfuzz failed on attempt {attempt_counter}.")
                    if attempt_counter >= max_retries:
                        break
                    else:
                        self._log_message("[INFO] Retrying...")
                else:
                    success = True
                    self._log_message("=== Wfuzz Results ===")
                    self._log_message(output)

            elapsed = time.time() - start_time
            if success:
                self.status_label.configure(text=f"Wfuzz finished in {elapsed:.2f} s.")
            else:
                self.status_label.configure(text="Wfuzz failed after multiple attempts.")

        Thread(target=wfuzz_thread, daemon=True).start()

    def _log_message(self, message):
        """Inserts messages into the TextBox and logs them."""
        self.results_text.configure(state="normal")
        self.results_text.insert("end", message + "\n")
        self.results_text.configure(state="disabled")
        self.results_text.see("end")
        self.logger.info(message)
