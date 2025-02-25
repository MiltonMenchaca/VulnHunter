"""
Main window for the Metasploit interface,
reusing the base layout defined in BaseWindow
without duplicating frames.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import logging
import json

# Import the class that manages the connection to Metasploit
from ...core.metasploit.manager import MetasploitConnectionManager
# Inherit from BaseWindow, which already defines left_frame and right_frame
from ..base_window import BaseWindow


class MetasploitWindow(BaseWindow):
    """Main window for the Metasploit interface."""

    def __init__(self, parent):
        # Call the BaseWindow constructor, which creates main_frame, left_frame, right_frame
        super().__init__(parent)

        self.title = "Metasploit Framework"
        self.description = "Interface for Metasploit Framework"

        # Instantiate MetasploitConnectionManager (ensure it has the necessary methods)
        self.msf_manager = MetasploitConnectionManager()

        # Internal references and lists
        self.info_windows = []
        self.exploit_modules = []
        self.payload_modules = []
        self.auxiliary_modules = []
        self.active_sessions = {}

        # Configure logging
        self.logger = logging.getLogger("MetasploitWindow")
        self.logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler("metasploit_window.log")
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Build the interface using the inherited left_frame and right_frame
        self._create_ui()

        # Start monitoring Metasploit status
        self._start_status_monitoring()

    def _create_ui(self):
        """
        In BaseWindow, we already have:
          - self.main_frame (parent of left_frame and right_frame)
          - self.left_frame
          - self.right_frame

        Here we use left_frame for controls,
        and optionally right_frame for something else (logs, etc.).
        """

        # ========== Top Section (status bar) in left_frame ==========
        top_frame = ctk.CTkFrame(self.left_frame)
        top_frame.pack(fill="x", padx=5, pady=5)

        self.status_label = ctk.CTkLabel(top_frame, text="Status: Disconnected", text_color="red")
        self.status_label.pack(side="left", padx=5)

        self.reconnect_button = ctk.CTkButton(
            top_frame,
            text="Reconnect",
            command=self._reconnect
        )
        self.reconnect_button.pack(side="left", padx=5)

        self.refresh_button = ctk.CTkButton(
            top_frame,
            text="Refresh",
            command=self._refresh_sessions
        )
        self.refresh_button.pack(side="left", padx=5)

        # ========== Notebook with Exploits, Payloads, Auxiliaries, Sessions ==========
        self.notebook = ttk.Notebook(self.left_frame)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self.exploits_tab = ctk.CTkFrame(self.notebook)
        self.payloads_tab = ctk.CTkFrame(self.notebook)
        self.auxiliaries_tab = ctk.CTkFrame(self.notebook)
        self.sessions_tab = ctk.CTkFrame(self.notebook)

        self.notebook.add(self.exploits_tab, text="Exploits")
        self.notebook.add(self.payloads_tab, text="Payloads")
        self.notebook.add(self.auxiliaries_tab, text="Auxiliaries")
        self.notebook.add(self.sessions_tab, text="Sessions")

        # Build the UI for each tab
        self._create_modules_ui(self.exploits_tab, "exploit")
        self._create_modules_ui(self.payloads_tab, "payload")
        self._create_modules_ui(self.auxiliaries_tab, "auxiliary")
        self._create_sessions_ui()

        # Asynchronous loading of modules
        self.after(1000, self._load_modules_async)
        # Update sessions every 5 seconds
        self.after(5000, self._refresh_sessions)

        # (Optional) We can use self.right_frame for logs or output panel
        # For example, a textbox for logs:
        self.log_text = ctk.CTkTextbox(self.right_frame, height=10)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    def _create_modules_ui(self, parent, module_type):
        """Creates the interface for Exploits, Payloads, or Auxiliaries in each tab."""
        main_frame = ctk.CTkFrame(parent)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        search_var = tk.StringVar()
        search_entry = ctk.CTkEntry(
            main_frame,
            placeholder_text=f"Search {module_type}s...",
            textvariable=search_var
        )
        search_entry.pack(fill="x", padx=5, pady=5)

        modules_list = tk.Listbox(
            main_frame,
            selectmode=tk.SINGLE,
            font=("Courier", 10),
            background="#2b2b2b",
            foreground="#ffffff",
            selectbackground="#404040"
        )
        modules_list.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=modules_list.yview)
        scrollbar.pack(side="right", fill="y")
        modules_list.configure(yscrollcommand=scrollbar.set)

        button_frame = ctk.CTkFrame(parent)
        button_frame.pack(fill="x", padx=5, pady=5)

        ctk.CTkButton(
            button_frame,
            text="View Info",
            command=lambda: self._show_module_info(
                module_type,
                modules_list.get(tk.ACTIVE) if modules_list.size() else None
            )
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            button_frame,
            text="View Code",
            command=lambda: self._display_source_code(
                parent,
                module_type,
                modules_list.get(tk.ACTIVE) if modules_list.size() else None
            )
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            button_frame,
            text="Execute",
            command=lambda: self._execute_module(
                module_type,
                modules_list.get(tk.ACTIVE) if modules_list.size() else None
            )
        ).pack(side="left", padx=5)

        # Save references
        setattr(self, f"{module_type}_list", modules_list)
        setattr(self, f"{module_type}_search", search_var)

        def on_search(*args):
            query = search_var.get().lower()
            modules_list.delete(0, tk.END)
            modules = getattr(self, f"{module_type}_modules", [])
            for m in modules:
                if query in m.lower():
                    modules_list.insert(tk.END, m)

        search_var.trace_add("write", on_search)

    def _create_sessions_ui(self):
        """Creates the interface for the Sessions tab."""
        main_frame = ctk.CTkFrame(self.sessions_tab)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.sessions_list = tk.Listbox(
            main_frame,
            selectmode=tk.SINGLE,
            font=("Courier", 10),
            background="#2b2b2b",
            foreground="#ffffff",
            selectbackground="#404040"
        )
        self.sessions_list.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.sessions_list.yview)
        scrollbar.pack(side="right", fill="y")
        self.sessions_list.configure(yscrollcommand=scrollbar.set)

        buttons_frame = ctk.CTkFrame(self.sessions_tab)
        buttons_frame.pack(fill="x", padx=5, pady=5)

        ctk.CTkButton(buttons_frame, text="Refresh", command=self._refresh_sessions).pack(side="left", padx=5)
        ctk.CTkButton(buttons_frame, text="Terminate Session", command=self._terminate_session).pack(side="left", padx=5)
        ctk.CTkButton(buttons_frame, text="View Details", command=self._view_session_details).pack(side="left", padx=5)

    def _load_modules_async(self):
        """Loads modules (exploits, payloads, auxiliaries) in a separate thread."""
        def load():
            try:
                self.exploit_modules = self.msf_manager.list_exploits()
                self._update_module_list("exploit")

                self.payload_modules = self.msf_manager.list_payloads()
                self._update_module_list("payload")

                self.auxiliary_modules = self.msf_manager.list_auxiliary()
                self._update_module_list("auxiliary")

            except Exception as e:
                self.logger.error(f"Error loading modules: {e}")

        threading.Thread(target=load, daemon=True).start()

    def _update_module_list(self, module_type):
        """Refreshes the list in the UI."""
        modules_list = getattr(self, f"{module_type}_list", None)
        modules = getattr(self, f"{module_type}_modules", [])

        if modules_list:
            modules_list.delete(0, tk.END)
            for m in modules:
                modules_list.insert(tk.END, m)

    def _start_status_monitoring(self):
        """Monitors Metasploit status."""
        def monitor():
            try:
                # is_connected() should be a method returning True/False
                if self.msf_manager.is_connected():
                    self.status_label.configure(text="Status: Connected", text_color="green")
                    self.reconnect_button.configure(state="disabled")
                else:
                    self.status_label.configure(text="Status: Disconnected", text_color="red")
                    self.reconnect_button.configure(state="normal")
            except Exception as e:
                self.logger.error(f"Error in monitoring: {e}")
                self.status_label.configure(text="Status: Error", text_color="red")
                self.reconnect_button.configure(state="normal")

            # Monitor again in 5s
            if not hasattr(self, '_monitoring'):
                self._monitoring = True
                self.after(5000, monitor)

        monitor()

    def _reconnect(self):
        """Reconnects to Metasploit."""
        try:
            self.status_label.configure(text="Status: Starting service...", text_color="orange")
            self.reconnect_button.configure(state="disabled")
            self.update()

            # (Optional) kill msfrpcd if running
            import subprocess
            try:
                subprocess.run(['pkill', '-f', 'msfrpcd'], capture_output=True)
                self.update()
                self.status_label.configure(text="Status: Stopping previous service...")
                time.sleep(2)
            except Exception:
                pass

            if self.msf_manager.connect():
                self.status_label.configure(text="Status: Connected", text_color="green")
                self.after(1000, self._load_modules_async)
            else:
                self.status_label.configure(text="Status: Error connecting", text_color="red")

        except Exception as e:
            self.logger.error(f"Error reconnecting: {e}")
            self.status_label.configure(text=f"Status: Error - {str(e)}", text_color="red")
        finally:
            self.reconnect_button.configure(state="normal")

    def _refresh_sessions(self):
        """Refreshes the list of active sessions."""
        try:
            sessions = self.msf_manager.get_sessions()
            self.sessions_list.delete(0, tk.END)
            for sid, data in sessions.items():
                info = f"[{sid}] {data.get('type', 'Unknown')} - {data.get('info', 'No info')}"
                self.sessions_list.insert(tk.END, info)

            self.active_sessions = sessions
            self.after(5000, self._refresh_sessions)

        except Exception as e:
            self.logger.error(f"Error updating sessions: {e}")
            self.after(5000, self._refresh_sessions)

    def _interact_with_session(self):
        """Opens a window to interact with the selected session."""
        selection = self.sessions_list.curselection()
        if not selection:
            self.show_warning("Select a session first")
            return

        session_id = self.sessions_list.get(selection[0]).split(']')[0][1:]
        interaction_window = ctk.CTkToplevel()
        interaction_window.title(f"Session {session_id}")
        interaction_window.geometry("800x600")

        terminal = ctk.CTkTextbox(interaction_window)
        terminal.pack(fill="both", expand=True, padx=10, pady=5)

        cmd_frame = ctk.CTkFrame(interaction_window)
        cmd_frame.pack(fill="x", padx=10, pady=5)

        cmd_entry = ctk.CTkEntry(cmd_frame)
        cmd_entry.pack(side="left", fill="x", expand=True)

        def send_command():
            cmd = cmd_entry.get()
            if cmd:
                try:
                    output = self.msf_manager.execute_session_command(session_id, cmd)
                    terminal.insert("end", f"\n{output}")
                    terminal.see("end")
                    cmd_entry.delete(0, "end")
                    self._log(f"Command in session {session_id}: {cmd}")
                except Exception as e:
                    self.show_error(f"Error executing command: {str(e)}")

        send_button = ctk.CTkButton(cmd_frame, text="Send", command=send_command)
        send_button.pack(side="right", padx=5)

        self.info_windows.append(interaction_window)

    def _terminate_session(self):
        """Terminates the selected session."""
        selection = self.sessions_list.curselection()
        if not selection:
            self.show_warning("Select a session first")
            return

        session_id = self.sessions_list.get(selection[0]).split(']')[0][1:]

        if messagebox.askyesno("Confirm", f"Are you sure you want to terminate session {session_id}?"):
            try:
                self.msf_manager.terminate_session(session_id)
                self._refresh_sessions()
                self._log(f"Session {session_id} terminated")
            except Exception as e:
                self.show_error(f"Error terminating session: {str(e)}")

    def _view_session_details(self):
        """Shows details of the selected session."""
        selection = self.sessions_list.curselection()
        if not selection:
            self.show_warning("Select a session first")
            return

        session_id = self.sessions_list.get(selection[0]).split(']')[0][1:]
        session_info = self.active_sessions.get(session_id, {})

        details_window = ctk.CTkToplevel()
        details_window.title(f"Session Details {session_id}")
        details_window.geometry("600x400")

        details_frame = ctk.CTkScrollableFrame(details_window)
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)

        for key, value in session_info.items():
            label = ctk.CTkLabel(details_frame, text=f"{key}: {value}", justify="left", anchor="w")
            label.pack(fill="x", padx=5, pady=2)

        self.info_windows.append(details_window)

    def _show_module_info(self, module_type, module_name):
        """Displays detailed info of a module (exploit, payload, auxiliary)."""
        if not module_name:
            self.show_error("No module selected")
            return

        try:
            info = self.msf_manager.get_module_info(module_type, module_name)
            if not info:
                self.show_error("Could not retrieve module info")
                return

            info_window = ctk.CTkToplevel(self)
            info_window.title(f"{module_type.capitalize()}: {module_name}")
            info_window.geometry("800x600")

            notebook = ttk.Notebook(info_window)
            notebook.pack(fill="both", expand=True, padx=5, pady=5)

            info_tab = ctk.CTkFrame(notebook)
            source_tab = ctk.CTkFrame(notebook)

            notebook.add(info_tab, text="Information")
            notebook.add(source_tab, text="Source Code")

            self._display_module_info(info_tab, info)
            self._display_source_code(source_tab, module_type, module_name)

            self.info_windows.append(info_window)

        except Exception as e:
            self.show_error(f"Error showing information: {str(e)}")
            self.logger.error(f"Error showing information: {e}", exc_info=True)

    def _display_module_info(self, parent, info):
        """Displays the attributes of a module."""
        main_frame = ctk.CTkScrollableFrame(parent)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        display_order = [
            ("name", "Name"),
            ("description", "Description"),
            ("rank", "Rank"),
            ("platform", "Platform"),
            ("arch", "Architecture"),
            ("author", "Author(s)"),
            ("references", "References"),
            ("targets", "Targets"),
            ("options", "Options"),
        ]

        for attr, title in display_order:
            value = info.get(attr) if isinstance(info, dict) else getattr(info, attr, None)
            if not value:
                continue

            section = ctk.CTkFrame(main_frame)
            section.pack(fill="x", pady=2, padx=5)

            header = ctk.CTkLabel(
                section,
                text=title,
                font=ctk.CTkFont(size=12, weight="bold"),
                justify="left",
                anchor="w"
            )
            header.pack(fill="x", padx=5, pady=2)

            if isinstance(value, (list, dict)):
                content = json.dumps(value, indent=2, ensure_ascii=False)
            else:
                content = str(value)

            content_label = ctk.CTkLabel(
                section,
                text=content,
                justify="left",
                anchor="w",
                wraplength=700
            )
            content_label.pack(fill="x", padx=5, pady=2)

        # Example for payload size
        size = info.get("size") if isinstance(info, dict) else getattr(info, "size", None)
        if size:
            section = ctk.CTkFrame(main_frame)
            section.pack(fill="x", pady=2, padx=5)

            header = ctk.CTkLabel(
                section,
                text="Payload Size",
                font=ctk.CTkFont(size=12, weight="bold"),
                justify="left",
                anchor="w"
            )
            header.pack(fill="x", padx=5, pady=2)

            size_info = (
                f"Total size: {size} bytes\n"
                "Note: This is the compiled payload size, not the source code.\n"
                "The payload will be generated when you run the module."
            )
            content_label = ctk.CTkLabel(
                section,
                text=size_info,
                justify="left",
                anchor="w",
                wraplength=700
            )
            content_label.pack(fill="x", padx=5, pady=2)

    def _display_source_code(self, parent, module_type, module_name):
        """Displays the module's source code or extended info."""
        if not module_name:
            self.show_warning("Select a module first")
            return

        code_window = ctk.CTkToplevel(parent)
        code_window.title(f"Source code: {module_type}/{module_name}")
        code_window.geometry("1000x700")

        main_frame = ctk.CTkFrame(code_window)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        status_frame = ctk.CTkFrame(main_frame)
        status_frame.pack(fill="x", padx=5, pady=5)

        status_label = ctk.CTkLabel(status_frame, text="Retrieving source code...", font=("Arial", 12))
        status_label.pack(side="left", padx=5)

        code_frame = ctk.CTkScrollableFrame(main_frame)
        code_frame.pack(fill="both", expand=True, padx=5, pady=5)

        source_text = ctk.CTkTextbox(code_frame, font=("Courier", 12), wrap="none")
        source_text.pack(fill="both", expand=True, padx=5, pady=5)

        try:
            if not self.msf_manager.is_connected():
                raise ConnectionError("No connection to the Metasploit Framework")

            source = self.msf_manager.get_module_source(module_type, module_name)
            if source:
                if "No se pudo obtener el código fuente" in source:
                    status_label.configure(text="⚠️ Using alternative info", text_color="orange")
                else:
                    status_label.configure(text="✅ Source code loaded", text_color="green")
                source_text.insert("1.0", source)
            else:
                status_label.configure(text="❌ Could not retrieve the source code", text_color="red")
                source_text.insert("1.0", (
                    "Could not retrieve the source code\n\n"
                    "Possible reasons: compiled module, precompiled templates, "
                    "special privileges, non-standard location, etc."
                ))
        except Exception as e:
            status_label.configure(text=f"❌ Error: {str(e)}", text_color="red")
            source_text.insert("1.0", f"Error retrieving source code:\n{str(e)}")

        source_text.configure(state="disabled")

        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(fill="x", padx=5, pady=5)

        def copy_to_clipboard():
            code_window.clipboard_clear()
            code_window.clipboard_append(source_text.get("1.0", "end-1c"))
            messagebox.showinfo("Copied", "Content copied to clipboard")

        copy_button = ctk.CTkButton(button_frame, text="📋 Copy", command=copy_to_clipboard)
        copy_button.pack(side="right", padx=5)

        def reload_source():
            source_text.configure(state="normal")
            source_text.delete("1.0", "end")
            self._display_source_code(parent, module_type, module_name)
            code_window.lift()

        reload_button = ctk.CTkButton(button_frame, text="🔄 Reload", command=reload_source)
        reload_button.pack(side="right", padx=5)

        code_window.update()
        w_width = code_window.winfo_width()
        w_height = code_window.winfo_height()
        s_width = code_window.winfo_screenwidth()
        s_height = code_window.winfo_screenheight()
        x = (s_width - w_width) // 2
        y = (s_height - w_height) // 2
        code_window.geometry(f"+{x}+{y}")

    def _execute_module(self, module_type: str, module_name: str):
        """Executes a Metasploit module."""
        if not module_name:
            self.show_warning("Select a module from the list first")
            return

        try:
            info = self.msf_manager.get_module_info(module_type, module_name)
            if not info:
                self.show_error("Could not retrieve module info")
                return
        except Exception as e:
            self.show_error(f"Error retrieving module info: {str(e)}")
            return

        config_window = ctk.CTkToplevel(self)
        config_window.title(f"Configure {module_type}: {module_name}")
        config_window.geometry("600x400")

        main_frame = ctk.CTkScrollableFrame(config_window)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        option_widgets = {}

        options = info.options
        if isinstance(options, list):
            # Convert list to dict if necessary
            options_dict = {}
            for opt in options:
                if isinstance(opt, dict):
                    name = opt.get("name", "")
                    options_dict[name] = opt
            options = options_dict

        if not options:
            ctk.CTkLabel(main_frame, text="This module has no configurable options").pack()
        else:
            for option_name, option_info in options.items():
                option_frame = ctk.CTkFrame(main_frame)
                option_frame.pack(fill="x", padx=5, pady=5)

                required = option_info.get("required", False)
                header_text = option_name
                if required:
                    header_text += " (Required)"

                header = ctk.CTkLabel(option_frame, text=header_text, font=ctk.CTkFont(weight="bold"))
                header.pack(fill="x", padx=5)

                desc = option_info.get("desc", "")
                if desc:
                    desc_label = ctk.CTkLabel(option_frame, text=desc, wraplength=550)
                    desc_label.pack(fill="x", padx=5)

                entry = ctk.CTkEntry(option_frame)
                entry.pack(fill="x", padx=5, pady=5)

                default = option_info.get("default", "")
                if default:
                    entry.insert(0, str(default))

                option_widgets[option_name] = entry

        button_frame = ctk.CTkFrame(config_window)
        button_frame.pack(fill="x", padx=10, pady=10)

        def execute():
            opts = {}
            for name, widget in option_widgets.items():
                val = widget.get().strip()
                if val:
                    opts[name] = val

            try:
                if module_type == "exploit":
                    result = self.msf_manager.execute_exploit(module_name, **opts)
                elif module_type == "payload":
                    result = self.msf_manager.execute_payload(module_name, opts)
                else:
                    result = self.msf_manager.execute_auxiliary(module_name, opts)

                messagebox.showinfo("Success", f"Module executed successfully\nResult: {result}")
            except Exception as e:
                self.show_error(f"Error executing module: {str(e)}")
            finally:
                config_window.destroy()

        ctk.CTkButton(button_frame, text="Execute", command=execute).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Cancel", command=config_window.destroy).pack(side="right", padx=5)

        self.info_windows.append(config_window)

    def _log(self, message: str):
        """Adds a message to the log and optionally to the interface."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.logger.info(message)
        if hasattr(self, "log_text"):
            self.log_text.insert("end", f"[{timestamp}] {message}\n")
            self.log_text.see("end")
