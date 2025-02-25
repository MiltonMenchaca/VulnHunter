import customtkinter as ctk
import tkinter.messagebox as messagebox
from threading import Thread
import logging

# Adjust the import path according to your project's structure
from src.core.network.macchanger_logic import (
    generate_mac_address,
    change_mac,
    get_current_mac,
    list_interfaces,
    validate_mac_address
)

logging.basicConfig(
    filename="macchanger.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class MacChangerWindow(ctk.CTkFrame):
    """
    Frame for MacChanger, which includes:
      - A network interface selector (OptionMenu).
      - Shows the current MAC of the selected interface in a label.
      - Button to generate and change to a random MAC.
      - Field to manually enter a MAC and change to it.
      - Button to restore the original MAC if it has been saved.
      - A log of performed actions (TextBox).
    """

    def __init__(self, parent):
        super().__init__(parent)

        # Dictionaries to store the original MAC and the current MAC for each interface
        self.original_mac = {}
        self.current_mac = {}

        # List available interfaces
        self.interfaces = list_interfaces()
        if not self.interfaces:
            messagebox.showerror("Error", "No network interfaces found.")
            return

        self.interface_var = ctk.StringVar(self, value=self.interfaces[0])

        self._create_ui()

    def _create_ui(self):
        """Creates the user interface."""
        # --------------------------------------------------------------------------
        # 1) INTERFACE SELECTION
        # --------------------------------------------------------------------------
        interface_frame = ctk.CTkFrame(self)
        interface_frame.pack(padx=20, pady=10, fill="x")

        ctk.CTkLabel(
            interface_frame,
            text="Network interface:"
        ).pack(side="left", padx=5)

        interface_menu = ctk.CTkOptionMenu(
            interface_frame,
            variable=self.interface_var,
            values=self.interfaces,
            command=self._on_interface_change
        )
        interface_menu.pack(side="left", padx=5)

        # --------------------------------------------------------------------------
        # 2) SHOW CURRENT MAC
        # --------------------------------------------------------------------------
        mac_info_frame = ctk.CTkFrame(self)
        mac_info_frame.pack(padx=20, pady=10, fill="x")

        ctk.CTkLabel(
            mac_info_frame,
            text="Current MAC:"
        ).pack(side="left", padx=5)

        self.current_mac_label = ctk.CTkLabel(
            mac_info_frame,
            text="Loading..."
        )
        self.current_mac_label.pack(side="left", padx=5)

        # --------------------------------------------------------------------------
        # 3) RANDOM MAC CHANGE
        # --------------------------------------------------------------------------
        random_frame = ctk.CTkFrame(self)
        random_frame.pack(padx=20, pady=10, fill="x")

        self.random_mac_button = ctk.CTkButton(
            random_frame,
            text="Generate & Change Random MAC",
            command=self._change_random_mac
        )
        self.random_mac_button.pack(side="left", padx=5)

        # --------------------------------------------------------------------------
        # 4) MANUAL MAC CHANGE
        # --------------------------------------------------------------------------
        manual_frame = ctk.CTkFrame(self)
        manual_frame.pack(padx=20, pady=10, fill="x")

        ctk.CTkLabel(
            manual_frame,
            text="Manual MAC:"
        ).pack(side="left", padx=5)

        self.manual_mac_entry = ctk.CTkEntry(
            manual_frame,
            placeholder_text="00:11:22:33:44:55"
        )
        self.manual_mac_entry.pack(side="left", padx=5)

        self.manual_mac_button = ctk.CTkButton(
            manual_frame,
            text="Change MAC",
            command=self._change_manual_mac
        )
        self.manual_mac_button.pack(side="left", padx=5)

        # --------------------------------------------------------------------------
        # 5) RESTORE ORIGINAL MAC
        # --------------------------------------------------------------------------
        restore_frame = ctk.CTkFrame(self)
        restore_frame.pack(padx=20, pady=10, fill="x")

        self.restore_button = ctk.CTkButton(
            restore_frame,
            text="Restore Original MAC",
            command=self._restore_original_mac,
            state="disabled"
        )
        self.restore_button.pack(side="left", padx=5)

        # --------------------------------------------------------------------------
        # 6) ACTIONS LOG
        # --------------------------------------------------------------------------
        self.log_text = ctk.CTkTextbox(self, height=150)
        self.log_text.pack(padx=20, pady=10, fill="both", expand=True)

        # Initialize current MAC
        self._on_interface_change(self.interface_var.get())

    def _on_interface_change(self, interface):
        """Updates information when the interface changes."""
        try:
            # Get current MAC
            mac = get_current_mac(interface)
            self.current_mac[interface] = mac

            # If this is the first time we see this interface, save the original MAC
            if interface not in self.original_mac:
                self.original_mac[interface] = mac

            # Update UI
            self.current_mac_label.configure(text=mac)
            self.restore_button.configure(
                state="normal" if mac != self.original_mac[interface] else "disabled"
            )

            # Log
            self._log(f"Interface changed to {interface} (MAC: {mac})")

        except Exception as e:
            self._log(f"Error getting MAC of {interface}: {str(e)}")
            self.current_mac_label.configure(text="Error")

    def _change_random_mac(self):
        """Changes the MAC to a random one."""
        interface = self.interface_var.get()
        try:
            # Generate random MAC
            new_mac = generate_mac_address()

            # Try changing the MAC
            if change_mac(interface, new_mac):
                self._log(f"MAC changed to {new_mac}")
                self._on_interface_change(interface)
            else:
                raise Exception("Could not change the MAC")

        except Exception as e:
            self._log(f"Error changing MAC: {str(e)}")
            messagebox.showerror(
                "Error",
                f"Error changing MAC: {str(e)}"
            )

    def _change_manual_mac(self):
        """Changes the MAC to the one specified manually."""
        interface = self.interface_var.get()
        new_mac = self.manual_mac_entry.get().strip()

        # Validate MAC
        if not validate_mac_address(new_mac):
            messagebox.showerror(
                "Error",
                "Invalid MAC. Use the format 00:11:22:33:44:55"
            )
            return

        try:
            # Try changing the MAC
            if change_mac(interface, new_mac):
                self._log(f"MAC changed to {new_mac}")
                self._on_interface_change(interface)
            else:
                raise Exception("Could not change the MAC")

        except Exception as e:
            self._log(f"Error changing MAC: {str(e)}")
            messagebox.showerror(
                "Error",
                f"Error changing MAC: {str(e)}"
            )

    def _restore_original_mac(self):
        """Restores the original MAC of the interface."""
        interface = self.interface_var.get()
        original_mac = self.original_mac.get(interface)

        if not original_mac:
            messagebox.showerror(
                "Error",
                "Original MAC not found"
            )
            return

        try:
            # Try restoring the MAC
            if change_mac(interface, original_mac):
                self._log(f"MAC restored to {original_mac}")
                self._on_interface_change(interface)
            else:
                raise Exception("Could not restore the MAC")

        except Exception as e:
            self._log(f"Error restoring MAC: {str(e)}")
            messagebox.showerror(
                "Error",
                f"Error restoring MAC: {str(e)}"
            )

    def _log(self, message):
        """Adds a message to the log."""
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        logging.info(message)
