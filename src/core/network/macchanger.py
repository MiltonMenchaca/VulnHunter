import customtkinter as ctk
from tkinter import messagebox
import platform
import logging

from src.core.network.macchanger_logic import (
    generate_mac_address,
    change_mac,
    get_current_mac,
    list_interfaces,
    validate_mac_address,
    is_root
)

logging.basicConfig(
    filename="macchanger.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def mac_changer_window():
    """
    Creates an independent window (Toplevel) for changing the MAC address.
    Handles:
        - Interface selection (list_interfaces)
        - Displays the current MAC
        - Generates a random MAC
        - Changes to a manually entered MAC
        - Restores the original MAC (if saved at start)
        - Verifies that the user is root before proceeding
    """
    # Verify if the system is Linux:
    if platform.system().lower() != "linux":
        messagebox.showerror("Not Supported", "MAC changing is only available on Linux.")
        return

    # Verify if running as root
    if not is_root():
        messagebox.showerror("Insufficient Permissions", 
                             "Root privileges are required to change the MAC.\n"
                             "Run with: sudo python main.py")
        return

    window = ctk.CTkToplevel()
    window.title("MAC Address Changer")
    window.geometry("460x480")

    # Dictionaries to store the original and current MAC addresses
    original_mac = {}
    current_mac = {}

    # 1) INTERFACE LIST
    interfaces = list_interfaces()
    if not interfaces:
        messagebox.showerror("Error", "No network interfaces were found.")
        window.destroy()
        return

    interface_var = ctk.StringVar(value=interfaces[0])

    # Label + OptionMenu
    ctk.CTkLabel(window, text="Select an interface:").pack(pady=(15, 5))
    interface_menu = ctk.CTkOptionMenu(
        master=window,
        variable=interface_var,
        values=interfaces,
        width=200
    )
    interface_menu.pack(pady=5)

    # Label for current MAC
    current_mac_label = ctk.CTkLabel(window, text="Current MAC: -")
    current_mac_label.pack(pady=(5, 10))

    def update_current_mac():
        iface = interface_var.get()
        c_mac = get_current_mac(iface)
        if c_mac:
            current_mac_label.configure(text=f"Current MAC: {c_mac}")
        else:
            current_mac_label.configure(text="Current MAC: (not available)")

    def on_iface_change(*args):
        update_current_mac()

    interface_var.trace("w", on_iface_change)

    # Initialize label with the current MAC
    for iface in interfaces:
        mac = get_current_mac(iface)
        if mac:
            # Save the original MAC
            original_mac[iface] = mac
    update_current_mac()

    # Log field
    log_label = ctk.CTkLabel(window, text="Action Log:")
    log_label.pack(pady=(5, 5))

    # (Optionally, you could add a TextBox to view logs with scrolling)

    # Button to generate and change to a random MAC
    def change_mac_random():
        iface = interface_var.get()
        new_mac = generate_mac_address()
        if not messagebox.askyesno(
            "Confirm",
            f"Change the MAC of {iface} to\n{new_mac}?"
        ):
            return
        ok = change_mac(iface, new_mac)
        if ok:
            messagebox.showinfo("Success", f"The MAC of {iface} was changed to {new_mac}")
        else:
            messagebox.showerror("Error", f"Could not change the MAC of {iface}.")
        update_current_mac()

    ctk.CTkButton(
        window,
        text="Generate Random MAC",
        command=change_mac_random
    ).pack(pady=10)

    # Field for manual MAC entry
    ctk.CTkLabel(window, text="Enter a manual MAC:").pack()
    manual_mac_var = ctk.StringVar()
    manual_mac_entry = ctk.CTkEntry(
        window,
        textvariable=manual_mac_var,
        width=200,
        placeholder_text="AA:BB:CC:DD:EE:FF"
    )
    manual_mac_entry.pack(pady=5)

    def set_manual_mac():
        iface = interface_var.get()
        manual_mac = manual_mac_var.get().strip()
        if not validate_mac_address(manual_mac):
            messagebox.showerror("Error", f"The MAC '{manual_mac}' is not valid.")
            return
        if not messagebox.askyesno(
            "Confirm",
            f"Change the MAC of {iface} to\n{manual_mac}?"
        ):
            return
        ok = change_mac(iface, manual_mac)
        if ok:
            messagebox.showinfo("Success", f"The MAC of {iface} was changed to {manual_mac}")
        else:
            messagebox.showerror("Error", f"Could not change the MAC of {iface}.")
        update_current_mac()

    ctk.CTkButton(
        window,
        text="Change to Entered MAC",
        command=set_manual_mac
    ).pack(pady=10)

    # Restore original MAC
    def restore_mac():
        iface = interface_var.get()
        orig = original_mac.get(iface, None)
        if not orig:
            messagebox.showwarning("Warning", f"No original MAC saved for {iface}.")
            return
        if not messagebox.askyesno(
            "Confirm",
            f"Restore the original MAC of {iface} to\n{orig}?"
        ):
            return
        ok = change_mac(iface, orig)
        if ok:
            messagebox.showinfo("Success", f"The MAC of {iface} was restored to {orig}")
        else:
            messagebox.showerror("Error", f"Could not restore the original MAC of {iface}")
        update_current_mac()

    ctk.CTkButton(
        window,
        text="Restore Original MAC",
        command=restore_mac
    ).pack(pady=10)

    window.mainloop()
