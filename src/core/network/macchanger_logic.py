import subprocess
import random
import re
import platform
import logging
import os
import time

try:
    import netifaces
except ImportError:
    netifaces = None

logging.basicConfig(
    filename="macchanger.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def is_linux():
    """Checks if the operating system is Linux."""
    return platform.system().lower() == "linux"

def is_root():
    """
    Checks if the process is running with root privileges (Unix only).
    On Windows, os.geteuid() does not exist.
    """
    if hasattr(os, "geteuid"):
        return (os.geteuid() == 0)
    return False

def validate_mac_address(mac: str) -> bool:
    """Validates whether the MAC address is in the format XX:XX:XX:XX:XX:XX (hex)."""
    pattern = r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$"
    return bool(re.match(pattern, mac))

def generate_mac_address() -> str:
    """
    Generates a random valid MAC address.
    Ensures that it is a locally administered MAC (bit 1 in the first byte) and not multicast (bit 0).
    """
    # Byte 0: 0x02 => locally assigned (bit 1 = 1), unicast (bit 0 = 0)
    mac = [
        0x02,
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
    ]
    return ":".join(f"{x:02x}" for x in mac)

def run_command(cmd: list) -> str:
    """
    Executes a command using subprocess and returns stdout if returncode=0, or None if an error occurs.
    Also logs stderr and the returncode for diagnostics.
    """
    logging.debug(f"Executing command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error(
                f"Error executing {cmd} (returncode={result.returncode}): "
                f"stderr='{result.stderr.strip()}'"
            )
            return None
    except FileNotFoundError as e:
        logging.error(f"Command not found: {cmd[0]} - {e}")
        return None

def get_current_mac(interface: str) -> str:
    """
    Obtains the current MAC address of an interface using 'ip link' or 'ifconfig' as fallback.
    Returns the MAC in the format XX:XX:XX:XX:XX:XX, or None if it fails.
    """
    if not is_linux():
        logging.warning("get_current_mac is only supported on Linux.")
        return None

    if not is_root():
        logging.warning("Root privileges not available to read the MAC (may fail).")

    # 1) Try with 'ip link'
    cmd_ip = ["ip", "link", "show", interface]
    output = run_command(cmd_ip)
    if output:
        match = re.search(r"link/ether\s+([0-9A-Fa-f:]{17})", output)
        if match:
            return match.group(1)

    # 2) Try with ifconfig
    cmd_ifconfig = ["ifconfig", interface]
    output = run_command(cmd_ifconfig)
    if output:
        match = re.search(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", output)
        if match:
            return match.group(1)

    logging.error(f"Could not read the MAC address of {interface}.")
    return None

def change_mac(interface: str, new_mac: str) -> bool:
    """
    Changes the MAC address of an interface on Linux.
    Returns True if the change is successful, False if an error occurs.
    Includes a 1-second pause after bringing the interface up.
    """
    if not is_linux():
        logging.warning("MAC change is only supported on Linux.")
        return False

    if not is_root():
        logging.error("Root privileges are required to change the MAC.")
        return False

    if not validate_mac_address(new_mac):
        logging.error(f"MAC '{new_mac}' is not valid.")
        return False

    logging.info(f"Requesting MAC change on {interface} to {new_mac}")

    # 1) ip link set <iface> down
    down_cmd = ["ip", "link", "set", interface, "down"]
    if not run_command(down_cmd):
        logging.error(f"Could not bring down interface {interface}.")
        return False

    # 2) ip link set <iface> address <mac>
    hw_cmd = ["ip", "link", "set", interface, "address", new_mac]
    if not run_command(hw_cmd):
        logging.error(f"Could not change the MAC of {interface} to {new_mac}.")
        return False

    # 3) ip link set <iface> up
    up_cmd = ["ip", "link", "set", interface, "up"]
    if not run_command(up_cmd):
        logging.error(f"Could not bring up interface {interface}.")
        return False

    # Pause for 1 second to allow the system to settle the change
    time.sleep(1)

    # Verify MAC after the change
    after_mac = get_current_mac(interface)
    if after_mac and after_mac.lower() == new_mac.lower():
        logging.info(f"MAC of {interface} successfully changed to {new_mac}.")
        return True
    else:
        logging.warning(
            f"MAC of {interface} was not updated (obtained={after_mac}, expected={new_mac})."
        )
        return False

def list_interfaces() -> list:
    """
    Lists all available network interfaces.
    Uses netifaces if installed; otherwise, uses 'ip link'.
    Excludes 'lo' and others you might wish to exclude (modify if using Docker, etc.).
    """
    if not is_linux():
        logging.warning("list_interfaces is only supported on Linux.")
        return []

    # Check if 'ip' is available:
    which_ip = subprocess.run(["which", "ip"], capture_output=True, text=True)
    if which_ip.returncode != 0:
        logging.warning("'ip' not found in PATH. Is it installed?")

    if netifaces:
        all_ifaces = netifaces.interfaces()
        # Filter out 'lo'
        filtered = [i for i in all_ifaces if i not in ('lo',)]
        if not filtered:
            logging.warning("No network interfaces found or only 'lo' (netifaces).")
        return filtered
    else:
        output = run_command(["ip", "link", "show"])
        if not output:
            return []
        # Find interface names: e.g., "2: ens33: <..."
        found = re.findall(r"^\d+:\s+([^:]+):", output, re.MULTILINE)
        filtered = [iface for iface in found if iface not in ("lo",)]
        if not filtered:
            logging.warning("No interfaces found (or only 'lo') with 'ip link show'.")
        return filtered
