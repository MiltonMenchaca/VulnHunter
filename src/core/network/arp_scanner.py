import json
import csv
import logging
import ipaddress
import socket
from typing import List, Dict, Any, Union

from fpdf import FPDF
from scapy.all import ARP, Ether, srp

# --------------------------------------------------------------------
# Optional: try to import mac-vendor-lookup and netifaces
# --------------------------------------------------------------------
try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
except ImportError:
    mac_lookup = None

try:
    import netifaces
except ImportError:
    netifaces = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def detect_local_network() -> str:
    """
    Attempts to auto-detect the local subnet using netifaces.
    Returns a string with the network (e.g., "192.168.1.0/24") or a fallback value.
    """
    if not netifaces:
        logging.warning("The 'netifaces' library is not installed. Using fallback (192.168.1.0/24).")
        return "192.168.1.0/24"

    try:
        # This depends on the interface (eth0, wlan0, etc.)
        # You could iterate over netifaces.interfaces() to find one with AF_INET
        preferred_interface = "eth0"  # Adjust according to your case. You could auto-detect this.
        addrs = netifaces.ifaddresses(preferred_interface)[netifaces.AF_INET][0]
        ip_str = addrs["addr"]         # e.g., "192.168.1.100"
        netmask_str = addrs["netmask"]   # e.g., "255.255.255.0"

        interface = ipaddress.ip_interface(ip_str + "/" + netmask_str)
        network_str = str(interface.network)  # e.g., "192.168.1.0/24"
        logging.info(f"Auto-detected local subnet: {network_str}")
        return network_str
    except Exception as e:
        logging.error(f"Could not detect local subnet: {e}. Using fallback.")
        return "192.168.1.0/24"


def arp_scan(
    network: str,
    timeout: int = 2,
    retry: int = 1,
    verbose: bool = False,
    resolve_vendor: bool = False
) -> Dict[str, Any]:
    """
    Performs an ARP scan on the provided network and returns a dict:
        {"hosts": [{"IP": ..., "MAC": ..., "Hostname": ..., "Vendor": ...}, ...]}
    or {"error": "..."} if it fails.

    :param network: Network to scan, e.g., "192.168.1.0/24". 
                    Use detect_local_network() if you wish to auto-detect it.
    :param timeout: Timeout in seconds to wait for ARP responses.
    :param retry:   Number of ARP request retries.
    :param verbose: Displays Scapy verbosity.
    :param resolve_vendor: If True, attempts to obtain the MAC vendor.
                          Requires mac-vendor-lookup to be installed.
    """
    try:
        # Validate network
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return {"error": f"Invalid network format: {network}"}

        logging.info(f"Starting ARP scan on {net}, timeout={timeout}, retry={retry}, resolve_vendor={resolve_vendor}")
        arp_request = ARP(pdst=str(net))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered, _ = srp(
            arp_request_broadcast,
            timeout=timeout,
            retry=retry,
            verbose=verbose
        )

        hosts = []
        for _, received in answered:
            ip_address = received.psrc
            mac_address = received.hwsrc

            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                hostname = ""

            # Vendor detection
            if resolve_vendor and mac_lookup:
                try:
                    vendor = mac_lookup.lookup(mac_address)
                except Exception:
                    vendor = "Unknown"
            else:
                vendor = ""

            hosts.append({
                "IP": ip_address,
                "MAC": mac_address,
                "Hostname": hostname or "Unresolved",
                "Vendor": vendor or "Unresolved"
            })

        logging.info(f"Found {len(hosts)} hosts on network {net}.")
        return {"hosts": hosts}

    except Exception as e:
        logging.error(f"Error during ARP scan: {e}")
        return {"error": str(e)}


def export_arp_to_csv(filename: str, hosts: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Exports ARP scan results to a CSV file.
    Returns {"success": True} or {"error": "..."}.
    """
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP", "MAC", "Hostname", "Vendor"])
            for host in hosts:
                writer.writerow([
                    host.get("IP", ""),
                    host.get("MAC", ""),
                    host.get("Hostname", ""),
                    host.get("Vendor", "")
                ])
        logging.info(f"ARP results exported to {filename}")
        return {"success": True}
    except Exception as e:
        logging.error(f"Error exporting to CSV: {e}")
        return {"error": str(e)}


def export_arp_to_json(filename: str, hosts: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Exports ARP scan results to a JSON file.
    Returns {"success": True} or {"error": "..."}.
    """
    try:
        with open(filename, 'w', encoding="utf-8") as jsonfile:
            json.dump(hosts, jsonfile, indent=4, ensure_ascii=False)
        logging.info(f"ARP results exported to {filename}")
        return {"success": True}
    except Exception as e:
        logging.error(f"Error exporting to JSON: {e}")
        return {"error": str(e)}


def export_arp_to_pdf(filename: str, hosts: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Exports ARP scan results to a PDF file.
    Returns {"success": True} or {"error": "..."}.
    """
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="ARP Scan Results", ln=True, align='C')
        pdf.ln(10)

        for host in hosts:
            ip = host.get('IP', 'N/A')
            mac = host.get('MAC', 'N/A')
            hostname = host.get('Hostname', 'N/A')
            vendor = host.get('Vendor', 'N/A')
            pdf.cell(200, 10, txt=f"IP: {ip} - MAC: {mac} - Hostname: {hostname} - Vendor: {vendor}", ln=True)

        pdf.output(filename)
        logging.info(f"ARP results exported to {filename}")
        return {"success": True}
    except Exception as e:
        logging.error(f"Error exporting to PDF: {e}")
        return {"error": str(e)}
