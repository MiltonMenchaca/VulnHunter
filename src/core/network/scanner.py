import nmap
from src.core.web.whatweb import run_whatweb, is_whatweb_installed
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import shutil
import subprocess
from src.core.utils.utils import validate_ip_addresses, validate_port_range, sanitize_input
import yaml
import time

# Logging Configuration
logging.basicConfig(
    filename="logs/scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Load external configuration
def load_config(config_path='config/config.yaml'):
    """
    Loads configuration from a YAML file.

    Args:
        config_path (str): Path to the YAML configuration file.

    Returns:
        dict: Dictionary with the loaded configurations.
    """
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            logging.info(f"Configuration loaded from {config_path}.")
            return config
    except FileNotFoundError:
        logging.warning(f"{config_path} not found. Using default configurations.")
        return {}
    except yaml.YAMLError as e:
        logging.error(f"Error parsing {config_path}: {e}")
        return {}

config = load_config()

def which_nmap():
    """
    Checks if 'nmap' is available in the PATH.
    Returns True if found, False otherwise.

    Returns:
        bool: Installation status of Nmap.
    """
    try:
        nmap_path = shutil.which("nmap")
        if nmap_path:
            logging.info(f"Nmap is installed at: {nmap_path}")
            return True
        else:
            logging.warning("Nmap was not found in PATH.")
            return False
    except Exception as e:
        logging.error(f"Unexpected error while searching for nmap: {e}")
        return False

NMAP_INSTALLED = which_nmap()

def retry_on_exception(max_retries=3, delay=2, allowed_exceptions=(nmap.PortScannerError, subprocess.SubprocessError)):
    """
    Decorator to retry a function in case of certain exceptions.

    Args:
        max_retries (int): Maximum number of retries.
        delay (int): Delay between retries in seconds.
        allowed_exceptions (tuple): Exceptions that trigger a retry.

    Returns:
        function: The decorated function with retry logic.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_retries:
                try:
                    return func(*args, **kwargs)
                except allowed_exceptions as e:
                    attempts += 1
                    logging.warning(f"Attempt {attempts} failed for {func.__name__}: {e}")
                    time.sleep(delay)
            logging.error(f"Function {func.__name__} failed after {max_retries} attempts.")
            raise
        return wrapper
    return decorator

@retry_on_exception(max_retries=3, delay=2, allowed_exceptions=(nmap.PortScannerError, subprocess.SubprocessError))
def scan_with_http_enum(scanner, ip, port, log_message, log_error):
    """
    Executes HTTP-related Nmap scripts (http-enum, http-title, http-headers).

    Args:
        scanner (nmap.PortScanner): PortScanner instance.
        ip (str): IP address to scan.
        port (int): Port to scan.
        log_message (function): Callback for informational messages.
        log_error (function): Callback for error messages.
    """
    try:
        # -sT: TCP connect scan
        # --script: runs several HTTP-related scripts
        scanner.scan(ip, str(port), "-sT --script http-enum,http-title,http-headers")
        script_output = scanner[ip]['tcp'][port].get('script', {})
        if script_output:
            for script_name, output in script_output.items():
                description = str(output) if output else "No results"
                log_message(service=script_name, port=port, state="Info", description=description)
        else:
            log_message(service="HTTP Enum", port=port, state="Info", description=f"No advanced HTTP results found on {ip}:{port}")
    except nmap.PortScannerError as e:
        log_error(service="HTTP Enum", port=port, error_msg=f"[NMAP ERROR] HTTP script failed on {ip}:{port}: {e}")
    except Exception as e:
        log_error(service="HTTP Enum", port=port, error_msg=f"[ERROR] HTTP script failed on {ip}:{port}: {e}")

@retry_on_exception(max_retries=3, delay=2, allowed_exceptions=(nmap.PortScannerError,))
def scan_with_vuln(scanner, ip, port, log_message, log_error):
    """
    Scans for vulnerabilities on the port using Nmap's 'vuln' script.

    Args:
        scanner (nmap.PortScanner): PortScanner instance.
        ip (str): IP address to scan.
        port (int): Port to scan.
        log_message (function): Callback for informational messages.
        log_error (function): Callback for error messages.
    """
    try:
        scanner.scan(ip, str(port), "-sT --script vuln")
        script_output = scanner[ip]['tcp'][port].get('script', {})
        if script_output:
            log_message(service="Vuln", port=port, state="Info", description=f"Vulnerabilities detected on {ip}:{port}:")
            for script_name, output in script_output.items():
                description = str(output) if output else "No results"
                log_message(service=script_name, port=port, state="Info", description=description)
        else:
            log_message(service="Vuln", port=port, state="Info", description=f"No vulnerabilities found on {ip}:{port}")
    except nmap.PortScannerError as e:
        log_error(service="Vuln", port=port, error_msg=f"[NMAP ERROR] Vulnerability scan failed on {ip}:{port}: {e}")
    except Exception as e:
        log_error(service="Vuln", port=port, error_msg=f"[ERROR] Vulnerability scan failed on {ip}:{port}: {e}")

def scan_advanced_services(ip, scanner, ports, log_message, log_error):
    """
    Executes additional scans on specific services (HTTP, FTP, SSH...),
    and invokes 'scan_with_vuln' for each open port.

    Args:
        ip (str): IP address to scan.
        scanner (nmap.PortScanner): PortScanner instance.
        ports (list): List of open ports.
        log_message (function): Callback for informational messages.
        log_error (function): Callback for error messages.
    """
    for port in ports:
        if port in [80, 443]:
            log_message(service="HTTP", port=port, state="Info", description=f"Scanning HTTP/HTTPS on {ip}:{port}...")

            # WhatWeb
            if is_whatweb_installed():
                try:
                    whatweb_res = run_whatweb(ip, port)
                    description = str(whatweb_res).strip() if whatweb_res else "No results"
                    log_message(service="WhatWeb", port=port, state="Info", description=description)
                except Exception as e:
                    log_error(service="WhatWeb", port=port, error_msg=f"[ERROR] WhatWeb failed on {ip}:{port}: {e}")
            else:
                log_error(service="WhatWeb", port=port, error_msg="[ERROR] WhatWeb is not installed or not found in PATH.")

            # Nmap HTTP scripts
            scan_with_http_enum(scanner, ip, port, log_message, log_error)

        elif port == 21:  # FTP
            log_message(service="FTP", port=port, state="Info", description=f"Scanning FTP on {ip}:{port}...")
            try:
                scanner.scan(ip, str(port), "-sT --script ftp-anon")
                ftp_output = scanner[ip]['tcp'][port].get('script', {})
                if ftp_output:
                    for script_name, output in ftp_output.items():
                        description = str(output) if output else "No results"
                        log_message(service=script_name, port=port, state="Info", description=description)
                else:
                    log_message(service="FTP", port=port, state="Info", description=f"No relevant FTP scripts found on {ip}:{port}")
            except nmap.PortScannerError as e:
                log_error(service="FTP", port=port, error_msg=f"[NMAP ERROR] ftp-anon failed on {ip}:{port}: {e}")
            except Exception as e:
                log_error(service="FTP", port=port, error_msg=f"[ERROR] ftp-anon failed on {ip}:{port}: {e}")

        elif port == 22:  # SSH
            log_message(service="SSH", port=port, state="Info", description=f"Scanning SSH on {ip}:{port}...")
            try:
                scanner.scan(ip, str(port), "-sT --script ssh-hostkey")
                ssh_output = scanner[ip]['tcp'][port].get('script', {})
                if ssh_output:
                    for script_name, output in ssh_output.items():
                        description = str(output) if output else "No results"
                        log_message(service=script_name, port=port, state="Info", description=description)
                else:
                    log_message(service="SSH", port=port, state="Info", description=f"No ssh-hostkey results found on {ip}:{port}")
            except nmap.PortScannerError as e:
                log_error(service="SSH", port=port, error_msg=f"[NMAP ERROR] ssh-hostkey failed on {ip}:{port}: {e}")
            except Exception as e:
                log_error(service="SSH", port=port, error_msg=f"[ERROR] ssh-hostkey failed on {ip}:{port}: {e}")

        # Scan for vulnerabilities on each open port
        scan_with_vuln(scanner, ip, port, log_message, log_error)

@retry_on_exception(max_retries=3, delay=2, allowed_exceptions=(nmap.PortScannerError,))
def scan_single_ip(ip, port_range, log_message, log_error):
    """
    Scans a range of ports on an IP using nmap, then performs advanced scans
    on services and vulnerability scripts.

    Args:
        ip (str): IP address to scan.
        port_range (str): Port range in the format "start-end" (e.g., "1-1024").
        log_message (function): Callback for informational messages.
        log_error (function): Callback for error messages.
    """
    if not NMAP_INSTALLED:
        log_error(service="Nmap", port="-", error_msg="[ERROR] Nmap is not installed or not found in PATH.")
        return

    # Validate the IP
    valid_ips = validate_ip_addresses([ip])
    if not valid_ips:
        log_error(service="IP Validation", port="-", error_msg=f"[ERROR] Invalid IP address: {ip}")
        return

    try:
        scanner = nmap.PortScanner()
        log_message(service="Scanner", port="-", state="Info", description=f"[INFO] Scanning {ip} on port range: {port_range}...")

        # -sT: TCP connect scan
        # --unprivileged is used if not running as root
        scanner.scan(ip, port_range, "-sT --unprivileged")

        open_ports = []
        all_protocols = scanner[ip].all_protocols()
        for protocol in all_protocols:
            ports = scanner[ip][protocol].keys()
            for port in sorted(ports):
                state = scanner[ip][protocol][port]['state']
                log_message(service=f"Port {port}/{protocol}", port=port, state=state, description=f"Port {port}/{protocol}: {state}")
                if state == 'open' and protocol == 'tcp':
                    open_ports.append(port)

        if open_ports:
            # Execute additional scans
            scan_advanced_services(ip, scanner, open_ports, log_message, log_error)
        else:
            log_message(service="Scanner", port="-", state="Info", description=f"[INFO] No open ports found on {ip}.")

    except nmap.PortScannerError as e:
        log_error(service="Scanner", port="-", error_msg=f"[NMAP ERROR] Could not scan {ip}: {e}")
    except Exception as e:
        log_error(service="Scanner", port="-", error_msg=f"[ERROR] Error scanning {ip}: {e}")

def scan_ports(ip_value, port_range_value, log_message, log_error):
    """
    Executes the scan for the entered IPs (separated by commas or ranges).
    Uses ThreadPoolExecutor to handle multiple scans concurrently.

    Args:
        ip_value (str): String with IP addresses separated by commas or ranges.
        port_range_value (str): Port range in the format "start-end" (e.g., "1-1024").
        log_message (function): Callback for informational messages.
        log_error (function): Callback for error messages.
    """
    sanitized_ip_value = sanitize_input(ip_value)
    if not sanitized_ip_value:
        log_error(service="Input Sanitization", port="-", error_msg="[ERROR] IP inputs are not safe or invalid.")
        return

    ips = [ip.strip() for ip in sanitized_ip_value.split(",") if ip.strip()]
    port_range = port_range_value.strip()

    # Validate IPs and Ports
    valid_ips = validate_ip_addresses(ips)
    if not valid_ips:
        log_error(service="IP Validation", port="-", error_msg="[ERROR] No valid IP addresses to scan.")
        return

    if not validate_port_range(port_range):
        log_error(service="Port Validation", port="-", error_msg="[ERROR] The port range is invalid.")
        return

    # ThreadPoolExecutor configuration
    max_workers = config.get('max_workers', 10)
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_single_ip, ip, port_range, log_message, log_error): ip for ip in valid_ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    future.result()
                except Exception as e:
                    log_error(service="ThreadPoolExecutor", port="-", error_msg=f"[ERROR] Scan failed for {ip}: {e}")

        log_message(service="Scanner", port="-", state="Info", description="[INFO] Scan completed.")
    except Exception as e:
        log_error(service="ThreadPoolExecutor", port="-", error_msg=f"[ERROR] Error in concurrent scanning: {e}")
