import socket
import requests
import subprocess
import re
import json
import csv
from typing import Union, List, Dict, Optional, Any
from fpdf import FPDF

try:
    import whois  # pip install python-whois
except ImportError:
    whois = None

try:
    import geoip2.database  # pip install geoip2
except ImportError:
    geoip2 = None


# --------------------------------------------------------------------------------
#                                OSINT Functions
# --------------------------------------------------------------------------------

def whois_lookup(domain_or_ip: str) -> Dict[str, Any]:
    """
    Performs a WHOIS lookup for the given domain/IP.
    Returns a dict with the results or {'error': ...} if it fails.
    """
    if not whois:
        return {"error": "The 'python-whois' library is not installed."}

    try:
        info = whois.whois(domain_or_ip)
        return dict(info)  # Convert to dict to standardize
    except Exception as e:
        return {"error": f"WHOIS lookup for {domain_or_ip} failed: {e}"}


def geoip_lookup(ip: str, geoip_db_path: str = "GeoLite2-City.mmdb") -> Dict[str, Any]:
    """
    Queries the GeoLite2 database to obtain country, city, and lat/long for the IP.
    Returns {'error': ...} if it fails.
    """
    if not geoip2:
        return {"error": "The 'geoip2' library is not installed."}

    try:
        reader = geoip2.database.Reader(geoip_db_path)
        response = reader.city(ip)
        data = {
            "country": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude
        }
        reader.close()
        return data
    except Exception as e:
        return {"error": f"GeoIP lookup for {ip} failed: {e}"}


def dns_subdomain_lookup(domain: str, subdomains_list: List[str]) -> List[Dict[str, str]]:
    """
    Attempts to resolve a list of subdomains for the given 'domain'.
    Returns [{ 'subdomain': ..., 'ip': ... }, ...].
    """
    found_subdomains = []
    for subd in subdomains_list:
        host = f"{subd}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found_subdomains.append({"subdomain": host, "ip": ip})
        except socket.gaierror:
            pass
    return found_subdomains


def reverse_ip_lookup(ip: str) -> Union[str, Dict[str, str], None]:
    """
    Performs a reverse DNS lookup.
    Returns the hostname (str), None if unresolved,
    or {'error': ...} if an error occurs.
    """
    try:
        result = socket.gethostbyaddr(ip)
        host = result[0]
        return host
    except socket.herror:
        return None
    except Exception as e:
        return {"error": f"Error in reverse lookup for {ip}: {e}"}


def shodan_lookup(ip: str, api_key: str) -> Dict[str, Any]:
    """
    Calls the Shodan API to obtain information for the given 'ip'.
    Returns a dict with the information or {'error': ...}.
    """
    if not ip:
        return {"error": "No IP specified for Shodan."}
    if not api_key:
        return {"error": "Shodan API Key not provided."}

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"Shodan returned code {resp.status_code}: {resp.text}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Error connecting to Shodan for {ip}: {e}"}


# --------------------------------------------------------------------------------
#                    Additional Integrations
# --------------------------------------------------------------------------------

def theharvester_lookup(domain: str, limit: int = 100, use_dork: bool = False,
                        source: str = "all") -> Dict[str, Any]:
    """
    Calls theHarvester via CLI to gather information for the given 'domain'.
    - limit: maximum number of results to collect.
    - use_dork: if True, uses 'dork' mode in theHarvester.
    - source: 'all' for all sources, or specify one like 'google', 'bing', etc.

    Returns a dict with 'emails' (list) and 'hosts' (list) if successful,
    or {'error': ...} if it could not be executed.
    
    Requires theHarvester to be installed and accessible in PATH.
    """
    # theHarvester is executed, for example, with:
    # theHarvester -d example.com -l 100 -b all
    # if using dork: theHarvester -d example.com -l 100 -b all -e
    cmd = ["theHarvester",
           "-d", domain,
           "-l", str(limit),
           "-b", source]

    if use_dork:
        cmd.append("-e")  # Enable dork mode

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"error": f"theHarvester returned code {result.returncode}: {result.stderr}"}

        # Parse output to extract emails and hosts.
        emails = []
        hosts = []

        output_lines = result.stdout.splitlines()
        for line in output_lines:
            # Example email line: "[+] Email found: admin@example.com"
            if "Email found:" in line:
                email = line.split("Email found:")[-1].strip()
                emails.append(email)
            # Example host line: "[*] IP: 93.184.216.34 \tHost: example.com"
            if line.startswith("[*] IP:"):
                # Look for an IP and a host in the line
                match = re.search(r"\bIP:\s*([\d\.]+).+Host:\s*(\S+)", line)
                if match:
                    ip_found, host_found = match.group(1), match.group(2)
                    hosts.append({"ip": ip_found, "host": host_found})

        return {"emails": emails, "hosts": hosts}

    except FileNotFoundError:
        return {"error": "theHarvester is not installed or not found in PATH."}
    except subprocess.TimeoutExpired:
        return {"error": "theHarvester took too long to respond (timeout)."}
    except Exception as e:
        return {"error": f"Error executing theHarvester: {e}"}


def sublist3r_lookup(domain: str, threads: int = 30, ports: str = None) -> Dict[str, Any]:
    """
    Calls sublist3r via CLI to enumerate subdomains of the given 'domain'.
    - threads: number of threads to use.
    - ports: if specified (e.g., "80,443"), sublist3r performs a quick scan on those ports.

    Returns {'subdomains': [...]} with the list of found subdomains,
    or {'error': ...} if it could not be executed.

    Requires sublist3r to be installed and accessible in PATH.
    """
    cmd = ["sublist3r", "-d", domain, "-t", str(threads)]
    if ports:
        cmd += ["-p", ports]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"error": f"Sublist3r returned code {result.returncode}: {result.stderr}"}

        # Sublist3r generally prints subdomains at the end of the output
        # and sometimes creates a file on disk. We parse result.stdout:
        subdomains = []
        output_lines = result.stdout.splitlines()
        # Subdomains typically appear in a format like:
        # "Subdomain found: sub.example.com"
        for line in output_lines:
            if "Subdomain found:" in line:
                found_sub = line.split("Subdomain found:")[-1].strip()
                subdomains.append(found_sub)

        return {"subdomains": subdomains}

    except FileNotFoundError:
        return {"error": "sublist3r is not installed or not found in PATH."}
    except subprocess.TimeoutExpired:
        return {"error": "Sublist3r took too long to respond (timeout)."}
    except Exception as e:
        return {"error": f"Error executing Sublist3r: {e}"}


# --------------------------------------------------------------------------------
#                    Common Commands and Exports
# --------------------------------------------------------------------------------

def get_osint_commands() -> List[str]:
    """
    Returns a list of common OSINT tool names,
    including theHarvester and sublist3r.
    """
    return [
        "whois",
        "nslookup",
        "theHarvester",
        "Maltego",
        "Shodan",
        "sublist3r",
    ]


def export_osint_to_csv(filename: str, data: Dict[str, Any]) -> None:
    """
    Exports OSINT results to a simple CSV file.
    """
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Type", "Source", "Information"])
            for key, results in data.items():
                if isinstance(results, list):
                    for entry in results:
                        if isinstance(entry, dict):
                            for sub_key, sub_val in entry.items():
                                writer.writerow([key, sub_key, sub_val])
                        else:
                            writer.writerow([key, "Result", entry])
                elif isinstance(results, dict):
                    for sub_key, sub_val in results.items():
                        writer.writerow([key, sub_key, sub_val])
                else:
                    writer.writerow([key, "Result", results])
        print(f"[+] OSINT results exported to {filename}")
    except Exception as e:
        print(f"[-] Error exporting to CSV ({filename}): {e}")


def export_osint_to_json(filename: str, data: Dict[str, Any]) -> None:
    """
    Exports OSINT results to a JSON file.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=4, ensure_ascii=False)
        print(f"[+] OSINT results exported to {filename}")
    except Exception as e:
        print(f"[-] Error exporting to JSON ({filename}): {e}")


def export_osint_to_pdf(filename: str, data: Dict[str, Any]) -> None:
    """
    Exports OSINT results to a PDF file (using FPDF).
    """
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="OSINT Attack Results", ln=True, align='C')
        pdf.ln(10)

        for key, results in data.items():
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(200, 10, txt=str(key), ln=True)
            pdf.set_font("Arial", size=12)

            if isinstance(results, list):
                for entry in results:
                    if isinstance(entry, dict):
                        for sub_key, sub_val in entry.items():
                            pdf.cell(200, 10, txt=f"  {sub_key}: {sub_val}", ln=True)
                    else:
                        pdf.cell(200, 10, txt=f"  {entry}", ln=True)
            elif isinstance(results, dict):
                for sub_key, sub_val in results.items():
                    pdf.cell(200, 10, txt=f"  {sub_key}: {sub_val}", ln=True)
            else:
                pdf.cell(200, 10, txt=f"  {results}", ln=True)

            pdf.ln(5)

        pdf.output(filename)
        print(f"[+] OSINT results exported to {filename}")
    except Exception as e:
        print(f"[-] Error exporting to PDF ({filename}): {e}")
