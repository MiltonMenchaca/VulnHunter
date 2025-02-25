import re
import ipaddress
import logging

def validate_ip_addresses(ip_range):
    """
    Validates an IP address range.
    Accepts formats such as:
    - Single IP: 192.168.1.1
    - CIDR range: 192.168.1.0/24
    - List of IPs: 192.168.1.1,192.168.1.2
    - Hyphenated range: 192.168.1.1-192.168.1.10
    """
    try:
        # If it is a CIDR address
        if '/' in ip_range:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        # If it is a comma-separated list of IPs
        elif ',' in ip_range:
            for ip in ip_range.split(','):
                ipaddress.ip_address(ip.strip())
            return True
        # If it is a hyphenated range
        elif '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            ipaddress.ip_address(start_ip.strip())
            ipaddress.ip_address(end_ip.strip())
            return True
        # If it is a single IP
        else:
            ipaddress.ip_address(ip_range)
            return True
    except ValueError as e:
        logging.error(f"Error validating IP: {str(e)}")
        return False

def validate_port_range(port_range):
    """
    Validates a port range.
    Accepts formats such as:
    - Single port: 80
    - Port range: 80-100
    - List of ports: 80,443,8080
    """
    try:
        # If it is a hyphenated range
        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                return False
        # If it is a comma-separated list of ports
        elif ',' in port_range:
            for port in port_range.split(','):
                port = int(port.strip())
                if not 1 <= port <= 65535:
                    return False
        # If it is a single port
        else:
            port = int(port_range)
            if not 1 <= port <= 65535:
                return False
        return True
    except ValueError:
        return False

def sanitize_input(input_str):
    """
    Sanitizes the user input to prevent command injection.
    """
    # Allowed characters list
    allowed_pattern = r'^[a-zA-Z0-9\s\-\.,_/]+$'
    if not re.match(allowed_pattern, input_str):
        logging.warning(f"Potentially dangerous input detected: {input_str}")
        return False
    return True

def escape_special_characters(input_str):
    """
    Escapes special characters in the user input.
    """
    return re.escape(input_str)
