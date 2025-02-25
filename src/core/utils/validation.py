"""
Validation Utilities
"""

import re
import ipaddress

def validate_ip_addresses(*ips):
    """
    Validates that the provided IP addresses are valid.
    
    Args:
        *ips: One or more IP addresses to validate.
        
    Returns:
        bool: True if all IPs are valid, False otherwise.
    """
    try:
        for ip in ips:
            ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def sanitize_input(input_str):
    """
    Sanitizes an input string to prevent injection attacks.
    
    Args:
        input_str (str): The string to sanitize.
        
    Returns:
        str: The sanitized string.
    """
    # Remove dangerous characters
    sanitized = re.sub(r'[;&|`]', '', input_str)
    
    # Escape quotes
    sanitized = sanitized.replace('"', '\\"').replace("'", "\\'")
    
    return sanitized
