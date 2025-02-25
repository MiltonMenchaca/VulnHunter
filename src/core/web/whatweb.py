import subprocess
import re
import logging
from ..utils.validation import validate_ip_addresses, sanitize_input
import time

def retry_on_exception(max_retries=3, delay=2, allowed_exceptions=(subprocess.SubprocessError,)):
    """
    Decorator to retry a function in case of certain exceptions.

    Args:
        max_retries (int): Maximum number of retries.
        delay (int): Delay between retries in seconds.
        allowed_exceptions (tuple): Exceptions that trigger a retry.

    Returns:
        function: Decorated function with retry logic.
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

def clean_ansi_codes(text):
    """
    Removes ANSI codes (colors and styles) from text.

    Args:
        text (str): Text with ANSI codes.

    Returns:
        str: Clean text without ANSI codes.
    """
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def is_whatweb_installed():
    """
    Checks if 'whatweb' is installed on the system.

    Returns:
        bool: True if WhatWeb is installed, False otherwise.
    """
    try:
        result = subprocess.run(["which", "whatweb"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            logging.info("WhatWeb is installed.")
            return True
        else:
            logging.warning("WhatWeb was not found in PATH.")
            return False
    except subprocess.SubprocessError as e:
        logging.error(f"Subprocess error while searching for WhatWeb: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error while searching for WhatWeb: {e}")
        return False

@retry_on_exception(max_retries=3, delay=2, allowed_exceptions=(subprocess.SubprocessError,))
def run_whatweb(ip, port):
    """
    Executes WhatWeb on a specific port (ip:port).
    Returns the result with ANSI codes cleaned.

    Args:
        ip (str): IP address to scan.
        port (int): Port to scan.

    Returns:
        str: Scan result or error message.
    """
    # Validate and sanitize IP and port
    sanitized_ip = sanitize_input(ip)
    sanitized_port = sanitize_input(str(port))

    if not sanitized_ip or not sanitized_port:
        logging.error("Invalid or unsafe IP or port inputs.")
        return "[ERROR] Invalid or unsafe IP or port inputs."

    if not is_whatweb_installed():
        logging.error("WhatWeb is not installed or not found in PATH.")
        return "[ERROR] WhatWeb is not installed or not found in PATH."

    try:
        command = ["whatweb", f"{sanitized_ip}:{sanitized_port}"]
        logging.info(f"Executing WhatWeb: {' '.join(command)}")
        process = subprocess.run(command, capture_output=True, text=True)

        if process.returncode != 0:
            # An error occurred. Log stderr and return an error message.
            logging.error(f"WhatWeb failed with return code {process.returncode}, stderr={process.stderr.strip()}")
            return f"[ERROR] WhatWeb failed scanning {sanitized_ip}:{sanitized_port}: {process.stderr.strip()}"

        output = process.stdout.strip()
        if not output:
            logging.info(f"No relevant information found on {sanitized_ip}:{sanitized_port}")
            return f"No relevant information on {sanitized_ip}:{sanitized_port}"
        else:
            cleaned_output = clean_ansi_codes(output)
            logging.info(f"WhatWeb results for {sanitized_ip}:{sanitized_port}:\n{cleaned_output}")
            return cleaned_output

    except subprocess.SubprocessError as e:
        logging.error(f"Subprocess error while executing WhatWeb: {e}")
        return f"[ERROR] Subprocess error while executing WhatWeb: {e}"
    except Exception as e:
        logging.error(f"Exception while executing WhatWeb: {e}")
        return f"[ERROR] Error executing WhatWeb: {e}"
