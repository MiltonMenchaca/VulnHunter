"""
Helper utilities for VulnHunter.
This module provides common utility functions used throughout the application.
"""

import os
import re
import sys
import time
import random
import string
import logging
import platform
import subprocess
import urllib.parse
from datetime import datetime
from pathlib import Path

# Ensure the project's root directory is in PYTHONPATH
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.config import (
    LOGS_DIR, REPORTS_DIR, PAYLOADS_DIR, TEMP_DIR,
    DEFAULT_ENCODING, DEFAULT_TIMEOUT
)

def ensure_dir_exists(directory):
    """
    Ensure that a directory exists, creating it if necessary.
    
    Args:
        directory (str or Path): The directory path to check/create.
    
    Returns:
        Path: The Path object of the directory.
    """
    dir_path = Path(directory)
    os.makedirs(dir_path, exist_ok=True)
    return dir_path

def generate_random_string(length=10, include_special=False):
    """
    Generate a random string of specified length.
    
    Args:
        length (int): Length of the string to generate.
        include_special (bool): Whether to include special characters.
    
    Returns:
        str: A random string.
    """
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += string.punctuation
    
    return ''.join(random.choice(chars) for _ in range(length))

def generate_timestamp(format_str="%Y%m%d_%H%M%S"):
    """
    Generate a timestamp string.
    
    Args:
        format_str (str): Format string for the timestamp.
    
    Returns:
        str: Formatted timestamp.
    """
    return datetime.now().strftime(format_str)

def sanitize_filename(filename):
    """
    Sanitize a filename by removing invalid characters.
    
    Args:
        filename (str): The filename to sanitize.
    
    Returns:
        str: Sanitized filename.
    """
    # Replace invalid characters with underscore
    return re.sub(r'[\\/*?:"<>|]', "_", filename)

def get_file_extension(filename):
    """
    Get the extension of a file.
    
    Args:
        filename (str): The filename.
    
    Returns:
        str: The file extension.
    """
    return os.path.splitext(filename)[1].lower()

def is_valid_url(url):
    """
    Check if a URL is valid.
    
    Args:
        url (str): The URL to check.
    
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    if not url:
        return False
    
    # Basic URL validation
    url_pattern = re.compile(
        r'^(?:http|https)://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))

def normalize_url(url):
    """
    Normalize a URL by ensuring it has a scheme and handling trailing slashes.
    
    Args:
        url (str): The URL to normalize.
    
    Returns:
        str: Normalized URL.
    """
    if not url:
        return ""
    
    # Add http:// if no scheme is present
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Parse the URL
    parsed = urllib.parse.urlparse(url)
    
    # Reconstruct the URL with normalized components
    return urllib.parse.urlunparse(parsed)

def get_domain_from_url(url):
    """
    Extract the domain from a URL.
    
    Args:
        url (str): The URL.
    
    Returns:
        str: The domain.
    """
    if not url:
        return ""
    
    # Normalize the URL first
    url = normalize_url(url)
    
    # Parse the URL
    parsed = urllib.parse.urlparse(url)
    
    # Return the netloc (domain)
    return parsed.netloc

def get_base_url(url):
    """
    Get the base URL (scheme + domain) from a URL.
    
    Args:
        url (str): The URL.
    
    Returns:
        str: The base URL.
    """
    if not url:
        return ""
    
    # Normalize the URL first
    url = normalize_url(url)
    
    # Parse the URL
    parsed = urllib.parse.urlparse(url)
    
    # Return the scheme + netloc (base URL)
    return f"{parsed.scheme}://{parsed.netloc}"

def is_ip_address(host):
    """
    Check if a host is an IP address.
    
    Args:
        host (str): The host to check.
    
    Returns:
        bool: True if the host is an IP address, False otherwise.
    """
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return bool(ip_pattern.match(host))

def format_time_delta(seconds):
    """
    Format a time delta in seconds to a human-readable string.
    
    Args:
        seconds (float): Time in seconds.
    
    Returns:
        str: Formatted time string.
    """
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.2f} hours"

def get_system_info():
    """
    Get system information.
    
    Returns:
        dict: System information.
    """
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
        "username": os.getlogin() if hasattr(os, 'getlogin') else "unknown",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

def run_command(command, timeout=DEFAULT_TIMEOUT, shell=False):
    """
    Run a system command and return the output.
    
    Args:
        command (str or list): The command to run.
        timeout (int): Timeout in seconds.
        shell (bool): Whether to run the command in a shell.
    
    Returns:
        tuple: (stdout, stderr, return_code)
    """
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=timeout)
        return_code = process.returncode
        
        return stdout, stderr, return_code
    except subprocess.TimeoutExpired:
        process.kill()
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1

def is_port_open(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Check if a port is open on a host.
    
    Args:
        host (str): The host to check.
        port (int): The port to check.
        timeout (int): Timeout in seconds.
    
    Returns:
        bool: True if the port is open, False otherwise.
    """
    import socket
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def url_encode(text):
    """
    URL encode a string.
    
    Args:
        text (str): The string to encode.
    
    Returns:
        str: URL encoded string.
    """
    return urllib.parse.quote(text)

def url_decode(text):
    """
    URL decode a string.
    
    Args:
        text (str): The string to decode.
    
    Returns:
        str: URL decoded string.
    """
    return urllib.parse.unquote(text)

def html_encode(text):
    """
    HTML encode a string.
    
    Args:
        text (str): The string to encode.
    
    Returns:
        str: HTML encoded string.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def html_decode(text):
    """
    HTML decode a string.
    
    Args:
        text (str): The string to decode.
    
    Returns:
        str: HTML decoded string.
    """
    return text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")

def base64_encode(text):
    """
    Base64 encode a string.
    
    Args:
        text (str): The string to encode.
    
    Returns:
        str: Base64 encoded string.
    """
    import base64
    return base64.b64encode(text.encode(DEFAULT_ENCODING)).decode(DEFAULT_ENCODING)

def base64_decode(text):
    """
    Base64 decode a string.
    
    Args:
        text (str): The string to decode.
    
    Returns:
        str: Base64 decoded string.
    """
    import base64
    try:
        return base64.b64decode(text.encode(DEFAULT_ENCODING)).decode(DEFAULT_ENCODING)
    except:
        return ""

def md5_hash(text):
    """
    Calculate MD5 hash of a string.
    
    Args:
        text (str): The string to hash.
    
    Returns:
        str: MD5 hash.
    """
    import hashlib
    return hashlib.md5(text.encode(DEFAULT_ENCODING)).hexdigest()

def sha1_hash(text):
    """
    Calculate SHA1 hash of a string.
    
    Args:
        text (str): The string to hash.
    
    Returns:
        str: SHA1 hash.
    """
    import hashlib
    return hashlib.sha1(text.encode(DEFAULT_ENCODING)).hexdigest()

def sha256_hash(text):
    """
    Calculate SHA256 hash of a string.
    
    Args:
        text (str): The string to hash.
    
    Returns:
        str: SHA256 hash.
    """
    import hashlib
    return hashlib.sha256(text.encode(DEFAULT_ENCODING)).hexdigest()

def get_file_hash(file_path, algorithm="sha256"):
    """
    Calculate hash of a file.
    
    Args:
        file_path (str or Path): Path to the file.
        algorithm (str): Hash algorithm to use (md5, sha1, sha256).
    
    Returns:
        str: File hash.
    """
    import hashlib
    
    file_path = Path(file_path)
    if not file_path.exists() or not file_path.is_file():
        return ""
    
    if algorithm == "md5":
        hash_obj = hashlib.md5()
    elif algorithm == "sha1":
        hash_obj = hashlib.sha1()
    else:
        hash_obj = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()

def get_file_size(file_path):
    """
    Get the size of a file in bytes.
    
    Args:
        file_path (str or Path): Path to the file.
    
    Returns:
        int: File size in bytes.
    """
    file_path = Path(file_path)
    if not file_path.exists() or not file_path.is_file():
        return 0
    
    return file_path.stat().st_size

def format_file_size(size_bytes):
    """
    Format file size in bytes to a human-readable string.
    
    Args:
        size_bytes (int): File size in bytes.
    
    Returns:
        str: Formatted file size.
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def get_mime_type(file_path):
    """
    Get the MIME type of a file.
    
    Args:
        file_path (str or Path): Path to the file.
    
    Returns:
        str: MIME type.
    """
    import mimetypes
    
    file_path = Path(file_path)
    if not file_path.exists() or not file_path.is_file():
        return ""
    
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or "application/octet-stream"

def is_binary_file(file_path):
    """
    Check if a file is binary.
    
    Args:
        file_path (str or Path): Path to the file.
    
    Returns:
        bool: True if the file is binary, False otherwise.
    """
    file_path = Path(file_path)
    if not file_path.exists() or not file_path.is_file():
        return False
    
    # Check the first 1024 bytes for null bytes
    with open(file_path, "rb") as f:
        data = f.read(1024)
        return b"\x00" in data

def read_file(file_path, binary=False):
    """
    Read a file.
    
    Args:
        file_path (str or Path): Path to the file.
        binary (bool): Whether to read in binary mode.
    
    Returns:
        str or bytes: File contents.
    """
    file_path = Path(file_path)
    if not file_path.exists() or not file_path.is_file():
        return b"" if binary else ""
    
    mode = "rb" if binary else "r"
    encoding = None if binary else DEFAULT_ENCODING
    
    with open(file_path, mode, encoding=encoding) as f:
        return f.read()

def write_file(file_path, content, binary=False):
    """
    Write to a file.
    
    Args:
        file_path (str or Path): Path to the file.
        content (str or bytes): Content to write.
        binary (bool): Whether to write in binary mode.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        file_path = Path(file_path)
        
        # Create parent directories if they don't exist
        os.makedirs(file_path.parent, exist_ok=True)
        
        mode = "wb" if binary else "w"
        encoding = None if binary else DEFAULT_ENCODING
        
        with open(file_path, mode, encoding=encoding) as f:
            f.write(content)
        
        return True
    except Exception as e:
        logging.error(f"Error writing to file {file_path}: {e}")
        return False

def append_to_file(file_path, content, binary=False):
    """
    Append to a file.
    
    Args:
        file_path (str or Path): Path to the file.
        content (str or bytes): Content to append.
        binary (bool): Whether to append in binary mode.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        file_path = Path(file_path)
        
        # Create parent directories if they don't exist
        os.makedirs(file_path.parent, exist_ok=True)
        
        mode = "ab" if binary else "a"
        encoding = None if binary else DEFAULT_ENCODING
        
        with open(file_path, mode, encoding=encoding) as f:
            f.write(content)
        
        return True
    except Exception as e:
        logging.error(f"Error appending to file {file_path}: {e}")
        return False

def delete_file(file_path):
    """
    Delete a file.
    
    Args:
        file_path (str or Path): Path to the file.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        file_path = Path(file_path)
        if file_path.exists() and file_path.is_file():
            os.remove(file_path)
            return True
        return False
    except Exception as e:
        logging.error(f"Error deleting file {file_path}: {e}")
        return False

def list_files(directory, pattern=None, recursive=False):
    """
    List files in a directory.
    
    Args:
        directory (str or Path): Directory path.
        pattern (str): File pattern to match.
        recursive (bool): Whether to search recursively.
    
    Returns:
        list: List of file paths.
    """
    directory = Path(directory)
    if not directory.exists() or not directory.is_dir():
        return []
    
    if recursive:
        if pattern:
            return list(directory.glob(f"**/{pattern}"))
        else:
            return list(directory.glob("**/*"))
    else:
        if pattern:
            return list(directory.glob(pattern))
        else:
            return [f for f in directory.iterdir() if f.is_file()]

def list_directories(directory, pattern=None, recursive=False):
    """
    List subdirectories in a directory.
    
    Args:
        directory (str or Path): Directory path.
        pattern (str): Directory pattern to match.
        recursive (bool): Whether to search recursively.
    
    Returns:
        list: List of directory paths.
    """
    directory = Path(directory)
    if not directory.exists() or not directory.is_dir():
        return []
    
    if recursive:
        if pattern:
            return [d for d in directory.glob(f"**/{pattern}") if d.is_dir()]
        else:
            return [d for d in directory.glob("**/*") if d.is_dir()]
    else:
        if pattern:
            return [d for d in directory.glob(pattern) if d.is_dir()]
        else:
            return [d for d in directory.iterdir() if d.is_dir()]

def create_directory(directory):
    """
    Create a directory.
    
    Args:
        directory (str or Path): Directory path.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        directory = Path(directory)
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Error creating directory {directory}: {e}")
        return False

def delete_directory(directory, recursive=False):
    """
    Delete a directory.
    
    Args:
        directory (str or Path): Directory path.
        recursive (bool): Whether to delete recursively.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            return False
        
        if recursive:
            import shutil
            shutil.rmtree(directory)
        else:
            os.rmdir(directory)
        
        return True
    except Exception as e:
        logging.error(f"Error deleting directory {directory}: {e}")
        return False

def copy_file(source, destination):
    """
    Copy a file.
    
    Args:
        source (str or Path): Source file path.
        destination (str or Path): Destination file path.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        source = Path(source)
        destination = Path(destination)
        
        if not source.exists() or not source.is_file():
            return False
        
        # Create parent directories if they don't exist
        os.makedirs(destination.parent, exist_ok=True)
        
        import shutil
        shutil.copy2(source, destination)
        
        return True
    except Exception as e:
        logging.error(f"Error copying file from {source} to {destination}: {e}")
        return False

def move_file(source, destination):
    """
    Move a file.
    
    Args:
        source (str or Path): Source file path.
        destination (str or Path): Destination file path.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        source = Path(source)
        destination = Path(destination)
        
        if not source.exists() or not source.is_file():
            return False
        
        # Create parent directories if they don't exist
        os.makedirs(destination.parent, exist_ok=True)
        
        import shutil
        shutil.move(source, destination)
        
        return True
    except Exception as e:
        logging.error(f"Error moving file from {source} to {destination}: {e}")
        return False

def zip_files(files, zip_file):
    """
    Create a ZIP archive.
    
    Args:
        files (list): List of file paths to include.
        zip_file (str or Path): Path to the output ZIP file.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        import zipfile
        
        zip_file = Path(zip_file)
        
        # Create parent directories if they don't exist
        os.makedirs(zip_file.parent, exist_ok=True)
        
        with zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in files:
                file = Path(file)
                if file.exists() and file.is_file():
                    zf.write(file, file.name)
        
        return True
    except Exception as e:
        logging.error(f"Error creating ZIP archive {zip_file}: {e}")
        return False

def unzip_file(zip_file, extract_dir=None):
    """
    Extract a ZIP archive.
    
    Args:
        zip_file (str or Path): Path to the ZIP file.
        extract_dir (str or Path): Directory to extract to.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        import zipfile
        
        zip_file = Path(zip_file)
        
        if not zip_file.exists() or not zip_file.is_file():
            return False
        
        if extract_dir is None:
            extract_dir = zip_file.parent
        else:
            extract_dir = Path(extract_dir)
            os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_file, "r") as zf:
            zf.extractall(extract_dir)
        
        return True
    except Exception as e:
        logging.error(f"Error extracting ZIP archive {zip_file}: {e}")
        return False

def get_temp_file(prefix="tmp_", suffix=""):
    """
    Get a temporary file path.
    
    Args:
        prefix (str): Prefix for the filename.
        suffix (str): Suffix for the filename.
    
    Returns:
        Path: Path to the temporary file.
    """
    import tempfile
    
    # Create the temp directory if it doesn't exist
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    # Create a temporary file in the temp directory
    fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=TEMP_DIR)
    os.close(fd)
    
    return Path(temp_path)

def get_temp_dir(prefix="tmp_"):
    """
    Get a temporary directory path.
    
    Args:
        prefix (str): Prefix for the directory name.
    
    Returns:
        Path: Path to the temporary directory.
    """
    import tempfile
    
    # Create the temp directory if it doesn't exist
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    # Create a temporary directory in the temp directory
    temp_dir = tempfile.mkdtemp(prefix=prefix, dir=TEMP_DIR)
    
    return Path(temp_dir)

def clean_temp_files(older_than=86400):
    """
    Clean temporary files older than the specified age.
    
    Args:
        older_than (int): Age in seconds.
    
    Returns:
        int: Number of files deleted.
    """
    if not TEMP_DIR.exists() or not TEMP_DIR.is_dir():
        return 0
    
    count = 0
    current_time = time.time()
    
    for file in TEMP_DIR.iterdir():
        if file.is_file():
            file_age = current_time - file.stat().st_mtime
            if file_age > older_than:
                try:
                    os.remove(file)
                    count += 1
                except:
                    pass
    
    return count

# Initialize directories
for directory in [LOGS_DIR, REPORTS_DIR, PAYLOADS_DIR, TEMP_DIR]:
    ensure_dir_exists(directory)