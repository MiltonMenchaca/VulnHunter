"""
Configuration settings for VulnHunter.
This module defines global configuration settings and paths.
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent
PROJECT_ROOT = BASE_DIR.parent

# Directory for storing logs
LOGS_DIR = PROJECT_ROOT / "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# Directory for storing reports
REPORTS_DIR = PROJECT_ROOT / "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Directory for storing payloads
PAYLOADS_DIR = PROJECT_ROOT / "payloads"
os.makedirs(PAYLOADS_DIR, exist_ok=True)

# Directory for storing temporary files
TEMP_DIR = PROJECT_ROOT / "temp"
os.makedirs(TEMP_DIR, exist_ok=True)

# Log file path
LOG_FILE = LOGS_DIR / "vulnhunter.log"

# Default report template
REPORT_TEMPLATE = BASE_DIR / "templates" / "report_template.html"

# Default user agent for HTTP requests
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Default timeout for HTTP requests (in seconds)
DEFAULT_TIMEOUT = 10

# Default number of threads for concurrent operations
DEFAULT_THREADS = 5

# Default delay between requests (in seconds)
DEFAULT_DELAY = 0.5

# Maximum number of redirects to follow
MAX_REDIRECTS = 5

# Default encoding for file operations
DEFAULT_ENCODING = "utf-8"

# Default verbosity level (0-3)
DEFAULT_VERBOSITY = 1

# Default theme (dark or light)
DEFAULT_THEME = "dark"

# Default language
DEFAULT_LANGUAGE = "en"

# Default port for local server
DEFAULT_PORT = 8080

# Default IP for local server
DEFAULT_IP = "127.0.0.1"

# Default maximum file size for uploads (in bytes)
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

# Default maximum memory usage (in bytes)
MAX_MEMORY_USAGE = 512 * 1024 * 1024  # 512 MB

# Default maximum disk usage (in bytes)
MAX_DISK_USAGE = 1024 * 1024 * 1024  # 1 GB

# Default maximum CPU usage (in percentage)
MAX_CPU_USAGE = 80  # 80%

# Default maximum number of requests per second
MAX_REQUESTS_PER_SECOND = 10

# Default maximum number of concurrent connections
MAX_CONCURRENT_CONNECTIONS = 10

# Default maximum number of retries for failed requests
MAX_RETRIES = 3

# Default retry delay (in seconds)
RETRY_DELAY = 1

# Default proxy settings
DEFAULT_PROXY = None

# Default SSL verification
VERIFY_SSL = True

# Default headers for HTTP requests
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0"
}

# Default cookies for HTTP requests
DEFAULT_COOKIES = {}

# Default authentication settings
DEFAULT_AUTH = None

# Default content type for HTTP requests
DEFAULT_CONTENT_TYPE = "application/x-www-form-urlencoded"

# Default character set for HTTP requests
DEFAULT_CHARSET = "utf-8"

# Default timeout for database operations (in seconds)
DB_TIMEOUT = 30

# Default database path
DB_PATH = PROJECT_ROOT / "db" / "vulnhunter.db"
os.makedirs(DB_PATH.parent, exist_ok=True)

# Default database type
DB_TYPE = "sqlite"

# Default database name
DB_NAME = "vulnhunter"

# Default database user
DB_USER = "vulnhunter"

# Default database password
DB_PASSWORD = "vulnhunter"

# Default database host
DB_HOST = "localhost"

# Default database port
DB_PORT = 3306

# Default database connection string
DB_CONNECTION_STRING = f"sqlite:///{DB_PATH}"

# Default maximum number of database connections
DB_MAX_CONNECTIONS = 10

# Default maximum number of database retries
DB_MAX_RETRIES = 3

# Default database retry delay (in seconds)
DB_RETRY_DELAY = 1

# Default maximum number of database results
DB_MAX_RESULTS = 1000

# Default maximum number of database query execution time (in seconds)
DB_MAX_QUERY_TIME = 30

# Default maximum number of database transaction time (in seconds)
DB_MAX_TRANSACTION_TIME = 60

# Default maximum number of database idle time (in seconds)
DB_MAX_IDLE_TIME = 300

# Default maximum number of database connection lifetime (in seconds)
DB_MAX_CONNECTION_LIFETIME = 3600

# Default maximum number of database connection idle lifetime (in seconds)
DB_MAX_CONNECTION_IDLE_LIFETIME = 600

# Default maximum number of database connection checkout time (in seconds)
DB_MAX_CONNECTION_CHECKOUT_TIME = 30

# Default maximum number of database connection checkout retries
DB_MAX_CONNECTION_CHECKOUT_RETRIES = 3

# Default maximum number of database connection checkout retry delay (in seconds)
DB_MAX_CONNECTION_CHECKOUT_RETRY_DELAY = 1