import subprocess
import logging
import shutil
import os
import time
from typing import List, Optional, Dict

class WfuzzIntegration:
    def __init__(self, logger_name: str = __name__):
        """
        Initializes the integration with Wfuzz and sets up the logger.
        """
        self.logger = logging.getLogger(logger_name)

    def is_wfuzz_installed(self) -> bool:
        """
        Checks if Wfuzz is installed and available in the PATH.
        """
        return bool(shutil.which("wfuzz"))

    def run_wfuzz(
        self,
        target: str,
        wordlist: str,
        parameters: List[str],
        additional_options: Optional[List[str]] = None,
        hide_codes: Optional[List[str]] = None,
        filter_codes: Optional[List[str]] = None,
        rate_limit: Optional[int] = None,
        silent_mode: bool = False,
        debug_mode: bool = False,
        retries: int = 1,
    ) -> Dict[str, str]:
        """
        Executes a fuzzing attack with Wfuzz.

        :param target: Target URL.
        :param wordlist: Path to the wordlist (dictionary file).
        :param parameters: List of parameters to fuzz, using {FUZZ} as a placeholder.
        :param additional_options: (Optional) List of additional options for Wfuzz.
        :param hide_codes: HTTP status codes to hide (e.g., ["404", "403"]).
        :param filter_codes: HTTP status codes to filter (only show if matched).
        :param rate_limit: Request rate limit per second (e.g., 10).
        :param silent_mode: If True, does not show full output (reduces verbosity).
        :param debug_mode: If True, shows more detailed output (DEBUG-level logs).
        :param retries: Number of retries in case of connection failure or Wfuzz error.
        :return: Dictionary with the keys:
                 - "stdout": standard output from Wfuzz
                 - "stderr": error output from Wfuzz (if any)
                 - "returncode": exit code from the process
        """

        # 1. Validate if Wfuzz is installed
        if not self.is_wfuzz_installed():
            error_msg = "[ERROR] Wfuzz is not installed or not found in the PATH."
            self.logger.error(error_msg)
            return {
                "stdout": "",
                "stderr": error_msg,
                "returncode": 127
            }

        # 2. Build the basic command
        command = ["wfuzz"]

        # Silent mode (reduces verbosity) or color (default -c)
        if not silent_mode:
            command.append("-c")  # with color
        else:
            command.append("--silent")  # reduces Wfuzz output

        # Add the wordlist and fuzzing mode
        command += ["-w", wordlist]

        # 3. Add fuzzing parameters
        #    Example: if param = "/{FUZZ}/admin", we transform it to "/FUZZ/admin" when invoking Wfuzz.
        for param in parameters:
            fuzz_param = param.replace("{FUZZ}", "FUZZ")
            # Add file mode with 'FUZZ' as the value; Wfuzz will substitute it with wordlist contents
            # The user can add more modes if desired, e.g., -z list,"val1,val2", etc.
            command += ["-z", "file,FUZZ"]
        # Example: hide status code 404; this can be extended
        if hide_codes:
            for code in hide_codes:
                command += ["--hc", code]
        if filter_codes:
            for code in filter_codes:
                command += ["--sc", code]

        # 4. Rate limit control
        if rate_limit and rate_limit > 0:
            command += ["--rate", str(rate_limit)]

        # 5. Add additional options
        if additional_options:
            command += additional_options

        # 6. Append the target
        command.append(target)

        # Debug logging
        if debug_mode:
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug(f"Generated command for Wfuzz: {' '.join(command)}")
        else:
            self.logger.debug(f"Wfuzz command (non-debug mode): {' '.join(command)}")

        # 7. Execute with retry handling
        last_error = ""
        for attempt in range(1, retries + 1):
            start_time = time.time()
            self.logger.info(f"Starting Wfuzz (attempt {attempt}/{retries}) against {target}")
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False  # Do not force exception; handle it ourselves
                )
                end_time = time.time()
                duration = end_time - start_time

                # Handle the exit code
                returncode = result.returncode
                stdout = result.stdout
                stderr = result.stderr

                # Log level and duration
                self.logger.info(f"Wfuzz finished (code {returncode}) in {duration:.2f}s for {target}")
                if debug_mode and stderr:
                    self.logger.debug(f"Wfuzz stderr: {stderr}")

                if returncode == 0:
                    # Successful execution
                    return {
                        "stdout": stdout,
                        "stderr": stderr,
                        "returncode": 0
                    }
                else:
                    # Wfuzz ended with an error or warning
                    err_msg = f"[WARNING] Wfuzz finished with code {returncode}. Checking stderr: {stderr}"
                    self.logger.warning(err_msg)
                    last_error = stderr
                    # Optionally filter certain error codes here (e.g., 2 = no results)
                    if attempt < retries:
                        self.logger.info("Retrying Wfuzz execution.")
                    else:
                        # Return what we have
                        return {
                            "stdout": stdout,
                            "stderr": stderr,
                            "returncode": returncode
                        }
            except subprocess.CalledProcessError as cpe:
                # Critical error executing
                self.logger.error(f"Error executing Wfuzz: {cpe}")
                last_error = str(cpe)
                if attempt < retries:
                    self.logger.info(f"Retrying (attempt {attempt+1}/{retries}).")
                else:
                    return {
                        "stdout": "",
                        "stderr": f"CalledProcessError: {cpe}",
                        "returncode": cpe.returncode
                    }
            except FileNotFoundError:
                # Wfuzz not found
                error_msg = "[ERROR] Wfuzz was not found on the system."
                self.logger.error(error_msg)
                return {
                    "stdout": "",
                    "stderr": error_msg,
                    "returncode": 127
                }
            except Exception as e:
                # Other error
                self.logger.error(f"Unexpected exception: {e}", exc_info=True)
                last_error = str(e)
                if attempt < retries:
                    self.logger.info(f"Retrying (attempt {attempt+1}/{retries}).")
                else:
                    return {
                        "stdout": "",
                        "stderr": f"Exception: {e}",
                        "returncode": 1
                    }

        # If reached here without success after retries:
        return {
            "stdout": "",
            "stderr": f"Error after {retries} retries: {last_error}",
            "returncode": 1
        }
