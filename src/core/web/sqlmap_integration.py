import subprocess
import os

def check_sqlmap_installed():
    """
    Checks if SQLmap is installed and available in the PATH.

    :return: True if SQLmap is available, False otherwise.
    """
    try:
        subprocess.run(["sqlmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return True
    except FileNotFoundError:
        return False


def run_sqlmap(url, level=1, risk=1, technique=None, headers=None, cookies=None, user_agent=None, output_file="sqlmap_output.txt", callback=None):
    """
    Runs SQLmap with the provided options.

    :param url: Target URL.
    :param level: Detail level (--level).
    :param risk: Risk level (--risk).
    :param technique: Specific techniques (--technique).
    :param headers: Dictionary with custom HTTP headers.
    :param cookies: Cookies as a string.
    :param user_agent: Custom user agent (--user-agent).
    :param output_file: Name of the file to save the full output.
    :param callback: Function to handle real-time output.
    """
    if not check_sqlmap_installed():
        if callback:
            callback("[ERROR] SQLmap is not installed or not found in the PATH.")
        return

    command = [
        "sqlmap",
        "--url", url,
        "--batch",
        f"--level={level}",
        f"--risk={risk}"
    ]

    # Add additional options
    if technique:
        command.extend(["--technique", technique])
    if headers:
        for key, value in headers.items():
            command.extend(["--headers", f"{key}: {value}"])
    if cookies:
        command.extend(["--cookie", cookies])
    if user_agent:
        command.extend(["--user-agent", user_agent])

    try:
        with open(output_file, "w") as output:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            for line in process.stdout:
                output.write(line)  
                if callback:
                    callback(line.strip())

            process.wait()

            if process.returncode == 0:
                if callback:
                    callback("[INFO] SQLmap finished successfully.")
            else:
                if callback:
                    callback(f"[ERROR] SQLmap finished with errors. Exit code: {process.returncode}")

    except FileNotFoundError:
        if callback:
            callback("[ERROR] SQLmap is not installed or not found in the PATH.")
    except Exception as e:
        if callback:
            callback(f"[ERROR] Unexpected error: {str(e)}")
