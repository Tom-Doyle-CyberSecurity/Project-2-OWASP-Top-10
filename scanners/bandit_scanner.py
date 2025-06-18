"""
bandit_scanner.py

Automated static code analysis using Bandit for secure coding checks.

This module  runs Bandit on the local 'src/' directort to detect:
- Insecure coding practices
- Vulnerabilities like hardocded credentials, eval usage, command injection, etc.
- Potential OWASP Top 10 coding-related flaws

Outputs results to:
- JSON report file (for integration/automation with CI/CD)
- Terminal (for developer visibility)

Author Tom D.
Created: 2025

Dependencies:
- bandit (install via pip: `pip install bandit`)
"""

import os
import subprocess

# ========== Configuration ==========
SOURCE_DIR = "src"
REPORT_DIR = "reports"
REPORT_FILE = os.path.join(REPORT_DIR, "bandit_report.json")

def ensure_directories() -> None:
    """
    Ensure the output directory exists.
    """
    os.makedirs(REPORT_DIR, exist_ok = True)

def run_bandit_scan() -> None:
    """
    Run Bandit static code analysis on the source directory.
    Saves output to JSON and prints summary to terminal.
    """
    print(f"[+] Running Bandit scan on: {SOURCE_DIR}")
    
    result = subprocess.run(
    [
        "bandit",
        "-r", SOURCE_DIR,
        "-f", "json",
        "-o", REPORT_FILE
    ],
    capture_output = True,
    text = True
    )

    if result.returncode == 0:
        print("[+] Bandit scan completed successfully.")
    else:
        print("[!] Bandit scan completed with warnings/issues.")
        
    # Output summary to terminal
    print(result.stdout)
    print(f"[+] Report saved to: {REPORT_FILE}")

if __name__ == "__main__":
    ensure_directories()
    run_bandit_scan()
