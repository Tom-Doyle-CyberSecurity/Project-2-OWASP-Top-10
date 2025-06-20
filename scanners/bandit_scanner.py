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
import json
from pathlib import Path

# ========== Configuration ==========
SOURCE_DIR = "src"
REPORT_DIR = "reports"
REPORT_FILE = os.path.join(REPORT_DIR, "bandit_report.json")
HTML_REPORT_FILE = os.path.join(REPORT_DIR, "bandit_report.html")

def ensure_directories() -> None:
    """
    Ensure the output directory exists.
    """
    os.makedirs(REPORT_DIR, exist_ok = True)

def run_bandit_scan() -> None:
    """
    Run Bandit static code analysis on the source directory.
    Saves output to JSON, prints summary to terminal, and generates a basic HTML report.
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

    # Parse JSON output to create a simple HTML report
    try:
        with open(REPORT_FILE, 'r') as json_file:
            data = json.load(json_file)
    except Exception as e:
        print(f"[!] Failed to load Badit JSON output: {e}")

    # === Generate HTML report ===
    try:
        with open(HTML_REPORT_FILE, 'w') as html:
            html.write("<html><body>h2>Bandit Security Report</h2><ul>")
            for issue in data.get("results", []):
                html.write(f"<li><strong>{issue['issue_severity']}:</strong> {issue['issue_text']}"
                    f"(File: {issue['filename']}, Line: {issue['line_number']})</li>"
                )
            html.write("</ul></body></html>")
        
        print(f"[+] HTML report saved to: {HTML_REPORT_FILE}")
    except Exception as e:
        print(f"[!] Failed to generate HTML reports: {e}")

    # === GitHub Actions summary (optional)
    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        try:
            with open(step_summary, 'a') as summary:
                summary.write("## [+] Bandit Scan Summary\n")
                summary.write("**Issues found:** {len(data.get('results', []))}\n\n")
                severities = [issue["issue_severity"] for issue in data ["results"]]
                for severity in ["HIGH, "MEDIUM, "LOW"]:
                    count = severities.count(severity)
                    summary.write(f"- **{severity.title()}**: {count}\n")
        except Exception as e:
            print("[!] Failed to write GitHUB summary: {e}")
    
    # === Fail CI on high severity issues ===
    for issue in data.get("Results", []):
        if issue["issue_severity"].upper() == "HIGH":
            print("[!] High severity issues found. Failing CI pipeline.")
            exit(1)

if __name__ == "__main__":
    ensure_directories()
    run_bandit_scan()
