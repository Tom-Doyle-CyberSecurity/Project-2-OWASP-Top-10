"""
zap_scanner.py

Automated ZAP scanner script for OWASP Top 10 vulnerability assessment.

This module uses the OWASP ZAP API to:
- Access target web applications
- Perform spidering (crawl discovery) to discover endpoints (URLs)
- Perform active scanning (OWASP Top 10 vulnerabilities)
- Export alerts into structured report files

Author: Tom D.
Created: 2025

Dependencies:
- python-owasp-zap-v2.4
"""

from zapv2 import ZAPv2
import time
import os
import sys
import json

# ========== ZAP API Configuration ==========
API_KEY = 'Secure246Key' # If using API key, insert it here (optional)
ZAP_ADDRESS = 'localhost'
ZAP_PORT = '8080'
TARGET = 'http://juice-shop:3000'

# ========== Report Configuration ==========
REPORT_DIR = 'reports'
REPORT_FILE = os.path.join(REPORT_DIR, 'zap_report.txt')
HTML_REPORT_FILE = os.path.join(REPORT_DIR, 'zap_report.html')

def setup_environment() -> None:
    """
    Ensure the reports directory exists before scanning.
    
    """
    os.makedirs(REPORT_DIR, exist_ok=True)

def initialize_zap() -> ZAPv2:
    """
    Initialize and return the configured ZAP API client.

    :return: Instance of ZAPv2 client
    """
    return ZAPv2(apikey=API_KEY, proxies={
        'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
        'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'
    })

def access_target(zap: ZAPv2, target: str) -> None:
    """
    Access the target URL to initiate session

    :param zap: Initialized ZAP client
    :param target: Target URL to scan
    """
    print(f'Accessing target {target}')
    zap.urlopen(target)
    time.sleep(2)  # Wait for the site to load

def spider_target(zap: ZAPv2, target: str) -> None:
    """
    Perform spidering phase to discover URLs/endpoints.

    :param zap: Initialized ZAP client
    :param target: Target URL to spider
    """
    print('Spidering target...')
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        progress = zap.spider.status(scan_id)
        print(f"\rSpider progress: {progress}%", end="")
        sys.stdout.flush()
        time.sleep(1)
    print() # Finish line cleanly
    print(f"[+] Spider completed: {zap.spider.status(scan_id)}%")

def active_scan(zap: ZAPv2, target: str) -> None:
    """
    Perform active scanning phase to identify vulnerabilities.

    :param zap: Initialized ZAP client
    :param target: Target URL to actively scan
    """

    print(f"[+] Starting active scan on: {target}")
    scan_id = zap.ascan.scan(target)
    time.sleep(5)

    while int(zap.ascan.status(scan_id)) < 100:
        progress = zap.ascan.status(scan_id)
        print(f"\r[Active Scan] progress: {progress}%", end="")
        sys.stdout.flush()
        time.sleep(5)
    print("\n[+] Active scan complete.")

def export_alerts(zap: ZAPv2, txt_path: str, html_path: str) -> None:
    """
    Export all alerts to both plain text and basic HTML.

    :param zap: Initialized ZAP client
    :param report_path: Path to write report file
    """
    alerts = zap.core.alerts()
    print(f"[+] Total alerts discovered: {len(alerts)}")

    with open(txt_path, 'w') as f:
        for alert in alerts:
            f.write(json.dumps(alert, indent=2) + '\n')
    print(f"[+] Report successfully written: {txt_path}")

    try:
        with open(html_path, 'w') as html:
            html.write("<html><body><h2>Zap Security Report<h2><ul>")
            for alert in alerts:
                html.write(f"<li><strong>{alert['risk']}</strong>: {alert['alert']}<br>URL: {alert['url']}</li>")
            html.write("</ul></body></html>")
    except Exception as e:
        print(f"[!] Failed to generate HTMl report: {e}")

    # Fail if HIGH risk issues are found
    high_risk_count = sum(1 for a in alerts if a['risk'] == 'High')
    if high_risk_count > 0:
        print(f"[!] {high_risk_count} HIGH risk vulnerabilities found!")
        sys.exit(1)

def run_zap_scan():
    """
    Execute full ZAP scanning workflow: spider -> active scan -> export alerts.
    """

    setup_environment()
    zap = initialize_zap()

    access_target(zap, TARGET)
    spider_target(zap, TARGET)
    active_scan(zap, TARGET)
    export_alerts(zap, REPORT_FILE, HTML_REPORT_FILE)

    print("[+] ZAP scanning workflow completed successfully.")

if __name__ == "__main__":
    setup_environment()
    run_zap_scan()