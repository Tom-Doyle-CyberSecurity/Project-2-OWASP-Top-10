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

# ========== ZAP API Configuration ==========
API_KEY = '' # If using API key, insert it here (optional)
ZAP_ADDRESS = 'http://localhost'
ZAP_PORT = '8080'
TARGET = 'http://juice-shop:3000'

# ========== Report Configuration ==========
REPORT_DIR = 'reports'
REPORT_FILE = os.path.join(REPORT_DIR, 'zap_report.txt')



zap = ZAPv2(apikey=API_KEY, proxies={'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}', 'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'})

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
        print(f'Spider progress: {zap.spider.status(scan_id)}%')
        time.sleep(1) # Wait for spider to finish

def active_scan(zap: ZAPv2, target: str) -> None:
    """
    Perform active scanning pphase to identify vulnerabilities.

    :param zap: Initialized ZAP client
    :param target: Target URL to actively scan
    """

    print(f"[+] Starting active scan on: {target}")
    scan_id = zap.ascan.scan(target)
    time.sleep(5)

    while int(zap.ascan.status(scan_id)) < 100:
        print(f'Scan progress: {zap.ascan.status(scan_id)}%')
        time.sleep(5)
    print("[+] Active scan progress: {zap.ascan.status(scan_id0}%")
    time.sleep(5)

    print(f"[+] Active scan progress: {zap.ascan.status(scan_id)}%")

def export_alerts(zap: ZAPv2, report_path: str) -> None:
    """
    Ecport all alerts discovered into a structured report file.

    :param zap: Initialized ZAP client
    :param report_path: Path to write report file
    """
    alerts = zap.core.alerts()
    print(f"[+] Total alerts discovered: {len(alerts)}")

    with open('reports/zap_report.txt', 'w') as f:
        for alert in alerts:
            f.write(str(alert) + '\n')
    print(f"[+] Report successfully written: {report_path}")

def run_zap_scan():
    """
    Execute full ZAP scanning workflow: spider -> active scan -> export alerts.
    """

    setup_environment()
    zap = initialize_zap()

    access_target(zap, TARGET)
    spider_target(zap, TARGET)
    active_scan(zap, TARGET)
    export_alerts(zap, REPORT_FILE)

    print("[+] ZAP scanning workflow completed successfully.")