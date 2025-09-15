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
REPORT_FILE = os.path.join(REPORT_DIR, 'zap_report.json')
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
    Export all alerts to both JSON and styled HTML report.

    :param zap: Initialized ZAP client
    :param txt_path: Path to write JSON report
    :param html_path: Path to write HTML report
    """
    import html

    alerts = zap.core.alerts()
    print(f"[+] Total alerts discovered: {len(alerts)}")

    # Save JSON output
    with open(txt_path, 'w') as f:
        json.dump({"site": [{"alerts": alerts}]}, f, indent=2)

    try:
        with open("docs/zap_report_template.html", 'r') as template_file:
            template = template_file.read()
            rows = ""

            # Map risk strings to CSS classes
            risk_to_class = {
                'high': 'high',
                'medium': 'medium',
                'low': 'low',
                'informational': 'info',
                'info': 'info'
            }

            for alert in alerts:
                # Normalize risk string
                risk_display = alert.get('risk', 'Unknown')
                risk = (risk_display or 'Unknown').strip().lower()
                css_class = risk_to_class.get(risk, '')

                # Title fallback: prefer "alert", else "name"
                title = alert.get('alert') or alert.get('name') or 'N/A'

                # Description fallback
                desc = alert.get('desc') or alert.get('description') or ''

                # Build table row (escaped for HTML safety)
                rows += f"""
                <tr class="{html.escape(css_class, quote=True)}">
                    <td><span class="sev-badge">{html.escape(risk_display)}</span></td>
                    <td>{html.escape(title)}</td>
                    <td class="url">{html.escape(alert.get('url', 'N/A'))}</td>
                    <td>{html.escape(desc)}</td>
                </tr>
                """

            # Replace placeholders in the template
            output_html = template.replace("{{TARGET}}", TARGET).replace("{{ROWS}}", rows)

            # Write HTML file
            with open(html_path, "w") as out_file:
                out_file.write(output_html)

            print(f"[+] HTML report generated at: {html_path}")

    except Exception as e:
        print(f"[!] Failed to generate HTML report: {e}")

    # Fail CI if HIGH risk issues found
    high_risk_count = sum(1 for a in alerts if (a.get('risk') or '').lower() == 'high')
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