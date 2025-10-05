#!/usr/bin/env python3
"""
zap_scanner.py

Automated ZAP scanner script for OWASP Top 10 vulnerability assessment (Juice Shop version).

Enhancements:
- Uses cwe_mapping.py as the single source of truth for OWASP Top 10 (2021–2025) CWE IDs.
- Performs ZAP spider and active scans.
- Saves:
    - reports/zap_report.json (raw ZAP alerts)
    - reports/zap_cwe_summary.json (CWE summary built against ALL_CWES)
- Does NOT present any findings in the terminal.

Author: Tom D.
Created: 2025
"""

from zapv2 import ZAPv2
import time
import os
import sys
import json
from pathlib import Path
from collections import defaultdict

# ========= Import CWE Mapping (authoritative source) =========
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    from cwe_mapping import ALL_CWES, CWE_NAME_MAP
except Exception as e:
    raise SystemExit(
        f"[-] Failed to import cwe_mapping.py: {e}\n"
        "    Ensure cwe_mapping.py is co-located or on PYTHONPATH."
    )

# ========== ZAP API Configuration ==========
API_KEY = 'Secure246Key'  # Optional
ZAP_ADDRESS = 'localhost'
ZAP_PORT = '8080'
TARGET = 'http://juice-shop:3000'

# ========== Report Configuration ==========
REPORT_DIR = 'reports'
REPORT_FILE = os.path.join(REPORT_DIR, 'zap_report.json')
CWE_SUMMARY_FILE = os.path.join(REPORT_DIR, 'zap_cwe_summary.json')

# ========== Setup & Scan ==========
def setup_environment():
    os.makedirs(REPORT_DIR, exist_ok=True)

def initialize_zap():
    return ZAPv2(apikey=API_KEY, proxies={
        'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
        'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'
    })

def access_target(zap, target):
    print(f'[+] Accessing target {target}')
    zap.urlopen(target)
    time.sleep(2)

def spider_target(zap, target):
    print('[+] Spidering target...')
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"\rSpider progress: {zap.spider.status(scan_id)}%", end="")
        sys.stdout.flush()
        time.sleep(1)
    print("\n[+] Spider completed.")

def active_scan(zap, target):
    print(f"[+] Starting active scan on: {target}")
    scan_id = zap.ascan.scan(target)
    time.sleep(5)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"\rActive scan progress: {zap.ascan.status(scan_id)}%", end="")
        sys.stdout.flush()
        time.sleep(5)
    print("\n[+] Active scan complete.")

# ========== CWE Summary Builder (no terminal output) ==========
def _normalize_int(val):
    try:
        if val is None:
            return None
        s = str(val).strip()
        if s.isdigit():
            return int(s)
    except Exception:
        pass
    return None

def build_cwe_summary(alerts):
    found_cwes = set()
    cwe_to_alerts = defaultdict(list)

    for a in alerts:
        cwe_raw = a.get("cweid") or a.get("cweId") or a.get("cwe") or a.get("cwe_id")
        cwe = _normalize_int(cwe_raw)
        if cwe is not None:
            found_cwes.add(cwe)
            cwe_to_alerts[cwe].append({
                "alert": a.get("alert") or a.get("name"),
                "risk": a.get("risk"),
                "url": a.get("url"),
                "evidence": a.get("evidence"),
            })

    expected_set = set(ALL_CWES)
    not_found_cwes = sorted(expected_set - found_cwes)
    found_cwes_sorted = sorted(found_cwes)

    summary = {
        "total_cwes_expected": len(ALL_CWES),
        "found_count": len(found_cwes_sorted),
        "not_found_count": len(not_found_cwes),
        "found_cwes": found_cwes_sorted,
        "not_found_cwes": not_found_cwes,
        "details": {
            str(cid): {
                "cwe_id": cid,
                "cwe_name": CWE_NAME_MAP.get(cid),
                "alert_count": len(cwe_to_alerts[cid]),
                "alerts": cwe_to_alerts[cid],
            } for cid in found_cwes_sorted
        }
    }

    Path(CWE_SUMMARY_FILE).write_text(json.dumps(summary, indent=2))

# ========== Export & Run ==========
def export_alerts(zap):
    alerts = zap.core.alerts()
    with open(REPORT_FILE, "w") as f:
        json.dump({"alerts": alerts}, f, indent=2)
    build_cwe_summary(alerts)

def run_zap_scan():
    setup_environment()
    zap = initialize_zap()
    access_target(zap, TARGET)
    spider_target(zap, TARGET)
    active_scan(zap, TARGET)
    export_alerts(zap)
    print("[+] Scan complete. Reports available in 'reports/' directory.")

if __name__ == "__main__":
    run_zap_scan()