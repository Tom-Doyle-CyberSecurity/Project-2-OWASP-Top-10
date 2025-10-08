#!/usr/bin/env python3
"""
zap_scanner.py

Dynamic scan of OWASP Juice Shop aiming to exercise all OWASP Top 10 (2021)
categories via broader crawl coverage + full active scan.
- Classic spider + AJAX spider (fixed status call)
- Seeds high-value SPA routes and REST endpoints (forms, search, reviews)
- Waits for passive scanner to finish before exporting
- Active scan is recursive across discovered URLs
- Optional auth injection via env (unchanged)
- Same JSON outputs: reports/zap_report.json and zap_cwe_summary.json
"""

import os, sys, json, time
from pathlib import Path
from collections import defaultdict
from zapv2 import ZAPv2

# ========= CWE mapping (unchanged) =========
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    from cwe_mapping import ALL_CWES, CWE_NAME_MAP
except Exception as e:
    raise SystemExit(f"[-] Failed to import cwe_mapping.py: {e}")

# ========= ZAP settings (unchanged connection bits) =========
API_KEY     = 'Secure246Key'
ZAP_ADDRESS = 'localhost'
ZAP_PORT    = '8080'
TARGET      = 'http://juice-shop:3000'

REPORT_DIR        = 'reports'
REPORT_FILE       = os.path.join(REPORT_DIR, 'zap_report.json')
CWE_SUMMARY_FILE  = os.path.join(REPORT_DIR, 'zap_cwe_summary.json')

AUTH_HEADER = os.getenv("AUTH_HEADER")  # e.g. "Authorization: Bearer <jwt>"
AUTH_COOKIE = os.getenv("AUTH_COOKIE")  # e.g. "token=<jwt>; Path=/;"

# ========= Setup =========
def setup_environment():
    os.makedirs(REPORT_DIR, exist_ok=True)

def initialize_zap():
    return ZAPv2(
        apikey=API_KEY,
        proxies={
            'http':  f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
            'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
        }
    )

def wait_for_zap(zap, retries=8, delay=3):
    for i in range(retries):
        try:
            v = zap.core.version
            if v:
                print(f"[+] Connected to ZAP {v}")
                return
        except Exception as e:
            print(f"[!] Waiting for ZAP... ({i+1}/{retries}) {e}")
            time.sleep(delay)
    raise SystemExit("[-] Could not connect to ZAP after multiple attempts.")

# ========= Optional auth (unchanged) =========
def apply_auth(zap):
    try:
        if AUTH_HEADER:
            name, value = AUTH_HEADER.split(":", 1)
            zap.replacer.add_rule(
                description="AuthHeader",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring=name.strip(),
                replacement=value.strip(),
                initiators="",
                apikey=API_KEY
            )
            print(f"[+] Auth header applied: {name.strip()}")
        if AUTH_COOKIE:
            zap.replacer.add_rule(
                description="AuthCookie",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Cookie",
                replacement=AUTH_COOKIE,
                initiators="",
                apikey=API_KEY
            )
            print("[+] Auth cookie applied.")
    except Exception as e:
        print(f"[!] Failed to configure auth: {e}")

# ========= Crawl & attack =========
def access_target(zap, target):
    print(f"[+] Accessing {target}")
    try:
        zap.urlopen(target)
    except Exception:
        pass
    time.sleep(2)

def seed_high_value_paths(zap, base):
    """
    Hit common SPA routes and REST endpoints that exercise OWASP categories:
    - A03 Injection (search, feedback, reviews)
    - A07 Auth (login)
    - A01 Access control (admin, basket, account)
    """
    seeds = [
        "/#/login",
        "/#/search",
        "/#/contact",
        "/#/basket",
        "/#/account",
        "/#/administration",
        "/#/order-history",
        "/#/register",
        "/#/about",
        "/#/score-board",  # hidden but present
        "/rest/products/search?q=test",
        "/rest/products/1/reviews",
        "/api/Feedbacks/",
        "/rest/user/login",
    ]
    for p in seeds:
        url = f"{base}{p}"
        try:
            zap.urlopen(url)
        except Exception:
            pass
    time.sleep(1)

def tune_spider(zap):
    try:
        zap.spider.set_option_max_depth(10)
        zap.spider.set_option_thread_count(5)
        zap.spider.set_option_max_children(10)
    except Exception:
        pass

def spider_target(zap, target):
    tune_spider(zap)
    print("[+] Spidering target...")
    scan_id = zap.spider.scan(target, recurse=True)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"\rSpider progress: {zap.spider.status(scan_id)}%", end="")
        sys.stdout.flush()
        time.sleep(2)
    print("\n[+] Spider completed.")

def ajax_spider(zap, target):
    # fix: status is a property on some ZAP builds (not a callable)
    try:
        print("[+] Running AJAX spider...")
        zap.ajaxSpider.scan(target)
        while True:
            status = zap.ajaxSpider.status
            print(f"\rAJAX spider status: {status}", end="")
            if str(status).lower() == "stopped":
                break
            time.sleep(3)
        print("\n[+] AJAX spider completed.")
    except Exception as e:
        print(f"[!] AJAX spider skipped or failed: {e}")

def wait_for_passive_scan(zap):
    """Ensure passive scanner has processed all records (A05, headers, info leaks)."""
    try:
        while True:
            remaining = int(zap.pscan.records_to_scan)
            print(f"\rPassive scan queue: {remaining}", end="")
            if remaining == 0:
                break
            time.sleep(2)
        print("\n[+] Passive scan processing complete.")
    except Exception:
        # older ZAP versions may not expose this; safe to continue
        print("\n[~] Passive scan queue not available; continuing.")

def active_scan(zap, target):
    print(f"[+] Starting active scan on: {target}")
    # recurse=True to go after everything found by the spiders
    scan_id = zap.ascan.scan(url=target, recurse=True, inscopeonly=False)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"\rActive scan progress: {zap.ascan.status(scan_id)}%", end="")
        sys.stdout.flush()
        time.sleep(5)
    print("\n[+] Active scan complete.")

# ========= Reporting (unchanged) =========
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
        cwe_raw = a.get("cweid") or a.get("cweId") or a.get("cwe")
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

def export_alerts(zap):
    alerts = zap.core.alerts(baseurl=TARGET)
    with open(REPORT_FILE, "w") as f:
        json.dump({"alerts": alerts}, f, indent=2)
    build_cwe_summary(alerts)

# ========= Main =========
def run_zap_scan():
    setup_environment()
    zap = initialize_zap()
    wait_for_zap(zap)
    apply_auth(zap)

    access_target(zap, TARGET)
    # Seed key pages & REST calls so spiders/AScan hit injection/auth surfaces
    seed_high_value_paths(zap, TARGET)

    spider_target(zap, TARGET)
    ajax_spider(zap, TARGET)
    active_scan(zap, TARGET)
    wait_for_passive_scan(zap)

    export_alerts(zap)
    print("[+] Scan complete. Reports available in 'reports/' directory.")

if __name__ == "__main__":
    run_zap_scan()