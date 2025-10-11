#!/usr/bin/env python3

"""
active.py — Run ZAP Active Scan only, modernized OWASP ZAP active scan script from outdated zap scanner found at:
https://github.com/zaproxy/zaproxy/blob/main/python/scripts/generic-pytest/test_zap.py
-------------------------------------------------------------

Purpose: 
    This modernized version focuses soley on performing an Active Scan using the official OWASP ZAP Python API (zapv2). It is 
    designed for automation and CI/CD pipelines where ZAP is already running in daemon or Docker mode.

Key modernizations:
    1. Simplified scope - Active Scan only.
        - Legacy script performed multiple actions (start, spider, scan, stop, save).
        - This version runs only the Active scan phase for runtime vulnerability detection.
    
    2. Updated API - zapv2 instead of deprecated 'zap'
        - Replaces 'from zap import ZAP' with 'from zapv2 import ZAPv2'.
        - Ensures compatibility with ZAP 2.4+ and future versions.

    3. Improved argument parsing - argparse with better defaults and help messages.
        - Replaces SafeConfigParser (.ini) in configuration with argparse command-line options.
        - Easier integration in CI/CD environments with flexible runtime parameters.
    
    4. No local ZAP launching
        - Removes OS-dependent startup logic (zap.sh / zap.bat).
        - Assumes ZAP is already running, (e.g., via Docker or daemon mode).
        - Example:
            docker run -u zap -p 8080:8080 -d owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080
    
    5. Cleaner output and fail behaviour
        - Polls zap.ascan.status() until 100%
        - Displays progress and summarizes vulnerabilities.
        - Optional '--fail-on-alerts' flag exits with code 1 if any alerts remain.
        - Optional '--save' flag saves alerts to a JSON file.

    6. Safer, Platform-Agnostic Design
        - Removes hardcoded OS paths and fixed delays.
        - Eliminates unsafe 'ast.literal_eval' parsing.
        - Uses native ZAP API alert retrieval (zap.core.alerts()).
    
    7. New CLI Options
        --proxy          : Proxy URL for running ZAP instance
        --apikey         : ZAP API key (if set), or via API_KEY 
        --targets        : Comma-separated target URLs to scan
        --save           : Optional path to save JSON alerts 
        --fail-on-alerts : Exit with code 1 if any alerts found (for CI fail conditions)
        --poll-interval  : Seconds between status checks (default 5)

Requirements:
    pip install python-owasp-zap-v2.4

Usage examples:
    python3 zap_active_scan.py --proxy http://127.0.0.1:8080 --targets http://localhost:3000 --save /tmp/zap-alerts.txt --fail-on-alerts

    Or multiple targets:
    python3 zap_active_scan.py --proxy http://127.0.0.1:8080 --targets http://a:3000,http://b:3000
"""
import argparse, time, sys, os, json
from urllib.parse import urlparse
from zapv2 import ZAPv2

def _wait(zap, scanid, poll_interval=5):
    while True:
        try:
            pct = int(zap.ascan.status(scanid))
        except Exception:
            pct = 0
        print(f"\rActive scan {scanid} progress: {pct}%", end="", flush=True)
        if pct >= 100:
            print()
            break
        time.sleep(poll_interval)

def run_active(zap, target, *, poll_interval=5):
    print(f"[+] Active scanning: {target}")
    scanid = zap.ascan.scan(target, recurse=True, inscopeonly=False)
    _wait(zap, scanid, poll_interval=poll_interval)
    print("[+] Active scan complete.")

# ---- CLI remains for standalone use ----
def main():
    p = argparse.ArgumentParser(description="Run ZAP Active Scan only")
    p.add_argument('--proxy', required=True, help='e.g. http://127.0.0.1:8080')
    p.add_argument('--apikey', default=os.environ.get('ZAP_API_KEY', ''), help='ZAP API key')
    p.add_argument('--targets', required=True, help='Comma-separated URLs')
    p.add_argument('--save', default='', help='Path to save alerts JSON (optional)')
    p.add_argument('--fail-on-alerts', action='store_true', help='Exit 1 if any alerts found')
    p.add_argument('--poll-interval', type=int, default=5)
    args = p.parse_args()

    proxies = {'http': args.proxy, 'https': args.proxy}
    zap = ZAPv2(apikey=args.apikey, proxies=proxies)

    all_alerts = []
    for t in [x.strip() for x in args.targets.split(',') if x.strip()]:
        run_active(zap, t, poll_interval=args.poll_interval)
        try:
            alerts = zap.core.alerts(baseurl=t)
        except Exception:
            alerts = zap.core.alerts()
        all_alerts.extend(alerts)

    uniq = {(a.get('alert'), a.get('url'), a.get('param')): a for a in all_alerts}
    alerts_list = list(uniq.values())
    print(f"\nTotal unique alerts: {len(alerts_list)}")
    for a in alerts_list:
        print(f"- {a.get('risk')}: {a.get('alert')} @ {a.get('url')} param={a.get('param')}")

    if args.save:
        try:
            with open(args.save, 'w', encoding='utf-8') as fh:
                json.dump(alerts_list, fh, indent=2)
            print(f"Alerts saved to {args.save}")
        except Exception as e:
            print(f"Failed to save alerts: {e}", file=sys.stderr)

    if args.fail_on_alerts and alerts_list:
        sys.exit(1)

if __name__ == '__main__':
    main()