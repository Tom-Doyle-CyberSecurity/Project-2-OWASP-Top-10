#!/usr/bin/env python3
"""
zap_scanner.py — Orchestrate Full ZAP DAST (classic spider → AJAX spider → active → wait passive)
- Does NOT start/stop Docker or Juice Shop; main.sh owns lifecycle.
- Reads configuration from environment (with optional vars.py fallback).
- Exports: reports/zap_report.json and reports/zap_cwe_summary.json
"""
import os, sys, json, time
from pathlib import Path
from collections import defaultdict
from zapv2 import ZAPv2
from urllib.parse import urlparse

def _load_api_key():
    """Safely load ZAP API key from env or untracked vars.py."""
    key = os.getenv("ZAP_API_KEY")
    if key:
        return key
    try:
        from vars import API_KEY
        return API_KEY
    except ImportError:
        print("[~] No API key found (vars.py missing or not set). Proceeding without authentication.")
        return ""

# ---- config from env ----
TARGET       = os.getenv("TARGET_URL", "http://juice-shop:3000")
ZAP_BASE     = os.getenv("ZAP_API_BASE", "http://localhost:8080")
ZAP_API_KEY  = _load_api_key()

# reports
REPORT_DIR        = 'reports'
REPORT_FILE       = os.path.join(REPORT_DIR, 'zap_report.json')
CWE_SUMMARY_FILE  = os.path.join(REPORT_DIR, 'zap_cwe_summary.json')

# CWE mapping
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from cwe_mapping import ALL_CWES, CWE_NAME_MAP  # noqa: E402

# helpers
from spider_scan import run_spider            # noqa: E402
from ajax_scan   import run_ajax              # noqa: E402
from active      import run_active            # noqa: E402
from passive     import run_passive

AUTH_HEADER = os.getenv("AUTH_HEADER")  # "Authorization: Bearer <jwt>"
AUTH_COOKIE = os.getenv("AUTH_COOKIE")  # "token=<jwt>; Path=/;"

def _mkdirs():
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)

from urllib.parse import urlparse

def _zap_client():
    # Make sure shell proxies don't hijack localhost traffic
    for v in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ.pop(v, None)
    os.environ.setdefault("NO_PROXY", "localhost,127.0.0.1")

    parts = urlparse(ZAP_BASE)  # e.g. http://localhost:8080
    host_url = f"{parts.scheme}://{parts.hostname}"
    port = parts.port or 8080
    base_for_proxy = f"{host_url}:{port}"

    # Try modern client signature first; fall back to legacy proxies signature
    try:
        # works with 'zaproxy' package
        zap = ZAPv2(apikey=ZAP_API_KEY, zapurl=host_url, port=port)
    except TypeError:
        # works with legacy 'python-owasp-zap-v2.4==0.0.14'
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": base_for_proxy, "https": base_for_proxy})

    # Wait until ZAP API is responsive
    for i in range(10):
        try:
            version = zap.core.version
            if version:
                print(f"[+] Connected to ZAP {version}")
                return zap
        except Exception as e:
            print(f"[~] Waiting for ZAP... ({i+1}/10) {e}")
            time.sleep(3)

    raise SystemExit(f"[-] Could not connect to ZAP at {ZAP_BASE}.")

def _apply_auth(zap):
    try:
        if AUTH_HEADER:
            name, value = AUTH_HEADER.split(":", 1)
            zap.replacer.add_rule(
                description="AuthHeader", enabled=True,
                matchtype="REQ_HEADER", matchregex=False,
                matchstring=name.strip(), replacement=value.strip(),
                initiators="", apikey=ZAP_API_KEY,
            )
            print(f"[+] Auth header applied: {name.strip()}")
        if AUTH_COOKIE:
            zap.replacer.add_rule(
                description="AuthCookie", enabled=True,
                matchtype="REQ_HEADER", matchregex=False,
                matchstring="Cookie", replacement=AUTH_COOKIE,
                initiators="", apikey=ZAP_API_KEY,
            )
            print("[+] Auth cookie applied.")
    except Exception as e:
        print(f"[~] Auth config skipped/failed: {e}")

def _seed(zap, base):
    seeds = [
        "/#/login", "/#/register", "/#/account", "/#/basket",
        "/#/search", "/#/contact", "/#/order-history",
        "/#/administration", "/#/score-board",
        "/rest/products/search?q=test", "/rest/products/1/reviews",
        "/api/Feedbacks/", "/rest/user/login",
    ]
    for p in seeds:
        try:
            zap.urlopen(f"{base}{p}")
        except Exception:
            pass
    time.sleep(1)

def _normalize_int(val):
    try:
        s = str(val).strip()
        return int(s) if s.isdigit() else None
    except Exception:
        return None

def _build_cwe_summary(alerts):
    found_cwes = set()
    cwe_to_alerts = defaultdict(list)
    for a in alerts:
        cwe = _normalize_int(a.get("cweid") or a.get("cweId") or a.get("cwe"))
        if cwe is not None:
            found_cwes.add(cwe)
            cwe_to_alerts[cwe].append({
                "alert": a.get("alert") or a.get("name"),
                "risk": a.get("risk"),
                "url": a.get("url"),
                "evidence": a.get("evidence"),
            })
    expected = set(ALL_CWES)
    not_found = sorted(expected - found_cwes)
    summary = {
        "total_cwes_expected": len(ALL_CWES),
        "found_count": len(found_cwes),
        "not_found_count": len(not_found),
        "found_cwes": sorted(found_cwes),
        "not_found_cwes": not_found,
        "details": {
            str(cid): {
                "cwe_id": cid,
                "cwe_name": CWE_NAME_MAP.get(cid),
                "alert_count": len(cwe_to_alerts[cid]),
                "alerts": cwe_to_alerts[cid],
            } for cid in sorted(found_cwes)
        }
    }
    Path(CWE_SUMMARY_FILE).write_text(json.dumps(summary, indent=2))

def _export(zap):
    alerts = zap.core.alerts(baseurl=TARGET)
    Path(REPORT_FILE).write_text(json.dumps({"alerts": alerts}, indent=2))
    _build_cwe_summary(alerts)

def main():
    _mkdirs()
    zap = _zap_client()
    _apply_auth(zap)

    print(f"[+] Accessing {TARGET}")
    try:
        zap.urlopen(TARGET)
    except Exception:
        pass
    time.sleep(2)
    _seed(zap, TARGET)

    # --- Full DAST flow ---
    run_spider(zap, TARGET)
    run_ajax(zap, TARGET)
    run_active(zap, TARGET)
    run_passive(zap, TARGET)
    
    _export(zap)
    print("[+] ZAP scan complete. Reports in 'reports/'.")

if __name__ == "__main__":
    main()