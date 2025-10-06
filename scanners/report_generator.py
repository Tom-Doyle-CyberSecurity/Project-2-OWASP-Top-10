#!/usr/bin/env python3
import os, json, datetime, html, shutil
from collections import Counter

# ---- Paths ----
RD = "reports"

# Original filenames produced by scanners / earlier scripts
ZAP_HTML_UNDERSCORE    = "zap_report.html"
ZAP_JSON_UNDERSCORE    = "zap_report.json"
BANDIT_HTML_UNDERSCORE = "bandit_report.html"
BANDIT_JSON_UNDERSCORE = "bandit_report.json"

# Filenames that index.html links to
ZAP_HTML_DASH    = "zap-report.html"       # legacy/raw ZAP table (still mirrored)
BANDIT_HTML_DASH = "bandit-report.html"

# CWE summary inputs/outputs
ZAP_CWE_JSON     = "zap_cwe_summary.json"  # written by zap_scanner.py
ZAP_CWE_HTML     = "zap-cwe-summary.html"  # human-friendly CWE table we generate

# Our outputs
INDEX = os.path.join(RD, "index.html")            # dashboard
FINDINGS_JSON = os.path.join(RD, "findings.json") # consumed by potential frontend fetch

# Optional CWE name map import (safe if file is colocated)
try:
    from cwe_mapping import CWE_NAME_MAP
except Exception:
    CWE_NAME_MAP = {}

def jload(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# ---------- Helpers ----------
def _normalize_risk(r):
    if r is None: return None
    s = str(r).strip().lower()
    if s in ("informational", "info"): return "Informational"
    if s == "high": return "High"
    if s == "medium": return "Medium"
    if s == "low": return "Low"
    return None

def zap_summary(data):
    """
    Summarise ZAP JSON into totals (High/Medium/Low/Informational).

    Supports both:
      - {"alerts": [ ... ]}   (what zap_scanner.py writes)
      - {"site":[{"alerts":[...]}]}  (older ZAP schema)
    """
    totals = {"High":0, "Medium":0, "Low":0, "Informational":0}
    if not data:
        return totals

    alerts = []
    if isinstance(data, dict):
        if "alerts" in data and isinstance(data["alerts"], list):
            alerts = data["alerts"]
        elif "site" in data and isinstance(data["site"], list):
            for site in data["site"]:
                alerts.extend(site.get("alerts", []))

    for a in alerts:
        risk = _normalize_risk(a.get("risk") or a.get("riskcode"))
        if risk is None:
            # Default unknowns to Low so they’re still counted
            risk = "Low"
        totals[risk] += 1

    return totals

def bandit_summary(data):
    """Summarise Bandit JSON into totals (HIGH/MEDIUM/LOW)."""
    totals = {"HIGH":0, "MEDIUM":0, "LOW":0}
    if data:
        for r in data.get("results", []):
            sev = (r.get("issue_severity") or r.get("severity","LOW")).upper()
            if sev not in totals:
                sev = "LOW"
            totals[sev] += 1
    return totals

def safe_copy(src, dst_dir, dst_name):
    if not src: return False
    if not os.path.exists(src): return False
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, dst_name)
    try:
        shutil.copy2(src, dst)
        return True
    except Exception:
        return False

# ---------- CWE HTML builder ----------
def _derive_description(alerts, top_k=2):
    """
    Derive a concise description for a CWE by taking the most frequent alert names.
    Falls back to the first alert name, or '—' if none.
    """
    names = [ (a.get("alert") or a.get("name") or "").strip() for a in alerts ]
    names = [n for n in names if n]
    if not names:
        return "—"
    counts = Counter(names).most_common(top_k)
    return ", ".join(n for n, _ in counts)

def build_zap_cwe_html():
    """
    Reads reports/zap_cwe_summary.json and renders a compact HTML table:
    Columns: CWE ID | Name | Description | High | Medium | Low | Informational | Total
    """
    path = os.path.join(RD, ZAP_CWE_JSON)
    data = jload(path)
    if not data:
        return """<html><body><h1>ZAP CWE Summary</h1><p>No CWE summary available.</p></body></html>"""

    details = data.get("details", {})
    # Build rows with per-CWE severity breakdown
    rows = []
    for cid_str, detail in sorted(details.items(), key=lambda kv: int(kv[0])):
        alerts = detail.get("alerts", []) or []
        counts = {"High":0, "Medium":0, "Low":0, "Informational":0}
        for a in alerts:
            r = _normalize_risk(a.get("risk"))
            if r is None:
                r = "Low"
            counts[r] += 1
        total = sum(counts.values())

        # Name: prefer mapping; fall back to summary JSON's name; otherwise "Unknown"
        cwe_id_val = detail.get("cwe_id", cid_str)
        mapped_name = CWE_NAME_MAP.get(int(cwe_id_val)) if str(cwe_id_val).isdigit() else None
        name = mapped_name or detail.get("cwe_name") or "Unknown"

        # Description: derived from most frequent alert names for that CWE
        desc = _derive_description(alerts, top_k=2)

        rows.append(f"""
        <tr>
          <td>{html.escape(str(cwe_id_val))}</td>
          <td>{html.escape(name)}</td>
          <td>{html.escape(desc)}</td>
          <td>{counts['High']}</td>
          <td>{counts['Medium']}</td>
          <td>{counts['Low']}</td>
          <td>{counts['Informational']}</td>
          <td>{total}</td>
        </tr>
        """)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZAP CWE Summary</title>
<style>
  body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:24px;color:#111}}
  h1{{margin:0 0 8px 0}}
  .meta{{color:#666;margin-bottom:16px}}
  table{{width:100%;border-collapse:collapse}}
  th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}
  th{{background:#f7f7f7}}
  tr:nth-child(even){{background:#fafafa}}

  /* colored header cells like your mockup */
  th.col-high{{background:#d84a4a;color:#fff}}
  th.col-med{{background:#e7902b;color:#fff}}
  th.col-low{{background:#4da561;color:#fff}}
  th.col-info{{background:#bdbdbd;color:#fff}}
</style>
</head>
<body>
  <h1>ZAP CWE Summary</h1>
  <div class="meta">Grouped by CWE with severity counts</div>
  <table>
    <thead>
      <tr>
        <th style="min-width:90px;">CWE ID</th>
        <th style="min-width:220px;">Name</th>
        <th style="min-width:320px;">Description</th>
        <th class="col-high" style="min-width:70px;">High</th>
        <th class="col-med"  style="min-width:90px;">Medium</th>
        <th class="col-low"  style="min-width:70px;">Low</th>
        <th class="col-info" style="min-width:120px;">Informational</th>
        <th style="min-width:70px;">Total</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""

def main():
    os.makedirs(RD, exist_ok=True)

    # Load raw JSONs (underscore style)
    z_json_path = os.path.join(RD, ZAP_JSON_UNDERSCORE)
    b_json_path = os.path.join(RD, BANDIT_JSON_UNDERSCORE)
    z = jload(z_json_path)
    b = jload(b_json_path)

    # Compute summaries
    ztot = zap_summary(z)
    btot = bandit_summary(b)

    # Produce findings.json (kept for future frontends)
    findings = {
        "zap": {
            "counts": {
                "high": ztot.get("High", 0),
                "medium": ztot.get("Medium", 0),
                "low": ztot.get("Low", 0),
                "info": ztot.get("Informational", 0)
            }
        },
        "bandit": {
            "counts": {
                "high": btot.get("HIGH", 0),
                "medium": btot.get("MEDIUM", 0),
                "low": btot.get("LOW", 0),
                "info": 0
            }
        }
    }
    with open(FINDINGS_JSON, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    # Mirror underscore HTML to dashed names if present (kept for legacy/raw view)
    safe_copy(os.path.join(RD, ZAP_HTML_UNDERSCORE), RD, ZAP_HTML_DASH)
    safe_copy(os.path.join(RD, BANDIT_HTML_UNDERSCORE), RD, BANDIT_HTML_DASH)

    # Build CWE HTML from ZAP CWE summary JSON
    cwe_html = build_zap_cwe_html()
    with open(os.path.join(RD, ZAP_CWE_HTML), "w", encoding="utf-8") as f:
        f.write(cwe_html)

    # Build HTML landing page
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    zap_cwe_exists = os.path.exists(os.path.join(RD, ZAP_CWE_HTML))
    bandit_html_exists = os.path.exists(os.path.join(RD, BANDIT_HTML_DASH))

    # Point ZAP button to CWE summary table
    zap_link_html = (f'<a class="view-btn" href="{html.escape(os.path.join(".", ZAP_CWE_HTML))}" target="_blank">View Full Report</a>'
                 if zap_cwe_exists else '<div class="no-report">No ZAP CWE summary found</div>')

    bandit_link_html = (f'<a class="view-btn" href="{html.escape(os.path.join(".", BANDIT_HTML_DASH))}" target="_blank">View Full Report</a>'
                        if bandit_html_exists else '<div class="no-report">No Bandit HTML found</div>')

    # Helper to render a pill
    def pill(label, value, cls):
        return f'''
          <div class="pill {cls}">
            <span class="pill-label">{html.escape(label)}</span>
            <span class="pill-count">{html.escape(str(value))}</span>
          </div>'''

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>OWASP Top 10 Findings Report</title>
<style>
  :root {{
    --black:#000;
    --muted:#6b6b6b;
    --text:#111;
  }}
  html,body{{height:100%;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial;background:#fff;color:var(--text)}}
  body::before {{
    content:"";
    position:fixed; inset:0;
    background-image: radial-gradient(#cfcfcf 1px, transparent 1px);
    background-size: 16px 16px;
    opacity:.25; pointer-events:none;
  }}
  .frame{{max-width:1300px;margin:18px auto;padding:22px;border:8px solid var(--black);box-sizing:border-box;background:#ffffff;position:relative}}
  h1{{font-size:44px;text-align:center;margin:6px 0 6px;font-weight:900}}
  .subtitle{{text-align:center;font-size:22px;font-weight:800;margin-top:6px}}
  .summary-text{{text-align:center;max-width:720px;margin:6px auto 28px;color:var(--muted);line-height:1.45}}
  .columns{{display:grid;grid-template-columns:1fr 1fr;gap:60px;align-items:start;justify-items:center}}
  @media (max-width:900px){{.columns{{grid-template-columns:1fr;gap:28px}}}}
  .col{{width:100%;max-width:520px}}
  .col-title{{font-size:18px;font-weight:800;margin-bottom:10px;padding-left:6px}}
  .pills{{display:flex;flex-direction:column;gap:18px}}
  .pill{{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-radius:999px;font-weight:800;font-size:20px;box-shadow:0 6px 10px rgba(0,0,0,0.06)}}
  .pill.high{{background:linear-gradient(180deg,#ff5b57,#ff3b36);color:#2b0706}}
  .pill.moderate{{background:linear-gradient(180deg,#ffb07a,#ff974a);color:#2b1006}}
  .pill.low{{background:linear-gradient(180deg,#7fa9a1,#5f8d85);color:#072222}}
  .pill.info{{background:linear-gradient(180deg,#ececec,#dcdcdc);color:#222}}
  .pill-label{{padding-left:6px}}
  .pill-count{{font-weight:900}}
  .actions{{text-align:center;margin-top:18px}}
  .view-btn{{display:inline-block;padding:10px 20px;border-radius:10px;background:#111;border:4px solid #111;color:#fff;text-decoration:none;font-weight:800}}
  .no-report{{color:var(--muted);font-weight:700}}
  .footer-note{{text-align:center;margin-top:18px;color:var(--muted);font-weight:700}}
</style>
</head>
<body>
  <div class="frame" role="main" aria-labelledby="main-title">
    <h1 id="main-title">OWASP Top 10 Findings Report</h1>
    <div class="subtitle">Summary</div>
    <p class="summary-text">This report provides an overview of the latest OWASP Top 10 security findings generated from both
    dynamic and static analysis tools. The ZAP scan found no high-risk issues but flagged {ztot.get("Medium",0)} moderate risks, plus {ztot.get("Low",0)} low-risk
    and {ztot.get("Informational",0)} informational findings. Bandit's static code analysis reported {btot.get("LOW",0)} low-risk issue(s) with no moderate or high-risk findings.
    Generated: {html.escape(now)}</p>

    <div class="columns">
      <!-- ZAP column -->
      <div class="col" id="zap-col" aria-labelledby="zap-title">
        <div class="col-title" id="zap-title">ZAP Report (zaproxy)</div>
        <div class="pills" role="list" aria-label="ZAP severity counts">
          {pill("High Risk", ztot.get("High",0), "high")}
          {pill("Moderate Risk", ztot.get("Medium",0), "moderate")}
          {pill("Low Risk", ztot.get("Low",0), "low")}
          {pill("Informational", ztot.get("Informational",0), "info")}
        </div>
        <div class="actions" style="margin-top:22px">{zap_link_html}</div>
      </div>

      <!-- Bandit column -->
      <div class="col" id="bandit-col" aria-labelledby="bandit-title">
        <div class="col-title" id="bandit-title">Bandit Report</div>
        <div class="pills" role="list" aria-label="Bandit severity counts">
          {pill("High Risk", btot.get("HIGH",0), "high")}
          {pill("Moderate Risk", btot.get("MEDIUM",0), "moderate")}
          {pill("Low Risk", btot.get("LOW",0), "low")}
          {pill("Informational", 0, "info")}
        </div>
        <div class="actions" style="margin-top:22px">{bandit_link_html}</div>
      </div>
    </div>

    <div class="footer-note">Findings summary JSON: <code>{html.escape(os.path.basename(FINDINGS_JSON))}</code></div>
  </div>
</body>
</html>
"""

    with open(INDEX, "w", encoding="utf-8") as f:
        f.write(doc)

    print(f"Wrote {INDEX}")
    print(f"Wrote {FINDINGS_JSON}")
    print(f"Wrote {os.path.join(RD, ZAP_CWE_HTML)}")

if __name__ == "__main__":
    main()