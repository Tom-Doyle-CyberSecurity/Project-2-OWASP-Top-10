#!/usr/bin/env python3

"""
report_generator.py — Generate HTML dashboard and findings.json from ZAP and Bandit outputs
- Reads: reports/zap_report.json, reports/zap_cwe_summary.json, reports/bandit_report.json
- Writes: reports/index.html, reports/findings.json, reports/zap-cwe-summary.html, reports/bandit-cwe-summary.html
- Copies: reports/zap_report.html → reports/zap-report.html (if exists)
         reports/bandit_report.html → reports/bandit-report.html (if exists)
Designed by Tom D.
Created: 2025
"""
import os, json, datetime, html, shutil
from collections import Counter

# ==== Paths ====
RD = "reports"

# Original filenames produced by scanners / earlier scripts
ZAP_HTML_UNDERSCORE    = "zap_report.html"
ZAP_JSON_UNDERSCORE    = "zap_report.json"
BANDIT_HTML_UNDERSCORE = "bandit_report.html"
BANDIT_JSON_UNDERSCORE = "bandit_report.json"

# Filenames that index.html links to (legacy/raw)
ZAP_HTML_DASH    = "zap-report.html"
BANDIT_HTML_DASH = "bandit-report.html"

# CWE summary inputs/outputs (ZAP)
ZAP_CWE_JSON = "zap_cwe_summary.json"      # written by zap_scanner.py
ZAP_CWE_HTML = "zap-cwe-summary.html"      # human-friendly CWE table that is generated

# Bandit CWE-styled table output (to match ZAP table look/feel)
BANDIT_HTML_STYLED = "bandit-cwe-summary.html"

# Outputs
INDEX         = os.path.join(RD, "index.html")    # dashboard
FINDINGS_JSON = os.path.join(RD, "findings.json") # machine-friendly counts

# ---------- Optional maps ----------
# CWE name map (for pretty names when we have numeric CWE ids)
try:
    from cwe_mapping import CWE_NAME_MAP  # {int cwe_id: "Name"}
except Exception:
    CWE_NAME_MAP = {}

# Call bandit_cwe_map.py to get mapping
try:
    from bandit_cwe_map import BANDIT_TEST_TO_CWE          # same folder, script mode
except Exception:
    try:
        from .bandit_cwe_map import BANDIT_TEST_TO_CWE     # package/module mode
    except Exception:
        BANDIT_TEST_TO_CWE = {}  # no inline mapping; table will bucket by TEST:Bxxx if empty


# ---------- Utils ----------
# Loads and parses a JSON file from disk, returning None on failure.
# Opens the specified file using UTF-8 encoding and attempts to deserialize its contents with json.load()
# If the file is missing, unreadable, or contains invalid JSON, the function quietly returns None.
# Used throughout the project to safely handle optional or missing report inputs.
def jload(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# Safely copy a source file to a destination directory with error handling.
# Verifies that the source path exists before copying, created the destination directory if needed, and preserves file metadata using shutil.copy2().
# Returns True on success, False on any failure.
# Used to duplicate generated reports (e.g., ZAP/Bandit HTML reports) into the final reports directory without breaking the workflow if a file is missing or inaccessible.
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

# Standardize risk or severity labels across different scanner outputs.
# Accepts various string forms ("HIGH", "Info," "Informational") and normalizes them to a consistent set:
# "High", "Medium", "Low", "Informational".
# Returns None if the input cannot be mapped to a known category. 
# Used to unify severity ratings from ZAP, Bandit, and other tools before reporting.
def _normalize_risk(r):
    if r is None: return None
    s = str(r).strip().lower()
    if s in ("informational", "info"): return "Informational"
    if s == "high": return "High"
    if s == "medium": return "Medium"
    if s == "low": return "Low"
    return None

# ---------- Summaries for dashboard pills ----------
# Generate a summarized count of ZAP alerts by severity level.
# Supports both modern and legacy ZAP JSON formats:
# - {"alerts": [...]} (used by zap_scanner.py)
# - {"site": [{"alerts": [...]}]} (older ZAP schema)
# Extracts all alerts, normalizes their risk levels, via _normalize_risk(), and tallies totals for each category: High, Medium, Low, Informational.
# Returns a dictionary of severity counts for reporting and dashboard metrics.
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
            risk = "Low"
        totals[risk] += 1

    return totals

# Generate a summarized count of Bandit findings by severity level.
# Parses Bandit's JSON output, (list of results) and tallies occurrences of each severity: HIGH, MEDIUM, LOW.
# Falls back to "LOW" if a result's severity field is missing or invalid.
# Returns a dictionary of severity counts used for dashboard statistics and JSON report aggregation.
def bandit_summary(data):
    """Summarise Bandit JSON into totals (HIGH/MEDIUM/LOW)."""
    totals = {"HIGH":0, "MEDIUM":0, "LOW":0}
    if data and isinstance(data, dict):
        for r in data.get("results", []):
            sev = (r.get("issue_severity") or r.get("severity","LOW")).upper()
            if sev not in totals:
                sev = "LOW"
            totals[sev] += 1
    return totals

# ---------- Description helper (shared) ----------
# Generate a short, human-readable description for a CWE based on its most frequent alert names.
# Analyzes the provided alerts, counts how often each alert name appears, and returns the top_k (default 2) joined as a concise summary string.
# Falls back to the first alert name or an em dash ("—") if none exist.
# Used in CWE summaries and dashboards to provide a quick contextual label for grouping findings.
def _derive_description(alerts, top_k=2):
    """
    Derive a concise description for a CWE by taking the most frequent alert names.
    Falls back to the first alert name, or '—' if none.
    For Bandit, we pass alerts=[{"name": test_name}, ...].
    """
    names = [ (a.get("alert") or a.get("name") or "").strip() for a in alerts ]
    names = [n for n in names if n]
    if not names:
        return "—"
    counts = Counter(names).most_common(top_k)
    return ", ".join(n for n, _ in counts)

# ---------- ZAP CWE HTML ----------
# Build an HTML summary table of ZAP findings grouped by CWE.
# Reads the parsed CWE summary JSON (reports/zap_cwe_summary.json), computes per-severity counts (High, Medium, Low, Informational) for each CWE, and renders them into a compact HTML table.
# Each row includes: CWE ID, CWE Name, derived description, individual severity counts, and total findings.
# If no data is available, returns a minimal HTML page stating that no summary exists.
# Used by the report generator to produce a zap-cwe-summary.html for the dashboard view.
def build_zap_cwe_html():
    """
    Reads reports/zap_cwe_summary.json and renders a compact HTML table:
    Columns: CWE ID | Name | Description | High | Medium | Low | Informational | Total
    """
    path = os.path.join(RD, ZAP_CWE_JSON)
    data = jload(path)
    if not data:
        return """<!doctype html><html><body><h1>ZAP CWE Summary</h1><p>No CWE summary available.</p></body></html>"""

    details = data.get("details", {})
    rows = []
    for cid_str, detail in sorted(details.items(), key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 10**9):
        alerts = detail.get("alerts", []) or []
        counts = {"High":0, "Medium":0, "Low":0, "Informational":0}
        for a in alerts:
            r = _normalize_risk(a.get("risk"))
            if r is None:
                r = "Low"
            counts[r] += 1
        total = sum(counts.values())

        cwe_id_val = detail.get("cwe_id", cid_str)
        mapped_name = None
        if str(cwe_id_val).isdigit():
            mapped_name = CWE_NAME_MAP.get(int(cwe_id_val))
        name = mapped_name or detail.get("cwe_name") or "Unknown"
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

    return _tabular_html(
        title="ZAP CWE Summary",
        subtitle="Grouped by CWE with severity counts",
        rows_html="".join(rows)
    )

# ---------- Bandit: build a CWE-grouped structure ----------
# Convert Bandit scan results into a normalized CWE summary structure consistent with ZAP reports.
# Groups findings by CWE ID when available, or falls back to Bandit's test ID if no CWE mapping exists.
# Each CWE (or fallback bucket) entry includes:
# - cwe_id / bucket identifier
# - cwe_name (resolved CWE title or Bandit test name)
# - alerts: list of associated findings with name and normalized risk level
# Returns a dictionary formatted as {"details": {...}} for use in unified reporting and HTML generation.
def bandit_cwe_summary_structure(data):
    """
    Convert Bandit results into a ZAP-like CWE summary structure:
    {
      "details": {
        "<cwe_id or bucket>": {
          "cwe_id": <int or str>,
          "cwe_name": <str>,
          "alerts": [ {"name": <rule/test/issue>, "risk": "High|Medium|Low"} ... ]
        }, ...
      }
    }
    Falls back to grouping by the Bandit test_id if no CWE mapping exists.
    """
    if not data or "results" not in data:
        return {"details": {}}

    details = {}
    for result in data["results"]:
        test_id = (result.get("test_id") or "").strip()
        test_name = (
            (result.get("test_name") or "").strip()
            or (result.get("issue_text") or "").strip()
            or "Issue"
        )
        risk = normalize_risk(result.get("issue_severity"))
        cwe_id, bucket_key = resolve_cwe_and_bucket(test_id)
        cwe_name = resolve_cwe_name(cwe_id, test_name)

        entry = details.setdefault(bucket_key, {
            "cwe_id": cwe_id if cwe_id is not None else bucket_key,
            "cwe_name": cwe_name,
            "alerts": [],
        })
        entry["alerts"].append({"name": test_name, "risk": risk})

    return {"details": details}

# Normalise Bandit severity levels to standardised risk strings ("High", "Medium", "Low")
# Converts Bandit's raw severity (e.g., "HIGH", "MEDIUM", "LOW") to consistent format
def normalize_risk(severity):
    """Normalize Bandit severity levels."""
    sev_raw = (severity or "LOW").upper()
    return {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}.get(sev_raw, "Low")

# Resolve Bandit test ID to a corresponding CWE ID and create a bucket key
# If the CWE mapping exists, the bucket key uses the CWE ID. Otherwise, it falls back to a test-based identifier.
def resolve_cwe_and_bucket(test_id):
    """Determine the CWE ID and bucket key."""
    cwe_id = BANDIT_TEST_TO_CWE.get(test_id)
    bucket_key = str(cwe_id) if cwe_id is not None else f"TEST:{test_id or 'UNKNOWN'}"
    return cwe_id, bucket_key

# Return the human-readable CWE name if available, otherwise fallback to the Bandit test name
# Uses CWE_NAME_MAP to translate the CWE IDs into descriptive names for reporting.
def resolve_cwe_name(cwe_id, test_name):
    """Resolve CWE name or fallback to test name."""
    if isinstance(cwe_id, int) or (isinstance(cwe_id, str) and cwe_id.isdigit()):
        return CWE_NAME_MAP.get(int(cwe_id), "Unknown")
    return test_name

# ---------- Bandit CWE HTML (matches ZAP table look) ----------
# Build an HTML summary table of Bandit findings grouped by CWE or rule bucket.
# Reads Bandit's JSON output (reports/bandit_report.json), converts it into a ZAP-compatible CWE summary structure using bandit_cwe_summary_structure(), and aggregates severity counts
# (High, Medium, Low, Informational) for each CWE or Bandit rule.
# Each table row includes: CWE ID, Name, derived description, severity breakdowns, and total findings.
# If no data is found, returns a minimal HTML page indicating no results exist.
# Used to generate bandit-cwe-summary.html, ensuring visual and structural consistency with ZAP's CWE table.
def build_bandit_cwe_html():
    """
    Reads reports/bandit_report.json and renders an HTML table that MATCHES the ZAP CWE table:
    Columns: CWE ID | Name | Description | High | Medium | Low | Informational | Total
    """
    path = os.path.join(RD, BANDIT_JSON_UNDERSCORE)
    data = jload(path)
    if not data:
        return """<!doctype html><html><body><h1>Bandit Static Code Analysis Summary</h1><p>No results available.</p></body></html>"""

    summary = bandit_cwe_summary_structure(data)
    details = summary.get("details", {})

    # Build rows in numeric CWE order first, then non-numeric buckets
    def _sort_key(k):
        return (0, int(k)) if str(k).isdigit() else (1, k)
    rows = []

    for key in sorted(details.keys(), key=_sort_key):
        d = details[key]
        alerts = d.get("alerts", [])
        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for a in alerts:
            r = a.get("risk", "Low")
            counts[r] = counts.get(r, 0) + 1
        total = sum(counts.values())

        cwe_id = d.get("cwe_id", key)
        name   = d.get("cwe_name", "Unknown")
        desc   = _derive_description([{"name": a.get("name","")} for a in alerts], top_k=2)

        rows.append(f"""
        <tr>
          <td>{html.escape(str(cwe_id))}</td>
          <td>{html.escape(str(name))}</td>
          <td>{html.escape(desc)}</td>
          <td>{counts['High']}</td>
          <td>{counts['Medium']}</td>
          <td>{counts['Low']}</td>
          <td>{counts['Informational']}</td>
          <td>{total}</td>
        </tr>
        """)

    return _tabular_html(
        title="Bandit Static Code Analysis Summary",
        subtitle="Grouped by CWE (or Bandit rule bucket) with severity counts",
        rows_html="".join(rows)
    )

# ---------- Shared table chrome (identical look for ZAP/Bandit) ----------
# Generate a complete HTML document containing a styled table for CWE summaries.
# Accepts a title, subtitle, and pre-rendered table rows (rows_html), and returns a full HTML page string.
# The layout includes consistent typography, responsive sizing, and color-coded header cells for severity levels (High, Medium, Low, Informational) to match the report dashboard theme.
# Used by both built_zap_cwe_html() and build_bandit_cwe_html() to render their output as uniform tables.
def _tabular_html(title, subtitle, rows_html):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{html.escape(title)}</title>
<style>
  body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:24px;color:#111}}
  h1{{margin:0 0 8px 0}}
  .meta{{color:#666;margin-bottom:16px}}
  table{{width:100%;border-collapse:collapse}}
  th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}
  th{{background:#f7f7f7}}
  tr:nth-child(even){{background:#fafafa}}

  /* colored header cells like the mockup */
  th.col-high{{background:#d84a4a;color:#fff}}
  th.col-med{{background:#e7902b;color:#fff}}
  th.col-low{{background:#4da561;color:#fff}}
  th.col-info{{background:#bdbdbd;color:#fff}}
</style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <div class="meta">{html.escape(subtitle)}</div>
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
      {rows_html}
    </tbody>
  </table>
</body>
</html>"""

# ---------- Dashboard builder ----------
# Render a small, styled HTML "pill" element displaying a label and numeric value.
# Used in the dashboard header to visually highlight summary metrics such as total High, Medium, Low, and Informational findings.
# Each pill consists of a label (e.g., "High") and a count (e.g., "3"), styled using a CSS class (cls) for color coding.
# Apply color coding consistent with dashboard theme and severity levels.
def _pill(label, value, cls):
    return f'''
      <div class="pill {cls}">
        <span class="pill-label">{html.escape(label)}</span>
        <span class="pill-count">{html.escape(str(value))}</span>
      </div>'''

# Build the main index.html dashboard summarizing ZAP and Bandit findings.
# Generates a visually styled HTML landing page showing total counts of High, Medium, Low, and Informational findings from both dynamic (ZAP) and
# static (Bandit) analysis scans. 
# Includes "pill" components for quick severity visualization and buttons linking to the detailed CWE summary tables (zap-cwe-summary.html and bandit-cwe-summary.html).
# Automatically handles cases where report files are missing by displaying "No report found" notices.
# The final document serves as the unified entry point for all OWASP Top 10 scanner results.
def build_index(z_counts, b_counts, now_utc_str):
    # Buttons link to styled tables
    zap_cwe_path = os.path.join(".", ZAP_CWE_HTML)
    bandit_path  = os.path.join(".", BANDIT_HTML_STYLED)

    zap_link_html = (f'<a class="view-btn" href="{html.escape(zap_cwe_path)}" target="_blank">View Full Report</a>'
                     if os.path.exists(os.path.join(RD, ZAP_CWE_HTML))
                     else '<div class="no-report">No ZAP CWE summary found</div>')

    bandit_link_html = (f'<a class="view-btn" href="{html.escape(bandit_path)}" target="_blank">View Full Report</a>'
                        if os.path.exists(os.path.join(RD, BANDIT_HTML_STYLED))
                        else '<div class="no-report">No Bandit report found</div>')

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
    <p class="summary-text">
      This report provides an overview of the latest OWASP Top 10 security findings generated from both
      dynamic and static analysis tools. The ZAP scan found {z_counts.get("High",0)} high, {z_counts.get("Medium",0)} moderate,
      {z_counts.get("Low",0)} low and {z_counts.get("Informational",0)} informational items.
      Bandit's static code analysis reported {b_counts.get("HIGH",0)} high, {b_counts.get("MEDIUM",0)} moderate and {b_counts.get("LOW",0)} low items.
      Generated: {html.escape(now_utc_str)}
    </p>

    <div class="columns">
      <!-- ZAP column -->
      <div class="col" id="zap-col" aria-labelledby="zap-title">
        <div class="col-title" id="zap-title">ZAP Report (zaproxy)</div>
        <div class="pills" role="list" aria-label="ZAP severity counts">
          {_pill("High Risk", z_counts.get("High",0), "high")}
          {_pill("Moderate Risk", z_counts.get("Medium",0), "moderate")}
          {_pill("Low Risk", z_counts.get("Low",0), "low")}
          {_pill("Informational", z_counts.get("Informational",0), "info")}
        </div>
        <div class="actions" style="margin-top:22px">{zap_link_html}</div>
      </div>

      <!-- Bandit column -->
      <div class="col" id="bandit-col" aria-labelledby="bandit-title">
        <div class="col-title" id="bandit-title">Bandit Report</div>
        <div class="pills" role="list" aria-label="Bandit severity counts">
          {_pill("High Risk", b_counts.get("HIGH",0), "high")}
          {_pill("Moderate Risk", b_counts.get("MEDIUM",0), "moderate")}
          {_pill("Low Risk", b_counts.get("LOW",0), "low")}
          {_pill("Informational", 0, "info")}
        </div>
        <div class="actions" style="margin-top:22px">{bandit_link_html}</div>
      </div>
    </div>

    <div class="footer-note">Findings summary JSON: <code>{html.escape(os.path.basename(FINDINGS_JSON))}</code></div>
  </div>
</body>
</html>
"""
    return doc

# ---------- Main ----------
# Main orchestration function for generating all OWASP Top 10 scanner reports.
# Performs end-to-end aggregation of ZAP (DAST) and Bandit (SAST) outputs into unified artifacts.
# Steps:
# 1. Ensures the reports directory exists.
# 2. Loads raw ZAP an Bandit JSON reports (underscore filenames).
# 3. Computes severity summaries for each tool (used in dashboard "pill" metrics).
# 4. Generates findings.json, a lightweight summary for automation and CI integration
# 5. Copies Legacy raw HTML reports (underscore -> dashed filenames) for backward compatibility.
# 6. Builds and writes:
#    - zap-cwe-summary.html (ZAP CWE breakdown)
#    - bandit-cwe-summary.html (Bandit CWE breakdown in matching format)
#    - index.html (main dashboard summarizing all results).
# 7. Prints output file paths for verification and CI/CD logging.
# This function acts as the final step in the scanning pipeline, consolidating static and dynamic analysis findings into human-readable and machine-consumable reports.
def main():
    os.makedirs(RD, exist_ok=True)

    # Load raw JSONs (underscore style)
    z_json_path = os.path.join(RD, ZAP_JSON_UNDERSCORE)
    b_json_path = os.path.join(RD, BANDIT_JSON_UNDERSCORE)
    z_data = jload(z_json_path)
    b_data = jload(b_json_path)

    # Compute summaries for pills
    ztot = zap_summary(z_data)
    btot = bandit_summary(b_data)

    # Produce findings.json (for automation/frontends)
    findings = {
        "zap": {
            "counts": {
                "high": ztot.get("High", 0),
                "medium": ztot.get("Medium", 0),
                "low": ztot.get("Low", 0),
                "info": ztot.get("Informational", 0),
            }
        },
        "bandit": {
            "counts": {
                "high": btot.get("HIGH", 0),
                "medium": btot.get("MEDIUM", 0),
                "low": btot.get("LOW", 0),
                "info": 0,
            }
        }
    }
    with open(FINDINGS_JSON, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    # Mirror underscore HTML to dashed names if present (kept for legacy/raw view)
    safe_copy(os.path.join(RD, ZAP_HTML_UNDERSCORE), RD, ZAP_HTML_DASH)
    safe_copy(os.path.join(RD, BANDIT_HTML_UNDERSCORE), RD, BANDIT_HTML_DASH)

    # Build ZAP CWE HTML from ZAP CWE summary JSON
    zap_cwe_html = build_zap_cwe_html()
    with open(os.path.join(RD, ZAP_CWE_HTML), "w", encoding="utf-8") as f:
        f.write(zap_cwe_html)

    # Build Bandit CWE-styled HTML (matches ZAP table)
    bandit_html = build_bandit_cwe_html()
    with open(os.path.join(RD, BANDIT_HTML_STYLED), "w", encoding="utf-8") as f:
        f.write(bandit_html)

    # Build dashboard (index.html)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    index_html = build_index(ztot, btot, now)
    with open(INDEX, "w", encoding="utf-8") as f:
        f.write(index_html)

    print(f"Wrote {INDEX}")
    print(f"Wrote {FINDINGS_JSON}")
    print(f"Wrote {os.path.join(RD, ZAP_CWE_HTML)}")
    print(f"Wrote {os.path.join(RD, BANDIT_HTML_STYLED)}")

if __name__ == "__main__":
    main()