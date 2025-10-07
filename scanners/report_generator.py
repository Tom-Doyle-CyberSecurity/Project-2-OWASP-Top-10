#!/usr/bin/env python3
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
ZAP_CWE_HTML = "zap-cwe-summary.html"      # human-friendly CWE table we generate

# Bandit CWE-styled table output (to match ZAP table look/feel)
BANDIT_HTML_STYLED = "bandit-cwe-summary.html"

# Our outputs
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
def jload(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

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

def _normalize_risk(r):
    if r is None: return None
    s = str(r).strip().lower()
    if s in ("informational", "info"): return "Informational"
    if s == "high": return "High"
    if s == "medium": return "Medium"
    if s == "low": return "Low"
    return None

# ---------- Summaries for dashboard pills ----------
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
    If a CWE mapping is missing, we fall back to grouping by the Bandit test_id bucket: e.g., "TEST:B105".
    """
    details = {}
    if not data or "results" not in data:
        return {"details": details}

    for r in data["results"]:
        test_id   = (r.get("test_id") or "").strip()
        test_name = (r.get("test_name") or "").strip() or (r.get("issue_text") or "").strip() or "Issue"
        sev_raw   = (r.get("issue_severity") or "LOW").upper()
        risk = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}.get(sev_raw, "Low")

        cwe_id = BANDIT_TEST_TO_CWE.get(test_id)
        bucket_key = str(cwe_id) if cwe_id is not None else f"TEST:{test_id or 'UNKNOWN'}"

        if isinstance(cwe_id, int) or (isinstance(cwe_id, str) and cwe_id.isdigit()):
            name = CWE_NAME_MAP.get(int(cwe_id), "Unknown")
        else:
            # Non-CWE bucket; show the Bandit rule/test as the "name"
            name = test_name

        entry = details.setdefault(bucket_key, {
            "cwe_id": cwe_id if cwe_id is not None else bucket_key,
            "cwe_name": name,
            "alerts": [],
        })
        entry["alerts"].append({"name": test_name, "risk": risk})

    return {"details": details}

# ---------- Bandit CWE HTML (matches ZAP table look) ----------
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
def _pill(label, value, cls):
    return f'''
      <div class="pill {cls}">
        <span class="pill-label">{html.escape(label)}</span>
        <span class="pill-count">{html.escape(str(value))}</span>
      </div>'''

def build_index(z_counts, b_counts, now_utc_str):
    # Buttons link to our styled tables
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