#!/usr/bin/env python3
import os, json, datetime, html, shutil

# ---- Paths (kept your originals; added the dashed variants index.html expects) ----
RD = "reports"

# Original filenames produced by scanners / earlier scripts
ZAP_HTML_UNDERSCORE    = "zap_report.html"
ZAP_JSON_UNDERSCORE    = "zap_report.json"
BANDIT_HTML_UNDERSCORE = "bandit_report.html"
BANDIT_JSON_UNDERSCORE = "bandit_report.json"

# Filenames that index.html links to
ZAP_HTML_DASH    = "zap-report.html"
BANDIT_HTML_DASH = "bandit-report.html"

# Our outputs
INDEX = os.path.join(RD, "index.html")            # dashboard
FINDINGS_JSON = os.path.join(RD, "findings.json") # consumed by potential frontend fetch

def jload(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def zap_summary(data):
    """Summarise ZAP JSON into totals (High/Medium/Low/Informational)."""
    totals = {"High":0, "Medium":0, "Low":0, "Informational":0}
    if data:
        for site in data.get("site", []):
            for a in site.get("alerts", []):
                risk_raw = a.get("risk") or a.get("riskcode") or ""
                risk = (str(risk_raw)).title()
                if risk not in totals:
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

    # Mirror underscore HTML to dashed names if present
    safe_copy(os.path.join(RD, ZAP_HTML_UNDERSCORE), RD, ZAP_HTML_DASH)
    safe_copy(os.path.join(RD, BANDIT_HTML_UNDERSCORE), RD, BANDIT_HTML_DASH)

    # Build HTML landing page
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    zap_html_exists = os.path.exists(os.path.join(RD, ZAP_HTML_DASH))
    bandit_html_exists = os.path.exists(os.path.join(RD, BANDIT_HTML_DASH))

    zap_link_html = (f'<a class="view-btn" href="{html.escape(os.path.join(".", ZAP_HTML_DASH))}" target="_blank">View Full Report</a>'
                 if zap_html_exists else '<div class="no-report">No ZAP HTML found</div>')

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
  /* dotted background grid */
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
    dynamic and static analysis tools. The ZAP scan found no high-risk issues but flagged 131 moderate risks, plus 256 low-risk
    and 76 informational findings, indicating several areas for hardening despite no critical threats. Bandit's static code analysis
    reported only one low-risk issue with no moderate or high-risk findings, suggesting strong coding practices. However, CodeQL 
    findings via GitHub actions should also be examined. Overall, remediation should focus on the moderate risks from ZAP to further
    strengthen security posture. Generated: {html.escape(now)}</p>

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

    print(f"Wrote {INDEX} (ZAP html exists: {zap_html_exists}, Bandit html exists: {bandit_html_exists})")
    print(f"Wrote {FINDINGS_JSON}")

if __name__ == "__main__":
    main()