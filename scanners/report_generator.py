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
INDEX = os.path.join(RD, "index.html")           # dashboard
FINDINGS_JSON = os.path.join(RD, "findings.json")# consumed by potential frontend fetch

def jload(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def zap_summary(data):
    """Summarise ZAP JSON into totals and top rows (risk, title, url)."""
    totals = {"High":0, "Medium":0, "Low":0, "Informational":0}
    rows = []
    if data:
        for site in data.get("site", []):
            for a in site.get("alerts", []):
                risk_raw = a.get("risk") or a.get("riskcode") or ""
                risk = (str(risk_raw)).title()
                if risk not in totals:
                    risk = "Low"
                totals[risk] += 1
                title = a.get("alert","")
                uri = ""
                inst = a.get("instances") or []
                if inst and isinstance(inst, list):
                    uri = inst[0].get("uri","") or ""
                if not uri:
                    uri = site.get("@name","")
                rows.append((risk, title, uri))
    weight = {"High":3,"Medium":2,"Low":1,"Informational":0}
    rows.sort(key=lambda x: weight.get(x[0],0), reverse=True)
    return totals, rows[:10]

def bandit_summary(data):
    """Summarise Bandit JSON into totals and top rows (severity, issue, location)."""
    totals = {"HIGH":0, "MEDIUM":0, "LOW":0}
    rows = []
    if data:
        for r in data.get("results", []):
            sev = (r.get("issue_severity") or r.get("severity","LOW")).upper()
            if sev not in totals:
                sev = "LOW"
            totals[sev] += 1
            issue = r.get("issue_text","")
            loc = f"{r.get('filename','')}:{r.get('line_number','')}"
            rows.append((sev, issue, loc))
    return totals, rows[:10]

def pill(label, val, cls):
    return (f'<div class="pill {cls}"><span class="pill-label">{html.escape(label)}</span>'
            f'<span class="pill-count">{html.escape(str(val))}</span></div>')

def table(headers, rows):
    th = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    tb = "".join("<tr>"+"".join(f"<td>{html.escape(str(c))}</td>" for c in r)+"</tr>" for r in rows)
    return f"<table class=\"findings\"><thead><tr>{th}</tr></thead><tbody>{tb}</tbody></table>"

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
    ztot, zrows = zap_summary(z)
    btot, brows = bandit_summary(b)

    # Produce findings.json
    findings = {
        "zap": {
            "counts": {
                "high": ztot.get("High", 0),
                "medium": ztot.get("Medium", 0),
                "low": ztot.get("Low", 0),
                "info": ztot.get("Informational", 0)
            },
            "findings": [
                {"risk": r, "title": t, "url": u} for (r,t,u) in zrows
            ]
        },
        "bandit": {
            "counts": {
                "high": btot.get("HIGH", 0),
                "medium": btot.get("MEDIUM", 0),
                "low": btot.get("LOW", 0),
                "info": 0
            },
            "findings": [
                {"severity": s, "issue": t, "location": loc} for (s,t,loc) in brows
            ]
        }
    }
    with open(FINDINGS_JSON, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    # Mirror underscore HTML to dashed names if present
    safe_copy(os.path.join(RD, ZAP_HTML_UNDERSCORE), RD, ZAP_HTML_DASH)
    safe_copy(os.path.join(RD, BANDIT_HTML_UNDERSCORE), RD, BANDIT_HTML_DASH)

    # Build HTML dashboard
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    zap_html_exists = os.path.exists(os.path.join(RD, ZAP_HTML_DASH))
    bandit_html_exists = os.path.exists(os.path.join(RD, BANDIT_HTML_DASH))

    zap_link_html = (f'<a class="view-btn" href="{html.escape(os.path.join(".", ZAP_HTML_DASH))}" target="_blank">View Full Report</a>'
                     if zap_html_exists else '<div class="no-report">No ZAP HTML found.</div>')

    bandit_link_html = (f'<a class="view-btn" href="{html.escape(os.path.join(".", BANDIT_HTML_DASH))}" target="_blank">View Full Report</a>'
                        if bandit_html_exists else '<div class="no-report">No Bandit HTML found.</div>')

    zap_table_html = table(["Risk","Issue","URL"], zrows) if zrows else '<p class="no-findings">No findings in JSON.</p>'
    bandit_table_html = table(["Severity","Issue","Location"], brows) if brows else '<p class="no-findings">No findings in JSON.</p>'

    # NOTE: all literal CSS braces are doubled below so f-string doesn't try to interpret them.
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
  .frame{{max-width:1300px;margin:18px auto;padding:22px;border:8px solid var(--black);box-sizing:border-box;background:#ffffff}}
  h1{{font-size:44px;text-align:center;margin:6px 0 8px;font-weight:900}}
  .subtitle{{text-align:center;color:var(--muted);margin-bottom:22px;font-weight:700}}
  .reports{{display:grid;grid-template-columns:1fr 1fr;gap:60px;align-items:start}}
  @media (max-width:900px){{.reports{{grid-template-columns:1fr;gap:28px}}}}
  .card{{padding:6px 10px;text-align:center;}}
  .section-title{{font-size:20px;font-weight:800;margin-bottom:18px}}
  .pills{{display:flex;flex-direction:column;gap:22px;align-items:center}}
  .pill{{width:520px;max-width:92%;display:flex;justify-content:space-between;align-items:center;padding:18px 26px;border-radius:999px;font-weight:800;font-size:22px;box-shadow:0 6px 10px rgba(0,0,0,0.06)}}
  .pill.high{{background:linear-gradient(180deg,#ff5b57,#ff3b36);color:#2b0706}}
  .pill.moderate{{background:linear-gradient(180deg,#ffb07a,#ff974a);color:#2b1006}}
  .pill.low{{background:linear-gradient(180deg,#7fa9a1,#5f8d85);color:#072222}}
  .pill.info{{background:linear-gradient(180deg,#ececec,#dcdcdc);color:#222}}
  .pill-label{{padding-left:6px}}
  .pill-count{{background:rgba(0,0,0,0.08);padding:6px 12px;border-radius:999px;font-weight:900}}
  .view-btn{{display:inline-block;margin-top:18px;padding:10px 20px;border-radius:10px;background:#111;border:4px solid #111;color:#fff;text-decoration:none;font-weight:800}}
  .no-report{{color:var(--muted);font-weight:700;margin-top:18px}}
  .findings{{width:100%;margin-top:18px;border-collapse:collapse;color:var(--text);font-size:14px}}
  .findings thead th{{color:var(--muted);font-size:13px;text-align:left;padding:8px 12px;border-bottom:2px solid #eee}}
  .findings tbody td{{padding:10px 12px;border-bottom:1px solid #f3f3f3;vertical-align:top}}
  .no-findings{{color:var(--muted);font-weight:700}}
  .footer-note{{text-align:center;margin-top:22px;color:var(--muted);font-weight:700}}
</style>
</head>
<body>
  <div class="frame" role="main" aria-labelledby="main-title">
    <h1 id="main-title">OWASP Top 10 Findings Report</h1>
    <div class="subtitle">ZAP (dynamic) · Bandit (static) — generated: {html.escape(now)}</div>

    <div class="reports">
      <div class="card" id="zap-card" aria-labelledby="zap-title">
        <div class="section-title" id="zap-title">ZAP Report (zaproxy)</div>
        <div class="pills" role="list" aria-label="ZAP severity counts">
          {pill("High Risk", ztot.get("High",0), "high")}
          {pill("Moderate Risk", ztot.get("Medium",0), "moderate")}
          {pill("Low Risk", ztot.get("Low",0), "low")}
          {pill("Informational", ztot.get("Informational",0), "info")}
        </div>

        {zap_table_html}

        <div style="margin-top:12px">{zap_link_html}</div>
      </div>

      <div class="card" id="bandit-card" aria-labelledby="bandit-title">
        <div class="section-title" id="bandit-title">Bandit Report</div>
        <div class="pills" role="list" aria-label="Bandit severity counts">
          {pill("High Risk", btot.get("HIGH",0), "high")}
          {pill("Moderate Risk", btot.get("MEDIUM",0), "moderate")}
          {pill("Low Risk", btot.get("LOW",0), "low")}
        </div>

        {bandit_table_html}

        <div style="margin-top:12px">{bandit_link_html}</div>
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