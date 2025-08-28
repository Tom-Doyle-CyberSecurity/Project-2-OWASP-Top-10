#!/usr/bin/env python3
import os, json, datetime, html

RD = "reports"
ZAP_HTML = "zap_report.html"
ZAP_JSON = "zap_report.json"
BANDIT_HTML = "bandit_report.html"
BANDIT_JSON = "bandit_report.json"
INDEX = os.path.join(RD, "index.html")

def jload(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def zap_summary(data):
    totals = {"High":0, "Medium":0, "Low":0, "Informational":0}
    rows = []
    if data:
        for site in data.get("site", []):
            for a in site.get("alerts", []):
                risk = a.get("risk","").title()
                if risk not in totals: risk = "Low"
                totals[risk] += 1
                rows.append((risk, a.get("alert",""),
                             a.get("instances",[{}])[0].get("uri","") or site.get("@name","")))
    weight = {"High":3,"Medium":2,"Low":1,"Informational":0}
    rows.sort(key=lambda x: weight.get(x[0],0), reverse=True)
    return totals, rows[:10]

def bandit_summary(data):
    totals = {"HIGH":0, "MEDIUM":0, "LOW":0}
    rows = []
    if data:
        for r in data.get("results", []):
            sev = (r.get("issue_severity") or r.get("severity","LOW")).upper()
            totals.setdefault(sev, 0); totals[sev] += 1
            rows.append((sev, r.get("issue_text",""),
                         f"{r.get('filename','')}:{r.get('line_number','')}"))
    return totals, rows[:10]

def chip(lbl, val, cls): 
    return f'<div class="chip {cls}"><span>{html.escape(lbl)}</span><b>{val}</b></div>'

def table(headers, rows):
    th = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    tb = "".join("<tr>"+"".join(f"<td>{html.escape(str(c))}</td>" for c in r)+"</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{tb}</tbody></table>"

def main():
    os.makedirs(RD, exist_ok=True)
    z = jload(os.path.join(RD, ZAP_JSON))
    b = jload(os.path.join(RD, BANDIT_JSON))
    ztot, zrows = zap_summary(z)
    btot, brows = bandit_summary(b)

    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    doc = f"""<!doctype html><meta charset="utf-8">
<title>Pentest Reports</title>
<style>
body{{margin:0;font:14px system-ui;background:#0b0d10;color:#e6edf3}}
h1{{margin:0 0 6px;padding:20px;border-bottom:1px solid #1f242d}}
.grid{{display:grid;gap:16px;padding:16px;grid-template-columns:1fr 1fr}}
.card{{background:#11151b;border:1px solid #1f242d;border-radius:14px;padding:14px}}
.chips{{display:flex;gap:8px;margin:8px 0 12px}}
.chip{{display:flex;gap:6px;align-items:center;padding:6px 10px;border-radius:10px;border:1px solid #1f242d;background:#0e1319}}
.chip.danger b{{color:#ff6b6b}} .chip.warn b{{color:#ffd166}} .chip.ok b{{color:#77dd77}}
table{{width:100%;border-collapse:collapse;border:1px solid #1f242d;border-radius:8px;overflow:hidden}}
th,td{{padding:8px 10px;border-bottom:1px solid #1f242d;text-align:left}}
thead th{{background:#0f141a;color:#9aa4b2;font-weight:600;font-size:12px}}
iframe{{width:100%;height:65vh;border:1px solid #1f242d;border-radius:10px;background:#fff}}
@media(max-width:980px){{.grid{{grid-template-columns:1fr}}iframe{{height:55vh}}}}
a.btn{{display:inline-block;margin:8px 0;padding:8px 10px;border:1px solid #1f242d;border-radius:8px;text-decoration:none;color:#e6edf3}}
</style>
<h1>WebApp Pentest Lab — Reports <small style="color:#9aa4b2">({now})</small></h1>
<div class="grid">

<div class="card">
  <h2>ZAP (Dynamic)</h2>
  <div class="chips">
    {chip("High", ztot.get("High",0), "danger")}
    {chip("Medium", ztot.get("Medium",0), "warn")}
    {chip("Low", ztot.get("Low",0), "ok")}
    {chip("Info", ztot.get("Informational",0), "")}
  </div>
  {table(["Risk","Issue","URL"], zrows)}
  {'<a class="btn" href="""" + ZAP_HTML + """" target="_blank">Open full report</a>' if os.path.exists(os.path.join(RD,ZAP_HTML)) else '<p style="color:#9aa4b2">No ZAP HTML found.</p>'}
  {'<iframe src="""" + ZAP_HTML + """"></iframe>' if os.path.exists(os.path.join(RD,ZAP_HTML)) else ''}
</div>

<div class="card">
  <h2>Bandit (Static)</h2>
  <div class="chips">
    {chip("High", btot.get("HIGH",0), "danger")}
    {chip("Medium", btot.get("MEDIUM",0), "warn")}
    {chip("Low", btot.get("LOW",0), "ok")}
  </div>
  {table(["Severity","Issue","Location"], brows)}
  {'<a class="btn" href="""" + BANDIT_HTML + """" target="_blank">Open full report</a>' if os.path.exists(os.path.join(RD,BANDIT_HTML)) else '<p style="color:#9aa4b2">No Bandit HTML found.</p>'}
  {'<iframe src="""" + BANDIT_HTML + """"></iframe>' if os.path.exists(os.path.join(RD,BANDIT_HTML)) else ''}
</div>

</div>"""
    with open(INDEX, "w", encoding="utf-8") as f:
        f.write(doc)

if __name__ == "__main__":
    main()
