import json

with open('reports/bandit_output.json') as f:
    data = json.load(f)

with open('reports/bandit_report.html', 'w') as out:
    out.write('<html><body><h2>Bandit Report</h2><ul>')
    for issue in data['results']:
        out.write(f"<li><b>{issue['issue_severity']}</b>: {issue['issue_text']}</li>")
    out.write('</ul></body></html>')