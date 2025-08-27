#!/usr/bin/env bash
set -euo pipefail

echo "Bringing back up..."
docker compose up -d --build

# Wait for Juice Shop (port 3000) to be ready
echo "Waiting for Juice Shop on :3000..."
for i in {1..60}; do
if curl -fsS http://localhost:3000 >/dev/null 2>&1; then
    echo "Juice Shop is up at http://localhost:3000"
    break
fi
sleep 2
done

# ---- Run scanners ---- #
export TARGET_URL="http://localhost:3000"
export ZAP_API_BASE="http://localhost:8000"

echo "Bandit..."
python3 scanners/bandit_scanner.py

echo "Zap..."
python3 scanners/zap_scanner.py

# ---- Open Reports automatically via browser
REPORT_DIR="reports"
REPORT_FILE="zap_report.html"   # or bandit_report.html
PORT=9000

# Kill background server on script exit
trap 'kill $(jobs -p) >/dev/null 2>&1 || true' EXIT

if [ -d "$REPORT_DIR" ]; then
  echo "🌐 Serving $REPORT_DIR on http://localhost:$PORT ..."
  # Start a lightweight web server in the background
  python3 -m http.server "$PORT" --directory "$REPORT_DIR" >/dev/null 2>&1 &

  # Wait for the Codespaces forwarded URL to be ready
  URL_BASE=""
  for i in {1..30}; do
    URL_BASE="$(gp url "$PORT" 2>/dev/null || true)"
    if [ -n "$URL_BASE" ] && curl -fsS "$URL_BASE" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if [ -n "$URL_BASE" ]; then
    REPORT_URL="$URL_BASE/$REPORT_FILE"
    echo "📄 Report ready: $REPORT_URL"
    gp preview "$REPORT_URL" >/dev/null 2>&1 || echo "Open manually: $REPORT_URL"
  else
    echo "⚠️ Could not resolve Codespaces URL for port $PORT. Open the PORTS panel and click 9000."
  fi
else
  echo "⚠️ Report directory not found: $REPORT_DIR"
fi