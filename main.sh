#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Bringing back up..."
docker compose up -d --build

# ---------- Wait for services ----------
echo "Waiting for Juice Shop on localhost:3000..."
JUICE_OK=0
for i in {1..60}; do
  if curl -fsS http://localhost:3000 >/dev/null 2>&1; then
    echo "Juice Shop is up at http://localhost:3000"
    JUICE_OK=1
    break
  fi
  sleep 2
done
if [ "$JUICE_OK" -ne 1 ]; then
  echo "Juice Shop did not become ready in time"; exit 1
fi

echo "Waiting for ZAP on localhost:8080..."
ZAP_OK=0
for i in {1..120}; do   # give it up to ~4 minutes in Codespaces
  if curl -fsS http://localhost:8080/json/core/view/version/  >/dev/null 2>&1 || \
     curl -fsS http://localhost:8080/JSON/core/view/version/  >/dev/null 2>&1 || \
     curl -fsS http://localhost:8080/                        >/dev/null 2>&1 ; then
    echo "ZAP is up at http://localhost:8080"
    ZAP_OK=1
    break
  fi
  sleep 2
done

if [ "$ZAP_OK" -ne 1 ]; then
  echo "ZAP did not become ready in time"
  echo "---- last 150 lines of ZAP logs ----"
  # Use your compose service name here (e.g., 'zaproxy'); avoids hard-coded container ids
  docker compose logs --tail=150 zaproxy || true
  exit 1
fi

# ---------- Run scanners ----------
# IMPORTANT:
# - TARGET_URL must be resolvable by the ZAP CONTAINER.
#   Use the compose service name for container-to-container traffic.
export TARGET_URL="http://juice-shop:3000"
export ZAP_API_BASE="http://localhost:8080"

echo "Bandit..."
python3 scanners/bandit_scanner.py

echo "Zap..."
python3 scanners/zap_scanner.py

# Build the landing page and reports
python3 scanners/report_generator.py

# ---------- Serve reports ----------
REPORT_DIR="reports"
INDEX_HTML="$REPORT_DIR/index.html"

REPORT_FILE="index.html"

PORT=9000
cleanup() { kill "${SERVER_PID:-}" >/dev/null 2>&1 || true; }
trap cleanup INT TERM

echo "Serving $REPORT_DIR on http://localhost:$PORT ..."
# Bind all interfaces so Codespaces proxy can reach it
python3 -m http.server "$PORT" --bind 0.0.0.0 --directory "$REPORT_DIR" >/dev/null 2>&1 &
SERVER_PID=$!

echo "Local fallback: http://127.0.0.1:$PORT/$REPORT_FILE"

# GitHub Codespaces URL (gp helper or synthesize)
URL_BASE=""
if command -v gp >/dev/null 2>&1; then
  URL_BASE="$(gp url "$PORT" 2>/dev/null || true)"
elif [ "${CODESPACES:-false}" = "true" ] && [ -n "${CODESPACE_NAME:-}" ]; then
  DOMAIN="${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"
  URL_BASE="https://${CODESPACE_NAME}-${PORT}.${DOMAIN}"
fi

if [ -n "$URL_BASE" ]; then
  echo "Report ready: $URL_BASE/$REPORT_FILE"
  echo "(If it 401/404s, set port $PORT to Public in the PORTS panel and ensure you’re signed into GitHub.)"
else
  echo "Open the PORTS panel, click $PORT, then add /$REPORT_FILE to the end."
fi

echo "Press Ctrl+C to stop the report server."
wait "$SERVER_PID"