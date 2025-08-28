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
  docker logs --tail=150 project-2-webapp-pentest-secure-coding-zaproxy-1 || true
  exit 1
fi

# ---------- Run scanners ----------
# IMPORTANT:
# - TARGET_URL must be resolvable/reachable BY THE ZAP CONTAINER.
#   Use the compose service name for internal container-to-container traffic.
export TARGET_URL="http://juice-shop:3000"
export ZAP_API_BASE="http://localhost:8080"

echo "Bandit..."
python3 scanners/bandit_scanner.py

echo "Zap..."
python3 scanners/zap_scanner.py

# Build the landing page
python3 scanners/report_generator.py

# ---------- Serve reports ----------
REPORT_DIR="reports"

# serve the dashboard first; fall back if missing
REPORT_FILE="index.html"
if [ ! -f "$REPORT_DIR/$REPORT_FILE" ]; then
  if [ -f "$REPORT_DIR/zap_report.html" ]; then
    REPORT_FILE="zap_report.html"
  elif [ -f "$REPORT_DIR/bandit_report.html" ]; then
    REPORT_FILE="bandit_report.html"
  else
    REPORT_FILE=""
  fi
fi

PORT=9000
# keep server alive; only clean up on Ctrl+C / termination
cleanup() { kill "${SERVER_PID:-}" >/dev/null 2>&1 || true; }
trap cleanup INT TERM

if [ -d "$REPORT_DIR" ]; then
  echo "Serving $REPORT_DIR on http://localhost:$PORT ..."
  # bind to all interfaces so Codespaces proxy can reach it
  python3 -m http.server "$PORT" --bind 0.0.0.0 --directory "$REPORT_DIR" >/dev/null 2>&1 &
  SERVER_PID=$!

  [ -n "$REPORT_FILE" ] && echo "Local fallback: http://127.0.0.1:$PORT/$REPORT_FILE"

  # host helper if present; otherwise synthesize Codespaces URL
  URL_BASE=""
  if command -v gp >/dev/null 2>&1; then
    URL_BASE="$(gp url "$PORT" 2>/dev/null || true)"
  elif [ "${CODESPACES:-false}" = "true" ] && [ -n "${CODESPACE_NAME:-}" ]; then
    DOMAIN="${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"
    URL_BASE="https://${CODESPACE_NAME}-${PORT}.${DOMAIN}"
  fi

  if [ -n "$URL_BASE" ] && [ -n "$REPORT_FILE" ]; then
    echo "Report ready: $URL_BASE/$REPORT_FILE"
    echo "(If it 401/404s, set port $PORT to Public in PORTS and ensure you’re signed into GitHub.)"
  else
    echo "Open the PORTS panel, click $PORT, then add /$REPORT_FILE to the end."
  fi

  echo "Press Ctrl+C to stop the report server."
  wait "$SERVER_PID"
else
  echo "Report directory not found: $REPORT_DIR"
fi