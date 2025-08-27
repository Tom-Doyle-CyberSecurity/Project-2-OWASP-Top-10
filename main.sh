#!/usr/bin/env bash
set -euo pipefail

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

# ---------- Serve reports ----------
REPORT_DIR="reports"
REPORT_FILE="zap_report.html"  # or bandit_report.html
PORT=9000

# Kill background server on script exit
trap 'kill $(jobs -p) >/dev/null 2>&1 || true' EXIT

if [ -d "$REPORT_DIR" ]; then
  echo "Serving $REPORT_DIR on http://localhost:$PORT ..."
  python3 -m http.server "$PORT" --directory "$REPORT_DIR" >/dev/null 2>&1 &

  # Always print a usable local fallback
  echo "Local fallback: http://127.0.0.1:$PORT/$REPORT_FILE"

  if command -v gp >/dev/null 2>&1; then
    URL_BASE=""
    for i in {1..30}; do
      URL_BASE="$(gp url "$PORT" 2>/dev/null || true)"
      # IMPORTANT: test the file path, not just the root
      if [ -n "$URL_BASE" ] && curl -fsS "$URL_BASE/$REPORT_FILE" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done

    if [ -n "$URL_BASE" ]; then
      REPORT_URL="$URL_BASE/$REPORT_FILE"
      echo "Report ready: $REPORT_URL"
      gp preview "$REPORT_URL" >/devnull 2>&1 || echo "Open manually: $REPORT_URL"
    else
      echo "Could not resolve Codespaces URL for port $PORT."
      echo "Open the PORTS panel, click 9000, and add /$REPORT_FILE to the end."
    fi
  else
    echo "Codespaces 'gp' not found. Open: http://127.0.0.1:$PORT/$REPORT_FILE"
  fi
else
  echo "Report directory not found: $REPORT_DIR"
fi