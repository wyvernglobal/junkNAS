#!/bin/sh
set -eu

# ------------------------------------------------------------
# junknas-dashboard-entrypoint
#
# Rootless-safe entrypoint for the dashboard container.
# - Generates a config.json used by the SPA.
# - Serves static files on port 8080 by default.
# ------------------------------------------------------------

DASHBOARD_DIR="${DASHBOARD_DIR:-/srv/junknas-dashboard}"
PORT="${DASHBOARD_PORT:-8080}"

API_URL="${JUNKNAS_API_URL:-http://junknas-controller.junknas-controller.pod.local:8088/api}"
CLUSTER_NAME="${JUNKNAS_CLUSTER_NAME:-junkNAS}"
POLL_INTERVAL="${JUNKNAS_POLL_INTERVAL:-5}"
READONLY="${JUNKNAS_READONLY:-false}"

echo "[dashboard] starting on port ${PORT}"
echo "[dashboard] API endpoint: ${API_URL}"

if [ ! -d "$DASHBOARD_DIR" ]; then
  echo "[dashboard] ERROR: missing dashboard dir: $DASHBOARD_DIR"
  exit 1
fi

CONFIG_FILE="${DASHBOARD_DIR}/config.json"

cat > "$CONFIG_FILE" <<EOF
{
  "apiBaseUrl": "${API_URL}",
  "clusterName": "${CLUSTER_NAME}",
  "pollIntervalSeconds": ${POLL_INTERVAL},
  "readonly": ${READONLY}
}
EOF

echo "[dashboard] wrote config.json"

cd "$DASHBOARD_DIR"

# Prefer busybox httpd, fallback to python3 http.server
if command -v busybox >/dev/null 2>&1; then
  echo "[dashboard] serving with busybox httpd"
  exec busybox httpd -f -p "${PORT}" -h "${DASHBOARD_DIR}"
elif command -v python3 >/dev/null 2>&1; then
  echo "[dashboard] serving with python3 http.server"
  exec python3 -m http.server "${PORT}" --directory "${DASHBOARD_DIR}"
else
  echo "[dashboard] ERROR: no busybox or python3 found"
  exit 1
fi
