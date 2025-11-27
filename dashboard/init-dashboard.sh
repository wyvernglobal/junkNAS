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

API_PUBLIC_HOST="${JUNKNAS_API_PUBLIC_HOST:-junknas-controller.junknas-controller.pod.local}"
API_PUBLIC_PORT="${JUNKNAS_API_PUBLIC_PORT:-8008}"
API_URL="${JUNKNAS_API_URL:-http://${API_PUBLIC_HOST}:${API_PUBLIC_PORT}/api}"
CLUSTER_NAME="${JUNKNAS_CLUSTER_NAME:-junkNAS}"
POLL_INTERVAL="${JUNKNAS_POLL_INTERVAL:-5}"
READONLY="${JUNKNAS_READONLY:-false}"
SAMBA_ENABLED="${JUNKNAS_SAMBA_ENABLED:-true}"
SAMBA_PUBLIC_KEY="${JUNKNAS_SAMBA_PUBLIC_KEY:-}"
SAMBA_ENDPOINT="${JUNKNAS_SAMBA_ENDPOINT:-}"
SAMBA_ALLOWED_IPS="${JUNKNAS_SAMBA_ALLOWED_IPS:-10.44.0.0/16}"
SAMBA_CLIENT_ADDRESS="${JUNKNAS_SAMBA_CLIENT_ADDRESS:-auto-assigned}"
SAMBA_DNS="${JUNKNAS_SAMBA_DNS:-1.1.1.1}"
SAMBA_PRESHARED_KEY="${JUNKNAS_SAMBA_PRESHARED_KEY:-}"
SAMBA_CLIENT_TEMPLATE="${JUNKNAS_SAMBA_CLIENT_TEMPLATE:-}"
SAMBA_MESH_PUBLIC_KEY="${JUNKNAS_MESH_PUBLIC_KEY:-}"
SAMBA_NOTE="${JUNKNAS_SAMBA_NOTE:-The controller now serves Samba directly; use the dashboard to mint client WireGuard peers.}"

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
  "readonly": ${READONLY},
  "sambaGateway": {
    "enabled": ${SAMBA_ENABLED},
    "publicKey": "${SAMBA_PUBLIC_KEY}",
    "endpoint": "${SAMBA_ENDPOINT}",
    "allowedIps": "${SAMBA_ALLOWED_IPS}",
    "clientAddressCidr": "${SAMBA_CLIENT_ADDRESS}",
    "dns": "${SAMBA_DNS}",
    "presharedKey": "${SAMBA_PRESHARED_KEY}",
    "clientConfigTemplate": "${SAMBA_CLIENT_TEMPLATE}",
    "meshPublicKey": "${SAMBA_MESH_PUBLIC_KEY}",
    "note": "${SAMBA_NOTE}"
  }
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
