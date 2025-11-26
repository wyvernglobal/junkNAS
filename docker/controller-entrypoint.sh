#!/bin/sh
set -e

WG_CONF="${JUNKNAS_WG_CONF:-/etc/wireguard/junknas.conf}"
WG_IFACE="${WG_CONF##*/}"
WG_IFACE="${WG_IFACE%.conf}"
SAMBA_SHARE_DIR="${JUNKNAS_SAMBA_SHARE_DIR:-/srv/junknas-share}"
SAMBA_SHARE_NAME="${JUNKNAS_SAMBA_SHARE_NAME:-junknas}"
SAMBA_USER="${JUNKNAS_SAMBA_USER:-junknas}"
SAMBA_PASS="${JUNKNAS_SAMBA_PASS:-junknas}"
DASHBOARD_DIR="${DASHBOARD_DIR:-/srv/junknas-dashboard}"
API_PORT="${JUNKNAS_API_PORT:-8008}"
DASHBOARD_PORT="${JUNKNAS_DASHBOARD_PORT:-8080}"

API_PUBLIC_HOST="${JUNKNAS_API_PUBLIC_HOST:-127.0.0.1}"
API_PUBLIC_PORT="${JUNKNAS_API_PUBLIC_PORT:-${API_PORT}}"
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

export JUNKNAS_API_PORT="$API_PORT"
export JUNKNAS_DASHBOARD_PORT="$DASHBOARD_PORT"
export DASHBOARD_DIR

# Default to IPv6 overlay advertising to avoid clashing RFC1918 subnets.
export WG_ADDRESS_V6="${WG_ADDRESS_V6:-fd44::1/64}"

if [ -f "$WG_CONF" ]; then
  if wg show "$WG_IFACE" >/dev/null 2>&1; then
    echo "[controller] WireGuard interface $WG_IFACE already up"
  else
    echo "[controller] bringing up WireGuard interface $WG_IFACE from $WG_CONF"
    wg-quick up "$WG_CONF"
  fi
else
  echo "[controller] no WireGuard config at $WG_CONF; skipping bring-up"
fi

# Prepare Samba share rooted in the controller's allocated space.
mkdir -p "$SAMBA_SHARE_DIR"
chown -R root:root "$SAMBA_SHARE_DIR"

cat > /etc/samba/smb.conf <<EOF
[global]
  workgroup = WORKGROUP
  server role = standalone server
  map to guest = Bad User
  smb ports = 445
  log file = /var/log/samba/log.%m
  max log size = 50

[$SAMBA_SHARE_NAME]
  path = $SAMBA_SHARE_DIR
  browseable = yes
  read only = no
  guest ok = no
  create mask = 0664
  directory mask = 0775
EOF

if ! id -u "$SAMBA_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$SAMBA_USER"
fi

printf "%s\n%s\n" "$SAMBA_PASS" "$SAMBA_PASS" | smbpasswd -s -a "$SAMBA_USER"

echo "[controller] starting smbd for Samba share at $SAMBA_SHARE_DIR"
smbd -D

if [ -d "$DASHBOARD_DIR" ]; then
  cat >"${DASHBOARD_DIR}/config.json" <<EOF
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
  echo "[controller] dashboard config updated at ${DASHBOARD_DIR}/config.json (api=${API_URL})"
else
  echo "[controller] WARNING: dashboard dir missing at $DASHBOARD_DIR"
fi

echo "[controller] serving API on ${API_PORT}, dashboard on ${DASHBOARD_PORT}"

exec /usr/local/bin/junknas-controller "$@"
