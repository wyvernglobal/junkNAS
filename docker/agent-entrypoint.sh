#!/bin/sh
set -euo pipefail

WG_CONF="${JUNKNAS_WG_CONF:-/etc/wireguard/junknas.conf}"
CONTROLLER_URL="${JUNKNAS_CONTROLLER_URL:-http://[fd44::1]:8008/api}"

if [ ! -f "$WG_CONF" ]; then
  echo "[agent-entrypoint] WireGuard config $WG_CONF missing; cannot start agent"
  exit 1
fi

IFACE=$(basename "${WG_CONF%.*}")

if ! wg show "$IFACE" >/dev/null 2>&1; then
  echo "[agent-entrypoint] bringing up WireGuard interface $IFACE"
  wg-quick up "$WG_CONF"
else
  echo "[agent-entrypoint] WireGuard interface $IFACE already up"
fi

echo "[agent-entrypoint] waiting for controller at $CONTROLLER_URL over WireGuard"
until curl -fsS -g --max-time 3 "$CONTROLLER_URL/nodes" >/dev/null 2>&1; do
  echo "[agent-entrypoint] controller unreachable; retrying..."
  sleep 2
done

echo "[agent-entrypoint] controller reachable; starting agent"
exec /usr/local/bin/junknas-agent
