#!/bin/sh
set -e

WG_CONF="${JUNKNAS_WG_CONF:-/etc/wireguard/junknas.conf}"
WG_IFACE="${WG_CONF##*/}"
WG_IFACE="${WG_IFACE%.conf}"

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

exec /usr/local/bin/junknas-controller "$@"
