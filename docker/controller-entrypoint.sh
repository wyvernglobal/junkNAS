#!/bin/sh
set -e

WG_CONF="${JUNKNAS_WG_CONF:-/etc/wireguard/junknas.conf}"
WG_IFACE="${WG_CONF##*/}"
WG_IFACE="${WG_IFACE%.conf}"
SAMBA_SHARE_DIR="${JUNKNAS_SAMBA_SHARE_DIR:-/srv/junknas-share}"
SAMBA_SHARE_NAME="${JUNKNAS_SAMBA_SHARE_NAME:-junknas}"
SAMBA_USER="${JUNKNAS_SAMBA_USER:-junknas}"
SAMBA_PASS="${JUNKNAS_SAMBA_PASS:-junknas}"

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

exec /usr/local/bin/junknas-controller "$@"
