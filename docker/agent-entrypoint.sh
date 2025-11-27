#!/usr/bin/env bash
set -euo pipefail

WG_CONF="${JUNKNAS_WG_CONF:-/etc/wireguard/junknas.conf}"
PEER_CONF="${JUNKNAS_PEER_WG_CONF:-/etc/wireguard/junknas-peer.conf}"
STATE_DIR="${JUNKNAS_WG_STATE_DIR:-/var/lib/junknas/wireguard}"
CONTROLLER_API="${JUNKNAS_CONTROLLER_API:-http://127.0.0.1:8008/api}"

INTERFACE=$(basename "${WG_CONF%.*}")
mkdir -p "$STATE_DIR" "$(dirname "$WG_CONF")" "$(dirname "$PEER_CONF")"

AGENT_KEY_PATH="$STATE_DIR/agent.key"
PEER_KEY_PATH="$STATE_DIR/controller.key"
AGENT_PORT="${JUNKNAS_AGENT_PORT:-51820}"
CONTROLLER_PORT="${JUNKNAS_CONTROLLER_PORT:-51821}"
AGENT_ENDPOINT="${JUNKNAS_AGENT_ENDPOINT:-[::1]:${AGENT_PORT}}"
CONTROLLER_ENDPOINT="${JUNKNAS_CONTROLLER_ENDPOINT:-[::1]:${CONTROLLER_PORT}}"
AGENT_ADDRESS="${JUNKNAS_AGENT_ADDRESS:-fd44::2/128}"
CONTROLLER_ADDRESS="${JUNKNAS_CONTROLLER_ADDRESS:-fd44::1/128}"

if [ ! -s "$AGENT_KEY_PATH" ]; then
  echo "[agent-entrypoint] generating WireGuard keypair for agent interface"
  wg genkey | tee "$AGENT_KEY_PATH" >/dev/null
fi
if [ ! -s "$PEER_KEY_PATH" ]; then
  echo "[agent-entrypoint] generating WireGuard keypair for controller peer"
  wg genkey | tee "$PEER_KEY_PATH" >/dev/null
fi

AGENT_PRIVATE_KEY=$(cat "$AGENT_KEY_PATH")
AGENT_PUBLIC_KEY=$(printf '%s' "$AGENT_PRIVATE_KEY" | wg pubkey)
PEER_PRIVATE_KEY=$(cat "$PEER_KEY_PATH")
PEER_PUBLIC_KEY=$(printf '%s' "$PEER_PRIVATE_KEY" | wg pubkey)

cat >"$WG_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${AGENT_PRIVATE_KEY}
Address = ${AGENT_ADDRESS}
ListenPort = ${AGENT_PORT}
SaveConfig = true

[Peer]
PublicKey = ${PEER_PUBLIC_KEY}
AllowedIPs = ${CONTROLLER_ADDRESS}
Endpoint = ${CONTROLLER_ENDPOINT}
PersistentKeepalive = 25
EOF_CONF

echo "[agent-entrypoint] bringing up WireGuard interface ${INTERFACE} from ${WG_CONF}"
if wg show "$INTERFACE" >/dev/null 2>&1; then
  wg-quick down "$INTERFACE" || true
fi
wg-quick up "$WG_CONF"

cat >"$PEER_CONF" <<EOF_PEER
[Interface]
PrivateKey = ${PEER_PRIVATE_KEY}
Address = ${CONTROLLER_ADDRESS}
ListenPort = ${CONTROLLER_PORT}
SaveConfig = true

[Peer]
PublicKey = ${AGENT_PUBLIC_KEY}
AllowedIPs = ${AGENT_ADDRESS}
Endpoint = ${AGENT_ENDPOINT}
PersistentKeepalive = 25
EOF_PEER

CONFIG_B64=$(base64 <"$PEER_CONF" | tr -d '\n')
PAYLOAD=$(cat <<EOF
{"interface":"$INTERFACE","path":"$PEER_CONF","config_base64":"$CONFIG_B64"}
EOF
)

echo "[agent-entrypoint] sending peer config to controller at ${CONTROLLER_API}/mesh/peer-config"
curl -fsS -X POST "${CONTROLLER_API}/mesh/peer-config" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"

echo "[agent-entrypoint] starting agent over WireGuard"
exec /usr/local/bin/junknas-agent
