#!/bin/sh
set -eu

# ------------------------------------------------------------
# Rootless installer for junkNAS using Podman
# ------------------------------------------------------------

ORIGINAL_PWD="$(pwd)"

JUNKNAS_YAML_URL="${JUNKNAS_YAML_URL:-}"
JUNKNAS_YAML_PATH="${JUNKNAS_YAML_PATH:-./junknas.yaml}"
JUNKNAS_SOURCE_DIR="${JUNKNAS_SOURCE_DIR:-}"
JUNKNAS_REPO_URL="https://github.com/wyvernglobal/junkNAS.git"
JUNKNAS_KEEP_SOURCE="${JUNKNAS_KEEP_SOURCE:-0}"
SOURCE_DIR_WAS_AUTO=0
AUTO_CLONE_ROOT=""

# ------------------------------------------------------------
# Logging (stderr to avoid corrupting stdout for var assignment)
# ------------------------------------------------------------
log() {
  printf '[install] %s\n' "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

# ------------------------------------------------------------
resolve_path() {
  case "$1" in
    /*) echo "$1" ;;
    *) echo "${ORIGINAL_PWD}/$1" ;;
  esac
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 not found in PATH"
}

# ------------------------------------------------------------
# SAFE DETECTION OF SOURCE DIRECTORY (stdout MUST ONLY print path)
# ------------------------------------------------------------
detect_source_dir() {

  # 1. User provided explicit directory
  if [ -n "$JUNKNAS_SOURCE_DIR" ]; then
    resolved="$(resolve_path "$JUNKNAS_SOURCE_DIR")"
    [ ! -d "$resolved" ] && fail "JUNKNAS_SOURCE_DIR does not exist: $resolved"
    printf "%s\n" "$resolved"
    return
  fi

  # 2. Local junkNAS folder exists
  if [ -d "./junkNAS" ]; then
    printf "%s\n" "$(resolve_path ./junkNAS)"
    return
  fi

  # 3. Clone repo
  require_cmd git
  log "cloning junkNAS from ${JUNKNAS_REPO_URL}"
  git clone "$JUNKNAS_REPO_URL" "./junkNAS"
  AUTO_CLONE_ROOT="./junkNAS"
  SOURCE_DIR_WAS_AUTO=1

  printf "%s\n" "$(resolve_path ./junkNAS)"
}

# ------------------------------------------------------------
cleanup_source_dir() {
  [ "$JUNKNAS_KEEP_SOURCE" = "1" ] && return
  [ "$SOURCE_DIR_WAS_AUTO" = "1" ] || return

  if [ -n "$AUTO_CLONE_ROOT" ] && [ -d "$AUTO_CLONE_ROOT" ]; then
    log "removing auto-cloned source directory $AUTO_CLONE_ROOT"
    rm -rf "$AUTO_CLONE_ROOT"
  fi
}

# ------------------------------------------------------------
detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then echo apt-get
  elif command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v yum >/dev/null 2>&1; then echo yum
  else echo ""
  fi
}

install_podman() {
  pmgr=$(detect_pkg_manager)
  [ -z "$pmgr" ] && fail "No package manager found to install podman"

  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else SUDO=""; fi

  log "installing podman using $pmgr"

  case "$pmgr" in
    apt-get)
      $SUDO apt-get update -y
      $SUDO apt-get install -y podman
      ;;
    dnf)
      $SUDO dnf install -y podman
      ;;
    yum)
      $SUDO yum install -y podman
      ;;
  esac
}

ensure_podman() {
  if ! command -v podman >/dev/null 2>&1; then
    install_podman
  fi

  command -v podman >/dev/null 2>&1 || fail "podman installation failed"
}

ensure_wireguard_tools() {
  if command -v wg >/dev/null 2>&1; then
    return
  fi

  pmgr=$(detect_pkg_manager)
  [ -z "$pmgr" ] && fail "wireguard-tools not found and no package manager available"

  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else SUDO=""; fi

  log "installing wireguard-tools using $pmgr"

  case "$pmgr" in
    apt-get)
      $SUDO apt-get update -y
      $SUDO apt-get install -y wireguard wireguard-tools
      ;;
    dnf)
      $SUDO dnf install -y wireguard wireguard-tools
      ;;
    yum)
      $SUDO yum install -y wireguard wireguard-tools
      ;;
  esac
}

# ------------------------------------------------------------
build_image() {
  name="$1"
  dockerfile="$2"

  [ ! -f "$dockerfile" ] && fail "Dockerfile not found: $dockerfile"

  log "building image $name"
  podman build -f "$dockerfile" -t "$name" "$JUNKNAS_SOURCE_DIR"
}

detect_podman_gateway() {
  command -v podman >/dev/null 2>&1 || return 0

  if ! podman network inspect podman >/dev/null 2>&1; then
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    podman network inspect podman 2>/dev/null | python3 - <<'PY'
import json, sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

if not data:
    sys.exit(0)

net = data[0]
gateway = None

for plugin in net.get("plugins", []):
    ipam = plugin.get("ipam", {})
    for rng in ipam.get("ranges", []):
        if not rng:
            continue
        gateway = rng[0].get("gateway")
        if gateway:
            break
    if gateway:
        break

if not gateway:
    for subnet in net.get("subnets", []):
        gateway = subnet.get("gateway")
        if gateway:
            break

if gateway:
    print(gateway)
PY
  fi
}

wireguard_config_dir() {
  if [ "$(id -u)" -eq 0 ]; then
    echo "/etc/wireguard"
  else
    echo "${XDG_CONFIG_HOME:-$HOME/.config}/wireguard"
  fi
}

generate_wireguard_mesh_configs() {
  ensure_wireguard_tools

  WG_PORT="${JUNKNAS_WG_PORT:-51820}"
  WG_SUBNET="${JUNKNAS_WG_SUBNET:-10.44.0.0/16}"
  WG_CTRL_ADDR="${JUNKNAS_WG_CONTROLLER_ADDRESS:-10.44.0.1/32}"
  WG_AGENT_ADDR="${JUNKNAS_WG_AGENT_ADDRESS:-10.44.0.2/32}"

  gateway="$(detect_podman_gateway)"
  endpoint_host="${JUNKNAS_WG_ENDPOINT_HOST:-${gateway:-127.0.0.1}}"
  endpoint="${endpoint_host}:${WG_PORT}"

  cfg_dir="$(wireguard_config_dir)"
  mkdir -p "$cfg_dir"
  chmod 700 "$cfg_dir"

  # Generate key pairs
  ctrl_priv="$(wg genkey)"
  ctrl_pub="$(printf '%s' "$ctrl_priv" | wg pubkey)"
  agent_priv="$(wg genkey)"
  agent_pub="$(printf '%s' "$agent_priv" | wg pubkey)"

  ctrl_cfg="$cfg_dir/junknas-controller.conf"
  agent_cfg="$cfg_dir/junknas-agent.conf"

  old_umask="$(umask)"
  umask 077
  cat >"$ctrl_cfg" <<EOF
[Interface]
Address = ${WG_CTRL_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${ctrl_priv}

[Peer]
PublicKey = ${agent_pub}
AllowedIPs = ${WG_AGENT_ADDR}
EOF

  cat >"$agent_cfg" <<EOF
[Interface]
Address = ${WG_AGENT_ADDR}
PrivateKey = ${agent_priv}

[Peer]
PublicKey = ${ctrl_pub}
AllowedIPs = ${WG_SUBNET}
Endpoint = ${endpoint}
PersistentKeepalive = 25
EOF

  umask "$old_umask"
  chmod 600 "$ctrl_cfg" "$agent_cfg"
  log "wrote WireGuard configs to $cfg_dir (controller=${WG_CTRL_ADDR}, agent=${WG_AGENT_ADDR}, endpoint=${endpoint})"
}

# ------------------------------------------------------------
generate_default_yaml() {
  log "generating default junknas.yaml"

  mkdir -p "$(dirname "$JUNKNAS_YAML_PATH")"

  cat >"$JUNKNAS_YAML_PATH" <<'EOF'
# Default junkNAS manifest (with Samba sidecar)
apiVersion: v1
kind: Namespace
metadata:
  name: junknas
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: junknas-controller
  namespace: junknas
spec:
  replicas: 1
  selector:
    matchLabels:
      app: junknas-controller
  template:
    metadata:
      labels:
        app: junknas-controller
    spec:
      containers:
        - name: controller
          image: ghcr.io/junknas/controller:latest
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: junknas-controller
  namespace: junknas
spec:
  selector:
    app: junknas-controller
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: junknas-dashboard
  namespace: junknas
spec:
  replicas: 1
  selector:
    matchLabels:
      app: junknas-dashboard
  template:
    metadata:
      labels:
        app: junknas-dashboard
    spec:
      containers:
        - name: dashboard
          image: ghcr.io/junknas/dashboard:latest
          imagePullPolicy: IfNotPresent
          env:
            - name: JUNKNAS_API_URL
              value: "http://10.44.0.1:8080/api"  # WireGuard overlay endpoint
            - name: JUNKNAS_SAMBA_ENABLED
              value: "true"
            - name: JUNKNAS_SAMBA_PUBLIC_KEY
              value: "samba-sidecar-public-key"
            - name: JUNKNAS_SAMBA_ENDPOINT
              value: "junknas-samba.junknas.svc.cluster.local:51820"
            - name: JUNKNAS_SAMBA_ALLOWED_IPS
              value: "10.44.0.0/16"
            - name: JUNKNAS_SAMBA_CLIENT_ADDRESS
              value: "10.44.0.80/32"
            - name: JUNKNAS_SAMBA_DNS
              value: "1.1.1.1"
            - name: JUNKNAS_SAMBA_NOTE
              value: "Samba sidecar runs on the WireGuard VLAN; clients should use the generated key instead of cluster keys."
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: junknas-dashboard
  namespace: junknas
spec:
  selector:
    app: junknas-dashboard
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: junknas-agent
  namespace: junknas
spec:
  replicas: 1
  selector:
    matchLabels:
      app: junknas-agent
  template:
    metadata:
      labels:
        app: junknas-agent
    spec:
      containers:
        - name: junknas-agent
          image: ghcr.io/junknas/agent:latest
          env:
            - name: JUNKNAS_CONTROLLER_URL
              value: "http://10.44.0.1:8080/api"  # WireGuard overlay endpoint
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: junknas-samba
  namespace: junknas
spec:
  replicas: 1
  selector:
    matchLabels:
      app: junknas-samba
  template:
    metadata:
      labels:
        app: junknas-samba
    spec:
      containers:
        - name: junknas-agent
          image: ghcr.io/junknas/agent:latest
          imagePullPolicy: IfNotPresent
          args: ["mount", "/mnt/junknas"]
          env:
            - name: JUNKNAS_CONTROLLER_URL
              value: "http://10.44.0.1:8080/api"  # WireGuard overlay endpoint
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN"]
          volumeMounts:
            - name: fuse
              mountPath: /dev/fuse
            - name: junknas-data
              mountPath: /var/lib/junknas
            - name: junknas-mnt
              mountPath: /mnt/junknas
        - name: samba
          image: docker.io/dperson/samba:latest
          imagePullPolicy: IfNotPresent
          args: ["-s", "junknas;/srv/junknas;yes;no;yes"]
          env:
            - name: USER
              value: junknas
            - name: PASS
              value: junknas
          ports:
            - containerPort: 445
          volumeMounts:
            - name: junknas-mnt
              mountPath: /srv/junknas
      volumes:
        - name: fuse
          hostPath:
            path: /dev/fuse
        - name: junknas-data
          emptyDir: {}
        - name: junknas-mnt
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: junknas-samba
  namespace: junknas
spec:
  selector:
    app: junknas-samba
  ports:
    - name: smb
      port: 445
      targetPort: 445
EOF
}

# ------------------------------------------------------------
# Begin installer
# ------------------------------------------------------------
log "junkNAS installer (rootless)"

JUNKNAS_YAML_PATH="$(resolve_path "$JUNKNAS_YAML_PATH")"

require_cmd curl
ensure_podman
ensure_wireguard_tools

# Resolve working directory safely
log "resolving junkNAS source directory"
JUNKNAS_SOURCE_DIR="$(detect_source_dir)"
log "using source directory: $JUNKNAS_SOURCE_DIR"

cd "$JUNKNAS_SOURCE_DIR"

[ "$(id -u)" -eq 0 ] && log "warning: running as root (rootless recommended)"

# ------------------------------------------------------------
# Fetch manifest (download or generate)
# ------------------------------------------------------------
if [ -n "$JUNKNAS_YAML_URL" ]; then
  log "downloading manifest from $JUNKNAS_YAML_URL"
  curl -fsSL "$JUNKNAS_YAML_URL" -o "$JUNKNAS_YAML_PATH"
fi

if [ ! -f "$JUNKNAS_YAML_PATH" ]; then
  if [ -f "$JUNKNAS_SOURCE_DIR/deploy/junknas.yaml" ]; then
    log "using repo manifest"
    cp "$JUNKNAS_SOURCE_DIR/deploy/junknas.yaml" "$JUNKNAS_YAML_PATH"
  else
    generate_default_yaml
  fi
else
  log "using existing manifest"
fi

# ------------------------------------------------------------
# Generate WireGuard configs for the mesh
# ------------------------------------------------------------
generate_wireguard_mesh_configs

# ------------------------------------------------------------
# Build container images locally
# ------------------------------------------------------------
build_image ghcr.io/junknas/controller:latest "$JUNKNAS_SOURCE_DIR/docker/controller.Dockerfile"
build_image ghcr.io/junknas/dashboard:latest "$JUNKNAS_SOURCE_DIR/docker/dashboard.Dockerfile"
build_image ghcr.io/junknas/agent:latest "$JUNKNAS_SOURCE_DIR/docker/agent.Dockerfile"

# ------------------------------------------------------------
cd "$ORIGINAL_PWD"
cleanup_source_dir

log "deploying junkNAS via podman kube play"
podman kube play "$JUNKNAS_YAML_PATH"

log "done."
log "View running containers: podman ps"
