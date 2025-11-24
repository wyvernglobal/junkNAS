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

# ------------------------------------------------------------
build_image() {
  name="$1"
  dockerfile="$2"

  [ ! -f "$dockerfile" ] && fail "Dockerfile not found: $dockerfile"

  log "building image $name"
  podman build -f "$dockerfile" -t "$name" "$JUNKNAS_SOURCE_DIR"
}

# ------------------------------------------------------------
generate_default_yaml() {
  log "generating default junknas.yaml"

  mkdir -p "$(dirname "$JUNKNAS_YAML_PATH")"

  cat >"$JUNKNAS_YAML_PATH" <<'EOF'
# Default junkNAS manifest (shortened for brevity)
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
    - port: 80
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
          ports:
            - containerPort: 80
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
    - port: 80
      targetPort: 80
EOF
}

# ------------------------------------------------------------
# Begin installer
# ------------------------------------------------------------
log "junkNAS installer (rootless)"

JUNKNAS_YAML_PATH="$(resolve_path "$JUNKNAS_YAML_PATH")"

require_cmd curl
ensure_podman

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
