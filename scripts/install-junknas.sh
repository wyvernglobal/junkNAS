#!/bin/sh
set -eu

# The installer is designed to be pipeable, e.g.:
#   curl -fsSL https://example.com/install-junknas.sh | sh
# so avoid relying on relative script paths.

# ------------------------------------------------------------
# install-junknas.sh
#
# Rootless installer for junkNAS using Podman.
# Assumptions:
#   - podman is installed and rootless configured.
#   - you have junknas.yaml available locally OR via URL.
#
# Usage:
#   curl -fsSL https://example.com/install-junknas.sh | sh
#
# Environment overrides:
#   JUNKNAS_YAML_URL   - URL to junknas.yaml (if not using local file)
#   JUNKNAS_YAML_PATH  - Local path to junknas.yaml (default ./junknas.yaml)
#   JUNKNAS_SOURCE_DIR - Where Dockerfiles/manifests live when building locally (default pwd)
# ------------------------------------------------------------

JUNKNAS_YAML_URL="${JUNKNAS_YAML_URL:-}"
JUNKNAS_YAML_PATH="${JUNKNAS_YAML_PATH:-./junknas.yaml}"
# Root directory containing dockerfiles/deploy manifests.
JUNKNAS_SOURCE_DIR="${JUNKNAS_SOURCE_DIR:-$(pwd)}"

log() {
  printf '[install] %s\n' "$*"
}

fail() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "$1 not found in PATH"
  fi
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo apt-get
  elif command -v dnf >/dev/null 2>&1; then
    echo dnf
  elif command -v yum >/dev/null 2>&1; then
    echo yum
  else
    echo ""
  fi
}
git clone https://github.com/wyvernglobal/junkNAS.git
cd junkNAS
install_podman() {
  pmgr=$(detect_pkg_manager)
  if [ -z "$pmgr" ]; then
    fail "podman is required but no supported package manager (apt-get/dnf/yum) was found"
  fi

  sudo_bin=""
  if command -v sudo >/dev/null 2>&1; then
    sudo_bin="sudo"
  elif [ "$(id -u)" -ne 0 ]; then
    fail "sudo is required to install podman (or rerun this script as root for installation only)"
  fi

  log "installing podman via ${pmgr}"
  case "$pmgr" in
    apt-get)
      ${sudo_bin:+$sudo_bin }apt-get update -y
      ${sudo_bin:+$sudo_bin }apt-get install -y podman
      ;;
    dnf)
      ${sudo_bin:+$sudo_bin }dnf install -y podman
      ;;
    yum)
      ${sudo_bin:+$sudo_bin }yum install -y podman
      ;;
  esac
}

ensure_podman() {
  if command -v podman >/dev/null 2>&1; then
    return
  fi

  install_podman

  if ! command -v podman >/dev/null 2>&1; then
    fail "podman could not be installed automatically"
  fi
}

build_image() {
  name="$1"
  dockerfile="$2"

  if [ ! -f "$dockerfile" ]; then
    fail "Dockerfile not found: $dockerfile"
  fi

  log "building image ${name} from ${dockerfile}"
  podman build -f "$dockerfile" -t "$name" "$JUNKNAS_SOURCE_DIR"
}

generate_default_yaml() {
  log "generating default junknas.yaml at ${JUNKNAS_YAML_PATH}"
  mkdir -p "$(dirname "$JUNKNAS_YAML_PATH")"
  cat >"$JUNKNAS_YAML_PATH" <<'EOF'
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
            - name: http
              containerPort: 8080
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
      port: 80
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
              value: "http://junknas-controller.junknas.svc.cluster.local/api"
          ports:
            - name: http
              containerPort: 80
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
      port: 80
      targetPort: 80
  type: ClusterIP
---
# Rootless-safe agent deployment
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
        - name: agent
          image: ghcr.io/junknas/agent:latest
          imagePullPolicy: IfNotPresent
          env:
            - name: JUNKNAS_CONTROLLER_URL
              value: "http://junknas-controller.junknas.svc.cluster.local/api"
EOF
}

log "junkNAS installer (rootless)"

require_cmd curl
ensure_podman

if [ "$(id -u)" -eq 0 ]; then
  log "warning: running as root; podman is rootless-friendly, consider running as an unprivileged user"
fi

# Fetch YAML if a URL is provided
if [ -n "$JUNKNAS_YAML_URL" ]; then
  log "downloading junknas.yaml from ${JUNKNAS_YAML_URL}"
  curl -fsSL "$JUNKNAS_YAML_URL" -o "$JUNKNAS_YAML_PATH"
fi

if [ ! -f "$JUNKNAS_YAML_PATH" ]; then
  if [ -f "$JUNKNAS_SOURCE_DIR/deploy/junknas.yaml" ]; then
    log "using repo manifest ${JUNKNAS_SOURCE_DIR}/deploy/junknas.yaml"
    mkdir -p "$(dirname "$JUNKNAS_YAML_PATH")"
    cp "$JUNKNAS_SOURCE_DIR/deploy/junknas.yaml" "$JUNKNAS_YAML_PATH"
  else
    generate_default_yaml
  fi
else
  log "using existing manifest at $JUNKNAS_YAML_PATH"
fi

# Build container images locally so podman kube play can use them even without registry access.
build_image ghcr.io/junknas/controller:latest "$JUNKNAS_SOURCE_DIR/docker/controller.Dockerfile"
build_image ghcr.io/junknas/dashboard:latest "$JUNKNAS_SOURCE_DIR/docker/dashboard.Dockerfile"
build_image ghcr.io/junknas/agent:latest "$JUNKNAS_SOURCE_DIR/docker/agent.Dockerfile"

log "applying junkNAS stack via podman kube play"

# podman kube play runs Kubernetes-style YAML rootlessly.
podman kube play "$JUNKNAS_YAML_PATH"

log "done."
log "Use 'podman ps' to see controller/dashboard/agent containers."
