#!/bin/sh
set -eu

ORIGINAL_PWD="$(pwd)"

JUNKNAS_YAML_URL="${JUNKNAS_YAML_URL:-}"
JUNKNAS_YAML_PATH="${JUNKNAS_YAML_PATH:-./junknas.yaml}"
JUNKNAS_SOURCE_DIR="${JUNKNAS_SOURCE_DIR:-}"    # <-- IMPORTANT: default empty
JUNKNAS_REPO_URL="https://github.com/wyvernglobal/junkNAS.git"
JUNKNAS_KEEP_SOURCE="${JUNKNAS_KEEP_SOURCE:-0}"
SOURCE_DIR_WAS_AUTO=0
AUTO_CLONE_ROOT=""

log() { printf '[install] %s\n' "$*"; }
fail() { log "ERROR: $*"; exit 1; }

resolve_path() {
  case "$1" in
    /*) echo "$1";;
    *)  echo "${ORIGINAL_PWD}/$1";;
  esac
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "$1 not found in PATH"
  fi
}

detect_source_dir() {
  # 1. If user provided a path, use it
  if [ -n "$JUNKNAS_SOURCE_DIR" ]; then
    resolved="$(resolve_path "$JUNKNAS_SOURCE_DIR")"
    if [ ! -d "$resolved" ]; then
      fail "JUNKNAS_SOURCE_DIR does not exist: $resolved"
    fi
    echo "$resolved"
    return
  fi

  # 2. If local junkNAS exists, use it
  if [ -d "./junkNAS" ]; then
    echo "$(resolve_path ./junkNAS)"
    return
  fi

  # 3. Otherwise clone fresh
  require_cmd git
  log "cloning junkNAS from ${JUNKNAS_REPO_URL}"
  git clone "$JUNKNAS_REPO_URL" "./junkNAS"
  AUTO_CLONE_ROOT="./junkNAS"
  SOURCE_DIR_WAS_AUTO=1
  echo "$(resolve_path ./junkNAS)"
}

cleanup_source_dir() {
  if [ "$JUNKNAS_KEEP_SOURCE" = "1" ]; then return; fi
  if [ "$SOURCE_DIR_WAS_AUTO" != "1" ]; then return; fi
  if [ -n "$AUTO_CLONE_ROOT" ] && [ -d "$AUTO_CLONE_ROOT" ]; then
    log "removing auto-cloned source directory $AUTO_CLONE_ROOT"
    rm -rf "$AUTO_CLONE_ROOT"
  fi
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then echo apt-get
  elif command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v yum >/dev/null 2>&1; then echo yum
  else echo ""
  fi
}

install_podman() {
  pmgr=$(detect_pkg_manager)
  [ -z "$pmgr" ] && fail "No supported package manager found for podman install"

  if command -v sudo >/dev/null 2>&1; then S="sudo"; else S=""; fi

  log "Installing podman using $pmgr"
  case "$pmgr" in
    apt-get)
      $S apt-get update -y
      $S apt-get install -y podman;;
    dnf) $S dnf install -y podman;;
    yum) $S yum install -y podman;;
  esac
}

ensure_podman() {
  if ! command -v podman >/dev/null 2>&1; then
    install_podman
  fi
  command -v podman >/dev/null 2>&1 || fail "podman installation failed"
}

build_image() {
  name="$1"
  dockerfile="$2"
  [ ! -f "$dockerfile" ] && fail "Dockerfile missing: $dockerfile"
  log "building image $name"
  podman build -f "$dockerfile" -t "$name" "$JUNKNAS_SOURCE_DIR"
}

generate_default_yaml() {
  mkdir -p "$(dirname "$JUNKNAS_YAML_PATH")"
  log "generating default junknas.yaml"
  cat >"$JUNKNAS_YAML_PATH" <<'EOF'
# default manifest omitted for brevity (unchanged)
EOF
}

# -------------------------------------------------------------
# Start installer
# -------------------------------------------------------------
log "junkNAS installer (rootless)"

JUNKNAS_YAML_PATH="$(resolve_path "$JUNKNAS_YAML_PATH")"

require_cmd curl
ensure_podman

# FIX: properly detect / clone directory
log "resolving junkNAS source directory"
JUNKNAS_SOURCE_DIR="$(detect_source_dir)"
log "using source directory: $JUNKNAS_SOURCE_DIR"

cd "$JUNKNAS_SOURCE_DIR"

[ "$(id -u)" -eq 0 ] && log "warning: running as root (rootless recommended)"

# Fetch YAML if URL provided
if [ -n "$JUNKNAS_YAML_URL" ]; then
  log "downloading manifest from $JUNKNAS_YAML_URL"
  curl -fsSL "$JUNKNAS_YAML_URL" -o "$JUNKNAS_YAML_PATH"
fi

# Use default or repo manifest
if [ ! -f "$JUNKNAS_YAML_PATH" ]; then
  if [ -f "$JUNKNAS_SOURCE_DIR/deploy/junknas.yaml" ]; then
    cp "$JUNKNAS_SOURCE_DIR/deploy/junknas.yaml" "$JUNKNAS_YAML_PATH"
    log "using repo manifest"
  else
    generate_default_yaml
  fi
else
  log "using existing manifest"
fi

# Build images
build_image ghcr.io/junknas/controller:latest "$JUNKNAS_SOURCE_DIR/docker/controller.Dockerfile"
build_image ghcr.io/junknas/dashboard:latest "$JUNKNAS_SOURCE_DIR/docker/dashboard.Dockerfile"
build_image ghcr.io/junknas/agent:latest "$JUNKNAS_SOURCE_DIR/docker/agent.Dockerfile"

cd "$ORIGINAL_PWD"
cleanup_source_dir

log "deploying junkNAS via podman kube play"
podman kube play "$JUNKNAS_YAML_PATH"

log "done."
log "View running containers: podman ps"
