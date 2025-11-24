#!/bin/sh
set -eu

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
# ------------------------------------------------------------

JUNKNAS_YAML_URL="${JUNKNAS_YAML_URL:-}"
JUNKNAS_YAML_PATH="${JUNKNAS_YAML_PATH:-./junknas.yaml}"

echo "[install] junkNAS installer (rootless)"

if ! command -v podman >/dev/null 2>&1; then
  echo "[install] ERROR: podman not found in PATH"
  exit 1
fi

# Fetch YAML if a URL is provided
if [ -n "$JUNKNAS_YAML_URL" ]; then
  echo "[install] downloading junknas.yaml from ${JUNKNAS_YAML_URL}"
  curl -fsSL "$JUNKNAS_YAML_URL" -o "$JUNKNAS_YAML_PATH"
fi

if [ ! -f "$JUNKNAS_YAML_PATH" ]; then
  echo "[install] ERROR: junknas.yaml not found at $JUNKNAS_YAML_PATH"
  exit 1
fi

echo "[install] applying junkNAS stack via podman kube play"

# podman kube play runs Kubernetes-style YAML rootlessly.
podman kube play "$JUNKNAS_YAML_PATH"

echo "[install] done."
echo "[install] Use 'podman ps' to see controller/dashboard/agent containers."
