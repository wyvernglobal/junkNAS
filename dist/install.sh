#!/usr/bin/env bash
# JunkNAS installer — Linux only
set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
DATA_DIR="${DATA_DIR:-/var/lib/junknas}"
CONFIG_DIR="${CONFIG_DIR:-/etc/junknas}"
SERVICE_USER="junknas"

info()  { echo -e "\033[34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[32m[ OK ]\033[0m  $*"; }
warn()  { echo -e "\033[33m[WARN]\033[0m  $*"; }
error() { echo -e "\033[31m[ERR ]\033[0m  $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root: sudo bash install.sh"

# ── Dependencies ──────────────────────────────────────────────────────────
info "Checking dependencies..."
MISSING=()
for cmd in go cmake i2pd smbd mergerfs mount.cifs fusermount; do
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd found at $(command -v "$cmd")"
    else
        warn "$cmd not found"
        MISSING+=("$cmd")
    fi
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing: ${MISSING[*]}"
    echo ""
    echo "  Install on Debian/Ubuntu:"
    echo "    sudo apt install golang-go cmake i2pd samba samba-common-bin cifs-utils mergerfs fuse"
    echo ""
    read -rp "Continue anyway? [y/N] " cont
    [[ "$cont" =~ ^[Yy]$ ]] || exit 1
fi

# ── System user ───────────────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    info "Creating system user: $SERVICE_USER"
    # Set home directory to DATA_DIR so i2pd (which falls back to $HOME/.i2pd)
    # uses our directory rather than its compiled-in /var/lib/i2pd default.
    useradd --system --home-dir "$DATA_DIR" --no-create-home \
            --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "User $SERVICE_USER created with home=$DATA_DIR"
else
    # Update home dir of existing user in case it was created without one.
    usermod --home "$DATA_DIR" "$SERVICE_USER" 2>/dev/null || true
    ok "User $SERVICE_USER home set to $DATA_DIR"
fi

# ── Go dependencies ───────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

info "Resolving Go dependencies..."
cd "$ROOT_DIR"
go mod tidy
ok "go mod tidy complete"

# ── Build ─────────────────────────────────────────────────────────────────
info "Building JunkNAS..."
mkdir -p "$BUILD_DIR"
cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
cmake --build "$BUILD_DIR" --parallel "$(nproc)"
cmake --install "$BUILD_DIR"
ok "Build and install complete → $INSTALL_PREFIX/bin/junknasd"

# ── Directories ───────────────────────────────────────────────────────────
info "Creating runtime directories..."

mkdir -p "$DATA_DIR/smb"
mkdir -p "$DATA_DIR/storage"
mkdir -p "$CONFIG_DIR"
mkdir -p /mnt/junknas
mkdir -p /mnt/junknas-peers
mkdir -p /run/junknas

# Give the junknas user full ownership and write access to its entire tree.
# i2pd creates destinations/, netDb/, addressbook/ etc. inside the i2p
# datadir at runtime — the whole tree must be writable.
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" /mnt/junknas /mnt/junknas-peers
chmod 755 /mnt/junknas /mnt/junknas-peers "$DATA_DIR"

# .i2pd is i2pd's native home directory — no symlink needed.

ok "Directories ready"

# ── SMB password ──────────────────────────────────────────────────────────
if [[ ! -f "$CONFIG_DIR/smb.secret" ]]; then
    info "Setting Samba password for the '$SERVICE_USER' system account..."
    read -rsp "Enter Samba password: " smb_pass; echo
    read -rsp "Confirm password: "    smb_conf; echo
    [[ "$smb_pass" == "$smb_conf" ]] || error "Passwords do not match"
    printf '%s' "$smb_pass" > "$CONFIG_DIR/smb.secret"
    chmod 600 "$CONFIG_DIR/smb.secret"
    chown root:root "$CONFIG_DIR/smb.secret"
    ok "Password stored in $CONFIG_DIR/smb.secret"
fi


# ── Systemd ───────────────────────────────────────────────────────────────
info "Installing systemd service..."
cp "$BUILD_DIR/junknas.service" /etc/systemd/system/junknas.service
chmod 644 /etc/systemd/system/junknas.service
systemctl daemon-reload
systemctl enable junknas.service
ok "Service installed and enabled"

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
ok "═══════════════════════════════════════════"
ok " JunkNAS installed successfully!"
ok "═══════════════════════════════════════════"
echo ""
echo "  Start:       systemctl start junknas"
echo "  Stop:        systemctl stop junknas"
echo "  Logs:        journalctl -u junknas -f"
echo "  TUI:         junknasd --tui-only"
echo "  Cloud mount: /mnt/junknas"
echo ""
