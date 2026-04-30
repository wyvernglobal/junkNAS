# JunkNAS

**Distributed private cloud over I2P — SMB3 · mergerfs · Zero central server**

JunkNAS lets you pool storage across any number of machines into a single
network filesystem, tunnelled entirely through I2P. No accounts, no cloud
provider, no central server. Every node is equal. The cloud is accessible
from any node in the mesh.

---

## Architecture

```
[Node A]──I2P──[Node B]──I2P──[Node C]
    \                              /
     └──────── mergerfs ──────────┘
                   │
            /mnt/junknas   ← unified filesystem on every node
```

Each node runs:
- **i2pd** — the full I2P router, launched as a subprocess by junknasd.
  Exposes a SOCKS5 proxy on `127.0.0.1:4447` and a SAM bridge on `127.0.0.1:7656`.
  All inter-node HTTP traffic is routed through this proxy.
- **Samba** (smbd) — SMB3 file share, bound to `127.0.0.1` only
- **mergerfs** — union filesystem over all peer SMB mounts
- **junknasd** — the Go daemon that manages all of the above
- **junknas-gui** (optional) — Qt6 desktop GUI
- **junknasd --tui** (optional) — terminal UI for headless servers

---

## Node Roles

| Role    | Stores files | Mounts cloud | Participates in mesh |
|---------|:---:|:---:|:---:|
| Storage | ✅  | ✅  | ✅  |
| Leech   | ❌  | ✅  | ✅  |

Leech nodes are useful as workstations or access points that don't contribute
storage but still have full read/write access to the cloud.

---

## Adding a Node

### On an existing node

1. Open JunkNAS (GUI or TUI)
2. Go to **Add Node**
3. Share the displayed **B32 address** and **3-word passphrase** with the
   operator of the new machine

### On the new machine

1. Install JunkNAS
2. Go to **Join Cloud**
3. Paste the B32 address
4. Enter each of the three passphrase words in the separate fields
5. Choose whether this node stores files and how much quota to allocate
6. Click **Join**

The new node will:
- Authenticate with a SHA-256 hash of the passphrase (plaintext never sent)
- Receive the full peer list
- Be announced to all existing nodes
- Establish I2P tunnels and SMB3 mounts to every peer
- Be merged into the cloud via mergerfs

The invite token is **single-use** and expires after **10 minutes**.

---

## Installation

### Dependencies

```bash
# Debian / Ubuntu
sudo apt install \
  golang-go cmake \
  qt6-base-dev qt6-base-dev-tools \
  samba samba-common-bin cifs-utils \
  mergerfs fuse \
  i2pd

# Arch
sudo pacman -S go cmake qt6-base samba cifs-utils mergerfs fuse2 i2pd
```

### Build & Install

```bash
git clone https://github.com/junknas/junknas
cd junknas
sudo bash dist/install.sh
```

### Manual Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

Produces:
- `build/junknasd`   — Go daemon binary
- `build/junknas-gui` — Qt6 GUI binary

---

## Running

### Desktop (GUI + daemon)
```bash
junknasd --storage=/mnt/mydata --quota=500
```

### Server (TUI + daemon)
```bash
junknasd --tui --storage=/srv/junknas --quota=1000
```

### Systemd service (headless daemon)
```bash
sudo systemctl start junknas
# Connect TUI from any terminal:
junknasd --tui-only
```

### Leech mode (no local storage)
```bash
junknasd --tui  # omit --storage flag
```

---

## Data Layout

```
~/.junknas/
├── registry.json        ← node registry (peers, invites, self)
├── i2p/
│   ├── i2pd.conf        ← auto-generated
│   ├── tunnels.conf     ← auto-generated, reloaded on peer changes
│   ├── i2pd.log
│   └── keys/
│       ├── smb-server.dat          ← this node's I2P destination key
│       └── peer-word1-word2-word3.dat
└── smb/
    └── smb.conf         ← auto-generated

/mnt/junknas/            ← merged cloud filesystem (mergerfs)
/mnt/junknas-peers/      ← individual SMB mounts per peer
    └── apple-storm-delta/
```

---

## Security

- All inter-node traffic is encrypted by I2P (EdDSA + ECIES)
- SMB3 mandatory encryption adds a second layer
- Join tokens are SHA-256 hashes — plaintext passphrase never leaves the local machine
- Invites are single-use with a 10-minute TTL
- Samba binds to `127.0.0.1` only — no direct network exposure

---

## Project Structure

```
junknas/
├── cmd/junknas/         Go daemon entry point
├── internal/
│   ├── words/           Phrase generation (EFF wordlist)
│   ├── registry/        JSON persistence, peer/self structs
│   ├── i2p/             libi2pd cgo bridge, tunnel config
│   ├── join/            Invite, handshake, announce protocol
│   ├── smb/             smb.conf generation, smbd lifecycle
│   ├── mergerfs/        Union mount management
│   ├── api/             Localhost REST API (GUI/TUI IPC)
│   └── daemon/          Main orchestration, watchdog, heartbeat
├── tui/                 Terminal UI (tview)
├── gui/                 Qt6 desktop GUI
├── assets/wordlist.txt  EFF large wordlist
└── dist/                Installer, systemd service
```

---

## Bandwidth Scaling

Aggregate write bandwidth scales linearly with storage node count.
Single-file read speed is bounded by the node that file lives on.
Parallel reads of different files scale across all nodes.

| Nodes | Theoretical aggregate write | Realistic (I2P overhead) |
|-------|---:|---:|
| 1     | ~5 Mbps   | ~2–4 Mbps  |
| 5     | ~25 Mbps  | ~8–15 Mbps |
| 10    | ~50 Mbps  | ~15–25 Mbps|

---

## License

MIT
