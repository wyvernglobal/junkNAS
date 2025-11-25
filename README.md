# junkNAS  
### A Rootless, Distributed, Mesh-Native Cloud Filesystem

junkNAS is a fully distributed, rootless, FUSE-powered filesystem that allows any device to join a decentralized NAS cluster.
Nodes automatically discover each other, synchronize metadata via a lightweight controller, and exchange file chunks over an encrypted userspace mesh overlay.

The system runs entirely unprivileged, using Podman rootless containers, userspace WireGuard, and a pure-Rust FUSE layer.
You can build your own personal "cloud" using Raspberry Pis, laptops, servers, and anything else that supports containers.

---

# Features

### Distributed Filesystem (FUSE3)
- Mount a unified filesystem across any number of devices.
- Files are transparently split into 64 KiB chunks and distributed across nodes.
- Local and remote reads using CHUNK_FETCH RPC.
- Full write support with CHUNK_STORE RPC.
- Automatic chunk placement based on node performance, free space, and mesh quality.

### Userspace Mesh Overlay (rootless WireGuard-like)
- Encrypted UDP overlay (OverlayTransport).
- Peer discovery via controller.
- NAT-friendly design.
- Peers communicate using MessagePack-encoded MeshMessage packets.

### Controller Node
- Holds authoritative metadata for directories, files, chunks, and nodes.
- Exposes a REST API consumed by agents.
- Provides a dashboard UI for cluster status.

### Dashboard
- Lightweight HTML dashboard served from the controller.
- Displays cluster nodes, storage, mesh scores, chunk distribution, and online/offline status.
- Provides a "Connect via SAMBA" flow that shows the Samba sidecar WireGuard peer, plus QR/download helpers for clients (no private keys are ever shown).

### Rootless by Default
- No privileged syscalls.
- Runs inside unprivileged Podman.
- Uses userspace FUSE (fuse3).
- Optional userspace WireGuard (boringtun).

---

# Installing junkNAS (One-Line Installer)

You can bootstrap Podman + junkNAS with:

curl -fsSL https://raw.githubusercontent.com/wyvernglobal/junkNAS/main/scripts/install-junknas.sh | bash


This will:
1. Install rootless Podman (if missing).
2. Create a ~/junknas working directory.
3. Clone the repository.
4. Build the agent + controller containers.
5. Install alias scripts:
   - junknas-agent
   - junknas-controller
6. Print next-steps instructions.

The install script will not elevate privileges and is safe for unprivileged systems.

---


# Running the Controller

podman run -it -e JUNKNAS_MODE=controller -p 8080:8080 junknas

Dashboard available at: http://localhost:8080

---

# Running an Agent

podman run -it --device /dev/fuse --cap-add SYS_ADMIN --userns=keep-id     -v junknas-data:/var/lib/junknas junknas

---

# Testing the Filesystem

Inside an agent container:

echo "hello" > /mnt/junknas/hello.txt
cat /mnt/junknas/hello.txt

Across nodes:

echo "distributed!" > /mnt/junknas/example.txt
cat /mnt/junknas/example.txt

---

# Accessing junkNAS over Samba

To let traditional SMB clients browse the cluster, attach a gateway host (or run a Samba sidecar) on the WireGuard VLAN and export the mounted filesystem via Samba. The dashboard exposes public-only WireGuard metadata for the sidecar and offers a **Connect via SAMBA** button that renders a QR code and downloadable client config stub. See [docs/samba-access.md](docs/samba-access.md) for a step-by-step guide to creating the WireGuard peer, mounting the agent locally, and publishing the share without leaking junkNAS private keys.

---

# Repository Layout

junknas/
├── agent/
├── controller/
├── dashboard/
├── Dockerfile
└── run.sh

---
