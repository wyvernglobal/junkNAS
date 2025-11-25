# junkNAS  
### A Rootless, Distributed, Mesh-Native Cloud Filesystem

<img width="517" height="233" alt="junkNAS" src="https://github.com/user-attachments/assets/edaf999c-30b0-4079-8a1e-9bf29311fedc" />

junkNAS is a fully distributed, rootless, FUSE-powered filesystem that allows any device to join a decentralized NAS cluster.
Nodes automatically discover each other, synchronize metadata via a lightweight controller, and exchange file chunks over an encrypted userspace mesh overlay.

The system runs entirely unprivileged, using Podman rootless containers, kernel WireGuard, and a pure-Rust FUSE layer.
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
- Provides a "Connect via SAMBA" flow that shows the Samba sidecar WireGuard peer, plus QR/download helpers for clients (no private keys are ever shown). The dashboard now generates a Samba-only WireGuard private key for the QR code and config download so the junkNAS mesh private key stays dedicated to syncing.

### Rootless by Default
- No privileged syscalls.
- Runs inside unprivileged Podman.
- Uses userspace FUSE (fuse3).
- Uses kernel WireGuard for the mesh overlay.

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
6. Launch a Samba sidecar pod (agent + Samba containers) that mounts the junkNAS filesystem, attaches to the WireGuard mesh, and exports it over the VLAN.
7. Print next-steps instructions.

The install script will not elevate privileges and is safe for unprivileged systems.

---


# Running the Controller

podman kube play junknas.yaml

Dashboard available at: http://localhost:8080

Agents expect to talk to the controller over the WireGuard overlay so that rootless
Podman + Kubernetes deployments can crosstalk across a full junkNAS mesh. The
default overlay endpoint is `http://10.44.0.1:8080/api`; ensure your controller
advertises a reachable WireGuard IP and update `JUNKNAS_CONTROLLER_URL` if you use
another address. Only one controller should own a given junkNAS mesh—once nodes
are synchronized, scale down or delete any extra controllers so a single endpoint
remains managed by Kubernetes.

Controller and agent pods will automatically run `wg-quick up` against
`/etc/wireguard/junknas.conf` on startup when the config is mounted (for
example via a `junknas-wireguard` Secret). Treat the controller as the
WireGuard host and register each agent as a peer in that config so the overlay
comes up as soon as Kubernetes schedules the pods.

Agents skip any block devices whose mountpoint is marked `[SWAP]`, ensuring swap
partitions are never used for junkNAS storage.

For local testing without WireGuard, agents will probe a few sane defaults—first
`host.containers.internal:8088`/`127.0.0.1:8088`, then `host.containers.internal:8080`/`127.0.0.1:8080`
—before falling back to the overlay address. If `JUNKNAS_CONTROLLER_URL` is set but
unreachable, the agent now falls back to probing those addresses unless you set
`JUNKNAS_CONTROLLER_URL_STRICT=1` to force the configured endpoint.

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


