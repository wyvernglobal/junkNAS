# Expose junkNAS over Samba via the WireGuard VLAN

This guide describes how to make the junkNAS filesystem available to traditional SMB/Samba clients. The simplest approach is to run a **Samba sidecar** that sits next to the controller/agent, joins the WireGuard-backed junkNAS VLAN, mounts the filesystem locally, and exports it as a Samba share so any device that joins the WireGuard network can browse the NAS. The dashboard now exposes the WireGuard peer info (public-only) for this sidecar, plus a QR code and downloadable config stub to help clients join. Private keys for junkNAS remain hidden—only peer metadata is surfaced.

## Prerequisites
- A running junkNAS controller and at least one agent with data mounted at `/mnt/junknas`.
- A host (VM, server, or laptop) that will act as the Samba gateway.
- WireGuard and Samba installed on that host (for Debian/Ubuntu: `sudo apt install wireguard samba`).

## 1) Add the Samba host as a WireGuard peer (sidecar)
1. Generate a keypair on the Samba host:
   ```bash
   umask 077
   wg genkey | tee ~/junknas-samba.key | wg pubkey > ~/junknas-samba.pub
   ```
2. Register this peer with the junkNAS mesh. Add the public key from `junknas-samba.pub` to the controller’s WireGuard peer list with an address from your overlay subnet (for example `10.44.0.50/32`).
3. Create `/etc/wireguard/junknas.conf` on the Samba host with the assigned address and the controller/relay endpoint:
   ```ini
   [Interface]
   Address = 10.44.0.50/32
   PrivateKey = <contents of junknas-samba.key>
   DNS = 1.1.1.1

   [Peer]
   PublicKey = <controller-public-key>
   AllowedIPs = 10.44.0.0/16
   Endpoint = <controller-public-endpoint>:51820
   PersistentKeepalive = 25
   ```
4. Bring up the interface and confirm reachability:
   ```bash
   sudo wg-quick up junknas
   ping -c3 10.44.0.1   # replace with your controller’s WireGuard IP
   ```

### Deploying the sidecar
In Kubernetes or Podman, run a small companion container that mounts junkNAS and serves Samba. The pod should live next to the controller or an agent so it can reuse the overlay network:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: junknas-samba
spec:
  containers:
    - name: junknas-agent
      image: junknas:latest
      env:
        - name: JUNKNAS_MODE
          value: agent
      volumeMounts:
        - name: junknas-data
          mountPath: /var/lib/junknas
        - name: junknas-mnt
          mountPath: /mnt/junknas
    - name: samba
      image: docker.io/library/samba:latest
      volumeMounts:
        - name: junknas-mnt
          mountPath: /srv/junknas
      args: ["-s", "junknas;/srv/junknas;yes;no;yes"]
  volumes:
    - name: junknas-data
      emptyDir: {}
    - name: junknas-mnt
      emptyDir: {}
```

The Samba sidecar is a regular WireGuard peer; it never requires the cluster’s private keys. Give it a dedicated overlay IP (for example `10.44.0.50/32`) and register only its **public** WireGuard key with the controller.

## 2) Mount junkNAS on the Samba host
Run the junkNAS agent on the same host so the WireGuard peer can read/write the distributed filesystem locally:
```bash
podman run -it --device /dev/fuse --cap-add SYS_ADMIN --userns=keep-id \
  -e JUNKNAS_CONTROLLER_URL="http://<controller-wg-ip>:8080/api" \
  -v junknas-samba-data:/var/lib/junknas \
  -v /mnt/junknas:/mnt/junknas \
  junknas
```
Verify that `/mnt/junknas` contains your cluster data before proceeding.

## 3) Export the mount over Samba
1. Add a share definition to `/etc/samba/smb.conf` (or a drop-in under `/etc/samba/smb.conf.d/`):
   ```ini
   [junknas]
   comment = junkNAS cluster
   path = /mnt/junknas
   browseable = yes
   read only = no
   guest ok = no
   force create mode = 0664
   force directory mode = 0775
   ```
2. Create a Samba user or enable your preferred auth backend, then restart Samba:
   ```bash
   sudo smbpasswd -a <username>
   sudo systemctl restart smbd
   ```

## 4) Connect from clients
Any client that joins the same WireGuard VLAN as a peer can browse the share. Configure the client as a WireGuard peer, then connect to the Samba host using its WireGuard IP:
- macOS Finder / Windows Explorer: `\\10.44.0.50\junknas`
- Linux: `sudo mount -t cifs //10.44.0.50/junknas /mnt/remote -o username=<username>`

### Dashboard helpers
- Open the junkNAS dashboard and click **Connect via SAMBA**. This pops a QR code and a `junknas-samba.conf` download with the WireGuard peer details for the Samba sidecar. The `PrivateKey` line is a placeholder—generate a key on your client before using it.
- The dashboard also shows the sidecar’s WireGuard public key, endpoint, and allowed IPs so you can cross-check peers in the controller. It never exposes the controller or agent private keys.

This approach keeps junkNAS traffic isolated on the mesh while exposing a familiar SMB interface for users and applications.
