use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use crate::fuse_daemon::{internal_read_local_chunk, internal_store_local_chunk};
use crate::nat::{attempt_hole_punch, ConnectivityMode};
use crate::transport::OverlayTransport;
use crate::wireguard::WGTunnel;

#[derive(Debug, Clone)]
pub struct PeerConnection {
    pub node_id: String,
    pub addr: SocketAddr,
    pub mode: ConnectivityMode,
    pub nat_type: crate::nat::NatType,
}

static ACTIVE_PEERS: OnceCell<Mutex<Vec<PeerConnection>>> = OnceCell::new();
static GLOBAL_TRANSPORT: OnceCell<OverlayTransport> = OnceCell::new();
static ROOTLESS_TUNNEL: OnceCell<Mutex<WGTunnel>> = OnceCell::new();

/// Initialize global transport and remember current peers.
pub fn run_mesh(_private_key: String, peers: Vec<PeerConnection>, port: u16) -> Result<()> {
    let transport = OverlayTransport::bind(port)?;
    let _ = GLOBAL_TRANSPORT.set(transport);

    // Bring up rootless WireGuard tunnel via boringtun so packet handling stays in userspace.
    let tunnel =
        ROOTLESS_TUNNEL.get_or_try_init(|| WGTunnel::start(&_private_key).map(Mutex::new))?;

    let store = ACTIVE_PEERS.get_or_init(|| Mutex::new(Vec::new()));
    *store.lock().unwrap() = peers.clone();

    // Run a minimal discovery burst so the compiler-flagged mesh paths stay active.
    for peer in peers {
        println!(
            "[mesh] preparing peer {} {:?} via {:?}",
            peer.node_id, peer.nat_type, peer.mode
        );

        match peer.mode {
            ConnectivityMode::Direct => {
                global_transport().send(peer.addr, b"wg:direct-probe")?;
            }
            ConnectivityMode::HolePunch => {
                let _ = attempt_hole_punch(port, peer.addr, Duration::from_millis(750));
                global_transport().send(peer.addr, b"wg:hole-punch-probe")?;
            }
            ConnectivityMode::Relay => {
                global_transport().send(peer.addr, b"wg:relay-probe")?;
            }
        }

        // Record at least one encrypted write for the userspace WG child.
        let _ = tunnel
            .lock()
            .unwrap()
            .write_packet(format!("hello:{}", peer.node_id).as_bytes());
    }

    // Non-blocking poll for any packet boringtun produced so recv path is exercised.
    if let Ok(Some(pkt)) = tunnel.lock().unwrap().read_packet() {
        if let Some((_, peer)) = get_active_peers().into_iter().enumerate().next() {
            let _ = global_transport().send(peer.addr, &pkt);
        }
    }

    Ok(())
}

pub fn get_active_peers() -> Vec<PeerConnection> {
    ACTIVE_PEERS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .clone()
}

pub fn global_transport() -> &'static OverlayTransport {
    GLOBAL_TRANSPORT
        .get()
        .expect("global transport not initialized")
}

pub fn fetch_remote_chunk(
    transport: &OverlayTransport,
    peer: &PeerConnection,
    path: &str,
    index: u64,
) -> Result<Vec<u8>> {
    // If the data is local, short-circuit via the helper used by mesh RPCs.
    if let Ok(buf) = internal_read_local_chunk(path, index) {
        return Ok(buf);
    }

    let msg = format!("FETCH {} {}", path, index);
    transport.send(peer.addr, msg.as_bytes())?;

    if let Some((buf, _from)) = transport.recv() {
        return Ok(buf);
    }

    Err(anyhow!("remote chunk fetch not implemented"))
}

pub fn store_remote_chunk(
    _transport: &OverlayTransport,
    peer: &PeerConnection,
    path: &str,
    index: u64,
    data: &[u8],
) -> Result<()> {
    internal_store_local_chunk(path, index, &peer.node_id, data, "")
}
