use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use std::net::SocketAddr;
use std::sync::Mutex;

use crate::nat::ConnectivityMode;
use crate::transport::OverlayTransport;

#[derive(Debug, Clone)]
pub struct PeerConnection {
    pub node_id: String,
    pub addr: SocketAddr,
    pub mode: ConnectivityMode,
    pub nat_type: crate::nat::NatType,
}

static ACTIVE_PEERS: OnceCell<Mutex<Vec<PeerConnection>>> = OnceCell::new();
static GLOBAL_TRANSPORT: OnceCell<OverlayTransport> = OnceCell::new();

/// Initialize global transport and remember current peers.
pub fn run_mesh(_private_key: String, peers: Vec<PeerConnection>, port: u16) -> Result<()> {
    let transport = OverlayTransport::bind(port)?;
    let _ = GLOBAL_TRANSPORT.set(transport);

    let store = ACTIVE_PEERS.get_or_init(|| Mutex::new(Vec::new()));
    *store.lock().unwrap() = peers;

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
    _transport: &OverlayTransport,
    _peer: &PeerConnection,
    _path: &str,
    _index: u64,
) -> Result<Vec<u8>> {
    Err(anyhow!("remote chunk fetch not implemented"))
}

pub fn store_remote_chunk(
    _transport: &OverlayTransport,
    _peer: &PeerConnection,
    _path: &str,
    _index: u64,
    _data: &[u8],
) -> Result<()> {
    Err(anyhow!("remote chunk store not implemented"))
}
