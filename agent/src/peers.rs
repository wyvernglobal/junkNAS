use anyhow::Result;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MeshPeer {
    pub node_id: String,
    pub endpoint: String, // "ip:port"
    pub public_key: String,
    pub score: f32,
    pub nat_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MeshInfo {
    pub peers: Vec<MeshPeer>,
    pub gateway: Option<String>,
}

/// Fetch /api/mesh from controller.
///
/// controller_url: reachable via the WireGuard overlay, e.g. "http://10.44.0.1:8008/api"
pub fn fetch_mesh_info(controller_url: &str) -> Result<MeshInfo> {
    let client = Client::new();
    let url = format!("{}/mesh", controller_url.trim_end_matches('/'));
    let info = client.get(url).send()?.json::<MeshInfo>()?;
    Ok(info)
}
