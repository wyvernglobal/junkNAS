use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;
mod fs;
mod wireguard;
// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    Pure,
    Samba,
}

/// Per-drive info sent by agent.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DriveState {
    pub id: String,
    pub path: String,
    pub used_bytes: u64,
    pub allocated_bytes: u64,
}

/// Node info stored by controller and returned to dashboard.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeState {
    pub node_id: String,
    pub hostname: String,
    pub nickname: String,
    pub drives: Vec<DriveState>,
    pub role: AgentRole,
    pub ip: Option<String>,
    pub mesh_port: Option<u16>,

    // NAT + Mesh metadata (optional until fully populated)
    pub mesh_endpoint: Option<String>,
    pub mesh_public_key: Option<String>,
    pub mesh_private_key: Option<String>,
    pub mesh_score: Option<f32>,
    pub mesh_nat_type: Option<String>,
}

/// Mesh peer info stored separately per node.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MeshPeer {
    pub node_id: String,
    pub endpoint: String, // "ip:port"
    pub public_key: String,
    pub score: f32,
    pub nat_type: Option<String>, // e.g. FullCone / Symmetric
}

/// Mesh state returned to agents.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MeshInfo {
    pub peers: Vec<MeshPeer>,
    pub gateway: Option<String>,
}

/// WireGuard identity managed by dashboard.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireGuardKeyPair {
    pub node_id: String,
    pub public_key: String,
    pub private_key: String,
}

/// What agents send during heartbeat.
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub hostname: String,
    pub nickname: String,
    pub role: AgentRole,
    pub ip: Option<String>,
    pub mesh_port: Option<u16>,
    pub drives: Vec<DriveState>,

    // Mesh metadata
    pub mesh_endpoint: Option<String>,
    pub mesh_public_key: Option<String>,
    pub mesh_score: Option<f32>,
    pub mesh_nat_type: Option<String>,
}

/// Controller’s reply to heartbeat.
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub desired_allocation_bytes: u64,
    pub eject: bool,
    pub mesh_public_key: Option<String>,
    pub mesh_private_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SambaHostState {
    pub node_id: String,
    pub ip: Option<String>,
    pub mesh_port: Option<u16>,
    pub status: String,
}
/// Shared controller state across API handlers.
#[derive(Debug)]
pub struct ControllerState {
    pub nodes: HashMap<String, NodeState>,
    pub desired_allocations: HashMap<String, u64>,
    pub eject_flags: HashMap<String, bool>,
    pub mesh_peers: HashMap<String, MeshPeer>,

    /// Optional WireGuard keypairs managed via dashboard.
    pub wg_keys: HashMap<String, WireGuardKeyPair>,

    /// Filesystem entries, keyed by absolute path.
    pub fs_entries: HashMap<String, fs::FsEntry>,

    /// Samba hosts tracked separately.
    pub samba_hosts: HashMap<String, SambaHostState>,
}

impl Default for ControllerState {
    fn default() -> Self {
        use fs::{FsEntry, FsNodeType};

        let mut s = ControllerState {
            nodes: HashMap::new(),
            desired_allocations: HashMap::new(),
            eject_flags: HashMap::new(),
            mesh_peers: HashMap::new(),
            wg_keys: HashMap::new(),
            fs_entries: HashMap::new(),
            samba_hosts: HashMap::new(),
        };

        // Create root directory entry.
        let root = FsEntry {
            path: "/".into(),
            node_type: FsNodeType::Directory,
            size: 0,
            mode: 0o755,
            mtime: 0,
            ctime: 0,
            chunks: Vec::new(),
            children: Vec::new(),
        };

        s.fs_entries.insert("/".into(), root);
        s
    }
}

pub type SharedState = Arc<Mutex<ControllerState>>;

// -----------------------------------------------------------------------------
// Main entry
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Pretty logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let state: SharedState = Arc::new(Mutex::new(ControllerState::default()));

    // Build API routes
    let app = Router::new()
        .route("/api/nodes", get(list_nodes))
        .route("/api/samba-hosts", get(list_samba_hosts))
        .route("/api/agents/heartbeat", post(heartbeat))
        .route("/api/mesh", get(mesh_info))
        .route("/api/mesh/keys", get(list_wg_keys).post(upsert_wg_keys))
        // NEW: filesystem metadata API
        .route("/api/fs/lookup", get(fs::lookup))
        .route("/api/fs/list", get(fs::list))
        .route("/api/fs/create", post(fs::create))
        .route("/api/fs/update-size", post(fs::update_size))
        .route("/api/fs/update-chunks", post(fs::update_chunks))
        .route("/api/fs/delete", axum::routing::delete(fs::delete))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    info!("junkNAS Controller listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

// -----------------------------------------------------------------------------
// API Handlers
// -----------------------------------------------------------------------------

/// GET /api/nodes
/// Dashboard uses this to show all nodes.
async fn list_nodes(State(state): State<SharedState>) -> Json<Vec<NodeState>> {
    let st = state.lock().unwrap();
    let mut nodes: Vec<NodeState> = st
        .nodes
        .values()
        .filter(|n| n.role == AgentRole::Pure)
        .cloned()
        .collect();

    // Fill in NAT/mesh fields from mesh_peers if missing.
    for node in nodes.iter_mut() {
        if let Some(peer) = st.mesh_peers.get(&node.node_id) {
            node.mesh_endpoint = Some(peer.endpoint.clone());
            node.mesh_public_key = Some(peer.public_key.clone());
            node.mesh_score = Some(peer.score);
            node.mesh_nat_type = peer.nat_type.clone();
        }

        if let Some(kp) = st.wg_keys.get(&node.node_id) {
            if node.mesh_public_key.is_none() {
                node.mesh_public_key = Some(kp.public_key.clone());
            }
            node.mesh_private_key = Some(kp.private_key.clone());
        }
    }

    Json(nodes)
}

/// GET /api/samba-hosts
/// Dashboard uses this to list Samba-only sidecars.
async fn list_samba_hosts(State(state): State<SharedState>) -> Json<Vec<SambaHostState>> {
    let st = state.lock().unwrap();
    let hosts: Vec<SambaHostState> = st.samba_hosts.values().cloned().collect();
    Json(hosts)
}

/// POST /api/agents/heartbeat
/// Agents send storage info + NAT info here.
async fn heartbeat(
    State(state): State<SharedState>,
    Json(body): Json<HeartbeatRequest>,
) -> Json<HeartbeatResponse> {
    let mut st = state.lock().unwrap();
    let keypair = st.wg_keys.get(&body.node_id).cloned();

    if body.role == AgentRole::Samba {
        st.samba_hosts.insert(
            body.node_id.clone(),
            SambaHostState {
                node_id: body.node_id.clone(),
                ip: body.ip.clone(),
                mesh_port: body.mesh_port,
                status: "online".into(),
            },
        );

        let resp = Json(HeartbeatResponse {
            desired_allocation_bytes: 0,
            eject: false,
            mesh_public_key: keypair.as_ref().map(|k| k.public_key.clone()),
            mesh_private_key: keypair.as_ref().map(|k| k.private_key.clone()),
        });

        drop(st);
        sync_wireguard_config(&state);
        return resp;
    }

    // Update node record
    st.nodes.insert(
        body.node_id.clone(),
        NodeState {
            node_id: body.node_id.clone(),
            hostname: body.hostname.clone(),
            nickname: body.nickname.clone(),
            drives: body.drives.clone(),
            role: body.role,
            ip: body.ip.clone(),
            mesh_port: body.mesh_port,
            mesh_endpoint: body.mesh_endpoint.clone(),
            mesh_public_key: body
                .mesh_public_key
                .clone()
                .or_else(|| keypair.as_ref().map(|k| k.public_key.clone())),
            mesh_private_key: keypair.as_ref().map(|k| k.private_key.clone()),
            mesh_score: body.mesh_score,
            mesh_nat_type: body.mesh_nat_type.clone(),
        },
    );

    // Update mesh peer record
    if body.role == AgentRole::Pure {
        if let (Some(endpoint), Some(pk), Some(score)) = (
            body.mesh_endpoint.clone(),
            body.mesh_public_key.clone(),
            body.mesh_score,
        ) {
            st.mesh_peers.insert(
                body.node_id.clone(),
                MeshPeer {
                    node_id: body.node_id.clone(),
                    endpoint,
                    public_key: pk,
                    score,
                    nat_type: body.mesh_nat_type.clone(),
                },
            );
        }
    }

    // Default desired state
    let alloc = st
        .desired_allocations
        .get(&body.node_id)
        .cloned()
        .unwrap_or(1_073_741_824); // 1 GiB

    let eject = st.eject_flags.get(&body.node_id).cloned().unwrap_or(false);
    let resp = Json(HeartbeatResponse {
        desired_allocation_bytes: alloc,
        eject,
        mesh_public_key: keypair.as_ref().map(|k| k.public_key.clone()),
        mesh_private_key: keypair.as_ref().map(|k| k.private_key.clone()),
    });

    drop(st);
    sync_wireguard_config(&state);

    resp
}

/// GET /api/mesh
/// Agents call this to get:
///   - All mesh peers
///   - Gateway selection
async fn mesh_info(State(state): State<SharedState>) -> Json<MeshInfo> {
    let st = state.lock().unwrap();
    let mut peers: Vec<MeshPeer> = st.mesh_peers.values().cloned().collect();

    // Ensure peers derived from dashboard-managed keys are also exposed.
    for (node_id, keys) in &st.wg_keys {
        if peers.iter().any(|p| p.node_id == *node_id) {
            continue;
        }

        if let Some(node) = st.nodes.get(node_id) {
            if let Some(endpoint) = &node.mesh_endpoint {
                peers.push(MeshPeer {
                    node_id: node_id.clone(),
                    endpoint: endpoint.clone(),
                    public_key: keys.public_key.clone(),
                    score: node.mesh_score.unwrap_or(0.0),
                    nat_type: node.mesh_nat_type.clone(),
                });
            }
        }
    }

    // Elect gateway by highest score
    let gateway = peers
        .iter()
        .max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|p| p.node_id.clone());

    Json(MeshInfo { peers, gateway })
}

/// POST /api/mesh/keys
/// Dashboard stores or updates WireGuard keys per node.
async fn upsert_wg_keys(
    State(state): State<SharedState>,
    Json(body): Json<WireGuardKeyPair>,
) -> StatusCode {
    let mut st = state.lock().unwrap();
    st.wg_keys.insert(body.node_id.clone(), body.clone());

    // Update node record for dashboard convenience
    if let Some(node) = st.nodes.get_mut(&body.node_id) {
        node.mesh_public_key = Some(body.public_key.clone());
        node.mesh_private_key = Some(body.private_key.clone());
    }

    drop(st);
    sync_wireguard_config(&state);

    StatusCode::NO_CONTENT
}

/// GET /api/mesh/keys
/// Dashboard can retrieve all configured WireGuard identities.
async fn list_wg_keys(State(state): State<SharedState>) -> Json<Vec<WireGuardKeyPair>> {
    let st = state.lock().unwrap();
    let keys: Vec<WireGuardKeyPair> = st.wg_keys.values().cloned().collect();
    Json(keys)
}

fn sync_wireguard_config(state: &SharedState) {
    let rendered = {
        let st = state.lock().unwrap();
        wireguard::render(&st)
    };

    if let Some(cfg) = rendered {
        if let Err(e) = wireguard::write_and_reload(cfg) {
            warn!("Failed to apply WireGuard config: {}", e);
        }
    } else {
        info!("WireGuard config generation skipped (no controller keypair)");
    }
}
