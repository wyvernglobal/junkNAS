mod agent_state;
mod allocation;
mod fs_types;
mod fuse_daemon;
mod mesh;
mod nat;
mod peers;
mod transport;
mod wireguard;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    net::{SocketAddr, UdpSocket},
    os::unix::fs as unix_fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use walkdir::WalkDir;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::mesh::PeerConnection;
use crate::nat::{compute_score, discover_public_endpoint, measure_controller_rtt, NatType};
use crate::peers::{fetch_mesh_info, MeshInfo};
use crate::{
    fs_types::{ChunkMeta, FsNodeType, ListResponse},
    nat::ConnectivityMode,
};

const DEFAULT_CONTROLLER_URL: &str = "http://10.44.0.1:8008/api";

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    Pure,
    Samba,
}

impl AgentRole {
    fn from_env() -> Self {
        match std::env::var("JUNKNAS_AGENT_ROLE")
            .unwrap_or_else(|_| "pure".to_string())
            .to_lowercase()
            .as_str()
        {
            "samba" => AgentRole::Samba,
            _ => AgentRole::Pure,
        }
    }

    fn suffix(&self) -> &'static str {
        match self {
            AgentRole::Pure => "pure",
            AgentRole::Samba => "samba",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AgentConfig {
    agent_id: String,
    role: AgentRole,
    ip: String,
    port: u16,
    mesh_public_key: Option<String>,
    mesh_private_key: Option<String>,
    allocated_bytes: u64,
    drives: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct WireGuardKeyPair {
    node_id: String,
    public_key: String,
    #[allow(dead_code)]
    private_key: String,
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<LsblkBlockDevice>,
}

#[derive(Debug, Deserialize)]
struct LsblkBlockDevice {
    name: String,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    children: Vec<LsblkBlockDevice>,
}

fn choose_controller_url() -> String {
    let mut candidates = vec![
        // Preferred host-forwarded ports (dashboards typically live at 8080)
        "http://localhost:8008/api".to_string(),
        "http://localhost:8088/api".to_string(),
        // Overlay defaults
        "http://10.44.0.1:8008/api".to_string(),
        DEFAULT_CONTROLLER_URL.to_string(),
        // Legacy port on host
        "http://localhost:8080/api".to_string(),
    ];

    if let Ok(url) = std::env::var("JUNKNAS_CONTROLLER_URL") {
        println!(
            "[agent] using controller from JUNKNAS_CONTROLLER_URL={}",
            url
        );

        if controller_reachable(&url) {
            return url;
        }

        println!("[agent] JUNKNAS_CONTROLLER_URL unreachable; probing fallbacks");

        if std::env::var("JUNKNAS_CONTROLLER_URL_STRICT").is_ok() {
            return url;
        }

        if !candidates.contains(&url) {
            candidates.insert(0, url);
        }
    }

    for url in &candidates {
        if controller_reachable(url) {
            println!("[agent] using controller endpoint {}", url);
            return url.clone();
        }

        println!("[agent] controller probe failed for {}", url);
    }

    println!(
        "[agent] no controller endpoints reachable; falling back to {}",
        DEFAULT_CONTROLLER_URL
    );

    DEFAULT_CONTROLLER_URL.to_string()
}

fn controller_reachable(url: &str) -> bool {
    if let Ok(client) = Client::builder().timeout(Duration::from_secs(1)).build() {
        if client.get(format!("{}/nodes", url)).send().is_ok() {
            return true;
        }
    }

    false
}

fn agent_config_dir() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?;
    let dir = home.join(".junknas").join("agent").join("config");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn detect_primary_ip() -> String {
    let ip = UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            let _ = sock.connect("8.8.8.8:80");
            sock.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    ip
}

fn wireguard_config_path() -> PathBuf {
    std::env::var("JUNKNAS_WG_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/wireguard/junknas.conf"))
}

fn ensure_wireguard_overlay() {
    let cfg = wireguard_config_path();
    if !cfg.exists() {
        println!(
            "[agent] no WireGuard config found at {:?}; skipping bring-up",
            cfg
        );
        return;
    }

    let iface = cfg
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("junknas");

    let already_up = Command::new("wg")
        .arg("show")
        .arg(iface)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if already_up {
        println!("[agent] WireGuard interface {} already up", iface);
        return;
    }

    println!(
        "[agent] bringing up WireGuard interface {} using {:?}",
        iface, cfg
    );

    match Command::new("wg-quick").arg("up").arg(&cfg).status() {
        Ok(status) if status.success() => {
            println!("[agent] WireGuard interface {} is up", iface);
        }
        Ok(status) => {
            eprintln!(
                "[agent] wg-quick up {:?} failed with status {}",
                cfg, status
            );
        }
        Err(err) => {
            eprintln!(
                "[agent] failed to invoke wg-quick with {:?}: {:?}",
                cfg, err
            );
        }
    }
}

fn advertised_endpoint_port() -> u16 {
    std::env::var("JUNKNAS_WG_ENDPOINT_PORT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|p| p.min(u16::MAX as u32) as u16)
        .unwrap_or(u16::MAX)
}

fn advertised_endpoint_host() -> String {
    std::env::var("JUNKNAS_WG_ENDPOINT_HOST")
        .unwrap_or_else(|_| "host.containers.internal".to_string())
}

fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn derive_ipv6_address(agent_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    let bytes = hasher.finalize();

    let suffix = ((bytes[0] as u16) << 8) | bytes[1] as u16;
    format!("fd44::{:x}/64", suffix)
}

fn render_agent_wireguard_config(
    cfg: &AgentConfig,
    controller_public_key: &str,
) -> anyhow::Result<String> {
    let private_key = cfg
        .mesh_private_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("agent WireGuard private key missing"))?;

    let listen_port = std::env::var("JUNKNAS_WG_LISTEN_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(cfg.port);

    let allowed_ips =
        std::env::var("JUNKNAS_WG_ALLOWED_IPS").unwrap_or_else(|_| "fd44::/64".into());
    let dns = std::env::var("JUNKNAS_WG_DNS").unwrap_or_else(|_| "fd44::1".into());
    let address = std::env::var("JUNKNAS_WG_ADDRESS_V6")
        .unwrap_or_else(|_| derive_ipv6_address(&cfg.agent_id));

    let endpoint = std::env::var("JUNKNAS_WG_ENDPOINT")
        .or_else(|_| std::env::var("WG_ENDPOINT_OVERRIDE"))
        .unwrap_or_else(|_| {
            format_endpoint(&advertised_endpoint_host(), advertised_endpoint_port())
        });

    let mut lines = vec!["[Interface]".to_string()];
    lines.push(format!("PrivateKey = {}", private_key));
    lines.push(format!("Address = {}", address));
    lines.push(format!("ListenPort = {}", listen_port));
    lines.push(format!("DNS = {}", dns));

    lines.push(String::new());
    lines.push("[Peer]".to_string());
    lines.push(format!("PublicKey = {}", controller_public_key));
    lines.push(format!("AllowedIPs = {}", allowed_ips));
    lines.push(format!("Endpoint = {}", endpoint));
    lines.push("PersistentKeepalive = 25".to_string());

    Ok(lines.join("\n") + "\n")
}

fn fetch_controller_wg_public_key(
    controller_url: &str,
    controller_node_id: &str,
) -> anyhow::Result<Option<String>> {
    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let url = format!("{}/mesh/keys", controller_url.trim_end_matches('/'));
    let resp = client.get(url).send()?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let keys = resp.json::<Vec<WireGuardKeyPair>>()?;
    Ok(keys
        .into_iter()
        .find(|k| k.node_id == controller_node_id)
        .map(|k| k.public_key))
}

fn write_wireguard_config(cfg: &AgentConfig, controller_url: &str) -> anyhow::Result<()> {
    let controller_node_id =
        std::env::var("CONTROLLER_NODE_ID").unwrap_or_else(|_| "controller".to_string());

    let Some(controller_public_key) =
        fetch_controller_wg_public_key(controller_url, &controller_node_id)?
    else {
        println!("[agent] controller WireGuard public key unavailable; skipping config render");
        return Ok(());
    };

    let contents = render_agent_wireguard_config(cfg, &controller_public_key)?;
    let path = wireguard_config_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if let Ok(existing) = fs::read_to_string(&path) {
        if existing == contents {
            return Ok(());
        }
    }

    fs::write(&path, contents)?;
    println!("[agent] wrote WireGuard config to {:?}", path);
    Ok(())
}

fn load_agent_config(
    agent_id: &str,
    role: AgentRole,
    preferred_port: u16,
) -> anyhow::Result<AgentConfig> {
    let dir = agent_config_dir()?;
    let path = dir.join(format!("{}.conf", agent_id));

    if path.exists() {
        if let Ok(raw) = fs::read(&path) {
            if let Ok(cfg) = serde_json::from_slice::<AgentConfig>(&raw) {
                let used_ports = gather_used_ports(&dir);
                if used_ports.iter().filter(|p| **p == cfg.port).count() > 1
                    || port_in_use(cfg.port)
                {
                    let mut updated = cfg.clone();
                    updated.port = select_available_port(cfg.port, &used_ports);
                    persist_agent_config(&updated)?;
                    return Ok(updated);
                }

                return Ok(cfg);
            }
        }
    }

    let used_ports = gather_used_ports(&dir);
    let port = select_available_port(preferred_port, &used_ports);
    let cfg = AgentConfig {
        agent_id: agent_id.to_string(),
        role,
        ip: detect_primary_ip(),
        port,
        mesh_public_key: None,
        mesh_private_key: None,
        allocated_bytes: 0,
        drives: Vec::new(),
    };

    persist_agent_config(&cfg)?;

    Ok(cfg)
}

fn gather_used_ports(dir: &Path) -> Vec<u16> {
    let mut ports = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                if let Ok(raw) = fs::read(entry.path()) {
                    if let Ok(cfg) = serde_json::from_slice::<AgentConfig>(&raw) {
                        ports.push(cfg.port);
                    }
                }
            }
        }
    }

    ports
}

fn select_available_port(preferred: u16, used: &[u16]) -> u16 {
    let mut port = preferred.max(1024);
    while used.contains(&port) || port_in_use(port) {
        port = port.saturating_add(1);
        if port == 0 {
            port = 1024;
        }
    }
    port
}

fn port_in_use(port: u16) -> bool {
    UdpSocket::bind(("0.0.0.0", port)).is_err()
}

fn persist_agent_config(cfg: &AgentConfig) -> anyhow::Result<()> {
    let dir = agent_config_dir()?;
    let path = dir.join(format!("{}.conf", cfg.agent_id));
    let json = serde_json::to_vec_pretty(cfg)?;
    fs::write(path, json)?;
    Ok(())
}

fn generate_agent_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let private_key = STANDARD.encode(secret.to_bytes());
    let public_key = STANDARD.encode(public.to_bytes());

    (private_key, public_key)
}

fn ensure_agent_keypair(cfg: &mut AgentConfig) -> anyhow::Result<()> {
    if cfg.mesh_public_key.is_none() || cfg.mesh_private_key.is_none() {
        let (private_key, public_key) = generate_agent_keypair();
        cfg.mesh_public_key = Some(public_key);
        cfg.mesh_private_key = Some(private_key);
        persist_agent_config(cfg)?;
        println!(
            "[agent] generated WireGuard mesh keypair for {}",
            cfg.agent_id
        );
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Data exchanged with controller
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DriveReport {
    pub id: String,
    pub path: String,
    pub used_bytes: u64,
    pub allocated_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub hostname: String,
    pub nickname: String,
    pub role: AgentRole,
    pub ip: Option<String>,
    pub mesh_port: Option<u16>,
    pub drives: Vec<DriveReport>,

    pub mesh_endpoint: Option<String>,
    pub mesh_public_key: Option<String>,
    pub mesh_private_key: Option<String>,
    pub mesh_score: Option<f32>,
    pub mesh_nat_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub desired_allocation_bytes: u64,
    pub eject: bool,
    pub mesh_public_key: Option<String>,
    pub mesh_private_key: Option<String>,
}

// -----------------------------------------------------------------------------
// main()
// -----------------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    // ---------------------------------------------------------
    // detect FUSE mount mode: junknas-agent mount /mnt/junknas
    // ---------------------------------------------------------
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() >= 3 && args[1] == "mount" {
            let mountpoint = PathBuf::from(&args[2]);
            let controller = choose_controller_url();

            println!("[agent] starting FUSE daemon on {:?}", mountpoint);

            // run async FUSE
            let rt = tokio::runtime::Runtime::new()?;
            let result = rt.block_on(async { fuse_daemon::run_fuse(mountpoint, controller).await });

            if let Err(err) = &result {
                eprintln!("[agent] FUSE mount failed: {err:?}");
            }

            return result;
        }
    }

    // ---------------------------------------------------------
    // Normal agent mode
    // ---------------------------------------------------------

    let controller_url = choose_controller_url();

    let hostname = hostname::get()?.to_string_lossy().into_owned();
    let role = AgentRole::from_env();

    let node_id = std::env::var("JUNKNAS_AGENT_ID").unwrap_or_else(|_| {
        if matches!(role, AgentRole::Pure) {
            hostname.clone()
        } else {
            format!("{}-{}", hostname, role.suffix())
        }
    });

    let nickname = std::env::var("JUNKNAS_NICKNAME").unwrap_or_else(|_| hostname.clone());

    // Local storage location (pure agents only)
    let base_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("could not find local data dir"))?
        .join("junknas")
        .join("storage");

    if matches!(role, AgentRole::Pure) {
        fs::create_dir_all(&base_dir)?;
        println!("[agent] base_dir = {:?}", base_dir);
    }

    // Mesh config with per-host port avoidance
    let preferred_port: u16 = std::env::var("JUNKNAS_MESH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if matches!(role, AgentRole::Samba) {
            42100
        } else {
            42000
        });

    let mut agent_config = load_agent_config(&node_id, role, preferred_port)?;
    ensure_agent_keypair(&mut agent_config)?;
    agent_config.ip = detect_primary_ip();
    agent_config.role = role;
    persist_agent_config(&agent_config)?;

    let mesh_port = agent_config.port;

    write_wireguard_config(&agent_config, &controller_url)?;
    ensure_wireguard_overlay();

    // NAT discovery
    println!("[agent] NAT discovery…");

    let public = match discover_public_endpoint("stun.l.google.com:19302", mesh_port) {
        Ok(ep) => {
            println!("[agent] NAT public endpoint = {}", ep.public_addr);
            println!("[agent] NAT type = {:?}", ep.nat_type);
            ep
        }
        Err(e) => {
            eprintln!("[agent] STUN failed: {:?}, using localhost", e);
            nat::PublicEndpoint {
                public_addr: SocketAddr::from(([127, 0, 0, 1], mesh_port)),
                nat_type: NatType::Unknown,
            }
        }
    };

    // Compute dynamic mesh score
    let rtt_ms = measure_controller_rtt(&controller_url);
    let mesh_score = compute_score(&public.nat_type, rtt_ms);

    println!("[agent] RTT to controller ≈ {} ms", rtt_ms);
    println!("[agent] mesh score = {:.3}", mesh_score);

    let mesh_endpoint = public.public_addr.to_string();
    let mesh_public_key = std::env::var("JUNKNAS_MESH_PUBLIC_KEY")
        .ok()
        .or(agent_config.mesh_public_key.clone())
        .unwrap_or_else(|| "dummy-key".into());
    let mesh_private_key = agent_config
        .mesh_private_key
        .clone()
        .unwrap_or_else(|| "dummy-private-key".into());

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = shutdown.clone();
        ctrlc::set_handler(move || {
            flag.store(true, Ordering::SeqCst);
        })?;
    }

    // ---------------------------------------------------------
    // spawn mesh thread
    // ---------------------------------------------------------
    let controller_clone = controller_url.clone();
    let node_id_clone = node_id.clone();
    let our_nat_type = public.nat_type.clone();
    let mesh_private_key_clone = mesh_private_key.clone();

    thread::spawn(move || {
        loop {
            println!("[mesh-thread] fetching /api/mesh…");

            match fetch_mesh_info(&controller_clone) {
                Ok(MeshInfo { peers, gateway }) => {
                    println!("[mesh-thread] {} peers, gateway={:?}", peers.len(), gateway);

                    // Build enriched PeerConnection entries
                    let mut conns = Vec::new();
                    for p in peers {
                        if p.node_id == node_id_clone {
                            continue;
                        }
                        if let Ok(addr) = p.endpoint.parse::<SocketAddr>() {
                            let peer_nat = match p.nat_type.as_deref() {
                                Some("FullCone") => NatType::FullCone,
                                Some("RestrictedCone") => NatType::RestrictedCone,
                                Some("PortRestrictedCone") => NatType::PortRestrictedCone,
                                Some("Symmetric") => NatType::Symmetric,
                                _ => NatType::Unknown,
                            };

                            let mode = nat::select_connectivity_mode(&our_nat_type, &peer_nat);

                            println!(
                                "[mesh-thread] peer {} {} NAT={:?} → mode={:?}",
                                p.node_id, addr, peer_nat, mode
                            );

                            conns.push(PeerConnection {
                                node_id: p.node_id.clone(),
                                addr,
                                mode,
                                nat_type: peer_nat,
                            });
                        }
                    }

                    if let Err(e) = mesh::run_mesh(mesh_private_key_clone.clone(), conns, mesh_port)
                    {
                        eprintln!("[mesh-thread] mesh error: {:?}", e);
                    }
                }
                Err(e) => {
                    eprintln!("[mesh-thread] /api/mesh failed: {:?}", e);
                }
            }

            thread::sleep(Duration::from_secs(15));
        }
    });

    // ---------------------------------------------------------
    // Heartbeat loop
    // ---------------------------------------------------------

    let client = Client::new();

    while !shutdown.load(Ordering::SeqCst) {
        let drives = if matches!(role, AgentRole::Pure) {
            discover_drives(&base_dir)?
        } else {
            Vec::new()
        };

        let hb = HeartbeatRequest {
            node_id: node_id.clone(),
            hostname: hostname.clone(),
            nickname: nickname.clone(),
            role,
            ip: Some(agent_config.ip.clone()),
            mesh_port: Some(mesh_port),
            drives: drives.clone(),
            mesh_endpoint: Some(mesh_endpoint.clone()),
            mesh_public_key: Some(mesh_public_key.clone()),
            mesh_private_key: Some(mesh_private_key.clone()),
            mesh_score: Some(mesh_score),
            mesh_nat_type: Some(format!("{:?}", public.nat_type)),
        };

        let resp = client
            .post(format!("{}/agents/heartbeat", controller_url))
            .json(&hb)
            .send();

        if let Ok(r) = resp {
            if let Ok(desired) = r.json::<HeartbeatResponse>() {
                if matches!(role, AgentRole::Pure) {
                    apply_desired(&base_dir, &desired)?;
                } else {
                    println!("[agent] samba role active; skipping storage allocation");
                }

                update_config_from_heartbeat(
                    &mut agent_config,
                    desired.desired_allocation_bytes,
                    &drives,
                    desired.mesh_public_key.clone(),
                    desired.mesh_private_key.clone(),
                    &controller_url,
                )?;
            } else {
                eprintln!("[agent] heartbeat: invalid response");
            }
        } else {
            eprintln!("[agent] controller unreachable");
        }

        for _ in 0..5 {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    println!("[agent] shutdown requested — attempting to offload local chunks");

    if matches!(role, AgentRole::Pure) {
        if let Err(err) = offload_local_chunks(&base_dir, &controller_url, &node_id) {
            eprintln!("[agent] offload failed: {err:?}");
        }
    }

    println!("[agent] exiting");

    Ok(())
}

fn offload_local_chunks(
    base_dir: &Path,
    controller_url: &str,
    node_id: &str,
) -> anyhow::Result<()> {
    let client = Client::new();
    let mut local_chunks = Vec::new();
    collect_local_chunks(&client, controller_url, "/", node_id, &mut local_chunks)?;

    if local_chunks.is_empty() {
        println!("[agent] no local chunks to offload");
        return Ok(());
    }

    let mesh_info = fetch_mesh_info(controller_url)?;
    let peers = mesh_info_to_connections(mesh_info, node_id);

    if peers.is_empty() {
        println!("[agent] no peers available for offload; data remains on local disk");
        return Ok(());
    }

    let transport = mesh::global_transport();

    for (path, meta) in local_chunks {
        let chunk_path = base_dir
            .join(&meta.drive_id)
            .join(format!("chunk_{}", meta.index));

        match fs::read(&chunk_path) {
            Ok(buf) => {
                for peer in &peers {
                    match mesh::store_remote_chunk(transport, peer, &path, meta.index, &buf) {
                        Ok(_) => {
                            println!(
                                "[agent] offloaded {} chunk {} to {}",
                                path, meta.index, peer.node_id
                            );
                            break;
                        }
                        Err(err) => {
                            eprintln!(
                                "[agent] offload to {} failed for {} chunk {}: {:?}",
                                peer.node_id, path, meta.index, err
                            );
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "[agent] unable to read {:?} for offload: {:?}",
                    chunk_path, err
                );
            }
        }
    }

    Ok(())
}

fn collect_local_chunks(
    client: &Client,
    controller_url: &str,
    path: &str,
    node_id: &str,
    acc: &mut Vec<(String, ChunkMeta)>,
) -> anyhow::Result<()> {
    let url = format!("{}/fs/list?path={}", controller_url, path);
    let res = client.get(&url).send()?;

    if !res.status().is_success() {
        return Ok(());
    }

    let listing = res.json::<ListResponse>()?;

    for (_name, entry) in listing.entries {
        match entry.node_type {
            FsNodeType::Directory => {
                collect_local_chunks(client, controller_url, &entry.path, node_id, acc)?;
            }
            FsNodeType::File => {
                for chunk in entry.chunks {
                    if chunk.node_id == node_id {
                        acc.push((entry.path.clone(), chunk));
                    }
                }
            }
        }
    }

    Ok(())
}

fn mesh_info_to_connections(info: MeshInfo, node_id: &str) -> Vec<PeerConnection> {
    let mut peers = Vec::new();

    for p in info.peers {
        if p.node_id == node_id {
            continue;
        }

        if let Ok(addr) = p.endpoint.parse::<SocketAddr>() {
            let peer_nat = match p.nat_type.as_deref() {
                Some("FullCone") => NatType::FullCone,
                Some("RestrictedCone") => NatType::RestrictedCone,
                Some("PortRestrictedCone") => NatType::PortRestrictedCone,
                Some("Symmetric") => NatType::Symmetric,
                _ => NatType::Unknown,
            };

            peers.push(PeerConnection {
                node_id: p.node_id,
                addr,
                mode: ConnectivityMode::Direct,
                nat_type: peer_nat,
            });
        }
    }

    peers
}

// -----------------------------------------------------------------------------
// Storage discovery
// -----------------------------------------------------------------------------

fn discover_drives(base_dir: &PathBuf) -> anyhow::Result<Vec<DriveReport>> {
    let mut drives = Vec::new();

    for (id, path) in drive_paths(base_dir)? {
        let (data_bytes, reserved_bytes) = drive_usage(&path)?;

        drives.push(DriveReport {
            id,
            path: path.display().to_string(),
            used_bytes: data_bytes,
            allocated_bytes: data_bytes + reserved_bytes,
        });
    }

    Ok(drives)
}

fn drive_paths(base_dir: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let mut drives = Vec::new();

    fs::create_dir_all(base_dir)?;

    let mut mount_targets = match collect_lsblk_mounts() {
        Ok(devs) => devs,
        Err(err) => {
            eprintln!(
                "[agent] lsblk probe failed; using local fallback at {}: {:?}",
                base_dir.display(),
                err
            );
            Vec::new()
        }
    };
    if mount_targets.is_empty() {
        println!(
            "[agent] lsblk reported no mounted drives; falling back to {}",
            base_dir.display()
        );
        let fallback = base_dir.join("drive-fallback");
        fs::create_dir_all(&fallback)?;
        mount_targets.push(("drive-fallback".to_string(), fallback));
    }

    for (id, target) in mount_targets {
        let alias = base_dir.join(&id);

        if alias.exists() {
            let existing = alias.canonicalize().unwrap_or(alias.clone());
            if existing != target {
                if alias.is_dir() {
                    fs::remove_dir_all(&alias)?;
                } else {
                    let _ = fs::remove_file(&alias);
                }
            }
        }

        if !alias.exists() {
            if alias == target {
                fs::create_dir_all(&alias)?;
            } else {
                fs::create_dir_all(target.parent().unwrap_or(&target))?;
                if let Err(err) = unix_fs::symlink(&target, &alias) {
                    eprintln!(
                        "[agent] unable to link drive {} to {}: {:?}",
                        id,
                        target.display(),
                        err
                    );
                }
            }
        }

        drives.push((id, target));
    }

    drives.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(drives)
}

fn collect_lsblk_mounts() -> anyhow::Result<Vec<(String, PathBuf)>> {
    let output = Command::new("lsblk")
        .args(["-J", "-b", "-o", "NAME,MOUNTPOINT,SIZE,TYPE"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("lsblk failed with status {}", output.status);
    }

    let parsed: LsblkOutput = serde_json::from_slice(&output.stdout)?;
    let mut mounts = Vec::new();

    fn walk(dev: &LsblkBlockDevice, acc: &mut Vec<(String, PathBuf)>) {
        if dev.kind == "loop" {
            return;
        }

        if let (Some(mp), Some(size)) = (&dev.mountpoint, dev.size) {
            let trimmed = mp.trim();
            let is_swap = trimmed
                .trim_matches(['[', ']'])
                .eq_ignore_ascii_case("swap");

            if is_swap {
                println!("[agent] skipping swap-designated device {}", dev.name);
            } else if !mp.is_empty() && size > 0 {
                let id = format!("drive-{}", dev.name);
                let data_root = PathBuf::from(mp).join("junknas");
                let _ = fs::create_dir_all(&data_root);
                acc.push((id, data_root));
            }
        }

        for child in &dev.children {
            walk(child, acc);
        }
    }

    for dev in parsed.blockdevices {
        walk(&dev, &mut mounts);
    }

    Ok(mounts)
}

fn drive_usage(path: &Path) -> anyhow::Result<(u64, u64)> {
    let mut data_bytes = 0;
    let mut reserved_bytes = 0;

    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let len = entry.metadata()?.len();
            if entry.file_name() == ".allocation" {
                reserved_bytes += len;
            } else {
                data_bytes += len;
            }
        }
    }

    Ok((data_bytes, reserved_bytes))
}

// -----------------------------------------------------------------------------
// Apply controller’s desired state
// -----------------------------------------------------------------------------

fn apply_desired(base_dir: &PathBuf, desired: &HeartbeatResponse) -> anyhow::Result<()> {
    let drives = drive_paths(base_dir)?;
    let desired_bytes = desired.desired_allocation_bytes;

    if desired.eject {
        println!("[agent] eject requested — clearing storage");
        for (_id, path) in &drives {
            if path.exists() {
                fs::remove_dir_all(path)?;
            }
            fs::create_dir_all(path)?;
        }
        return Ok(());
    }

    if drives.is_empty() {
        println!("[agent] no drives discovered; skipping allocation");
    } else {
        let per_drive = desired_bytes / drives.len() as u64;
        let remainder = desired_bytes % drives.len() as u64;

        for (idx, (id, path)) in drives.iter().enumerate() {
            let (data_bytes, reserved_bytes) = drive_usage(path)?;

            let mut target_total = per_drive;
            if (idx as u64) < remainder {
                target_total += 1;
            }

            if target_total < data_bytes {
                target_total = data_bytes;
            }

            let target_reserved = target_total.saturating_sub(data_bytes);
            let reserved_path = path.join(".allocation");

            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&reserved_path)?;
            file.set_len(target_reserved)?;

            if reserved_bytes != target_reserved {
                println!(
                    "[agent] drive {} reservation {} → {} bytes (data {})",
                    id, reserved_bytes, target_reserved, data_bytes
                );
            }
        }
    }

    if let (Some(public), Some(private)) = (&desired.mesh_public_key, &desired.mesh_private_key) {
        let mesh_dir = base_dir.join("mesh");
        fs::create_dir_all(&mesh_dir)?;

        let key_path = mesh_dir.join("wg_keys.json");
        let payload = json!({
            "public_key": public,
            "private_key": private,
        });

        fs::write(&key_path, serde_json::to_vec_pretty(&payload)?)?;
        println!("[agent] synced WireGuard keys to {:?}", key_path);
    }

    Ok(())
}

fn update_config_from_heartbeat(
    cfg: &mut AgentConfig,
    _allocated_bytes: u64,
    drives: &[DriveReport],
    mesh_public_key: Option<String>,
    mesh_private_key: Option<String>,
    controller_url: &str,
) -> anyhow::Result<()> {
    cfg.allocated_bytes = drives.iter().map(|d| d.allocated_bytes).sum();
    cfg.drives = drives.iter().map(|d| d.id.clone()).collect();
    cfg.ip = detect_primary_ip();

    if let Some(pk) = mesh_public_key {
        cfg.mesh_public_key = Some(pk);
    }

    if let Some(sk) = mesh_private_key {
        cfg.mesh_private_key = Some(sk);
    }

    persist_agent_config(cfg)?;
    write_wireguard_config(cfg, controller_url)?;
    ensure_wireguard_overlay();

    Ok(())
}
