mod agent_state;
mod allocation;
mod fs_types;
mod fuse_daemon;
mod mesh;
mod nat;
mod peers;
mod transport;
mod wireguard;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    net::SocketAddr,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use walkdir::WalkDir;

use crate::mesh::PeerConnection;
use crate::nat::{compute_score, discover_public_endpoint, measure_controller_rtt, NatType};
use crate::peers::{fetch_mesh_info, MeshInfo};

const DEFAULT_CONTROLLER_URL: &str = "http://10.44.0.1:8080/api";

fn choose_controller_url() -> String {
    let mut candidates = vec![
        // Preferred host-forwarded port
        "http://host.containers.internal:8088/api".to_string(),
        "http://127.0.0.1:8088/api".to_string(),
        // Legacy port on host
        "http://host.containers.internal:8080/api".to_string(),
        "http://127.0.0.1:8080/api".to_string(),
        // Overlay defaults
        "http://10.44.0.1:8088/api".to_string(),
        DEFAULT_CONTROLLER_URL.to_string(),
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
    pub drives: Vec<DriveReport>,

    pub mesh_endpoint: Option<String>,
    pub mesh_public_key: Option<String>,
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
            return rt.block_on(async { fuse_daemon::run_fuse(mountpoint, controller).await });
        }
    }

    // ---------------------------------------------------------
    // Normal agent mode
    // ---------------------------------------------------------

    let controller_url = choose_controller_url();

    let hostname = hostname::get()?.to_string_lossy().into_owned();
    let node_id = hostname.clone();

    let nickname = std::env::var("JUNKNAS_NICKNAME").unwrap_or_else(|_| hostname.clone());

    // Local storage location
    let base_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("could not find local data dir"))?
        .join("junknas")
        .join("storage");

    fs::create_dir_all(&base_dir)?;

    println!("[agent] base_dir = {:?}", base_dir);

    // Mesh config
    let mesh_port: u16 = std::env::var("JUNKNAS_MESH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(42000);

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
    let mesh_public_key = std::env::var("JUNKNAS_MESH_PUBLIC_KEY").unwrap_or("dummy-key".into());

    // ---------------------------------------------------------
    // spawn mesh thread
    // ---------------------------------------------------------
    let controller_clone = controller_url.clone();
    let node_id_clone = node_id.clone();
    let our_nat_type = public.nat_type.clone();

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

                    if let Err(e) = mesh::run_mesh("dummy-private-key".into(), conns, mesh_port) {
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

    loop {
        let drives = discover_drives(&base_dir)?;

        let hb = HeartbeatRequest {
            node_id: node_id.clone(),
            hostname: hostname.clone(),
            nickname: nickname.clone(),
            drives: drives.clone(),
            mesh_endpoint: Some(mesh_endpoint.clone()),
            mesh_public_key: Some(mesh_public_key.clone()),
            mesh_score: Some(mesh_score),
            mesh_nat_type: Some(format!("{:?}", public.nat_type)),
        };

        let resp = client
            .post(format!("{}/agents/heartbeat", controller_url))
            .json(&hb)
            .send();

        if let Ok(r) = resp {
            if let Ok(desired) = r.json::<HeartbeatResponse>() {
                apply_desired(&base_dir, &desired)?;
            } else {
                eprintln!("[agent] heartbeat: invalid response");
            }
        } else {
            eprintln!("[agent] controller unreachable");
        }

        thread::sleep(Duration::from_secs(5));
    }
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

    for i in 0..3 {
        fs::create_dir_all(base_dir.join(format!("drive{}", i)))?;
    }

    for entry in fs::read_dir(base_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let id = entry.file_name().to_string_lossy().into_owned();
        if !id.starts_with("drive") {
            continue;
        }

        drives.push((id, path));
    }

    drives.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(drives)
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
    if desired.eject {
        println!("[agent] eject requested — clearing storage");
        if base_dir.exists() {
            fs::remove_dir_all(base_dir)?;
        }
        fs::create_dir_all(base_dir)?;
        return Ok(());
    }

    let drives = drive_paths(base_dir)?;
    let desired_bytes = desired.desired_allocation_bytes;

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
