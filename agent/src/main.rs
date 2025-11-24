mod fs_types;
mod fuse_daemon;
mod mesh;
mod nat;
mod peers;
mod transport;
mod wireguard;

use anyhow::Context;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fs, net::SocketAddr, path::PathBuf, thread, time::Duration};
use walkdir::WalkDir;

use crate::mesh::PeerConnection;
use crate::nat::{
    compute_score, discover_public_endpoint, measure_controller_rtt, ConnectivityMode, NatType,
};
use crate::peers::{fetch_mesh_info, MeshInfo};

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
            let controller = std::env::var("JUNKNAS_CONTROLLER_URL").unwrap_or_else(|_| {
                "http://junknas-controller.junknas.svc.cluster.local/api".into()
            });

            println!("[agent] starting FUSE daemon on {:?}", mountpoint);

            // run async FUSE
            let rt = tokio::runtime::Runtime::new()?;
            return rt.block_on(async { fuse_daemon::run_fuse(mountpoint, controller).await });
        }
    }

    // ---------------------------------------------------------
    // Normal agent mode
    // ---------------------------------------------------------

    let controller_url = std::env::var("JUNKNAS_CONTROLLER_URL")
        .unwrap_or_else(|_| "http://junknas-controller.junknas.svc.cluster.local/api".into());

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
        let used = folder_size(&path)?;

        drives.push(DriveReport {
            id,
            path: path.display().to_string(),
            used_bytes: used,
            allocated_bytes: used,
        });
    }

    Ok(drives)
}

fn folder_size(path: &PathBuf) -> anyhow::Result<u64> {
    let mut size = 0;
    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() {
            size += entry.metadata()?.len();
        }
    }
    Ok(size)
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

    println!(
        "[agent] desired allocation = {} (TODO implement allocator)",
        desired.desired_allocation_bytes
    );

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
