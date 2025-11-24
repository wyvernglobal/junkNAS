
use anyhow::{anyhow, Result};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// How we think we should talk to a peer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectivityMode {
    /// We can directly send UDP packets (hole punching either easy or not needed).
    Direct,
    /// We should attempt symmetric, timed UDP hole punching.
    HolePunch,
    /// Give up and use controller relay as a dumb middle.
    Relay,
}

/// A STUN-discovered public endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicEndpoint {
    pub public_addr: SocketAddr,
    pub nat_type: NatType,
}

/// NAT classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatType {
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    Unknown,
}

/// Minimal RFC5389 STUN binding request/response logic.
fn stun_request(sock: &UdpSocket, stun_addr: SocketAddr) -> Result<SocketAddr> {
    // Build binding request (no attributes).
    let mut tx = [0u8; 20];
    tx[0] = 0x00;
    tx[1] = 0x01; // Binding Request
    tx[2] = 0x00;
    tx[3] = 0x00; // Message Length = 0
    tx[4] = 0x21;
    tx[5] = 0x12;
    tx[6] = 0xA4;
    tx[7] = 0x42; // Magic Cookie
    // Random transaction ID.
    getrandom(&mut tx[8..])?;

    sock.send_to(&tx, stun_addr)?;

    let mut buf = [0u8; 256];
    let start = Instant::now();

    loop {
        if start.elapsed() > Duration::from_secs(2) {
            return Err(anyhow!("STUN timeout"));
        }

        let (size, _from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if size < 20 {
            continue;
        }

        // Scan attributes for XOR-MAPPED-ADDRESS (0x0020)
        let mut i = 20;
        while i + 4 <= size {
            let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
            let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            i += 4;
            if i + attr_len > size {
                break;
            }

            if attr_type == 0x0020 && attr_len >= 8 {
                // family byte is at i+1, IPv4=0x01
                let family = buf[i + 1];
                if family != 0x01 {
                    return Err(anyhow!("STUN: only IPv4 supported"));
                }

                // XOR port and IP
                let xor_port = u16::from_be_bytes([buf[i + 2], buf[i + 3]]);
                let port = xor_port ^ 0x2112;

                let xor_addr = [
                    buf[i + 4] ^ 0x21,
                    buf[i + 5] ^ 0x12,
                    buf[i + 6] ^ 0xA4,
                    buf[i + 7] ^ 0x42,
                ];

                let addr = SocketAddr::from((xor_addr, port));
                return Ok(addr);
            }

            i += attr_len;
        }
    }
}

/// Discover a public endpoint using the given STUN server.
pub fn discover_public_endpoint(
    stun_server: &str,
    bind_port: u16,
) -> Result<PublicEndpoint> {
    let stun_addr: SocketAddr = stun_server.parse()?;
    let sock = UdpSocket::bind(("0.0.0.0", bind_port))?;
    sock.set_nonblocking(false)?;

    let observed_1 = stun_request(&sock, stun_addr)?;
    std::thread::sleep(Duration::from_millis(200));
    let observed_2 = stun_request(&sock, stun_addr)?;

    let nat_type = classify_nat(observed_1, observed_2)?;

    Ok(PublicEndpoint {
        public_addr: observed_1,
        nat_type,
    })
}

/// Crude NAT type classification from two STUN observations.
fn classify_nat(o1: SocketAddr, o2: SocketAddr) -> Result<NatType> {
    if o1 == o2 {
        // Same mapping: could be full-cone or restricted; we treat as FullCone.
        return Ok(NatType::FullCone);
    }

    if o1.ip() == o2.ip() && o1.port() != o2.port() {
        // Same IP, different port → port-restricted style.
        return Ok(NatType::PortRestrictedCone);
    }

    if o1 != o2 {
        // Different IP or unpredictable mapping → symmetric.
        return Ok(NatType::Symmetric);
    }

    Ok(NatType::Unknown)
}

/// Measure RTT (ms) to the controller via a cheap HTTP GET.
/// This is used to refine mesh score.
pub fn measure_controller_rtt(controller_base: &str) -> f32 {
    let client = reqwest::blocking::Client::new();
    let url = format!("{}/nodes", controller_base.trim_end_matches('/'));

    let start = Instant::now();
    let res = client.get(url).send();
    let elapsed = start.elapsed();

    if res.is_err() {
        // If unreachable, treat as very bad RTT.
        return 5000.0;
    }

    elapsed.as_millis() as f32
}

/// Compute a mesh score (0.0 to 1.0) from NAT type + RTT.
pub fn compute_score(nat_type: &NatType, rtt_ms: f32) -> f32 {
    // NAT base score
    let nat_score = match nat_type {
        NatType::FullCone => 1.0,
        NatType::RestrictedCone => 0.8,
        NatType::PortRestrictedCone => 0.6,
        NatType::Symmetric => 0.2,
        NatType::Unknown => 0.4,
    };

    // RTT factor: 0ms ~ 1.0, 5000ms+ ~ 0.0
    let rtt_factor = (1.0 - (rtt_ms / 5000.0)).clamp(0.0, 1.0);

    // Weighted combination
    (nat_score * 0.7 + rtt_factor * 0.3).clamp(0.0, 1.0)
}

/// Suggest a connectivity mode for us <-> peer.
pub fn select_connectivity_mode(our_nat: &NatType, peer_nat: &NatType) -> ConnectivityMode {
    use ConnectivityMode::*;

    match (our_nat, peer_nat) {
        // Best case – at least one side is cone-like: direct is usually OK.
        (NatType::FullCone, _) | (_, NatType::FullCone) => Direct,
        (NatType::RestrictedCone, NatType::RestrictedCone) => HolePunch,
        (NatType::RestrictedCone, NatType::PortRestrictedCone)
        | (NatType::PortRestrictedCone, NatType::RestrictedCone)
        | (NatType::PortRestrictedCone, NatType::PortRestrictedCone) => HolePunch,
        // Symmetric NAT on either side is really nasty; often relay is safest.
        (NatType::Symmetric, _) | (_, NatType::Symmetric) => Relay,
        // Unknown: try hole punching.
        _ => HolePunch,
    }
}

/// Attempt symmetric UDP hole punching with a peer.
///
/// Both sides must call this around the same time, sending to each other.
/// We return true if any "hole punch" packet comes back from `peer_addr`.
pub fn attempt_hole_punch(local_port: u16, peer_addr: SocketAddr, timeout: Duration) -> bool {
    let sock = match UdpSocket::bind(("0.0.0.0", local_port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[nat] failed to bind for hole punching: {:?}", e);
            return false;
        }
    };
    sock.set_nonblocking(false).ok();

    let punch_packet = b"junknas-holepunch";
    let start = Instant::now();
    let mut buf = [0u8; 256];

    loop {
        let _ = sock.send_to(punch_packet, peer_addr);

        if let Ok((size, from)) = sock.recv_from(&mut buf) {
            if from == peer_addr && &buf[..size] == punch_packet {
                println!("[nat] hole punching succeeded with {}", peer_addr);
                return true;
            }
        }

        if start.elapsed() > timeout {
            println!("[nat] hole punching timed out for {}", peer_addr);
            return false;
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}
