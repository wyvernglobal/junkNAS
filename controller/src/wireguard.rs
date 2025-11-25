use anyhow::Result;
use std::{
    env, fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
};
use tracing::{info, warn};

use crate::{ControllerState, MeshPeer, NodeState};

/// Rendered WireGuard configuration plus file/iface metadata.
pub struct RenderedConfig {
    pub interface: String,
    pub path: PathBuf,
    pub contents: String,
}

/// Builds a WireGuard server config for the controller using in-memory state.
///
/// The controller node id defaults to `controller` but can be overridden with
/// `CONTROLLER_NODE_ID`. Endpoint host portions can be overridden with
/// `WG_ENDPOINT_OVERRIDE` to cope with VPN/NAT detection quirks.
/// IPv6 endpoints are preferred when present.
pub fn render(state: &ControllerState) -> Option<RenderedConfig> {
    let controller_node_id =
        env::var("CONTROLLER_NODE_ID").unwrap_or_else(|_| "controller".to_string());

    let keypair = state.wg_keys.get(&controller_node_id)?.clone();
    let interface = env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string());
    let path = config_path(&interface);

    let endpoint_override = env::var("WG_ENDPOINT_OVERRIDE").ok();
    let default_allowed =
        env::var("WG_ALLOWED_FALLBACK").unwrap_or_else(|_| "0.0.0.0/0,::/0".to_string());

    let listen_port = env::var("WG_LISTEN_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .or_else(|| {
            state
                .nodes
                .get(&controller_node_id)
                .and_then(|n| n.mesh_port)
        })
        .unwrap_or(51820);

    let mut interface_addresses = Vec::new();
    if let Ok(addr) = env::var("WG_ADDRESS") {
        interface_addresses.push(addr);
    } else if let Some(node) = state.nodes.get(&controller_node_id) {
        if let Some(ip) = &node.ip {
            interface_addresses.push(ip_to_cidr(ip));
        }
    }

    if let Ok(addr_v6) = env::var("WG_ADDRESS_V6") {
        interface_addresses.push(addr_v6);
    }

    let mut lines = Vec::new();
    lines.push("[Interface]".to_string());
    lines.push(format!("PrivateKey = {}", keypair.private_key));
    lines.push(format!("ListenPort = {}", listen_port));
    lines.push("SaveConfig = true".to_string());
    for addr in interface_addresses {
        lines.push(format!("Address = {}", addr));
    }
    if let Some(override_host) = &endpoint_override {
        lines.push(format!("# Endpoint override: {}", override_host));
    }

    for peer in state.mesh_peers.values() {
        if peer.node_id == controller_node_id {
            continue;
        }
        let node_meta = state.nodes.get(&peer.node_id);
        let endpoint = compute_endpoint(node_meta, peer, endpoint_override.as_deref());
        let allowed_ips = node_meta
            .and_then(|n| n.ip.as_ref())
            .map(|ip| ip_to_cidr(ip))
            .unwrap_or_else(|| default_allowed.clone());

        lines.push(String::new());
        lines.push("[Peer]".to_string());
        lines.push(format!("PublicKey = {}", peer.public_key));
        lines.push(format!("AllowedIPs = {}", allowed_ips));

        if let Some(ep) = endpoint {
            lines.push(format!("Endpoint = {}", ep));
            lines.push("PersistentKeepalive = 25".to_string());
        }
    }

    let contents = lines.join("\n") + "\n";

    Some(RenderedConfig {
        interface,
        path,
        contents,
    })
}

/// Writes a rendered config to disk and restarts the WireGuard interface.
pub fn write_and_reload(cfg: RenderedConfig) -> Result<()> {
    if let Some(parent) = cfg.path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&cfg.path, &cfg.contents)?;

    info!(
        "WireGuard config updated at {} (interface {})",
        cfg.path.display(),
        cfg.interface
    );

    restart_interface(&cfg.interface);
    Ok(())
}

fn restart_interface(interface: &str) {
    // Stop interface if it exists; ignore errors so a missing interface doesn't block startup.
    if let Err(e) = Command::new("wg-quick").arg("down").arg(interface).status() {
        warn!("wg-quick down {} failed: {}", interface, e);
    }

    if let Err(e) = Command::new("wg-quick").arg("up").arg(interface).status() {
        warn!("wg-quick up {} failed: {}", interface, e);
    }
}

fn config_path(interface: &str) -> PathBuf {
    if let Ok(p) = env::var("WG_CONFIG_PATH") {
        Path::new(&p).to_path_buf()
    } else {
        Path::new("/etc/wireguard")
            .join(format!("{}.conf", interface))
            .to_path_buf()
    }
}

fn ip_to_cidr(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("{}/128", ip),
        _ => format!("{}/32", ip),
    }
}

fn compute_endpoint(
    node: Option<&NodeState>,
    peer: &MeshPeer,
    override_host: Option<&str>,
) -> Option<String> {
    let mut endpoint = if !peer.endpoint.is_empty() {
        Some(peer.endpoint.clone())
    } else if let Some(n) = node {
        match (n.ip.as_ref(), n.mesh_port) {
            (Some(ip), Some(port)) => Some(format_endpoint(ip, port)),
            _ => None,
        }
    } else {
        None
    }?;

    if let Some(host) = override_host {
        if let Some((_, port)) = split_endpoint(&endpoint) {
            endpoint = format_endpoint(host, port);
        }
    }

    Some(endpoint)
}

fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn split_endpoint(ep: &str) -> Option<(String, u16)> {
    if let Some(end) = ep.rfind(']') {
        if let Some(colon) = ep[end..].find(':') {
            let port_str = &ep[end + colon + 1..];
            let port = port_str.parse::<u16>().ok()?;
            let host = ep[1..end].to_string();
            return Some((host, port));
        }
    }

    if let Some((host, port_str)) = ep.rsplit_once(':') {
        let port = port_str.parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_override_preserves_port() {
        let original = "192.168.1.5:51820";
        let overridden = compute_endpoint(
            None,
            &MeshPeer {
                node_id: "n1".into(),
                endpoint: original.into(),
                public_key: "abc".into(),
                score: 1.0,
                nat_type: None,
            },
            Some("203.0.113.9"),
        )
        .unwrap();
        assert_eq!(overridden, "203.0.113.9:51820");
    }

    #[test]
    fn format_endpoint_brackets_ipv6() {
        assert_eq!(format_endpoint("2001:db8::1", 7777), "[2001:db8::1]:7777");
    }

    #[test]
    fn ip_to_cidr_handles_ipv6() {
        assert_eq!(ip_to_cidr("2001:db8::1"), "2001:db8::1/128");
        assert_eq!(ip_to_cidr("10.0.0.5"), "10.0.0.5/32");
    }
}
