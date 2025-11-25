use anyhow::Result;
use std::process::Command;

/// Lightweight wrapper that validates WireGuard tooling is available.
/// When running in rootless containers, the agent relies on the kernel
/// WireGuard implementation accessed via `wg` instead of a userspace
/// tunnel like boringtun.
pub struct WGTunnel;

impl WGTunnel {
    pub fn start(_key: &str) -> Result<Self> {
        // Ensure the kernel WireGuard tooling is present so deployments fail fast
        // if the container image is missing the dependency.
        let status = Command::new("wg").arg("show").status()?;
        if !status.success() {
            anyhow::bail!("wg command is present but returned non-zero: {status}");
        }
        Ok(Self)
    }

    /// Kernel WireGuard handles packet flow directly; nothing to surface here yet.
    pub fn read_packet(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// No-op placeholder to keep mesh plumbing intact while the kernel driver owns I/O.
    pub fn write_packet(&mut self, _pkt: &[u8]) -> Result<()> {
        Ok(())
    }
}
