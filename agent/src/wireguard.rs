use anyhow::Result;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// Launch boringtun in userspace.
/// - Runs in "tun disabled" mode
/// - Inputs/outputs encrypted packets through stdin/stdout
pub struct WGTunnel {
    child: std::process::Child,
}

impl WGTunnel {
    pub fn start(key: &str) -> Result<Self> {
        let child = Command::new("boringtun")
            .arg("--disable-drop-privileges")
            .arg("--foreground")
            .arg("--key")
            .arg(key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        Ok(Self { child })
    }

    /// Read one encrypted WG packet from boringtun.
    pub fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let size = self.child.stdout.as_mut().unwrap().read(&mut buf)?;
        buf.truncate(size);
        Ok(buf)
    }

    /// Send encrypted WG packet into boringtun.
    pub fn write_packet(&mut self, pkt: &[u8]) -> Result<()> {
        self.child.stdin.as_mut().unwrap().write_all(pkt)?;
        Ok(())
    }
}
