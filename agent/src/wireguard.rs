use anyhow::{anyhow, Result};
use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
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

        // Make the child pipes non-blocking so we can poll without hanging.
        if let Some(stdout) = child.stdout.as_ref() {
            set_nonblocking(stdout)?;
        }
        if let Some(stdin) = child.stdin.as_ref() {
            set_nonblocking(stdin)?;
        }

        Ok(Self { child })
    }

    /// Read one encrypted WG packet from boringtun.
    pub fn read_packet(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; 65535];
        match self.child.stdout.as_mut().unwrap().read(&mut buf) {
            Ok(0) => Ok(None),
            Ok(size) => {
                buf.truncate(size);
                Ok(Some(buf))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Send encrypted WG packet into boringtun.
    pub fn write_packet(&mut self, pkt: &[u8]) -> Result<()> {
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("wg stdin closed"))?;

        match stdin.write_all(pkt) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

fn set_nonblocking<T: AsRawFd>(io: &T) -> Result<()> {
    unsafe {
        let fd = io.as_raw_fd();
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(anyhow!("failed to read flags"));
        }

        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(anyhow!("failed to mark fd non-blocking"));
        }
    }

    Ok(())
}
