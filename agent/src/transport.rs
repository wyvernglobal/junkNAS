use anyhow::Result;
use std::net::{SocketAddr, UdpSocket};

pub struct OverlayTransport {
    socket: UdpSocket,
}

impl OverlayTransport {
    /// Bind to a local UDP port, rootless-safe (must be >= 1024).
    pub fn bind(port: u16) -> Result<Self> {
        let sock = UdpSocket::bind(("0.0.0.0", port))?;
        sock.set_nonblocking(true)?;
        Ok(Self { socket: sock })
    }

    /// Send a packet to a peer.
    pub fn send(&self, peer: SocketAddr, data: &[u8]) -> Result<()> {
        self.socket.send_to(data, peer)?;
        Ok(())
    }

    /// Attempt to receive a packet; returns None if no data is available.
    pub fn recv(&self) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65535];
        match self.socket.recv_from(&mut buf) {
            Ok((size, addr)) => {
                buf.truncate(size);
                Some((buf, addr))
            }
            Err(_) => None,
        }
    }
}
