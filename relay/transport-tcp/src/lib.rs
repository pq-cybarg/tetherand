//! TCP/LAN transport with mDNS service discovery.
//!
//! Status: built but unused by M1's CLI. See `tetherand-transport-adb`
//! for the same disposition rationale.
//!
//! Phone advertises `_tetherand._tcp.local` and listens on a TCP port.
//! Mac discovers via mDNS and dials.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use tetherand_codec::Frame;
use tetherand_transport_api::{Capabilities, Transport, TransportError, TransportId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub const SERVICE_TYPE: &str = "_tetherand._tcp.local.";
pub const DEFAULT_PORT: u16 = 31417;

pub struct TcpTransport {
    addr: Option<SocketAddr>,
    discover_timeout: Duration,
    stream: Option<TcpStream>,
    read_buf: BytesMut,
}

impl TcpTransport {
    pub fn direct(addr: SocketAddr) -> Self {
        Self {
            addr: Some(addr),
            discover_timeout: Duration::from_secs(0),
            stream: None,
            read_buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    pub fn discover(timeout: Duration) -> Self {
        Self {
            addr: None,
            discover_timeout: timeout,
            stream: None,
            read_buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    async fn resolve(&self) -> Result<SocketAddr, TransportError> {
        if let Some(a) = self.addr {
            return Ok(a);
        }
        let daemon = ServiceDaemon::new()
            .map_err(|e| TransportError::Other(format!("mdns: {e}")))?;
        let receiver = daemon.browse(SERVICE_TYPE)
            .map_err(|e| TransportError::Other(format!("mdns browse: {e}")))?;
        let deadline = tokio::time::Instant::now() + self.discover_timeout;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(TransportError::Other(format!(
                    "no {} service discovered within {:?}",
                    SERVICE_TYPE, self.discover_timeout
                )));
            }
            let remaining = deadline - now;
            let evt = tokio::time::timeout(remaining, async {
                receiver.recv_async().await
            })
            .await
            .map_err(|_| TransportError::Other("mdns timeout".into()))?
            .map_err(|e| TransportError::Other(format!("mdns recv: {e}")))?;
            if let ServiceEvent::ServiceResolved(info) = evt {
                let port = info.get_port();
                if let Some(ip) = info.get_addresses().iter().next().copied() {
                    let sa = SocketAddr::new(ip, port);
                    info!("mDNS resolved {} at {}", info.get_fullname(), sa);
                    return Ok(sa);
                }
                warn!("mDNS service {} resolved with no address", info.get_fullname());
            }
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&mut self) -> Result<Capabilities, TransportError> {
        let addr = self.resolve().await?;
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        debug!("TCP transport connected to {addr}");
        self.stream = Some(stream);
        Ok(Capabilities {
            id: TransportId::Tcp,
            mtu: 1500,
            bandwidth_hint_bps: 50_000_000,
            latency_hint_ms: 20,
        })
    }

    async fn next_frame(&mut self) -> Result<Frame, TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        loop {
            if let Some(frame) = Frame::decode(&mut self.read_buf)? {
                return Ok(frame);
            }
            let mut chunk = [0u8; 8192];
            let n = stream.read(&mut chunk).await?;
            if n == 0 { return Err(TransportError::Closed); }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        let bytes = frame.encode()?;
        stream.write_all(&bytes).await?;
        Ok(())
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let Some(mut s) = self.stream.take() { let _ = s.shutdown().await; }
        Ok(())
    }

    fn id(&self) -> TransportId { TransportId::Tcp }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tetherand_codec::FrameType;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });
        let mut t = TcpTransport::direct(addr);
        t.connect().await.unwrap();
        t.send_frame(Frame::new(FrameType::IpPacket, Bytes::from_static(b"hi"))).await.unwrap();
        let f = t.next_frame().await.unwrap();
        assert_eq!(&f.payload[..], b"hi");
        server.await.unwrap();
    }
}
