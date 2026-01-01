//! USB-ADB transport using Tetherand's Frame codec.
//!
//! Status: built but not wired into the M1 CLI. The M1 CLI delegates
//! directly to `tetherand_relay_core::relay()`, which speaks Gnirehtet's
//! native wire format (raw IPv4 packets delimited by the IPv4 header's
//! own length field) over a TCP socket.
//!
//! This crate exists for M2+ when transport multiplexing requires control
//! frames in addition to IP packets (e.g. for capability negotiation,
//! Bluetooth keepalives, AOA mode-switching, etc.). When that lands, the
//! CLI flips from `relay_core::relay()` to a transport-mux that loops
//! frames through this implementation.
//!
//! The implementation wraps a `tokio::net::TcpStream` over an
//! `adb forward tcp:N localabstract:tetherand` tunnel.

use std::process::Command;

use async_trait::async_trait;
use bytes::BytesMut;
use tetherand_codec::{Frame, FRAME_VERSION};
use tetherand_transport_api::{Capabilities, Transport, TransportError, TransportId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

pub const DEFAULT_PORT: u16 = 31416;
pub const ABSTRACT_NAME: &str = "tetherand";

pub struct AdbTransport {
    serial: Option<String>,
    port: u16,
    stream: Option<TcpStream>,
    read_buf: BytesMut,
}

impl AdbTransport {
    pub fn new(serial: Option<String>) -> Self {
        Self {
            serial,
            port: DEFAULT_PORT,
            stream: None,
            read_buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn ensure_adb_forward(&self) -> Result<(), TransportError> {
        let mut cmd = Command::new("adb");
        if let Some(s) = &self.serial {
            cmd.arg("-s").arg(s);
        }
        cmd.arg("forward")
           .arg(format!("tcp:{}", self.port))
           .arg(format!("localabstract:{}", ABSTRACT_NAME));
        let out = cmd.output().map_err(TransportError::Io)?;
        if !out.status.success() {
            return Err(TransportError::Other(format!(
                "adb forward failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        debug!("adb forward tcp:{} -> localabstract:{}", self.port, ABSTRACT_NAME);
        Ok(())
    }
}

#[async_trait]
impl Transport for AdbTransport {
    async fn connect(&mut self) -> Result<Capabilities, TransportError> {
        self.ensure_adb_forward()?;
        let stream = TcpStream::connect(("127.0.0.1", self.port)).await?;
        stream.set_nodelay(true)?;
        info!("USB-ADB connected on 127.0.0.1:{}", self.port);
        self.stream = Some(stream);
        Ok(Capabilities {
            id: TransportId::UsbAdb,
            mtu: 1500,
            bandwidth_hint_bps: 200_000_000,
            latency_hint_ms: 5,
        })
    }

    async fn next_frame(&mut self) -> Result<Frame, TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        loop {
            if let Some(frame) = Frame::decode(&mut self.read_buf)? {
                if frame.version != FRAME_VERSION {
                    return Err(TransportError::Other(format!(
                        "frame version mismatch: got {} expected {}",
                        frame.version, FRAME_VERSION
                    )));
                }
                return Ok(frame);
            }
            let mut chunk = [0u8; 8192];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(TransportError::Closed);
            }
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
        if let Some(mut s) = self.stream.take() {
            let _ = s.shutdown().await;
        }
        Ok(())
    }

    fn id(&self) -> TransportId { TransportId::UsbAdb }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tetherand_codec::FrameType;
    use tokio::net::TcpListener;

    /// Loopback test that skips `adb forward` entirely: stand up a TCP
    /// listener, dial it, exchange a frame, prove the codec wiring works.
    #[tokio::test]
    async fn loopback_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let mut t = AdbTransport::new(None).with_port(port);
        t.stream = Some(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
        t.send_frame(Frame::new(FrameType::IpPacket, Bytes::from_static(b"ping"))).await.unwrap();
        let echoed = t.next_frame().await.unwrap();
        assert_eq!(&echoed.payload[..], b"ping");

        server.await.unwrap();
    }
}
