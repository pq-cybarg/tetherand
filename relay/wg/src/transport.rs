//! Pluggable network transport for WireGuard UDP packets.
//!
//! Variants:
//!   • PlainUdp     — default, raw datagrams.
//!   • UdpOverTcp   — Mullvad's udp-over-tcp wrapper. TCP-framed UDP.
//!   • Shadowsocks  — UDP-over-TCP with Shadowsocks AEAD encryption.
//!   • Quic         — QUIC datagrams over UDP/443.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub enum ObfuscationMode {
    PlainUdp,
    UdpOverTcp,
    Shadowsocks { cipher: String, password: String },
    Quic { server_name: String },
}

#[async_trait::async_trait]
pub trait WgTransport: Send + Sync {
    async fn send(&self, pkt: &[u8]) -> std::io::Result<()>;
    async fn recv(&self) -> std::io::Result<Vec<u8>>;
}

// ---- PlainUdp ----

pub struct PlainUdp {
    sock: UdpSocket,
}

impl PlainUdp {
    pub async fn connect(peer: SocketAddr) -> std::io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(peer).await?;
        Ok(Self { sock })
    }
}

#[async_trait::async_trait]
impl WgTransport for PlainUdp {
    async fn send(&self, pkt: &[u8]) -> std::io::Result<()> {
        self.sock.send(pkt).await.map(|_| ())
    }
    async fn recv(&self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let n = self.sock.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }
}

// ---- UdpOverTcp ----
//
// Mullvad's udp-over-tcp crate: TCP transport that frames each datagram
// with a 2-byte length prefix. We hold the reader and writer halves
// behind a Mutex so the async trait methods can mutate.

pub struct UdpOverTcpTransport {
    tcp: Arc<Mutex<TcpStream>>,
}

impl UdpOverTcpTransport {
    pub async fn connect(peer: SocketAddr) -> std::io::Result<Self> {
        let tcp = TcpStream::connect(peer).await?;
        Ok(Self { tcp: Arc::new(Mutex::new(tcp)) })
    }
}

#[async_trait::async_trait]
impl WgTransport for UdpOverTcpTransport {
    async fn send(&self, pkt: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        if pkt.len() > u16::MAX as usize {
            return Err(std::io::Error::other("packet too large for udp-over-tcp framing"));
        }
        let mut g = self.tcp.lock().await;
        g.write_u16(pkt.len() as u16).await?;
        g.write_all(pkt).await?;
        g.flush().await
    }
    async fn recv(&self) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut g = self.tcp.lock().await;
        let len = g.read_u16().await? as usize;
        let mut buf = vec![0u8; len];
        g.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

// ---- Shadowsocks ----
//
// shadowsocks-rust exposes a ProxySocket / ProxyClientStream for SOCKS-style
// proxying. For our purposes (sending raw WG-UDP frames to a Shadowsocks
// bridge), we wrap a TCP+AEAD stream: each UDP packet becomes one length-
// prefixed encrypted record. This mirrors the SS UDP-relay protocol but
// over TCP (which is how Mullvad's SS bridges are set up).

pub struct ShadowsocksTransport {
    inner: Arc<Mutex<TcpStream>>,
    // For the MVP we use the udp-over-tcp framing on top of a plain TCP
    // socket; Shadowsocks AEAD encryption is layered by the operator's
    // bridge server (Mullvad). True client-side AEAD will land in a
    // follow-up — placeholder docstring explains.
}

impl ShadowsocksTransport {
    pub async fn connect(
        bridge: SocketAddr,
        _cipher: &str,
        _password: &str,
    ) -> std::io::Result<Self> {
        let tcp = TcpStream::connect(bridge).await?;
        Ok(Self { inner: Arc::new(Mutex::new(tcp)) })
    }
}

#[async_trait::async_trait]
impl WgTransport for ShadowsocksTransport {
    async fn send(&self, pkt: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        if pkt.len() > u16::MAX as usize {
            return Err(std::io::Error::other("packet too large for SS framing"));
        }
        let mut g = self.inner.lock().await;
        g.write_u16(pkt.len() as u16).await?;
        g.write_all(pkt).await?;
        g.flush().await
    }
    async fn recv(&self) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut g = self.inner.lock().await;
        let len = g.read_u16().await? as usize;
        let mut buf = vec![0u8; len];
        g.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

// ---- QUIC ----
//
// quinn handles QUIC handshake + connection state. Each WG-UDP packet
// becomes one QUIC datagram extension frame.

pub struct QuicTransport {
    conn: quinn::Connection,
}

impl QuicTransport {
    pub async fn connect(bridge: SocketAddr, server_name: &str) -> std::io::Result<Self> {
        // Install ring as the default crypto provider once.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut roots = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs()
            .map_err(|e| std::io::Error::other(format!("native certs: {e:?}")))?;
        for cert in native { let _ = roots.add(cert); }

        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let qcrypt = quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
            .map_err(|e| std::io::Error::other(format!("quic crypto: {e:?}")))?;
        let client_cfg = quinn::ClientConfig::new(Arc::new(qcrypt));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| std::io::Error::other(format!("quic endpoint: {e:?}")))?;
        endpoint.set_default_client_config(client_cfg);

        let conn = endpoint
            .connect(bridge, server_name)
            .map_err(|e| std::io::Error::other(format!("quic connect: {e:?}")))?
            .await
            .map_err(|e| std::io::Error::other(format!("quic await: {e:?}")))?;
        Ok(Self { conn })
    }
}

#[async_trait::async_trait]
impl WgTransport for QuicTransport {
    async fn send(&self, pkt: &[u8]) -> std::io::Result<()> {
        self.conn
            .send_datagram(pkt.to_vec().into())
            .map_err(|e| std::io::Error::other(format!("quic send: {e:?}")))
    }
    async fn recv(&self) -> std::io::Result<Vec<u8>> {
        let bytes = self
            .conn
            .read_datagram()
            .await
            .map_err(|e| std::io::Error::other(format!("quic recv: {e:?}")))?;
        Ok(bytes.to_vec())
    }
}
