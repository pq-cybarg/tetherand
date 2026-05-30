//! Minimal SOCKS5 proxy server that funnels every accepted connection
//! through arti's [`TorClient::connect()`]. Inspired by Orbot's
//! Android pattern: rather than write a userspace TCP responder on
//! the Kotlin side, we expose a local SOCKS5 endpoint and let
//! interested apps (or our own per-flow forwarder, post-v1) dial it.
//!
//! Supported subset of RFC 1928:
//!   - VER 5, METHODS = NO AUTH (0x00) only.
//!   - CMD = CONNECT (0x01).
//!   - ATYP = IPv4 (0x01), DOMAIN (0x03), IPv6 (0x04).
//!
//! Anything else gets a SOCKS5 failure reply.

use arti_client::{TorClient, DataStream};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tor_rtcompat::PreferredRuntime;

/// Spawn a SOCKS5 listener bound to 127.0.0.1:0 on the supplied tokio
/// runtime. Returns the chosen port (so the Kotlin side can plumb it
/// into the UI / per-flow forwarder).
pub fn spawn(
    rt: &tokio::runtime::Runtime,
    client: TorClient<PreferredRuntime>,
) -> std::io::Result<u16> {
    let listener = rt.block_on(async {
        TcpListener::bind("127.0.0.1:0").await
    })?;
    let port = listener.local_addr()?.port();
    let client = Arc::new(client);
    rt.spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    log::warn!("socks accept: {e}");
                    continue;
                }
            };
            let client = client.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_one(sock, client).await {
                    log::warn!("socks session: {e}");
                }
            });
        }
    });
    Ok(port)
}

async fn handle_one(
    mut sock: TcpStream,
    client: Arc<TorClient<PreferredRuntime>>,
) -> Result<(), String> {
    // ---- Greeting: VER NMETHODS METHODS... ----
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await.map_err(|e| format!("greet hdr: {e}"))?;
    if hdr[0] != 0x05 { return Err(format!("bad ver: {}", hdr[0])); }
    let n = hdr[1] as usize;
    let mut methods = vec![0u8; n];
    sock.read_exact(&mut methods).await.map_err(|e| format!("methods: {e}"))?;
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xFF]).await.ok();
        return Err("no acceptable method".into());
    }
    sock.write_all(&[0x05, 0x00]).await.map_err(|e| format!("greet ack: {e}"))?;

    // ---- Request: VER CMD RSV ATYP ... ----
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await.map_err(|e| format!("req hdr: {e}"))?;
    if req[0] != 0x05 { return Err("bad ver in req".into()); }
    if req[1] != 0x01 {
        // Only CONNECT supported in v1. Reply with "command not supported".
        reply(&mut sock, 0x07).await;
        return Err("only CONNECT supported".into());
    }
    let host: String = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await.map_err(|e| format!("v4: {e}"))?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await.map_err(|e| format!("dnlen: {e}"))?;
            let mut n = vec![0u8; l[0] as usize];
            sock.read_exact(&mut n).await.map_err(|e| format!("dn: {e}"))?;
            String::from_utf8_lossy(&n).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await.map_err(|e| format!("v6: {e}"))?;
            let p: [u16; 8] = std::array::from_fn(|i| u16::from_be_bytes([a[i*2], a[i*2+1]]));
            format!("[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]",
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        }
        other => {
            reply(&mut sock, 0x08).await;
            return Err(format!("bad atyp: {other}"));
        }
    };
    let mut pb = [0u8; 2];
    sock.read_exact(&mut pb).await.map_err(|e| format!("port: {e}"))?;
    let port = u16::from_be_bytes(pb);

    // ---- Dial through arti ----
    let stream: DataStream = match client.connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("arti connect {host}:{port}: {e}");
            reply(&mut sock, 0x05).await; // connection refused
            return Ok(());
        }
    };

    // ---- Success reply ----
    reply(&mut sock, 0x00).await;

    // ---- Bidirectional copy ----
    let (mut a_r, mut a_w) = tokio::io::split(sock);
    let (mut s_r, mut s_w) = tokio::io::split(stream);
    let _ = tokio::try_join!(
        tokio::io::copy(&mut a_r, &mut s_w),
        tokio::io::copy(&mut s_r, &mut a_w),
    );
    Ok(())
}

async fn reply(sock: &mut TcpStream, status: u8) {
    // Minimal SOCKS5 reply: VER STATUS RSV ATYP=v4 0.0.0.0 PORT=0.
    let _ = sock.write_all(&[0x05, status, 0x00, 0x01, 0,0,0,0, 0,0]).await;
}
