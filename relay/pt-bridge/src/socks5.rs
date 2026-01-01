// Minimal SOCKS5 server. We accept the upstream client (arti) talking
// SOCKS5 to us, parse the target + PT args (via SOCKS5 username/password
// auth field per pt-spec — that's how arti hands per-bridge args like
// cert= and iat-mode=), and return the parsed target + a ready-to-use
// TcpStream to the handler. The handler writes/reads bytes; on close
// we shutdown both halves.

use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Returns (target, args, ready-stream-back-to-arti).
pub async fn handshake(mut sock: TcpStream) -> Result<(Target, HashMap<String, String>, TcpStream), String> {
    // Greeting: VER NMETHODS METHODS...
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await.map_err(|e| format!("hdr: {e}"))?;
    if hdr[0] != 0x05 { return Err(format!("bad ver: {}", hdr[0])); }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await.map_err(|e| format!("methods: {e}"))?;

    // Prefer username/password so we get the args. Per pt-spec arti
    // always uses SOCKS5 user/pass to ship per-bridge PT args.
    let use_userpass = methods.contains(&0x02);
    let method = if use_userpass { 0x02 } else if methods.contains(&0x00) { 0x00 } else {
        sock.write_all(&[0x05, 0xFF]).await.ok();
        return Err("no acceptable auth".into());
    };
    sock.write_all(&[0x05, method]).await.map_err(|e| format!("ack auth: {e}"))?;

    let mut args = HashMap::new();
    if use_userpass {
        let mut h = [0u8; 2];
        sock.read_exact(&mut h).await.map_err(|e| format!("up ver: {e}"))?;
        let ulen = h[1] as usize;
        let mut user = vec![0u8; ulen];
        sock.read_exact(&mut user).await.map_err(|e| format!("user: {e}"))?;
        let mut pl = [0u8; 1];
        sock.read_exact(&mut pl).await.map_err(|e| format!("plen: {e}"))?;
        let mut pass = vec![0u8; pl[0] as usize];
        sock.read_exact(&mut pass).await.map_err(|e| format!("pass: {e}"))?;
        // Per pt-spec: user+pass concatenated form k=v pairs separated by ;.
        let joined = String::from_utf8_lossy(&[&user[..], &pass[..]].concat()).to_string();
        for entry in joined.split(';') {
            if let Some((k, v)) = entry.split_once('=') {
                args.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        sock.write_all(&[0x01, 0x00]).await.map_err(|e| format!("up ack: {e}"))?;
    }

    // Request: VER CMD RSV ATYP DST...
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await.map_err(|e| format!("req: {e}"))?;
    if req[0] != 0x05 || req[1] != 0x01 { return Err("bad req".into()); }
    let host = match req[3] {
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
            format!("[{}:{}:{}:{}:{}:{}:{}:{}]", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        }
        _ => return Err("bad atyp".into()),
    };
    let mut pb = [0u8; 2];
    sock.read_exact(&mut pb).await.map_err(|e| format!("port: {e}"))?;
    let port = u16::from_be_bytes(pb);

    // Reply: SUCCEEDED with a dummy bind addr. arti doesn't care.
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await.map_err(|e| format!("reply: {e}"))?;

    Ok((Target { host, port }, args, sock))
}
