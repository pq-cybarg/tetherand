// webtunnel client per gitlab.torproject.org/.../webtunnel.
//
// Wire protocol:
//   - TLS to the bridge with SNI matching the configured URL host
//   - HTTP/1.1 Upgrade request to the configured path with
//     `Upgrade: websocket` and the standard Sec-WebSocket-Key/Version
//   - Once upgraded, binary WS frames carry Tor cells unaltered
//
// Bridge args (from SOCKS5 user/pass per pt-spec):
//   url=  the full https:// URL ending in the upgrade path
//   ver=  protocol version string

use crate::socks5::Target;
use futures::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async_with_config, tungstenite::handshake::client::Request};
use url::Url;

pub async fn dial(target: Target, args: HashMap<String, String>, mut arti_sock: TcpStream) -> Result<(), String> {
    let url_str = args.get("url").cloned()
        .unwrap_or_else(|| format!("wss://{}/", target.host));
    let url = Url::parse(&url_str).map_err(|e| format!("url: {e}"))?;
    let host = url.host_str().ok_or("no host")?.to_string();
    let port = url.port_or_known_default().ok_or("no port")?;
    let ver = args.get("ver").cloned().unwrap_or_else(|| "1".to_string());

    // TLS connect.
    let tls_config = build_tls_config();
    let connector = TlsConnector::from(tls_config);
    let dns_name = ServerName::try_from(host.clone()).map_err(|e| format!("dns: {e}"))?;
    let tcp = TcpStream::connect((host.as_str(), port)).await
        .map_err(|e| format!("tcp: {e}"))?;
    let tls = connector.connect(dns_name, tcp).await
        .map_err(|e| format!("tls: {e}"))?;

    // WS upgrade.
    let req = Request::builder()
        .uri(url.as_str())
        .header("Host", host.as_str())
        .header("X-Tor-Webtunnel-Version", ver)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key())
        .body(()).map_err(|e| format!("req: {e}"))?;
    let (ws, _resp) = client_async_with_config(req, tls, None).await
        .map_err(|e| format!("ws: {e}"))?;

    // Bidirectional byte shovel between the upstream SOCKS5 socket
    // (arti) and the WebSocket frame stream (bridge). The webtunnel
    // wire format puts opaque bytes inside binary WS frames, so each
    // direction reads chunks and emits / consumes binary Message
    // frames.  Coalesce small reads to keep frame overhead low; cap
    // the chunk at 16 KiB so each Tor cell (max 514 bytes today; a
    // proposed v3 cell is at most 4 KiB) plus a handful of headers
    // fits in one frame without fragmentation.
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut arti_r, mut arti_w) = arti_sock.split();

    let up = async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match arti_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if ws_tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.send(Message::Close(None)).await;
    };
    let down = async move {
        while let Some(msg) = ws_rx.next().await {
            let msg = match msg { Ok(m) => m, Err(_) => break };
            match msg {
                Message::Binary(bytes) => {
                    if arti_w.write_all(&bytes).await.is_err() { break; }
                }
                Message::Close(_) => break,
                // Ping / Pong / Text are not part of the webtunnel wire
                // format; tokio-tungstenite handles control frames
                // automatically. Text and unexpected frames we drop.
                _ => {}
            }
        }
    };
    tokio::join!(up, down);
    Ok(())
}

fn build_tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    #[test] fn ws_key_is_24_chars_b64() {
        let k = tokio_tungstenite::tungstenite::handshake::client::generate_key();
        assert_eq!(k.len(), 24);
    }
}
