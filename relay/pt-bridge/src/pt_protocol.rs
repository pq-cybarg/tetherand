// Tor PT-spec client-side I/O.
//
// References:
//   https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt
//
// Required env on entry:
//   TOR_PT_CLIENT_TRANSPORTS=obfs4,meek,webtunnel   (comma list)
//   TOR_PT_STATE_LOCATION=/path/for/state           (per-PT state dir)
//   TOR_PT_MANAGED_TRANSPORT_VER=1                  (version we negotiate)
//   TOR_PT_EXIT_ON_STDIN_CLOSE=1                    (clean shutdown)
//
// Required output on stdout, one line each:
//   VERSION 1
//   CMETHOD <name> socks5 127.0.0.1:<port>
//   CMETHOD ...
//   CMETHODS DONE
// Optionally:
//   ENV-ERROR <reason>
//   CMETHOD-ERROR <name> <reason>
//   LOG SEVERITY=warning MESSAGE="..."

use crate::{meek, obfs4, socks5, webtunnel};
use std::io::Write;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpListener;

#[derive(Debug, Error)]
pub enum PtError {
    #[error("env error: {0}")] Env(String),
    #[error("listener error: {0}")] Listener(String),
    #[error("unknown transport: {0}")] UnknownTransport(String),
}

pub async fn run() -> Result<(), PtError> {
    let ver = std::env::var("TOR_PT_MANAGED_TRANSPORT_VER").unwrap_or_default();
    if !ver.split(',').any(|v| v.trim() == "1") {
        println!("VERSION-ERROR no-version");
        return Err(PtError::Env("no compatible PT version".into()));
    }
    println!("VERSION 1");

    let transports = std::env::var("TOR_PT_CLIENT_TRANSPORTS")
        .unwrap_or_else(|_| "obfs4,meek,webtunnel".into());

    for t in transports.split(',') {
        let t = t.trim();
        if t.is_empty() { continue; }
        match listen_socks5(t).await {
            Ok(addr) => println!("CMETHOD {t} socks5 {addr}"),
            Err(e) => println!("CMETHOD-ERROR {t} {e}"),
        }
    }
    println!("CMETHODS DONE");
    std::io::stdout().flush().ok();

    // Sleep forever. Per the PT spec, arti will SIGTERM us at shutdown.
    // EXIT_ON_STDIN_CLOSE asks us to terminate when stdin closes — we
    // honor it by spawning a watcher.
    if std::env::var("TOR_PT_EXIT_ON_STDIN_CLOSE").as_deref() == Ok("1") {
        std::thread::spawn(|| {
            use std::io::Read;
            let mut buf = [0u8; 1024];
            let mut stdin = std::io::stdin();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => std::process::exit(0),
                    Ok(_) => {}
                }
            }
        });
    }
    std::future::pending::<()>().await;
    Ok(())
}

async fn listen_socks5(transport: &str) -> Result<SocketAddr, String> {
    let listener = TcpListener::bind("127.0.0.1:0").await
        .map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| format!("local_addr: {e}"))?;
    let transport = transport.to_string();
    tokio::spawn(async move { socks5_loop(listener, transport).await });
    Ok(addr)
}

async fn socks5_loop(listener: TcpListener, transport: String) {
    loop {
        let (sock, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => { emit_pt_log(&format!("accept {transport}: {e}")); continue; }
        };
        let transport = transport.clone();
        tokio::spawn(async move {
            let (target, args, conn) = match socks5::handshake(sock).await {
                Ok(x) => x,
                Err(e) => { emit_pt_log(&format!("socks {transport}: {e}")); return; }
            };
            let res = match transport.as_str() {
                "obfs4" => obfs4::dial(target, args, conn).await,
                "meek"  => meek::dial(target, args, conn).await,
                "webtunnel" => webtunnel::dial(target, args, conn).await,
                other => Err(format!("unknown transport: {other}")),
            };
            if let Err(e) = res { emit_pt_log(&format!("{transport} dial: {e}")); }
        });
    }
}

pub fn emit_pt_log(msg: &str) {
    // PT spec LOG lines (used for visibility in arti's log).
    let escaped = msg.replace('"', "'");
    println!("LOG SEVERITY=warning MESSAGE=\"{escaped}\"");
    std::io::stdout().flush().ok();
}
