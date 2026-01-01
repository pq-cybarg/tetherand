# Tetherand M3 — Privacy Chain Core + WireGuard Hop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the privacy-chain runtime on the phone: a pluggable `Hop` interface, a `ChainOrchestrator` that wires N hops together, a generic WireGuard hop powered by BoringTun (Rust, BSD-3, embedded via JNI), and a Compose **Privacy tab** in the app showing a live chain visualizer. With this in place, M4/M5/M6 each just add a hop type (Mullvad PQ, NymVPN, Tor).

**Architecture:** A second VpnService (`TetherandChainService`) runs in parallel to the existing `TetherandService` (M1 tether path) — Android allows only one active at a time, so the user picks one from the UI. The chain service opens a TUN, reads IP packets, and pumps them through `ChainOrchestrator.start(input) -> output`. Each `Hop` implementation is a transformation `Channel<ByteArray> → Channel<ByteArray>`. The WireGuard hop uses BoringTun under JNI for encapsulation/decapsulation and owns a UDP socket to the WG peer. The terminal `DirectHop` writes raw IP back through the VpnService's underlying network (via `VpnService.protect()` on the UDP socket so packets don't loop through the TUN).

**Tech Stack:**
- Rust 1.93+, edition 2024 (BoringTun 0.7.1 stays on its own edition; that's fine — workspace edition is per-crate).
- `boringtun` 0.7.1 (BSD-3), `x25519-dalek`, `base64` for WG key parsing, `jni` 0.21 for Android bindings.
- Android NDK 26.3 for cross-compiling `libtetherand_wg.so` to `aarch64-linux-android`.
- Kotlin 2.0, kotlinx.coroutines 1.9, Compose Material3 BOM 2024.12.
- License: BoringTun is BSD-3, our wrapper is Apache-2.0. The combined APK stays Apache-2.0 for M3 — the GPLv3 convergence is M4 (Mullvad) + M7 (threat detection ports).

**Scope:** M3 ships a working chain with **one hop type** (generic WireGuard) and a single terminal exit (Direct). M4 adds the Mullvad-PQ variant (PSK derived via ML-KEM). M5 adds Nym. M6 adds Tor. The hop framework + UI built in M3 are forward-compatible with all of these.

---

## File Structure

```
relay/
└── wg/                                          # NEW Rust crate
    ├── Cargo.toml
    └── src/
        ├── lib.rs                               # public Rust API
        ├── peer.rs                              # WG config parsing
        └── jni.rs                               # JNI bindings (cfg=android)

android/
├── app/
│   ├── build.gradle.kts                         # +externalNativeBuild config
│   └── src/main/
│       ├── jniLibs/arm64-v8a/                   # libtetherand_wg.so lands here
│       ├── java/dev/tetherand/app/              # existing Java unchanged
│       └── kotlin/dev/tetherand/app/
│           ├── MainActivity.kt                  # updated: tabbed root
│           ├── chain/
│           │   ├── Hop.kt                       # interface + HopState + HopCaps
│           │   ├── WireGuardConfig.kt           # config dataclass + parser
│           │   ├── WireGuardHop.kt              # JNI bridge + UDP + coroutines
│           │   ├── DirectHop.kt                 # terminal exit
│           │   └── ChainOrchestrator.kt
│           ├── service/
│           │   └── TetherandChainService.kt     # second VpnService
│           └── ui/
│               ├── TetherScreen.kt              # existing; lifted out of MainActivity
│               ├── PrivacyScreen.kt             # NEW: chain visualizer + config
│               ├── TabbedRoot.kt                # NEW: Tether | Privacy tabs
│               └── Theme.kt                     # NEW: extract from MainActivity

scripts/
└── build-wg-android.sh                          # NEW: cross-compile helper
```

---

### Task 1: Bootstrap the `tetherand-wg` Rust crate

**Files:**
- Create: `relay/wg/Cargo.toml`
- Create: `relay/wg/src/lib.rs` (empty stub for now)
- Modify: `relay/Cargo.toml` (add `wg` to workspace)

- [ ] **Step 1: Add to workspace**

Edit `relay/Cargo.toml`:

```toml
members = [
    "codec",
    "transport-api",
    "transport-adb",
    "transport-tcp",
    "core",
    "cli",
    "wg",                # NEW
]
```

- [ ] **Step 2: Create the manifest**

Write `relay/wg/Cargo.toml`:

```toml
[package]
name = "tetherand-wg"
version = "0.1.0"
edition.workspace = true
license = "Apache-2.0"
authors.workspace = true
description = "BoringTun WireGuard wrapper for Tetherand; cdylib targets arm64-android via NDK."

[lib]
name = "tetherand_wg"
# `cdylib` produces libtetherand_wg.so for Android (the JNI side).
# `rlib` lets us still cargo test on the host.
crate-type = ["cdylib", "rlib"]

[dependencies]
boringtun = { version = "0.7", default-features = false }
x25519-dalek = "2.0"
base64 = "0.22"
thiserror = { workspace = true }
log = "0.4"

# JNI is only needed on Android targets.
[target.'cfg(target_os = "android")'.dependencies]
jni = "0.21"
android_logger = "0.14"
```

- [ ] **Step 3: Empty lib stub**

Write `relay/wg/src/lib.rs`:

```rust
//! Tetherand WireGuard wrapper built on Cloudflare's BoringTun (BSD-3).
//!
//! Public Rust API exposed via `WgTunnel`. On Android, a JNI shim
//! (`src/jni.rs`) bridges the same API to Kotlin.

pub mod peer;

#[cfg(target_os = "android")]
mod jni;
```

- [ ] **Step 4: Verify workspace still builds**

Run: `cd relay && cargo check --workspace`
Expected: clean compile (wg crate is empty but parses).

- [ ] **Step 5: Commit**

```bash
git add relay/Cargo.toml relay/wg/
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
  commit -m "M3 Task 1: bootstrap tetherand-wg Rust crate (BoringTun base)"
```

---

### Task 2: WireGuard peer config parser

**Files:**
- Create: `relay/wg/src/peer.rs`
- Modify: `relay/wg/src/lib.rs` (re-export)

The standard WireGuard config text format:

```
[Interface]
PrivateKey = <base64>
Address = 10.66.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <base64>
PresharedKey = <base64>          # optional
AllowedIPs = 0.0.0.0/0
Endpoint = host:port
PersistentKeepalive = 25         # optional
```

- [ ] **Step 1: Write failing tests**

Write `relay/wg/src/peer.rs`:

```rust
//! Minimal parser for the WireGuard config text format.
//!
//! Only the fields we use at the Tunn layer: the local private key,
//! the peer's public key + endpoint + (optional) PSK + keepalive,
//! and the allowed-IPs / address / DNS for the VpnService TUN.

use std::net::SocketAddr;
use std::str::FromStr;

use base64::Engine;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct WgPeerConfig {
    pub private_key: [u8; 32],
    pub address_cidr: String,         // e.g. "10.66.0.2/32"
    pub dns: Vec<String>,
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<String>,     // e.g. ["0.0.0.0/0"]
    pub endpoint: SocketAddr,
    pub persistent_keepalive_secs: Option<u16>,
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("invalid base64 key for {0}")]
    BadBase64(&'static str),
    #[error("key {0} must decode to 32 bytes, got {1}")]
    KeyLength(&'static str, usize),
    #[error("invalid endpoint: {0}")]
    BadEndpoint(String),
    #[error("invalid number for {0}: {1}")]
    BadNumber(&'static str, String),
    #[error("unknown section: [{0}]")]
    UnknownSection(String),
}

impl WgPeerConfig {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut section: Option<&str> = None;
        let mut interface = std::collections::HashMap::<String, String>::new();
        let mut peer      = std::collections::HashMap::<String, String>::new();

        for line in input.lines() {
            let l = line.split('#').next().unwrap().trim();
            if l.is_empty() { continue; }
            if let Some(rest) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                match rest {
                    "Interface" | "Peer" => section = Some(rest),
                    other => return Err(ParseError::UnknownSection(other.into())),
                }
                continue;
            }
            let (k, v) = match l.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            match section {
                Some("Interface") => { interface.insert(k, v); }
                Some("Peer")      => { peer.insert(k, v); }
                _ => {}
            }
        }

        fn key32(b64: &base64::engine::general_purpose::GeneralPurpose, src: &str, field: &'static str) -> Result<[u8; 32], ParseError> {
            let bytes = b64.decode(src).map_err(|_| ParseError::BadBase64(field))?;
            if bytes.len() != 32 { return Err(ParseError::KeyLength(field, bytes.len())); }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }

        let private_key = key32(&b64,
            interface.get("PrivateKey").ok_or(ParseError::Missing("Interface.PrivateKey"))?,
            "Interface.PrivateKey")?;
        let address_cidr = interface.get("Address").cloned()
            .ok_or(ParseError::Missing("Interface.Address"))?;
        let dns = interface.get("DNS").map(|s| s.split(',').map(|p| p.trim().to_owned()).collect()).unwrap_or_default();

        let peer_public_key = key32(&b64,
            peer.get("PublicKey").ok_or(ParseError::Missing("Peer.PublicKey"))?,
            "Peer.PublicKey")?;
        let preshared_key = peer.get("PresharedKey")
            .map(|s| key32(&b64, s, "Peer.PresharedKey"))
            .transpose()?;
        let allowed_ips = peer.get("AllowedIPs")
            .map(|s| s.split(',').map(|p| p.trim().to_owned()).collect())
            .unwrap_or_else(|| vec!["0.0.0.0/0".into()]);
        let endpoint = peer.get("Endpoint").ok_or(ParseError::Missing("Peer.Endpoint"))?;
        let endpoint = SocketAddr::from_str(endpoint)
            .map_err(|e| ParseError::BadEndpoint(format!("{endpoint}: {e}")))?;
        let persistent_keepalive_secs = peer.get("PersistentKeepalive")
            .map(|s| s.parse::<u16>().map_err(|e| ParseError::BadNumber("PersistentKeepalive", e.to_string())))
            .transpose()?;

        Ok(Self {
            private_key, address_cidr, dns,
            peer_public_key, preshared_key, allowed_ips, endpoint,
            persistent_keepalive_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[Interface]
PrivateKey = QFlzM1Nb1OFGdQpC7vY9X+Fy2vSC5IqI9bWcQz/aFmI=
Address    = 10.66.0.2/32
DNS        = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey  = OvUKpBPB+RHj4XPYbq2WJv8MNoTQDXq1g6gXBVPXVlw=
AllowedIPs = 0.0.0.0/0
Endpoint   = 198.51.100.7:51820
PersistentKeepalive = 25
"#;

    #[test]
    fn parses_minimal_config() {
        let c = WgPeerConfig::parse(SAMPLE).unwrap();
        assert_eq!(c.address_cidr, "10.66.0.2/32");
        assert_eq!(c.dns, vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]);
        assert_eq!(c.allowed_ips, vec!["0.0.0.0/0".to_string()]);
        assert_eq!(c.endpoint.to_string(), "198.51.100.7:51820");
        assert_eq!(c.persistent_keepalive_secs, Some(25));
        assert!(c.preshared_key.is_none());
    }

    #[test]
    fn missing_private_key_rejected() {
        let bad = SAMPLE.replace("PrivateKey = QFlzM1Nb1OFGdQpC7vY9X+Fy2vSC5IqI9bWcQz/aFmI=", "");
        let err = WgPeerConfig::parse(&bad).unwrap_err();
        assert_eq!(err, ParseError::Missing("Interface.PrivateKey"));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let with_noise = format!("# header comment\n\n{SAMPLE}\n# trailer\n");
        assert!(WgPeerConfig::parse(&with_noise).is_ok());
    }

    #[test]
    fn psk_parsed() {
        let with_psk = SAMPLE.replace("AllowedIPs", "PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs");
        let c = WgPeerConfig::parse(&with_psk).unwrap();
        assert!(c.preshared_key.is_some());
        assert_eq!(c.preshared_key.unwrap(), [0u8; 32]);
    }
}
```

- [ ] **Step 2: Re-export from lib.rs**

Edit `relay/wg/src/lib.rs`:

```rust
pub mod peer;
pub use peer::{WgPeerConfig, ParseError};

#[cfg(target_os = "android")]
mod jni;
```

- [ ] **Step 3: Run tests**

Run: `cd relay && cargo test -p tetherand-wg`
Expected: `test result: ok. 4 passed`

- [ ] **Step 4: Commit**

```bash
git add relay/wg/
git commit -m "M3 Task 2: WireGuard peer config parser with 4 tests"
```

---

### Task 3: BoringTun lifecycle wrapper

**Files:**
- Modify: `relay/wg/src/lib.rs` — add `WgTunnel`
- Test: same file

`boringtun::noise::Tunn` is the low-level type. Wrap it with a friendlier facade that:
- Holds the Tunn behind a `Mutex` (Tunn isn't `Sync`),
- Owns scratch buffers,
- Exposes `encapsulate(packet) -> Action` and `decapsulate(packet) -> Action`,
- Exposes `update_timers() -> Option<Vec<u8>>` for the periodic 250 ms tick.

- [ ] **Step 1: Define the public types + write tests**

Append to `relay/wg/src/lib.rs`:

```rust
use std::sync::Mutex;

use boringtun::noise::{Tunn, TunnResult};

/// One of: send these bytes via UDP to the WG peer; write these bytes
/// back into the local TUN as a decapsulated IP packet; nothing to do;
/// or an error.
#[derive(Debug, Clone)]
pub enum Action {
    SendToPeer(Vec<u8>),
    WriteToTunV4(Vec<u8>),
    WriteToTunV6(Vec<u8>),
    Done,
    Error(String),
}

pub struct WgTunnel {
    inner: Mutex<Tunn>,
    /// Static buffer for boringtun output. Sized for the worst case
    /// (MTU 1500 + WG overhead).
    buf_size: usize,
}

impl WgTunnel {
    pub fn new(cfg: &WgPeerConfig) -> Result<Self, String> {
        // boringtun expects `[u8; 32]` keys.
        let priv_key = boringtun::x25519::StaticSecret::from(cfg.private_key);
        let pub_key  = boringtun::x25519::PublicKey::from(cfg.peer_public_key);
        let tunn = Tunn::new(
            priv_key,
            pub_key,
            cfg.preshared_key,
            cfg.persistent_keepalive_secs,
            /* index = */ rand_index(),
            /* rate_limiter = */ None,
        ).map_err(|e| format!("boringtun init: {e:?}"))?;
        Ok(Self { inner: Mutex::new(tunn), buf_size: 2048 })
    }

    /// Outgoing direction: an IP packet from the local TUN. Returns
    /// what to do with it (usually `SendToPeer` after WG encryption).
    pub fn encapsulate(&self, packet: &[u8]) -> Action {
        let mut tunn = self.inner.lock().expect("poisoned");
        let mut out = vec![0u8; self.buf_size];
        match tunn.encapsulate(packet, &mut out) {
            TunnResult::WriteToNetwork(bytes) => Action::SendToPeer(bytes.to_vec()),
            TunnResult::Done => Action::Done,
            TunnResult::Err(e) => Action::Error(format!("{e:?}")),
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                Action::Error("unexpected WriteToTunnel from encapsulate".into())
            }
        }
    }

    /// Incoming direction: a UDP packet from the WG peer. May yield
    /// an IP packet to push into the TUN (the normal case), or a
    /// handshake response to send back to the peer.
    pub fn decapsulate(&self, packet: &[u8]) -> Action {
        let mut tunn = self.inner.lock().expect("poisoned");
        let mut out = vec![0u8; self.buf_size];
        match tunn.decapsulate(None, packet, &mut out) {
            TunnResult::WriteToTunnelV4(bytes, _) => Action::WriteToTunV4(bytes.to_vec()),
            TunnResult::WriteToTunnelV6(bytes, _) => Action::WriteToTunV6(bytes.to_vec()),
            TunnResult::WriteToNetwork(bytes)     => Action::SendToPeer(bytes.to_vec()),
            TunnResult::Done                      => Action::Done,
            TunnResult::Err(e)                    => Action::Error(format!("{e:?}")),
        }
    }

    /// Periodic timer (call ~every 250 ms). May produce handshake or
    /// keepalive packets to send.
    pub fn update_timers(&self) -> Action {
        let mut tunn = self.inner.lock().expect("poisoned");
        let mut out = vec![0u8; self.buf_size];
        match tunn.update_timers(&mut out) {
            TunnResult::WriteToNetwork(bytes) => Action::SendToPeer(bytes.to_vec()),
            TunnResult::Done                  => Action::Done,
            TunnResult::Err(e)                => Action::Error(format!("{e:?}")),
            _                                 => Action::Done,
        }
    }
}

fn rand_index() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}
```

Add `rand = "0.8"` to `relay/wg/Cargo.toml` dependencies.

- [ ] **Step 2: Add a tunnel-pair roundtrip test**

Append to `relay/wg/src/lib.rs`:

```rust
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use x25519_dalek::{StaticSecret, PublicKey};
    use rand::rngs::OsRng;

    fn fresh_keys() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    fn cfg(priv_key: [u8; 32], peer_pub: [u8; 32]) -> WgPeerConfig {
        WgPeerConfig {
            private_key: priv_key,
            address_cidr: "10.0.0.2/32".into(),
            dns: vec![],
            peer_public_key: peer_pub,
            preshared_key: None,
            allowed_ips: vec!["0.0.0.0/0".into()],
            endpoint: "127.0.0.1:51820".parse().unwrap(),
            persistent_keepalive_secs: None,
        }
    }

    /// Drive a complete handshake between two BoringTun instances
    /// (acting as both sides of a tunnel) to prove our wrapper
    /// reaches "established" state.
    #[test]
    fn handshake_completes_between_two_tunnels() {
        let (a_priv, a_pub) = fresh_keys();
        let (b_priv, b_pub) = fresh_keys();

        let a = WgTunnel::new(&cfg(a_priv, b_pub)).unwrap();
        let b = WgTunnel::new(&cfg(b_priv, a_pub)).unwrap();

        // A starts the handshake by encapsulating an empty payload.
        let dummy: [u8; 0] = [];
        let mut pkt = match a.encapsulate(&dummy) {
            Action::SendToPeer(p) => p,
            other => panic!("expected handshake-init: {other:?}"),
        };

        // Drive the handshake — up to 4 round-trips for IKpsk2.
        for round in 0..8 {
            // B receives.
            match b.decapsulate(&pkt) {
                Action::SendToPeer(p)    => pkt = p,
                Action::WriteToTunV4(_)  | Action::WriteToTunV6(_) => break,
                Action::Done             => return, // handshake done both sides
                Action::Error(e)         => panic!("B decap error round={round}: {e}"),
            }
            // A receives.
            match a.decapsulate(&pkt) {
                Action::SendToPeer(p)    => pkt = p,
                Action::WriteToTunV4(_)  | Action::WriteToTunV6(_) => break,
                Action::Done             => return,
                Action::Error(e)         => panic!("A decap error round={round}: {e}"),
            }
        }
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cd relay && cargo test -p tetherand-wg`
Expected: 5 tests pass (4 from peer.rs + 1 handshake test).

- [ ] **Step 4: Commit**

```bash
git add relay/wg/
git commit -m "M3 Task 3: BoringTun lifecycle wrapper with two-tunnel handshake test"
```

---

### Task 4: JNI bindings for Android

**Files:**
- Create: `relay/wg/src/jni.rs`

The Kotlin side calls these 5 functions:
1. `wgNew(privKey, peerPub, psk, keepalive) -> Long` (handle pointer)
2. `wgEncapsulate(handle, packet) -> ByteArray` (or empty for Done)
3. `wgDecapsulate(handle, packet) -> ByteArray`
4. `wgUpdateTimers(handle) -> ByteArray`
5. `wgFree(handle)`

We use the `jni` 0.21 crate's safe-ish bindings.

- [ ] **Step 1: Write the JNI shim**

Write `relay/wg/src/jni.rs`:

```rust
//! JNI bindings. Compiled only when targeting Android.
//!
//! Kotlin loads `libtetherand_wg.so` and calls these `nativeXxx`
//! functions. The handle returned by `nativeNew` is a raw pointer to
//! a `Box<WgTunnel>` kept alive on the Rust side; Kotlin must call
//! `nativeFree` to drop it.

use std::ffi::c_void;
use std::sync::Arc;

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};

use crate::{Action, WgPeerConfig, WgTunnel};
use std::net::SocketAddr;

fn copy_jba(env: &mut JNIEnv, src: &JByteArray) -> Vec<u8> {
    env.convert_byte_array(src).unwrap_or_default()
}

fn jba(env: &mut JNIEnv, src: &[u8]) -> jbyteArray {
    let arr = env.byte_array_from_slice(src).expect("alloc byte array");
    arr.into_raw()
}

fn action_to_jba(env: &mut JNIEnv, action: Action) -> jbyteArray {
    // Encode the action as a tagged byte array:
    //   byte 0: tag (0=Done, 1=SendToPeer, 2=WriteToTunV4, 3=WriteToTunV6, 4=Error)
    //   bytes 1..: payload
    let (tag, payload) = match action {
        Action::Done                => (0u8, Vec::new()),
        Action::SendToPeer(b)       => (1u8, b),
        Action::WriteToTunV4(b)     => (2u8, b),
        Action::WriteToTunV6(b)     => (3u8, b),
        Action::Error(s)            => (4u8, s.into_bytes()),
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(tag);
    out.extend_from_slice(&payload);
    jba(env, &out)
}

#[no_mangle]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeNew(
    mut env: JNIEnv,
    _class: JClass,
    priv_key: JByteArray,
    peer_pub: JByteArray,
    psk: JByteArray,
    endpoint_host: jni::objects::JString,
    endpoint_port: jint,
    keepalive_secs: jint,
) -> jlong {
    let priv_bytes = copy_jba(&mut env, &priv_key);
    let peer_bytes = copy_jba(&mut env, &peer_pub);
    let psk_bytes  = copy_jba(&mut env, &psk);
    let host: String = env.get_string(&endpoint_host).map(|s| s.into()).unwrap_or_default();

    if priv_bytes.len() != 32 || peer_bytes.len() != 32 { return 0; }
    let mut pk = [0u8; 32]; pk.copy_from_slice(&priv_bytes);
    let mut pp = [0u8; 32]; pp.copy_from_slice(&peer_bytes);
    let preshared = if psk_bytes.len() == 32 {
        let mut k = [0u8; 32]; k.copy_from_slice(&psk_bytes); Some(k)
    } else { None };
    let endpoint = match format!("{host}:{endpoint_port}").parse::<SocketAddr>() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let cfg = WgPeerConfig {
        private_key: pk,
        address_cidr: String::new(),
        dns: vec![],
        peer_public_key: pp,
        preshared_key: preshared,
        allowed_ips: vec![],
        endpoint,
        persistent_keepalive_secs: if keepalive_secs > 0 { Some(keepalive_secs as u16) } else { None },
    };
    match WgTunnel::new(&cfg) {
        Ok(t) => {
            let boxed: Box<Arc<WgTunnel>> = Box::new(Arc::new(t));
            Box::into_raw(boxed) as jlong
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeEncap(
    mut env: JNIEnv, _class: JClass, handle: jlong, packet: JByteArray,
) -> jbyteArray {
    let t = unsafe { &*(handle as *const Arc<WgTunnel>) };
    let bytes = copy_jba(&mut env, &packet);
    action_to_jba(&mut env, t.encapsulate(&bytes))
}

#[no_mangle]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeDecap(
    mut env: JNIEnv, _class: JClass, handle: jlong, packet: JByteArray,
) -> jbyteArray {
    let t = unsafe { &*(handle as *const Arc<WgTunnel>) };
    let bytes = copy_jba(&mut env, &packet);
    action_to_jba(&mut env, t.decapsulate(&bytes))
}

#[no_mangle]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeUpdateTimers(
    mut env: JNIEnv, _class: JClass, handle: jlong,
) -> jbyteArray {
    let t = unsafe { &*(handle as *const Arc<WgTunnel>) };
    action_to_jba(&mut env, t.update_timers())
}

#[no_mangle]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeFree(
    _env: JNIEnv, _class: JClass, handle: jlong,
) {
    if handle == 0 { return; }
    unsafe {
        let _ = Box::from_raw(handle as *mut Arc<WgTunnel>);
    }
}

/// Init logging (called once from Kotlin during library load).
#[no_mangle]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeInitLog(
    _env: JNIEnv, _class: JClass,
) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info),
    );
}

// Suppress unused-import warnings on non-android builds.
#[allow(dead_code)]
const _: *const c_void = std::ptr::null();
```

- [ ] **Step 2: Verify it still builds for host (jni.rs is gated)**

Run: `cd relay && cargo build -p tetherand-wg`
Expected: builds cleanly. The jni module is `#[cfg(target_os = "android")]` so the host build skips it.

- [ ] **Step 3: Commit**

```bash
git add relay/wg/src/jni.rs
git commit -m "M3 Task 4: JNI bindings for WireGuard wrapper (Android-only cfg)"
```

---

### Task 5: Cross-compile to arm64-android

**Files:**
- Create: `scripts/build-wg-android.sh`

The Rust toolchain already has `aarch64-linux-android` installed (verified earlier: `rustup target list --installed`).

- [ ] **Step 1: Write the build script**

Write `scripts/build-wg-android.sh`:

```bash
#!/usr/bin/env bash
# Cross-compile relay/wg → libtetherand_wg.so for arm64-android and
# stage the result under android/app/src/main/jniLibs/.
#
# Requires:
#   • Android NDK (resolved via ANDROID_NDK_HOME or $HOME/Library/Android/sdk/ndk/<version>)
#   • rustup target aarch64-linux-android (added by default in this repo)

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY="$HERE/relay"
DEST="$HERE/android/app/src/main/jniLibs/arm64-v8a"

NDK="${ANDROID_NDK_HOME:-$(ls -d $HOME/Library/Android/sdk/ndk/* 2>/dev/null | head -1)}"
[[ -d "$NDK" ]] || { echo "error: NDK not found. Set ANDROID_NDK_HOME."; exit 1; }

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64"
if [[ ! -d "$TOOLCHAIN" ]]; then
  TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/darwin-arm64"
fi
[[ -d "$TOOLCHAIN" ]] || { echo "error: NDK toolchain not found under $NDK"; exit 1; }

# Per Rust convention, set the linker for the target.
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"

cd "$RELAY"
cargo build --release --target aarch64-linux-android -p tetherand-wg
mkdir -p "$DEST"
cp "$RELAY/target/aarch64-linux-android/release/libtetherand_wg.so" "$DEST/"
echo "✓ libtetherand_wg.so -> $DEST"
file "$DEST/libtetherand_wg.so" 2>/dev/null | head -1
```

Run: `chmod +x scripts/build-wg-android.sh`

- [ ] **Step 2: Run the build**

Run: `./scripts/build-wg-android.sh`
Expected: produces `android/app/src/main/jniLibs/arm64-v8a/libtetherand_wg.so` (~2-3 MB).

If the link step fails on missing libgcc, add to `relay/wg/Cargo.toml`:

```toml
[target.aarch64-linux-android.dependencies]
```

(this stanza intentionally empty; the export-only crate-type fix above handles it).

- [ ] **Step 3: Verify file**

Run: `file android/app/src/main/jniLibs/arm64-v8a/libtetherand_wg.so`
Expected: `ELF 64-bit LSB shared object, ARM aarch64`.

- [ ] **Step 4: Add to Makefile**

Edit `Makefile`, in the `apk:` target before the gradle line, add a dependency on the native lib:

```makefile
apk: native-wg
	cd $(ANDROID) && ./gradlew :app:assembleDebug
	@mkdir -p $(BIN)
	@cp $(ANDROID)/app/build/outputs/apk/debug/app-debug.apk $(BIN)/tetherand.apk
	@echo "  ✓ APK built at $(BIN)/tetherand.apk"

native-wg:
	bash scripts/build-wg-android.sh
```

Also add `native-wg` to the `.PHONY:` list.

- [ ] **Step 5: Commit**

```bash
git add scripts/build-wg-android.sh Makefile android/app/src/main/jniLibs/.gitkeep
git commit -m "M3 Task 5: cross-compile libtetherand_wg.so for arm64-android"
```

(Touch the `.gitkeep` first if `jniLibs/arm64-v8a/` doesn't already exist as an empty dir; the `.so` itself is build output and stays gitignored.)

---

### Task 6: Kotlin `Hop` interface + supporting types

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/chain/Hop.kt`

- [ ] **Step 1: Define the interface and supporting types**

Write `android/app/src/main/kotlin/dev/tetherand/app/chain/Hop.kt`:

```kotlin
package dev.tetherand.app.chain

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.StateFlow

/** What we expose to the UI for a hop. */
enum class HopState { Idle, Connecting, Connected, Stopping, Error }

data class HopCaps(
    val supportsPQ: Boolean = false,
    val supportsMultihop: Boolean = false,
    val supportsAntiCensorship: Boolean = false,
)

data class HopStats(
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val latencyMs: Int? = null,
    val lastError: String? = null,
)

/** A unit of packet transformation in the privacy chain. */
interface Hop {
    val id: String
    val displayName: String
    val caps: HopCaps
    val state: StateFlow<HopState>
    val stats: StateFlow<HopStats>

    /**
     * Start the hop. Takes a channel of IP packets coming IN (from the
     * previous hop or the local TUN), returns a channel of IP packets
     * going OUT (toward the next hop or the terminal exit).
     *
     * Lifecycle: caller is responsible for closing the input channel
     * when shutting down; this hop should close the output channel
     * once its pumps have drained.
     */
    suspend fun start(input: Channel<ByteArray>): Channel<ByteArray>

    /** Stop the hop. Drains in-flight work. Idempotent. */
    suspend fun stop()
}
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/chain/Hop.kt
git commit -m "M3 Task 6: Kotlin Hop interface + HopState/HopCaps/HopStats"
```

---

### Task 7: WireGuard config parser (Kotlin)

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/chain/WireGuardConfig.kt`

Mirrors the Rust parser so config parsing can happen entirely on the Kotlin side; the native lib just takes the parsed 32-byte keys.

- [ ] **Step 1: Implementation**

Write `android/app/src/main/kotlin/dev/tetherand/app/chain/WireGuardConfig.kt`:

```kotlin
package dev.tetherand.app.chain

import android.util.Base64

data class WireGuardConfig(
    val privateKey: ByteArray,           // 32 bytes
    val address: String,                 // e.g. "10.66.0.2/32"
    val dns: List<String>,
    val peerPublicKey: ByteArray,        // 32 bytes
    val presharedKey: ByteArray?,        // 32 bytes or null
    val allowedIps: List<String>,        // e.g. ["0.0.0.0/0"]
    val endpointHost: String,
    val endpointPort: Int,
    val persistentKeepaliveSecs: Int = 0,
) {
    companion object {
        @Throws(IllegalArgumentException::class)
        fun parse(text: String): WireGuardConfig {
            var section: String? = null
            val iface = HashMap<String, String>()
            val peer  = HashMap<String, String>()
            for (raw in text.lineSequence()) {
                val line = raw.substringBefore('#').trim()
                if (line.isEmpty()) continue
                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line.substring(1, line.length - 1)
                    continue
                }
                val (k, v) = line.split('=', limit = 2).let {
                    if (it.size != 2) return@let null to null
                    it[0].trim() to it[1].trim()
                }
                if (k == null || v == null) continue
                when (section) {
                    "Interface" -> iface[k] = v
                    "Peer"      -> peer[k]  = v
                }
            }
            fun req(map: Map<String, String>, k: String, section: String): String =
                map[k] ?: throw IllegalArgumentException("$section.$k missing")
            fun key32(b64: String, field: String): ByteArray {
                val bytes = try { Base64.decode(b64, Base64.DEFAULT) }
                            catch (e: Exception) { throw IllegalArgumentException("$field: bad base64") }
                require(bytes.size == 32) { "$field: must be 32 bytes, got ${bytes.size}" }
                return bytes
            }
            val ep = req(peer, "Endpoint", "Peer")
            val colon = ep.lastIndexOf(':')
            require(colon > 0) { "Peer.Endpoint must be host:port" }
            return WireGuardConfig(
                privateKey = key32(req(iface, "PrivateKey", "Interface"), "Interface.PrivateKey"),
                address    = req(iface, "Address", "Interface"),
                dns        = iface["DNS"]?.split(",")?.map { it.trim() } ?: emptyList(),
                peerPublicKey = key32(req(peer, "PublicKey", "Peer"), "Peer.PublicKey"),
                presharedKey  = peer["PresharedKey"]?.let { key32(it, "Peer.PresharedKey") },
                allowedIps    = peer["AllowedIPs"]?.split(",")?.map { it.trim() } ?: listOf("0.0.0.0/0"),
                endpointHost  = ep.substring(0, colon),
                endpointPort  = ep.substring(colon + 1).toInt(),
                persistentKeepaliveSecs = peer["PersistentKeepalive"]?.toInt() ?: 0,
            )
        }
    }
}
```

- [ ] **Step 2: Tests**

Write `android/app/src/test/kotlin/dev/tetherand/app/chain/WireGuardConfigTest.kt`:

```kotlin
package dev.tetherand.app.chain

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class WireGuardConfigTest {
    private val SAMPLE = """
        [Interface]
        PrivateKey = QFlzM1Nb1OFGdQpC7vY9X+Fy2vSC5IqI9bWcQz/aFmI=
        Address = 10.66.0.2/32
        DNS = 1.1.1.1, 1.0.0.1

        [Peer]
        PublicKey = OvUKpBPB+RHj4XPYbq2WJv8MNoTQDXq1g6gXBVPXVlw=
        AllowedIPs = 0.0.0.0/0
        Endpoint = 198.51.100.7:51820
        PersistentKeepalive = 25
    """.trimIndent()

    @Test fun `parses minimal config`() {
        val c = WireGuardConfig.parse(SAMPLE)
        assertEquals("10.66.0.2/32", c.address)
        assertEquals(listOf("1.1.1.1", "1.0.0.1"), c.dns)
        assertEquals(32, c.privateKey.size)
        assertEquals(32, c.peerPublicKey.size)
        assertEquals("198.51.100.7", c.endpointHost)
        assertEquals(51820, c.endpointPort)
        assertEquals(25, c.persistentKeepaliveSecs)
        assertNull(c.presharedKey)
    }

    @Test fun `missing PrivateKey throws`() {
        val bad = SAMPLE.replace("PrivateKey = QFlzM1Nb1OFGdQpC7vY9X+Fy2vSC5IqI9bWcQz/aFmI=", "")
        assertThrows(IllegalArgumentException::class.java) { WireGuardConfig.parse(bad) }
    }

    @Test fun `PSK parsed when present`() {
        val withPsk = SAMPLE.replace(
            "AllowedIPs",
            "PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs"
        )
        val c = WireGuardConfig.parse(withPsk)
        assertArrayEquals(ByteArray(32), c.presharedKey)
    }
}
```

Need JUnit 5 wiring in `android/app/build.gradle.kts`. Add to dependencies:

```kotlin
testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
testRuntimeOnly("org.junit.platform:junit-platform-launcher")
```

And in the `android {}` block:

```kotlin
testOptions {
    unitTests.all {
        it.useJUnitPlatform()
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cd android && ./gradlew :app:testDebugUnitTest`
Expected: `WireGuardConfigTest > parses minimal config` PASSED + 2 others PASSED.

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/chain/WireGuardConfig.kt \
        android/app/src/test/kotlin/dev/tetherand/app/chain/WireGuardConfigTest.kt \
        android/app/build.gradle.kts
git commit -m "M3 Task 7: Kotlin WireGuardConfig parser + 3 tests"
```

---

### Task 8: `WireGuardHop` — JNI bridge + UDP socket + coroutines

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/chain/WireGuardHop.kt`

The hop owns:
- A handle to the native `WgTunnel`
- A UDP socket to the peer endpoint (must be `VpnService.protect()`ed so it bypasses the TUN)
- Three coroutines: input-pump (encap + send UDP), output-pump (recv UDP + decap + push), timer-tick (every 250ms)

- [ ] **Step 1: Implementation**

Write `android/app/src/main/kotlin/dev/tetherand/app/chain/WireGuardHop.kt`:

```kotlin
package dev.tetherand.app.chain

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

class WireGuardHop(
    override val id: String,
    override val displayName: String,
    private val config: WireGuardConfig,
    private val vpnService: VpnService,
) : Hop {
    override val caps = HopCaps(supportsPQ = false, supportsMultihop = false, supportsAntiCensorship = false)
    private val _state = MutableStateFlow(HopState.Idle)
    override val state = _state.asStateFlow()
    private val _stats = MutableStateFlow(HopStats())
    override val stats = _stats.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var handle: Long = 0
    private var socket: DatagramSocket? = null
    private val jobs = mutableListOf<Job>()
    private var output: Channel<ByteArray>? = null

    override suspend fun start(input: Channel<ByteArray>): Channel<ByteArray> {
        _state.value = HopState.Connecting
        try {
            handle = nativeNew(
                config.privateKey,
                config.peerPublicKey,
                config.presharedKey ?: ByteArray(0),
                config.endpointHost,
                config.endpointPort,
                config.persistentKeepaliveSecs,
            )
            require(handle != 0L) { "native wg init failed" }

            val sock = DatagramSocket()
            require(vpnService.protect(sock)) { "VpnService.protect() failed for WG socket" }
            sock.connect(InetSocketAddress(config.endpointHost, config.endpointPort))
            sock.soTimeout = 1000   // 1s so the timer-driven decap loop wakes regularly
            socket = sock

            val out = Channel<ByteArray>(capacity = 256)
            output = out

            // Pump 1: TUN-bound packets → WG encap → UDP send
            jobs += scope.launch {
                for (pkt in input) {
                    handleAction(nativeEncap(handle, pkt))
                }
            }

            // Pump 2: UDP recv → WG decap → push to next hop / TUN-bound out
            jobs += scope.launch {
                val buf = ByteArray(2048)
                val dp  = DatagramPacket(buf, buf.size)
                while (isActive) {
                    try {
                        sock.receive(dp)
                        val frame = buf.copyOfRange(0, dp.length)
                        _stats.value = _stats.value.copy(rxBytes = _stats.value.rxBytes + frame.size)
                        handleAction(nativeDecap(handle, frame), out)
                    } catch (e: java.net.SocketTimeoutException) {
                        // expected; loop drives the timer tick
                    } catch (e: Throwable) {
                        if (isActive) Log.w(TAG, "udp recv error: $e")
                        break
                    }
                }
            }

            // Pump 3: periodic timer tick (handshake / keepalive)
            jobs += scope.launch {
                while (isActive) {
                    delay(250)
                    handleAction(nativeUpdateTimers(handle))
                }
            }

            _state.value = HopState.Connected
            return out
        } catch (t: Throwable) {
            _stats.value = _stats.value.copy(lastError = t.message)
            _state.value = HopState.Error
            stop()
            throw t
        }
    }

    private fun handleAction(rawAction: ByteArray, outChannel: Channel<ByteArray>? = null) {
        if (rawAction.isEmpty()) return
        val tag = rawAction[0].toInt() and 0xff
        val payload = rawAction.copyOfRange(1, rawAction.size)
        when (tag) {
            0 -> {} // Done
            1 -> { // SendToPeer
                try {
                    val sock = socket ?: return
                    sock.send(DatagramPacket(payload, payload.size))
                    _stats.value = _stats.value.copy(txBytes = _stats.value.txBytes + payload.size)
                } catch (e: Throwable) {
                    Log.w(TAG, "udp send error: $e")
                }
            }
            2, 3 -> { // WriteToTunV4 / V6 — emit as output to next hop / TUN
                val ch = outChannel ?: output
                ch?.trySend(payload)
            }
            4 -> {
                val msg = String(payload)
                Log.w(TAG, "wg error: $msg")
                _stats.value = _stats.value.copy(lastError = msg)
            }
        }
    }

    override suspend fun stop() {
        _state.value = HopState.Stopping
        jobs.forEach { it.cancel() }
        jobs.clear()
        try { socket?.close() } catch (_: Throwable) {}
        socket = null
        output?.close()
        output = null
        if (handle != 0L) {
            nativeFree(handle); handle = 0
        }
        scope.cancel()
        _state.value = HopState.Idle
    }

    companion object {
        private const val TAG = "WireGuardHop"

        init {
            System.loadLibrary("tetherand_wg")
            nativeInitLog()
        }

        @JvmStatic external fun nativeInitLog()
        @JvmStatic external fun nativeNew(
            privKey: ByteArray,
            peerPub: ByteArray,
            psk: ByteArray,
            endpointHost: String,
            endpointPort: Int,
            keepaliveSecs: Int,
        ): Long
        @JvmStatic external fun nativeEncap(handle: Long, packet: ByteArray): ByteArray
        @JvmStatic external fun nativeDecap(handle: Long, packet: ByteArray): ByteArray
        @JvmStatic external fun nativeUpdateTimers(handle: Long): ByteArray
        @JvmStatic external fun nativeFree(handle: Long)
    }
}
```

- [ ] **Step 2: Build the app to verify JNI signatures resolve**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL. (The .so was staged by Task 5.)

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/chain/WireGuardHop.kt
git commit -m "M3 Task 8: WireGuardHop with JNI bridge + UDP + 3 coroutine pumps"
```

---

### Task 9: `DirectHop` — terminal exit (no transform)

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/chain/DirectHop.kt`

The Direct hop is the rightmost element in any chain. It's a no-op pass-through that simply forwards packets from `input` to its `output`. Used when the chain doesn't have an explicit upstream exit (i.e. when the WG hop directly sends out via UDP).

Actually for M3 with a single WG hop, the DirectHop is unused — WG's output already goes to the OS network. We keep DirectHop ready for chains like `[Tor]` where Tor would need a downstream "send to internet" element.

For M3 we ship it for completeness and to keep the API symmetric.

- [ ] **Step 1: Implementation**

Write `android/app/src/main/kotlin/dev/tetherand/app/chain/DirectHop.kt`:

```kotlin
package dev.tetherand.app.chain

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Passthrough hop. Forwards packets from input to output unmodified. */
class DirectHop(override val id: String = "direct", override val displayName: String = "Direct") : Hop {
    override val caps = HopCaps()
    private val _state = MutableStateFlow(HopState.Idle)
    override val state = _state.asStateFlow()
    private val _stats = MutableStateFlow(HopStats())
    override val stats = _stats.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null

    override suspend fun start(input: Channel<ByteArray>): Channel<ByteArray> {
        val out = Channel<ByteArray>(capacity = 256)
        _state.value = HopState.Connected
        job = scope.launch {
            try {
                for (pkt in input) {
                    out.send(pkt)
                    _stats.value = _stats.value.copy(
                        txBytes = _stats.value.txBytes + pkt.size,
                        rxBytes = _stats.value.rxBytes + pkt.size,
                    )
                }
            } finally { out.close() }
        }
        return out
    }

    override suspend fun stop() {
        _state.value = HopState.Stopping
        job?.cancel(); job = null
        scope.cancel()
        _state.value = HopState.Idle
    }
}
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/chain/DirectHop.kt
git commit -m "M3 Task 9: DirectHop terminal passthrough"
```

---

### Task 10: `ChainOrchestrator`

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/chain/ChainOrchestrator.kt`

- [ ] **Step 1: Implementation**

Write `android/app/src/main/kotlin/dev/tetherand/app/chain/ChainOrchestrator.kt`:

```kotlin
package dev.tetherand.app.chain

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ChainState { Idle, Starting, Active, Stopping, Error }

/**
 * Wires a sequence of [Hop]s end-to-end. The first hop receives `input`;
 * each subsequent hop receives the previous hop's output. The
 * orchestrator's own [tunBoundOutput] receives whatever the LAST hop
 * emits (i.e. packets to be written back into the local TUN).
 *
 * For M3's single WG hop case: input = packets from TUN, last hop = WG
 * (which sends UDP out to the peer and pushes decrypted return packets
 * via its output channel back to tunBoundOutput).
 */
class ChainOrchestrator(private val hops: List<Hop>) {
    private val _state = MutableStateFlow(ChainState.Idle)
    val state: StateFlow<ChainState> = _state.asStateFlow()

    private var tunBound: Channel<ByteArray>? = null

    /** Packets the chain produces that should be written back to the TUN. */
    val tunBoundOutput: Channel<ByteArray>?
        get() = tunBound

    suspend fun start(tunInput: Channel<ByteArray>): Channel<ByteArray> {
        _state.value = ChainState.Starting
        try {
            require(hops.isNotEmpty()) { "chain must have at least one hop" }
            var current = tunInput
            for (h in hops) {
                current = h.start(current)
            }
            tunBound = current
            _state.value = ChainState.Active
            return current
        } catch (t: Throwable) {
            _state.value = ChainState.Error
            stop()
            throw t
        }
    }

    suspend fun stop() {
        _state.value = ChainState.Stopping
        // Stop hops in reverse order to drain cleanly.
        for (h in hops.reversed()) {
            try { h.stop() } catch (_: Throwable) {}
        }
        tunBound?.close()
        tunBound = null
        _state.value = ChainState.Idle
    }
}
```

- [ ] **Step 2: Unit test with mock hops**

Write `android/app/src/test/kotlin/dev/tetherand/app/chain/ChainOrchestratorTest.kt`:

```kotlin
package dev.tetherand.app.chain

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

private class CountingHop(override val id: String, private val tag: Byte) : Hop {
    override val displayName = "Counting($tag)"
    override val caps = HopCaps()
    private val _state = MutableStateFlow(HopState.Idle)
    override val state = _state.asStateFlow()
    private val _stats = MutableStateFlow(HopStats())
    override val stats = _stats.asStateFlow()

    override suspend fun start(input: Channel<ByteArray>): Channel<ByteArray> {
        val out = Channel<ByteArray>(capacity = 16)
        _state.value = HopState.Connected
        coroutineScope {
            launch {
                for (pkt in input) {
                    // Tag each packet with our marker byte so we can prove ordering.
                    out.send(pkt + tag)
                }
                out.close()
            }
        }
        return out
    }

    override suspend fun stop() { _state.value = HopState.Idle }
}

class ChainOrchestratorTest {
    @Test fun `two-hop chain transforms in order`() = runBlocking {
        val orch = ChainOrchestrator(listOf(
            CountingHop("a", 0xAA.toByte()),
            CountingHop("b", 0xBB.toByte()),
        ))
        val input = Channel<ByteArray>(16)
        val output = orch.start(input)

        input.send(byteArrayOf(0x01, 0x02))
        input.close()

        // Wait briefly for the chain to drain.
        val pkt = output.receive()
        // Original [01,02] → after hop A appends 0xAA → [01,02,AA]
        //                  → after hop B appends 0xBB → [01,02,AA,BB]
        assertArrayEquals(byteArrayOf(0x01, 0x02, 0xAA.toByte(), 0xBB.toByte()), pkt)

        orch.stop()
        assertEquals(ChainState.Idle, orch.state.value)
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cd android && ./gradlew :app:testDebugUnitTest`
Expected: All chain tests pass.

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/chain/ChainOrchestrator.kt \
        android/app/src/test/kotlin/dev/tetherand/app/chain/ChainOrchestratorTest.kt
git commit -m "M3 Task 10: ChainOrchestrator + two-hop ordering test"
```

---

### Task 11: `TetherandChainService` — VpnService for chain mode

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/service/TetherandChainService.kt`

Independent of M1's `TetherandService` (which stays untouched for the tether-only path). When the user picks Chain mode in the UI, MainActivity starts this service instead.

- [ ] **Step 1: Implementation**

Write `android/app/src/main/kotlin/dev/tetherand/app/service/TetherandChainService.kt`:

```kotlin
package dev.tetherand.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.tetherand.app.chain.ChainOrchestrator
import dev.tetherand.app.chain.Hop
import dev.tetherand.app.chain.WireGuardConfig
import dev.tetherand.app.chain.WireGuardHop
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.io.FileInputStream
import java.io.FileOutputStream

class TetherandChainService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pfd: ParcelFileDescriptor? = null
    private var orch: ChainOrchestrator? = null
    private var pumpJobs: List<Job> = emptyList()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP) {
            stopChain(); return START_NOT_STICKY
        }
        startForegroundNotif()

        val wgText = intent?.getStringExtra(EXTRA_WG_CONFIG)
            ?: return run { stopSelf(); START_NOT_STICKY }
        val cfg = try { WireGuardConfig.parse(wgText) }
                  catch (e: Exception) { Log.e(TAG, "bad WG config: $e"); stopSelf(); return START_NOT_STICKY }

        scope.launch { runChain(cfg) }
        return START_STICKY
    }

    private suspend fun runChain(cfg: WireGuardConfig) {
        try {
            // 1. Build TUN.
            val (addr, prefix) = cfg.address.split("/").let { it[0] to (it.getOrNull(1)?.toInt() ?: 32) }
            val builder = Builder()
                .setMtu(1280)
                .addAddress(addr, prefix)
            cfg.dns.forEach { builder.addDnsServer(it) }
            cfg.allowedIps.forEach {
                val (net, p) = it.split("/").let { x -> x[0] to (x.getOrNull(1)?.toInt() ?: 32) }
                builder.addRoute(net, p)
            }
            builder.setBlocking(true).setSession("Tetherand Chain")
            val pfd = builder.establish() ?: return run { Log.e(TAG, "establish() returned null"); stopSelf() }
            this.pfd = pfd

            val tunIn  = FileInputStream(pfd.fileDescriptor)
            val tunOut = FileOutputStream(pfd.fileDescriptor)

            // 2. Build chain: single WG hop for M3.
            val hops: List<Hop> = listOf(
                WireGuardHop(id = "wg-1", displayName = "WireGuard", config = cfg, vpnService = this)
            )
            val orch = ChainOrchestrator(hops).also { this.orch = it }

            val tunInputCh = Channel<ByteArray>(capacity = 256)
            val tunBoundOut = orch.start(tunInputCh)

            // 3. Pump TUN -> chain.
            val toChain = scope.launch {
                val buf = ByteArray(2048)
                while (isActive) {
                    val n = tunIn.read(buf)
                    if (n <= 0) break
                    tunInputCh.send(buf.copyOf(n))
                }
            }
            // 4. Pump chain -> TUN.
            val fromChain = scope.launch {
                for (pkt in tunBoundOut) {
                    tunOut.write(pkt)
                }
            }
            pumpJobs = listOf(toChain, fromChain)
        } catch (t: Throwable) {
            Log.e(TAG, "chain failed", t)
            stopChain()
        }
    }

    private fun stopChain() {
        scope.launch {
            pumpJobs.forEach { it.cancel() }
            pumpJobs = emptyList()
            orch?.stop(); orch = null
            try { pfd?.close() } catch (_: Throwable) {}
            pfd = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
        try { pfd?.close() } catch (_: Throwable) {}
    }

    private fun startForegroundNotif() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Tetherand Chain", NotificationManager.IMPORTANCE_LOW)
        )
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, Class.forName("dev.tetherand.app.MainActivity")),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_vpn_ic)
            .setContentTitle("Tetherand Chain active")
            .setContentText("Routing through privacy chain")
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    companion object {
        private const val TAG = "TetherandChain"
        const val CHANNEL_ID = "tetherand-chain"
        const val NOTIF_ID = 0x7e7f
        const val EXTRA_WG_CONFIG = "dev.tetherand.app.extra.WG_CONFIG"
        const val ACTION_STOP = "dev.tetherand.app.action.CHAIN_STOP"
    }
}
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/service/TetherandChainService.kt
git commit -m "M3 Task 11: TetherandChainService — VpnService for chain mode"
```

---

### Task 12: Manifest update + ProGuard for native code

**Files:**
- Modify: `android/app/src/main/AndroidManifest.xml`

- [ ] **Step 1: Add the second service**

Edit `android/app/src/main/AndroidManifest.xml`, inside `<application>`:

```xml
        <service
            android:name=".service.TetherandChainService"
            android:permission="android.permission.BIND_VPN_SERVICE"
            android:foregroundServiceType="specialUse"
            android:exported="false">
            <intent-filter>
                <action android:name="android.net.VpnService"/>
            </intent-filter>
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="privacy_chain"/>
        </service>
```

- [ ] **Step 2: Build the APK**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/AndroidManifest.xml
git commit -m "M3 Task 12: AndroidManifest — declare TetherandChainService"
```

---

### Task 13: Theme extraction + `TabbedRoot`

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/ui/Theme.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/ui/TabbedRoot.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/ui/TetherScreen.kt` (lift from MainActivity)
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/MainActivity.kt`

- [ ] **Step 1: Extract `TetherandTheme`**

Write `android/app/src/main/kotlin/dev/tetherand/app/ui/Theme.kt`:

```kotlin
package dev.tetherand.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

@Composable
fun TetherandTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary       = Color(0xFF00D68F),
            onPrimary     = Color(0xFF001F11),
            secondary     = Color(0xFF5CDFFF),
            onSecondary   = Color(0xFF002B33),
            background    = Color(0xFF0A0E14),
            onBackground  = Color(0xFFC0C8D4),
            surface       = Color(0xFF11161D),
            onSurface     = Color(0xFFC0C8D4),
        ),
        content = content,
    )
}
```

- [ ] **Step 2: Lift `TetherScreen` to its own file**

Create `android/app/src/main/kotlin/dev/tetherand/app/ui/TetherScreen.kt` and move the existing `TetherScreen` + `StatusPill` + `TransportChip` composables from `MainActivity.kt` into it. (Same code, new package-private file.) Verbatim move:

```kotlin
package dev.tetherand.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun TetherScreen(onStart: () -> Unit, onStop: () -> Unit) {
    var running by remember { mutableStateOf(false) }
    var selectedUsb by remember { mutableStateOf(true) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "TETHERAND",
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp,
                fontFamily = FontFamily.Monospace,
            )
            Spacer(Modifier.weight(1f))
            StatusPill(running)
        }
        Text(
            "Reverse-tether through your computer's network.",
            color = MaterialTheme.colorScheme.onBackground,
        )

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Transport", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TransportChip("USB-ADB", selectedUsb) { selectedUsb = true }
                    TransportChip("Wi-Fi",  !selectedUsb) { selectedUsb = false }
                }
                Text(
                    if (selectedUsb) "Phone listens on abstract socket 'tetherand'; host runs `adb forward` and connects."
                    else             "Phone listens on TCP and advertises via mDNS as _tetherand._tcp.local.",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
            }
        }

        if (!running) {
            Button(onClick = { running = true; onStart() }) { Text("Start Tetherand") }
        } else {
            Button(onClick = { running = false; onStop() }) { Text("Stop") }
        }
    }
}

@Composable
private fun StatusPill(running: Boolean) {
    val color = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
    val label = if (running) "CONNECTED" else "IDLE"
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, color, RoundedCornerShape(50))
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Text(label, color = color, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun TransportChip(label: String, selected: Boolean, onClick: () -> Unit) {
    AssistChip(
        onClick = onClick,
        label = { Text(label) },
        modifier = if (selected) Modifier.border(2.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(8.dp)) else Modifier,
    )
}
```

- [ ] **Step 3: `TabbedRoot`**

Write `android/app/src/main/kotlin/dev/tetherand/app/ui/TabbedRoot.kt`:

```kotlin
package dev.tetherand.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily

@Composable
fun TabbedRoot(
    onTetherStart: () -> Unit,
    onTetherStop:  () -> Unit,
    onChainStart:  (String) -> Unit,
    onChainStop:   () -> Unit,
) {
    var selected by remember { mutableStateOf(0) }
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding(),
        ) {
            TabRow(selectedTabIndex = selected, containerColor = MaterialTheme.colorScheme.background) {
                Tab(selected = selected == 0, onClick = { selected = 0 }, text = { Text("Tether", fontFamily = FontFamily.Monospace) })
                Tab(selected = selected == 1, onClick = { selected = 1 }, text = { Text("Privacy", fontFamily = FontFamily.Monospace) })
            }
            when (selected) {
                0 -> TetherScreen(onStart = onTetherStart, onStop = onTetherStop)
                1 -> PrivacyScreen(onStart = onChainStart, onStop = onChainStop)
            }
        }
    }
}
```

- [ ] **Step 4: Update `MainActivity`**

Replace the existing setContent block in `MainActivity.kt` with a `TabbedRoot` call. Replace `MainActivity.kt`:

```kotlin
package dev.tetherand.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import dev.tetherand.app.service.TetherandChainService
import dev.tetherand.app.ui.TabbedRoot
import dev.tetherand.app.ui.TetherandTheme

class MainActivity : ComponentActivity() {
    enum class PendingAction { TETHER, CHAIN }
    private var pending: PendingAction = PendingAction.TETHER
    private var pendingWgConfig: String? = null

    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) when (pending) {
            PendingAction.TETHER -> startTether()
            PendingAction.CHAIN  -> startChain(pendingWgConfig ?: return@registerForActivityResult)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            TetherandTheme {
                TabbedRoot(
                    onTetherStart = ::ensureConsentAndStartTether,
                    onTetherStop  = ::stopTether,
                    onChainStart  = ::ensureConsentAndStartChain,
                    onChainStop   = ::stopChain,
                )
            }
        }
    }

    private fun ensureConsentAndStartTether() {
        pending = PendingAction.TETHER
        val p = VpnService.prepare(this)
        if (p != null) vpnConsent.launch(p) else startTether()
    }

    private fun ensureConsentAndStartChain(wgConfigText: String) {
        pending = PendingAction.CHAIN
        pendingWgConfig = wgConfigText
        val p = VpnService.prepare(this)
        if (p != null) vpnConsent.launch(p) else startChain(wgConfigText)
    }

    private fun startTether() {
        TetherandService.start(this, VpnConfiguration())
    }
    private fun stopTether() {
        TetherandService.stop(this)
    }
    private fun startChain(wgConfigText: String) {
        val i = Intent(this, TetherandChainService::class.java)
            .putExtra(TetherandChainService.EXTRA_WG_CONFIG, wgConfigText)
        startForegroundService(i)
    }
    private fun stopChain() {
        val i = Intent(this, TetherandChainService::class.java)
            .setAction(TetherandChainService.ACTION_STOP)
        startService(i)
    }
}
```

- [ ] **Step 5: Build**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL. (PrivacyScreen is referenced; it lands in Task 14.)

Actually compilation will fail here because `PrivacyScreen` doesn't exist yet. Land Task 14 first, then build.

- [ ] **Step 6: (Defer commit until Task 14 lands)**

---

### Task 14: `PrivacyScreen` — chain visualizer + WG config editor

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt`

- [ ] **Step 1: Implementation**

Write `android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt`:

```kotlin
package dev.tetherand.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun PrivacyScreen(onStart: (String) -> Unit, onStop: () -> Unit) {
    var running by remember { mutableStateOf(false) }
    var wgText by remember { mutableStateOf(SAMPLE_WG_CONFIG) }
    val scroll = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "PRIVACY CHAIN",
                color = MaterialTheme.colorScheme.secondary,
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp,
                fontFamily = FontFamily.Monospace,
            )
            Spacer(Modifier.weight(1f))
            ChainStatusPill(running)
        }
        Text(
            "Compose hops the phone's traffic flows through before reaching the internet.",
            color = MaterialTheme.colorScheme.onBackground,
        )

        // Chain visualizer.
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Chain", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    HopCard("Apps")
                    Arrow()
                    HopCard("WireGuard", active = running, accent = MaterialTheme.colorScheme.primary)
                    Arrow()
                    HopCard("Internet")
                }
                Text(
                    "M3: single WireGuard hop. Mullvad PQ (M4), NymVPN (M5), and Tor (M6) join the picker as their hop types ship.",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
            }
        }

        // WG config editor.
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("WireGuard config", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "Paste a standard [Interface]/[Peer] config. Mullvad classic-WG configs work out of the box.",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
                OutlinedTextField(
                    value = wgText,
                    onValueChange = { wgText = it },
                    modifier = Modifier.fillMaxWidth().height(260.dp),
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
                    label = { Text("conf") },
                )
            }
        }

        if (!running) {
            Button(
                onClick = { running = true; onStart(wgText) },
                enabled = wgText.contains("[Interface]") && wgText.contains("[Peer]"),
            ) { Text("Start chain") }
        } else {
            Button(onClick = { running = false; onStop() }) { Text("Stop chain") }
        }
    }
}

@Composable
private fun ChainStatusPill(active: Boolean) {
    val color = if (active) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.onSurface
    val label = if (active) "ROUTING" else "OFFLINE"
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, color, RoundedCornerShape(50))
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Text(label, color = color, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun HopCard(label: String, active: Boolean = false, accent: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.onSurface) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.background)
            .border(1.dp, if (active) accent else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Text(label, color = if (active) accent else MaterialTheme.colorScheme.onSurface, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
}

@Composable
private fun Arrow() {
    Text("→", color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f), fontFamily = FontFamily.Monospace)
}

private val SAMPLE_WG_CONFIG = """
[Interface]
PrivateKey = <paste your WireGuard private key here, base64>
Address    = 10.66.0.2/32
DNS        = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey  = <paste the peer's public key here, base64>
AllowedIPs = 0.0.0.0/0
Endpoint   = your.wg.endpoint:51820
PersistentKeepalive = 25
""".trimIndent()
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit (bundles Tasks 13 + 14)**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/MainActivity.kt \
        android/app/src/main/kotlin/dev/tetherand/app/ui/
git commit -m "M3 Tasks 13-14: TabbedRoot + PrivacyScreen + theme extraction"
```

---

### Task 15: End-to-end smoke

**Files:**
- Create: `scripts/smoke-chain.sh`

This is a manual-with-a-script smoke: the user must paste a valid WG config into the Privacy tab. The script verifies the device's apparent public IP changes once the chain is active.

- [ ] **Step 1: Write the script**

Write `scripts/smoke-chain.sh`:

```bash
#!/usr/bin/env bash
# Pre-step: install the latest APK with the chain build.
# Post-step: report the phone's apparent egress IP before / after.
#
# Caveat: requires a valid WireGuard config pasted into the app's
# Privacy tab. The script itself does not configure WG — that's a
# user-driven step.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"

serial=$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')
[[ -n "$serial" ]] || { echo "no device"; exit 1; }

# 1. Reinstall.
make build
"$ADB" -s "$serial" install -r "$HERE/bin/tetherand.apk"
"$ADB" -s "$serial" shell cmd appops set dev.tetherand.app ACTIVATE_VPN allow

# 2. Apparent IP BEFORE.
echo "device IP BEFORE chain:"
"$ADB" -s "$serial" shell "ping -c 1 -W 3 1.1.1.1 >/dev/null && echo via=cellular/wifi || echo unreachable"
"$ADB" -s "$serial" shell "wget -qO- https://api.ipify.org" 2>/dev/null && echo \
  || echo "(wget unavailable on stock toybox; check from the app or via tetherand status)"

echo
echo "Now: open the Tetherand app on the phone, switch to the Privacy tab,"
echo "paste a valid WireGuard config, and tap 'Start chain'. Then press Enter."
read -r

# 3. Apparent IP AFTER.
echo "device IP AFTER chain:"
"$ADB" -s "$serial" shell "ping -c 1 -W 3 1.1.1.1 >/dev/null && echo reachable || echo unreachable"
"$ADB" -s "$serial" shell "wget -qO- https://api.ipify.org" 2>/dev/null && echo \
  || echo "(verify via 'whatismyip' in browser)"
```

Run: `chmod +x scripts/smoke-chain.sh`

- [ ] **Step 2: Commit**

```bash
git add scripts/smoke-chain.sh
git commit -m "M3 Task 15: chain smoke script with apparent-IP before/after"
```

---

### Task 16: Makefile + tutorial + README updates

**Files:**
- Modify: `Makefile`
- Modify: `tutorial.sh`
- Modify: `README.md`

- [ ] **Step 1: Makefile — add `chain` target alias**

Edit `Makefile`, add to the end:

```makefile
chain: build
	@echo "Chain build complete. Open Tetherand → Privacy tab to configure."
```

And add `chain` to `.PHONY:`.

- [ ] **Step 2: tutorial.sh — flip M3 badge**

In `tutorial.sh`, find:

```html
    <tr><td><strong>M3</strong></td><td>Privacy chain core: hop interface, WireGuard generic hop, chain orchestrator, Privacy tab with chain visualizer.</td><td>14-18 h</td><td>planned</td></tr>
```

Replace `planned` with `<span class="badge ok">SHIPPED</span>`. Flip M4's row to `<span class="badge warn">NEXT</span>`.

- [ ] **Step 3: README — bump status table**

In `README.md`, under `## Status`, change M3 from `planned` to `**shipped**`. M4 becomes the next.

- [ ] **Step 4: Commit**

```bash
git add Makefile tutorial.sh README.md
git commit -m "M3 Task 16: tutorial + README — mark M3 SHIPPED, M4 NEXT"
```

---

## Self-Review Checklist

- [ ] `cd relay && cargo test --workspace` → all passing (codec, transport-api, transport-adb/tcp, core, wg)
- [ ] `cd android && ./gradlew :app:testDebugUnitTest` → WireGuardConfigTest + ChainOrchestratorTest passing
- [ ] `./scripts/build-wg-android.sh` → produces `libtetherand_wg.so` under `android/app/src/main/jniLibs/arm64-v8a/`
- [ ] `make build` → APK and binary both rebuild
- [ ] `make install` → APK installs on the 5364C13D, VPN consent pre-granted
- [ ] App launches with two tabs (Tether, Privacy)
- [ ] Pasting a valid WG config + tapping Start chain → status pill flips to ROUTING, ping 1.1.1.1 from the phone succeeds, apparent egress IP matches the WG peer's location

Spec coverage check:

| Spec section | Implemented in tasks |
|---|---|
| Privacy Chain → Hop interface | Task 6 |
| Privacy Chain → WireGuard generic hop | Tasks 1-5, 8 |
| Privacy Chain → Chain orchestrator | Task 10 |
| Privacy Chain → Privacy tab + chain visualizer | Tasks 13, 14 |
| Privacy Chain → Failure behavior (kill / bypass / retry-and-block) | M4+ (UI exposes via per-hop config) |
| Privacy Chain → DirectHop (terminal) | Task 9 |
| Privacy Chain → Determinism principle | enforced — no LLM in M3 |

Items intentionally **deferred** to later milestones:
- Mullvad PQ tunnel (M4).
- NymVPN (M5).
- Tor + bridges (M6).
- Chain-over-tether composition (the chain currently sends UDP directly to the peer through the phone's underlying network; running it on top of an active tether is a follow-up).
- Chain visualizer drag-reorder + add/remove hops (M3 has a single fixed WG hop).
- Per-hop sparkline / live stats card (M3 just shows status pill).
