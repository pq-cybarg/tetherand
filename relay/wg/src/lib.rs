//! Tetherand WireGuard wrapper built on Cloudflare's BoringTun (BSD-3).
//!
//! Public Rust API exposed via `WgTunnel`. On Android, a JNI shim
//! (`src/jni.rs`) bridges the same API to Kotlin.

use std::sync::Mutex;

use boringtun::noise::{Tunn, TunnResult};

pub mod peer;
pub mod kem;
pub use peer::{ParseError, WgPeerConfig};
pub use kem::{KemKeypair, CIPHERTEXT_BYTES, PUBLIC_KEY_BYTES, SHARED_SECRET_BYTES};

/// Generate a fresh X25519 keypair (32-byte private, 32-byte public).
/// Used by the Mullvad device-registration flow on the Kotlin side.
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    use rand::rngs::OsRng;
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

#[cfg(target_os = "android")]
mod jni;

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
    buf_size: usize,
}

impl WgTunnel {
    pub fn new(cfg: &WgPeerConfig) -> Result<Self, String> {
        let priv_key = boringtun::x25519::StaticSecret::from(cfg.private_key);
        let pub_key = boringtun::x25519::PublicKey::from(cfg.peer_public_key);
        // BoringTun 0.7 returns Tunn directly (infallible for valid 32-byte
        // keys; we already validated those in WgPeerConfig::parse).
        let tunn = Tunn::new(
            priv_key,
            pub_key,
            cfg.preshared_key,
            cfg.persistent_keepalive_secs,
            rand_index(),
            None,
        );
        Ok(Self {
            inner: Mutex::new(tunn),
            buf_size: 2048,
        })
    }

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

    pub fn decapsulate(&self, packet: &[u8]) -> Action {
        let mut tunn = self.inner.lock().expect("poisoned");
        let mut out = vec![0u8; self.buf_size];
        match tunn.decapsulate(None, packet, &mut out) {
            TunnResult::WriteToTunnelV4(bytes, _) => Action::WriteToTunV4(bytes.to_vec()),
            TunnResult::WriteToTunnelV6(bytes, _) => Action::WriteToTunV6(bytes.to_vec()),
            TunnResult::WriteToNetwork(bytes) => Action::SendToPeer(bytes.to_vec()),
            TunnResult::Done => Action::Done,
            TunnResult::Err(e) => Action::Error(format!("{e:?}")),
        }
    }

    pub fn update_timers(&self) -> Action {
        let mut tunn = self.inner.lock().expect("poisoned");
        let mut out = vec![0u8; self.buf_size];
        match tunn.update_timers(&mut out) {
            TunnResult::WriteToNetwork(bytes) => Action::SendToPeer(bytes.to_vec()),
            TunnResult::Done => Action::Done,
            TunnResult::Err(e) => Action::Error(format!("{e:?}")),
            _ => Action::Done,
        }
    }
}

fn rand_index() -> u32 {
    rand::random::<u32>()
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

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

    /// Drive a complete handshake between two BoringTun instances —
    /// proof our wrapper reaches "established" state.
    #[test]
    fn handshake_completes_between_two_tunnels() {
        let (a_priv, a_pub) = fresh_keys();
        let (b_priv, b_pub) = fresh_keys();

        let a = WgTunnel::new(&cfg(a_priv, b_pub)).unwrap();
        let b = WgTunnel::new(&cfg(b_priv, a_pub)).unwrap();

        // A starts handshake by encapsulating an empty payload.
        let dummy: [u8; 0] = [];
        let mut pkt = match a.encapsulate(&dummy) {
            Action::SendToPeer(p) => p,
            other => panic!("expected handshake-init: {other:?}"),
        };

        // Up to 8 rounds for IKpsk2 handshake completion.
        for round in 0..8 {
            match b.decapsulate(&pkt) {
                Action::SendToPeer(p) => pkt = p,
                Action::WriteToTunV4(_) | Action::WriteToTunV6(_) | Action::Done => return,
                Action::Error(e) => panic!("B decap error round={round}: {e}"),
            }
            match a.decapsulate(&pkt) {
                Action::SendToPeer(p) => pkt = p,
                Action::WriteToTunV4(_) | Action::WriteToTunV6(_) | Action::Done => return,
                Action::Error(e) => panic!("A decap error round={round}: {e}"),
            }
        }
    }
}
