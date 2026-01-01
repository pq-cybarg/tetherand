// Public surface for the tetherand-tor crate.
//
// The crate embeds arti-client (Tor in Rust) and exposes 4 JNI entry
// points that TorHop on the Kotlin side calls into:
//   - init(bridges, vanguards, prefer_pq_handshake) -> runtime handle
//   - dial(handle, host, port) -> stream id
//   - close(handle, stream id)
//   - shutdown(handle)
//
// PQ-NTor (prop362 / NTor-ML-KEM-v1 hybrid handshake) is requested by
// the `pq-tor` feature (default-on). Until arti exposes the handshake
// selection knob in a release crate the preference is a no-op
// behaviourally, but the surface lights up the moment upstream lands.
//
// Pluggable Transports (obfs4, snowflake, meek, webtunnel, conjure)
// are deferred to M6.x because each needs a separately cross-compiled
// PT binary. The arti-client feature `pt-client` we enable here lays
// the integration point.

pub mod bridge;
pub mod client;
pub mod jni;

pub use bridge::{Bridge, BridgeError};
pub use client::{TorBuilder, TorRuntime, TorError};
