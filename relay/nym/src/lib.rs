// Public surface for the tetherand-nym crate.
//
// Embeds the Nym mixnet client (nym-sdk 1.4). Exposes 4 JNI entry
// points that NymHop on the Kotlin side calls into:
//   - init(state_dir, mnemonic, entry_gateway, exit_gateway) -> handle
//   - dial(handle, host, port) -> stream id (proves circuit assembly)
//   - close(handle, stream_id)
//   - shutdown(handle)
//
// The Nym mixnet is Sphinx-format: each packet is wrapped in 3 layers
// of encryption corresponding to 3 mixnodes between the entry gateway
// and the exit gateway. This breaks the address-association that VPN-
// only hops (M3 WireGuard, M4 Mullvad, M6 Tor) can't.

pub mod client;
pub mod jni;

pub use client::{NymBuilder, NymRuntime, NymError};
