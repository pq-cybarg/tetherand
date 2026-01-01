// Integration test: bootstrap arti against the real Tor network and
// open a circuit to check.torproject.org:443.
//
// Skipped by default — run explicitly with
//   cd relay && cargo test -p tetherand-tor --test live_probe -- --ignored
//
// CI: keep this --ignored. We don't want every commit pinging the
// Tor network from build runners.

use tetherand_tor::client::TorBuilder;

#[test]
#[ignore = "requires internet egress to the Tor network"]
fn probe_torproject_org() {
    let cache = std::env::temp_dir().join("tetherand-tor-test-cache");
    let state = std::env::temp_dir().join("tetherand-tor-test-state");
    let _ = std::fs::create_dir_all(&cache);
    let _ = std::fs::create_dir_all(&state);
    let rt = TorBuilder::new(
        cache.to_string_lossy().to_string(),
        state.to_string_lossy().to_string(),
    ).build().expect("arti bootstrap");
    rt.dial("check.torproject.org", 443).expect("circuit established + stream");
}

#[test]
#[ignore = "requires internet egress to the Tor network"]
fn probe_onion_service() {
    // duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion (DDG)
    let cache = std::env::temp_dir().join("tetherand-tor-test-cache-onion");
    let state = std::env::temp_dir().join("tetherand-tor-test-state-onion");
    let _ = std::fs::create_dir_all(&cache);
    let _ = std::fs::create_dir_all(&state);
    let rt = TorBuilder::new(
        cache.to_string_lossy().to_string(),
        state.to_string_lossy().to_string(),
    ).build().expect("arti bootstrap");
    rt.dial(
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        443,
    ).expect("onion circuit");
}
