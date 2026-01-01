# Tetherand M6.x — PT Bridges + Per-Flow Forwarder + Live Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every gap left open by M6 — ship all 5 pluggable-transport client paths (obfs4, meek, webtunnel via pure-Rust impl; snowflake + conjure via cross-compile scripts pulling the upstream Go clients), the per-flow IP→arti DataStream forwarder reusing relay-core's TCP stack, and a live-Tor bootstrap integration test surface.

**Architecture:** A new `relay/pt-bridge/` Rust binary implements obfs4, meek, and webtunnel inline and speaks the Tor PT spec (pt-spec.txt) on stdin/stdout. arti's `TransportConfigBuilder.path(...)` points at this binary; arti spawns it as a subprocess and dispatches per-bridge `protocols` to the in-process handler. Snowflake and Conjure are pulled as upstream Go clients (`pion/snowflake/client/cmd/snowflake-client` and `refraction-networking/conjure/cmd/client`) and cross-compiled to arm64-android via `scripts/build-pts-android.sh` (Go's native cross-compile). All five binaries land in `android/app/src/main/jniLibs/arm64-v8a/` and are extracted to app's nativeLibraryDir at runtime so arti can exec them. The per-flow forwarder lifts `relay/core/src/tunnel/tcp.rs`'s TCP-flow tracker, replaces the host-side TCP socket with an `arti_client::DataStream`, and ships UDP packets to /dev/null with a flow-counter that surfaces in HopStats. Live test runs `cargo test -p tetherand-tor --test live_probe -- --ignored` and resolves an .onion + a clearnet host through arti.

**Tech Stack:**
- Existing: arti-client 0.27 (Managed PT API), tor-ptmgr 0.27, relay-core M1 TCP stack.
- New crates: `curve25519-dalek` 4, `hkdf` 0.12, `sha2` 0.10, `chacha20poly1305` 0.10, `hmac` 0.12 (obfs4 crypto).
- New crates: `tungstenite` 0.24, `tokio-tungstenite` 0.24, `rustls` 0.23, `hyper` 1 (meek/webtunnel HTTPS).
- Cross-compile: NDK r26+ for Rust target, Go 1.22+ for snowflake/conjure (script-fetched).

**License:** All new code GPLv3 (matches the converged-APK boundary).

**Hard constraint:** No telemetry. The PT bridge binary never connects to anything except the bridge addr handed to it by arti.

**Scope:** Ships everything M6 deferred. The only honestly-deferred items at the end of this plan are:
- Live tests against the real Tor network — requires the test runner to have working internet egress to Tor (CI-dependent; skip-on-failure is the standard pattern).
- arti's prop362 PQ-NTor cell-cipher selection at the arti-client surface — upstream-tracked; the `TorBuilder.prefer_pq_handshake` flag already lights up the moment arti exposes the knob.

---

## File Structure

```
relay/pt-bridge/                           # new Rust binary crate
├── Cargo.toml
└── src/
    ├── main.rs                            # PT spec stdin/stdout dispatcher
    ├── pt_protocol.rs                     # parses PT spec env + emits status lines
    ├── obfs4.rs                           # obfs4 client: ntor + chacha20-poly1305 + framing
    ├── meek.rs                            # meek client: HTTPS POST tunneling
    ├── webtunnel.rs                       # webtunnel client: HTTPS WS upgrade
    └── socks5.rs                          # SOCKS5 server that PT spec mandates
relay/Cargo.toml                            # +pt-bridge member
relay/tor/src/client.rs                     # accept managed transports config + wire path
android/app/src/main/kotlin/dev/tetherand/app/chain/TorFlowForwarder.kt
                                            # per-flow IP→arti DataStream forwarder
android/app/src/main/kotlin/dev/tetherand/app/chain/TorHop.kt
                                            # +forwarder hook + per-bridge PT dispatch
android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt
                                            # +PT picker dropdown next to bridges textarea
scripts/build-pts-android.sh                # cross-compile snowflake-client + conjure
scripts/build-pt-bridge-android.sh          # cross-compile tetherand-pt for arm64-android
relay/tor/tests/live_probe.rs               # ignored-by-default integration test
```

---

### Task 1: `relay/pt-bridge/` crate skeleton + PT spec dispatcher

**Files:**
- Create: `relay/pt-bridge/Cargo.toml`
- Create: `relay/pt-bridge/src/main.rs`
- Create: `relay/pt-bridge/src/pt_protocol.rs`
- Create: `relay/pt-bridge/src/socks5.rs`
- Modify: `relay/Cargo.toml`

Implements the Tor PT spec (pt-spec.txt) communication: read `TOR_PT_CLIENT_TRANSPORTS` env, emit `VERSION`, `CMETHOD <name> socks5 <addr>`, `CMETHODS DONE`. Open a SOCKS5 server on a random port per protocol, and dispatch each accepted connection to the matching handler (obfs4/meek/webtunnel).

[Step-by-step instructions ... — same TDD pattern as M6's plan.]

---

### Task 2: obfs4 client (pure Rust)

**Files:**
- Create: `relay/pt-bridge/src/obfs4.rs`

Implements the obfs4 protocol per [obfs4-spec.txt](https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt):
- Elligator2 representative encoding of curve25519 public keys
- ntor handshake variant (KEM cert = node fingerprint + node id + ntor public)
- HMAC-SHA256 mark
- ChaCha20-Poly1305 AEAD framing with length-prefixed cells
- iat-mode 0/1/2 (timing obfuscation)

Tests:
- Elligator2 roundtrip
- Handshake message construction matches the spec test vector

---

### Task 3: meek client (HTTPS POST tunneling)

**Files:**
- Create: `relay/pt-bridge/src/meek.rs`

Implements meek per [meek README](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/meek):
- HTTPS POST with `Host: <fronted-domain>`, `X-Session-Id: <random>`
- The body of each POST carries upstream-direction Tor cells; the response body carries downstream cells
- Long-poll (responses kept open up to 4 s)
- TLS verification against the SNI domain (rustls + webpki-roots)

Tests:
- HTTP framing round-trip
- Session-ID generation is random + 32 chars

---

### Task 4: webtunnel client (HTTPS WS upgrade)

**Files:**
- Create: `relay/pt-bridge/src/webtunnel.rs`

Implements webtunnel per [tor-spec/webtunnel-spec.md](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel):
- TLS to the bridge with SNI matching the configured URL
- HTTP/1.1 Upgrade request to the configured path
- Binary WebSocket frames carry Tor cells unaltered

Tests:
- WS handshake header generation
- Frame serialization round-trip

---

### Task 5: Wire managed-PT into TorBuilder

**Files:**
- Modify: `relay/tor/src/client.rs`

When `TorBuilder.bridges` contains any PT-prefixed bridge, add a `TransportConfig` pointing arti at the expected `tetherand-pt` binary path (passed in from Kotlin via `pt_binary_path` field on TorBuilder). For snowflake/conjure, add separate `TransportConfig`s pointing at `snowflake-client` / `conjure-client` paths.

---

### Task 6: `TorFlowForwarder.kt` + `TorHop` wiring

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/chain/TorFlowForwarder.kt`
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/chain/TorHop.kt`

`TorFlowForwarder`:
- Reads IPv4 packets from the input `Channel<ByteArray>`
- For each new (src_ip, dst_ip, dst_port, protocol) tuple:
  - If TCP: open an arti DataStream via JNI `nativeDial`, store the stream id, forward bytes
  - If UDP: drop, increment `udpDroppedCount` stat
- Implements a tiny TCP state machine (SYN→synAck→established→fin) to track flow lifetime
- Emits IP packets back to a return channel for the chain
- Reuses the existing M1 relay-core packet framing (10.0.0.2 = TUN, 10.0.0.1 = exit)

`TorHop.start()` now constructs the forwarder, hooks it into the input channel, returns the output channel (no longer pass-through).

---

### Task 7: PT picker UI + binary-presence indicator

**Files:**
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt`

Add a row of PT chips next to the bridges text-area: `[ Vanilla | obfs4 | snowflake | meek | webtunnel | conjure ]`. Each chip reports whether the corresponding binary is present in `nativeLibraryDir` (green = present, amber = not built). The chip selection scopes which bridges are parsed.

---

### Task 8: Cross-compile scripts

**Files:**
- Create: `scripts/build-pt-bridge-android.sh`
- Create: `scripts/build-pts-android.sh`

`build-pt-bridge-android.sh`:
- Mirrors `build-tor-android.sh`
- Builds `tetherand-pt` as `aarch64-linux-android` target
- Strips + installs to `android/app/src/main/jniLibs/arm64-v8a/libtetherand_pt.so` (named with `lib` prefix + `.so` extension so the APK packager keeps it; we rename at extraction time)

`build-pts-android.sh`:
- Requires `GOROOT` + `NDK_HOME`
- Clones snowflake + conjure from gitlab
- `GOOS=android GOARCH=arm64 CC=$NDK/.../aarch64-linux-android26-clang go build`
- Installs `libsnowflake_client.so` + `libconjure_client.so` to jniLibs/arm64-v8a/
- Documents the runtime extraction step (Android extracts these as executables when present)

---

### Task 9: PT binary extraction at runtime

**Files:**
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/chain/TorHop.kt`

At hop start, copy the bundled PT binaries from `nativeLibraryDir` to `cacheDir/pts/` (so they're executable — Android packs them as `.so` but they're actually Linux binaries) and chmod +x. The path passed to arti's `TransportConfig.path` points at `cacheDir/pts/tetherand-pt` etc.

---

### Task 10: Live-probe integration test

**Files:**
- Create: `relay/tor/tests/live_probe.rs`

```rust
#[tokio::test]
#[ignore = "requires internet egress to the Tor network"]
async fn probe_torproject_org() {
    use tetherand_tor::client::TorBuilder;
    let cache = std::env::temp_dir().join("tetherand-tor-test-cache");
    let state = std::env::temp_dir().join("tetherand-tor-test-state");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let rt = TorBuilder::new(
        cache.to_string_lossy().to_string(),
        state.to_string_lossy().to_string(),
    ).build().expect("arti bootstrap");
    rt.dial("check.torproject.org", 443).expect("circuit");
}
```

Run with: `cd relay && cargo test -p tetherand-tor --test live_probe -- --ignored`. Skips by default to keep CI deterministic.

---

### Task 11: Final wrap

**Files:**
- Modify: `README.md`
- Modify: `tutorial.sh`

Flip M6 row from "SCAFFOLDED" to "SHIPPED". Inline the new content surface (obfs4 + meek + webtunnel inline, snowflake + conjure via Go upstream, per-flow forwarder, live probe).

---

## Self-Review Checklist

- [ ] `cd relay && cargo build -p tetherand-pt` → clean.
- [ ] `cd relay && cargo build -p tetherand-tor` → clean.
- [ ] `cd relay && cargo test -p tetherand-pt --lib` → all units green (obfs4 elligator2, meek framing, webtunnel handshake).
- [ ] `cd relay && cargo test -p tetherand-tor --lib` → 3 bridge tests still green.
- [ ] `cd android && ./gradlew :app:assembleDebug` → BUILD SUCCESSFUL.
- [ ] Privacy tab Tor card surfaces the PT chip row and reports binary-presence.
- [ ] No code path opens a network connection that bypasses arti.

Items intentionally **deferred** (NONE per user directive — all in-scope):
- ~~PT bridges (obfs4/snowflake/meek/webtunnel/conjure)~~ → shipped here
- ~~Per-flow IP→arti DataStream forwarder~~ → shipped here
- ~~Live bootstrap testing~~ → shipped here (skip-on-failure pattern)
- arti's prop362 PQ-NTor cell-cipher selection at the arti-client surface — genuinely upstream-tracked; the `prefer_pq_handshake` toggle already exists at our config layer and will light up the moment arti releases the knob.
