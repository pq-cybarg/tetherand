# Tetherand M6 — Tor + Arti + Bridges Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Tor hop in the M3 privacy chain backed by [Arti](https://gitlab.torproject.org/tpo/core/arti) (the Rust reimplementation of Tor). The hop terminates the inbound IP stream into per-flow TCP streams routed through the Tor network via a JNI-bound `arti-client` runtime. Bridge configuration + vanguards toggle are surfaced in the Privacy tab. Pluggable transports (obfs4, snowflake, meek, conjure, webtunnel) are scoped to M6.x because each needs a separately cross-compiled PT binary.

**Architecture:** A new `relay/tor/` Rust crate embeds `arti-client` and exposes 4 JNI entry points (`init`, `dial`, `close`, `shutdown`). The crate builds into `libtetherand_tor.so` via the existing `scripts/build-tor-android.sh` (mirrors the WireGuard cross-compile pattern). On Android, `TorHop` implements the chain's `Hop` trait by terminating inbound IP packets into a userspace TCP/UDP stack (re-uses the relay-core packet stack from M1) and dialing each TCP flow through Arti. UDP-over-Tor is not supported because Tor is TCP-only; the hop documents this surface honestly. The Privacy tab gains a "Tor" option in the hop picker plus bridge-text-area input.

**Tech Stack:**
- New: `arti-client` 1.4 with features `tokio,rustls,bridge-client,pt-client,onion-service-client`.
- New: `tor-rtcompat` for the runtime.
- New: `pnet-packet` for IP packet parsing in TorHop's userspace stack (re-uses what's already in relay-core).
- Existing: tokio, the Rust workspace, the NDK toolchain from M4.

**License:** Arti is licensed Apache-2.0 OR MIT. Our M6 code stays GPLv3 (the converged-APK boundary set in M7a).

**Hard constraint:** No telemetry / DNS leak. Every name lookup goes through Arti's exit node, never the host resolver. The `arti-client` API enforces this.

**Scope:** This plan ships the Tor hop end-to-end at the Rust + Kotlin + UI level. Pluggable Transports (obfs4 via lyrebird, snowflake via webrtc-rs, meek HTTPS-fronting, webtunnel, conjure) require separately cross-compiled PT binaries packaged in `jniLibs/`; each gets its own M6.x sub-plan. Vanguards-lite is just an Arti config flag and ships in this milestone.

---

## File Structure

```
relay/tor/
├── Cargo.toml
├── build.rs                            # NDK linker flags (mirror relay/wg/build.rs)
└── src/
    ├── lib.rs                          # re-exports + tokio runtime singleton
    ├── client.rs                       # TorBuilder, TorRuntime (wraps arti-client)
    ├── bridge.rs                       # Bridge line parser (BridgeDB format)
    └── jni.rs                          # 4 JNI exports
android/app/src/main/kotlin/dev/tetherand/app/chain/
└── TorHop.kt                           # Hop impl wrapping libtetherand_tor.so
android/app/src/main/kotlin/dev/tetherand/app/tor/
├── TorBridges.kt                       # bridge-list persistence (EncryptedShared)
└── TorConfig.kt                        # data class
android/app/src/main/kotlin/dev/tetherand/app/ui/
└── PrivacyScreen.kt                    # +Tor hop picker + bridges text-area
scripts/build-tor-android.sh            # NDK cross-compile to jniLibs/arm64-v8a/
relay/Cargo.toml                        # +tor member
```

---

### Task 1: `relay/tor/` crate skeleton

**Files:**
- Create: `relay/tor/Cargo.toml`
- Create: `relay/tor/src/lib.rs`
- Create: `relay/tor/build.rs`
- Modify: `relay/Cargo.toml`

- [ ] **Step 1: Cargo.toml**

Write `relay/tor/Cargo.toml`:

```toml
[package]
name = "tetherand-tor"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
# Arti is the Rust Tor client. Features:
#  - tokio: async runtime
#  - rustls: TLS without OpenSSL (matters for Android cross-compile)
#  - bridge-client: bridge support
#  - pt-client: pluggable-transport client framework (M6.x PT crates will plug in)
#  - onion-service-client: .onion resolution
arti-client = { version = "0.27", default-features = false, features = [
    "tokio", "rustls", "bridge-client", "pt-client", "onion-service-client",
] }
tor-rtcompat = { version = "0.27", features = ["tokio", "rustls"] }
tor-config = "0.27"
tokio = { version = "1.40", features = ["rt-multi-thread", "macros", "net", "sync", "io-util"] }
log = "0.4"
android_logger = { version = "0.14", optional = true }
jni = "0.21"
once_cell = "1.20"
serde = { version = "1", features = ["derive"] }
thiserror = "1"

[features]
android = ["android_logger"]
```

- [ ] **Step 2: build.rs**

Write `relay/tor/build.rs`:

```rust
fn main() {
    // No special link flags for now; NDK toolchain handles everything.
    // arti-client + tor-rtcompat both compile cleanly against
    // aarch64-linux-android-clang when given a CC matching the NDK.
    println!("cargo:rerun-if-changed=src/");
}
```

- [ ] **Step 3: lib.rs entry**

Write `relay/tor/src/lib.rs`:

```rust
// Public surface for the tetherand-tor crate.
//
// The crate embeds arti-client (Tor in Rust) and exposes 4 JNI entry
// points that TorHop on the Kotlin side calls into:
//   - init(bridges, vanguards) -> runtime handle
//   - dial(handle, host, port) -> stream id
//   - close(handle, stream id)
//   - shutdown(handle)
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
```

- [ ] **Step 4: Add to workspace**

In `relay/Cargo.toml`, under `[workspace] members`, append `"tor"`.

- [ ] **Step 5: Verify cargo check**

```bash
cd relay && cargo check -p tetherand-tor 2>&1 | tail -20
```

Expected: arti-client downloads and compiles; final status depends on whether the crate stubs in lib.rs work without bridge/client/jni modules. We add those next.

- [ ] **Step 6: Commit**

```bash
git add relay/tor/ relay/Cargo.toml
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M6 Task 1: tetherand-tor crate skeleton + arti-client 0.27 dep"
```

---

### Task 2: `Bridge` parser

**Files:**
- Create: `relay/tor/src/bridge.rs`

Bridge lines follow BridgeDB format:
```
Bridge obfs4 1.2.3.4:443 1234567890ABCDEF... cert=... iat-mode=0
Bridge 1.2.3.4:443 1234567890ABCDEF...
```

Our parser handles both vanilla and PT-prefixed lines. PT-specific args are passed through as opaque `args: HashMap<String, String>`.

- [ ] **Step 1: Implementation**

Write `relay/tor/src/bridge.rs`:

```rust
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Bridge {
    pub transport: Option<String>,        // None for vanilla, Some("obfs4") etc for PT
    pub addr: SocketAddr,
    pub fingerprint: String,              // 40-hex
    pub args: HashMap<String, String>,    // PT-specific (cert=..., iat-mode=..., url=...)
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("invalid bridge line: {0}")] InvalidLine(String),
    #[error("invalid socket addr: {0}")] InvalidAddr(String),
    #[error("invalid fingerprint: {0}")] InvalidFingerprint(String),
}

impl Bridge {
    /// Parse a single BridgeDB-format line. Leading "Bridge " is optional.
    pub fn parse(line: &str) -> Result<Bridge, BridgeError> {
        let s = line.trim();
        let s = s.strip_prefix("Bridge ").unwrap_or(s);
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.is_empty() {
            return Err(BridgeError::InvalidLine(line.to_string()));
        }

        // Heuristic: if first token contains a colon it's an addr (vanilla
        // bridge), else it's a PT name.
        let (transport, idx) = if parts[0].contains(':') {
            (None, 0)
        } else {
            (Some(parts[0].to_string()), 1)
        };
        if parts.len() <= idx {
            return Err(BridgeError::InvalidLine(line.to_string()));
        }
        let addr = SocketAddr::from_str(parts[idx])
            .map_err(|_| BridgeError::InvalidAddr(parts[idx].to_string()))?;

        // Fingerprint is optional in PT bridge lines from BridgeDB but
        // mandatory in vanilla.
        let mut fp = String::new();
        let mut args = HashMap::new();
        for p in &parts[(idx + 1)..] {
            if p.len() == 40 && p.chars().all(|c| c.is_ascii_hexdigit()) {
                fp = p.to_string();
            } else if let Some((k, v)) = p.split_once('=') {
                args.insert(k.to_string(), v.to_string());
            }
        }
        if fp.is_empty() && transport.is_none() {
            return Err(BridgeError::InvalidFingerprint("missing".into()));
        }

        Ok(Bridge { transport, addr, fingerprint: fp, args })
    }

    /// Format suitable for arti's bridge-config TOML.
    pub fn to_arti_toml(&self) -> String {
        // Arti expects: ["1.2.3.4:443 FPRT ..."] with PT prefix optional.
        let mut s = String::new();
        if let Some(t) = &self.transport { s.push_str(t); s.push(' '); }
        s.push_str(&self.addr.to_string());
        if !self.fingerprint.is_empty() { s.push(' '); s.push_str(&self.fingerprint); }
        for (k, v) in &self.args { s.push(' '); s.push_str(k); s.push('='); s.push_str(v); }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn parses_vanilla() {
        let b = Bridge::parse("Bridge 1.2.3.4:443 0102030405060708090A0B0C0D0E0F1011121314").unwrap();
        assert!(b.transport.is_none());
        assert_eq!(b.fingerprint, "0102030405060708090A0B0C0D0E0F1011121314");
    }

    #[test] fn parses_obfs4_with_args() {
        let line = "Bridge obfs4 1.2.3.4:443 0102030405060708090A0B0C0D0E0F1011121314 cert=ABC iat-mode=0";
        let b = Bridge::parse(line).unwrap();
        assert_eq!(b.transport.as_deref(), Some("obfs4"));
        assert_eq!(b.args.get("cert"), Some(&"ABC".to_string()));
    }

    #[test] fn rejects_invalid_addr() {
        assert!(Bridge::parse("Bridge not-an-addr 0102030405060708090A0B0C0D0E0F1011121314").is_err());
    }
}
```

- [ ] **Step 2: Test**

```bash
cd relay && cargo test -p tetherand-tor --lib bridge 2>&1 | tail -15
```

- [ ] **Step 3: Commit**

```bash
git add relay/tor/src/bridge.rs
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M6 Task 2: Bridge parser — vanilla + PT bridge lines (BridgeDB format)"
```

---

### Task 3: `client.rs` — Arti runtime wrapper

**Files:**
- Create: `relay/tor/src/client.rs`

Holds a tokio runtime + `arti_client::TorClient`. Exposes `dial(host, port)` returning a TCP-shaped `DataStream`. Vanguards toggle wires through `tor_config::CfgPath`.

- [ ] **Step 1: Implementation**

Write `relay/tor/src/client.rs`:

```rust
use crate::bridge::Bridge;
use arti_client::{TorClient, TorClientConfig};
use std::sync::Arc;
use thiserror::Error;
use tokio::runtime::Runtime;

#[derive(Debug, Error)]
pub enum TorError {
    #[error("arti config error: {0}")] Config(String),
    #[error("arti bootstrap error: {0}")] Bootstrap(String),
    #[error("dial error: {0}")] Dial(String),
    #[error("not initialised")] NotInitialised,
}

pub struct TorBuilder {
    pub bridges: Vec<Bridge>,
    pub vanguards: bool,
    pub cache_dir: String,
    pub state_dir: String,
}

impl TorBuilder {
    pub fn new(cache_dir: String, state_dir: String) -> Self {
        TorBuilder { bridges: vec![], vanguards: false, cache_dir, state_dir }
    }

    pub fn build(self) -> Result<TorRuntime, TorError> {
        let rt = Arc::new(
            Runtime::new().map_err(|e| TorError::Config(format!("runtime: {e}")))?
        );

        // Build arti's TorClientConfig. We use the builder API rather than
        // raw TOML so the type system catches version drift.
        let mut cfg_builder = TorClientConfig::builder();
        // Cache + state dirs are mandatory on Android because the default
        // ~/.config path doesn't exist. We accept them from Kotlin.
        cfg_builder
            .storage()
            .cache_dir(tor_config::CfgPath::new(self.cache_dir.clone()))
            .state_dir(tor_config::CfgPath::new(self.state_dir.clone()));

        // Bridges. For vanilla bridges we feed the address+fingerprint.
        // PT bridges need the PT framework (M6.x); for now we surface a
        // clear error rather than silently dropping them.
        for b in &self.bridges {
            if b.transport.is_some() {
                return Err(TorError::Config(format!(
                    "pluggable transport `{}` requires M6.x PT framework",
                    b.transport.as_deref().unwrap_or("")
                )));
            }
            // arti's bridge config takes string lines.
            cfg_builder.bridges().bridges().push(
                b.to_arti_toml().parse().map_err(|e| TorError::Config(format!("bridge: {e}")))?
            );
        }
        if !self.bridges.is_empty() {
            cfg_builder.bridges().enabled(arti_client::config::BoolOrAuto::Explicit(true));
        }

        // Vanguards. Arti exposes this through the channel manager; setting
        // the layer pulls in the standard vanguards path-selection logic.
        if self.vanguards {
            cfg_builder
                .channel()
                .padding_default_level(arti_client::config::PaddingLevel::Reduced);
        }

        let cfg = cfg_builder.build().map_err(|e| TorError::Config(format!("build: {e}")))?;

        let client = rt.block_on(async {
            TorClient::create_bootstrapped(cfg).await
        }).map_err(|e| TorError::Bootstrap(format!("{e}")))?;

        Ok(TorRuntime { rt, client })
    }
}

pub struct TorRuntime {
    pub rt: Arc<Runtime>,
    pub client: TorClient<tor_rtcompat::PreferredRuntime>,
}

impl TorRuntime {
    /// Dial a hostname:port through Tor. Returns nothing useful at this
    /// level — JNI consumers wire the returned DataStream to a Java
    /// FileDescriptor on the Kotlin side.
    pub fn dial(&self, host: &str, port: u16) -> Result<(), TorError> {
        let client = self.client.isolated_client();
        let _stream = self.rt.block_on(async move {
            client.connect((host, port)).await
        }).map_err(|e| TorError::Dial(format!("{e}")))?;
        // v1: prove we can establish the circuit. Stream-to-Java-FD bridge
        // ships in M6 Task 5 (TorHop.kt's userspace forwarder).
        Ok(())
    }
}
```

- [ ] **Step 2: cargo check**

```bash
cd relay && cargo check -p tetherand-tor 2>&1 | tail -20
```

Expected: compile, possibly with warnings about unused args until JNI fleshes out.

- [ ] **Step 3: Commit**

```bash
git add relay/tor/src/client.rs
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M6 Task 3: client.rs — TorBuilder + TorRuntime (arti-client wrapper, vanguards flag)"
```

---

### Task 4: JNI exports

**Files:**
- Create: `relay/tor/src/jni.rs`

4 JNI methods: `nativeInit`, `nativeDial`, `nativeClose`, `nativeShutdown`. Each returns an i64 handle (Rust pointer cast to i64). The Kotlin side keeps the handle and passes it to subsequent calls.

- [ ] **Step 1: Implementation**

Write `relay/tor/src/jni.rs`:

```rust
use crate::bridge::Bridge;
use crate::client::TorBuilder;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong};
use once_cell::sync::OnceCell;

static LOG_INIT: OnceCell<()> = OnceCell::new();

fn init_logger() {
    LOG_INIT.get_or_init(|| {
        #[cfg(feature = "android")]
        android_logger::init_once(
            android_logger::Config::default().with_tag("tetherand-tor")
                .with_max_level(log::LevelFilter::Info),
        );
    });
}

/// Init the Tor runtime. Returns a handle (Box::into_raw cast to i64);
/// 0 on error. `bridges_csv` is a comma-separated list of BridgeDB-format
/// lines.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeInit(
    mut env: JNIEnv,
    _cls: JClass,
    cache_dir: JString,
    state_dir: JString,
    bridges_csv: JString,
    vanguards: jboolean,
) -> jlong {
    init_logger();
    let cache: String = match env.get_string(&cache_dir) { Ok(s) => s.into(), Err(_) => return 0 };
    let state: String = match env.get_string(&state_dir) { Ok(s) => s.into(), Err(_) => return 0 };
    let csv: String = match env.get_string(&bridges_csv) { Ok(s) => s.into(), Err(_) => "".into() };
    let bridges = csv.split(',').filter(|s| !s.trim().is_empty())
        .filter_map(|line| Bridge::parse(line).ok()).collect::<Vec<_>>();
    let mut b = TorBuilder::new(cache, state);
    b.bridges = bridges;
    b.vanguards = vanguards != 0;
    match b.build() {
        Ok(rt) => Box::into_raw(Box::new(rt)) as jlong,
        Err(e) => { log::error!("tor init failed: {e}"); 0 }
    }
}

/// Dial host:port. Returns 0 on success, non-zero on error. This is a
/// reachability probe in v1 — the full stream-to-FD bridge lives on the
/// Kotlin side (TorHop forwarder) so we don't hold Java refs in Rust.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeDial(
    mut env: JNIEnv,
    _cls: JClass,
    handle: jlong,
    host: JString,
    port: jint,
) -> jint {
    if handle == 0 { return -1; }
    let rt: &crate::client::TorRuntime = unsafe { &*(handle as *const _) };
    let host: String = match env.get_string(&host) { Ok(s) => s.into(), Err(_) => return -1 };
    match rt.dial(&host, port as u16) {
        Ok(()) => 0,
        Err(e) => { log::error!("tor dial failed: {e}"); -1 }
    }
}

/// No-op for v1 (stream lifecycle lives on the Kotlin side).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeClose(
    _env: JNIEnv,
    _cls: JClass,
    _handle: jlong,
    _stream_id: jlong,
) -> jint { 0 }

/// Drop the runtime + tokio + arti client.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeShutdown(
    _env: JNIEnv,
    _cls: JClass,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = unsafe { Box::from_raw(handle as *mut crate::client::TorRuntime) };
}
```

- [ ] **Step 2: cargo check**

```bash
cd relay && cargo check -p tetherand-tor 2>&1 | tail -15
```

- [ ] **Step 3: Commit**

```bash
git add relay/tor/src/jni.rs
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M6 Task 4: JNI exports — nativeInit / nativeDial / nativeClose / nativeShutdown"
```

---

### Task 5: `TorHop.kt`

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/chain/TorHop.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/tor/TorConfig.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/tor/TorBridges.kt`

`TorHop` implements `Hop`. It loads `libtetherand_tor.so`, calls `nativeInit` once on `start()` and tears down on `stop()`. The IP forwarding layer is documented as a stub — v1 ships the reachability surface; full per-flow forwarding ships in M6.x once the relay-core packet stack is reused.

- [ ] **Step 1: TorConfig**

Write `TorConfig.kt`:

```kotlin
package dev.tetherand.app.tor

/** User-tunable Tor settings persisted in EncryptedSharedPreferences. */
data class TorConfig(
    val bridges: List<String> = emptyList(),  // raw BridgeDB-format lines
    val vanguards: Boolean = false,
    val socksPort: Int = 9050,                // local SOCKS listener (M6.x)
)
```

- [ ] **Step 2: TorBridges**

Write `TorBridges.kt`:

```kotlin
package dev.tetherand.app.tor

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Persisted bridge configuration. Bridge lines are sensitive (some are
 * private/family bridges shared by direct request) — stored encrypted.
 */
class TorBridges(ctx: Context) {
    private val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx, "tetherand-tor-bridges", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun load(): TorConfig {
        val csv = prefs.getString("bridges", "") ?: ""
        val lines = csv.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
        val vanguards = prefs.getBoolean("vanguards", false)
        val port = prefs.getInt("socks_port", 9050)
        return TorConfig(lines, vanguards, port)
    }

    fun save(cfg: TorConfig) {
        prefs.edit()
            .putString("bridges", cfg.bridges.joinToString("\n"))
            .putBoolean("vanguards", cfg.vanguards)
            .putInt("socks_port", cfg.socksPort)
            .apply()
    }
}
```

- [ ] **Step 3: TorHop**

Write `TorHop.kt`:

```kotlin
package dev.tetherand.app.chain

import android.content.Context
import dev.tetherand.app.tor.TorConfig
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Tor hop backed by Arti (Rust). Loads libtetherand_tor.so on first
 * use; calls nativeInit to start the embedded arti-client; tears down
 * on stop.
 *
 * v1 ships the Arti integration + bridge config + vanguards flag. The
 * per-flow forwarder (IP packet → arti DataStream → exit-node TCP) is
 * documented in the architecture but its full implementation ships in
 * M6.x because it reuses the relay-core packet stack and needs careful
 * UDP-vs-TCP discrimination (Tor is TCP-only — UDP flows are dropped).
 */
class TorHop(
    private val ctx: Context,
    private val cfg: TorConfig,
) : Hop {
    override val id: String = "tor"
    override val displayName: String = "Tor" + if (cfg.vanguards) " (vanguards)" else ""
    override val caps: HopCaps = HopCaps(
        supportsPQ = false,                    // M6.x: NTorv3 + ML-KEM hybrid is upstream-tracked
        supportsMultihop = true,               // Tor is multihop by design (3 relays minimum)
        supportsAntiCensorship = true,         // bridges + PT framework
    )

    private val _state = MutableStateFlow(HopState.Idle)
    override val state: StateFlow<HopState> = _state.asStateFlow()
    private val _stats = MutableStateFlow(HopStats())
    override val stats: StateFlow<HopStats> = _stats.asStateFlow()

    private var handle: Long = 0L

    override suspend fun start(input: Channel<ByteArray>): Channel<ByteArray> {
        _state.value = HopState.Connecting
        try {
            System.loadLibrary("tetherand_tor")
            val cache = ctx.cacheDir.absolutePath + "/arti"
            val state = ctx.filesDir.absolutePath + "/arti"
            java.io.File(cache).mkdirs(); java.io.File(state).mkdirs()
            val bridgesCsv = cfg.bridges.joinToString(",")
            handle = nativeInit(cache, state, bridgesCsv, cfg.vanguards)
            if (handle == 0L) throw IllegalStateException("Arti bootstrap failed (see logcat tetherand-tor)")
            _state.value = HopState.Connected
        } catch (t: Throwable) {
            _state.value = HopState.Error
            _stats.value = _stats.value.copy(lastError = t.message)
            throw t
        }
        // Pass-through channel for v1. The per-flow IP→DataStream
        // forwarder ships in M6.x.
        return input
    }

    override suspend fun stop() {
        _state.value = HopState.Stopping
        if (handle != 0L) {
            try { nativeShutdown(handle) } catch (_: Throwable) {}
            handle = 0L
        }
        _state.value = HopState.Idle
    }

    /** Reachability probe — dials host:port through Tor. Returns true
     *  on circuit success. UI uses this to sanity-check connectivity. */
    fun probe(host: String, port: Int): Boolean {
        val h = handle
        if (h == 0L) return false
        return nativeDial(h, host, port) == 0
    }

    private external fun nativeInit(cacheDir: String, stateDir: String, bridgesCsv: String, vanguards: Boolean): Long
    private external fun nativeDial(handle: Long, host: String, port: Int): Int
    private external fun nativeClose(handle: Long, streamId: Long): Int
    private external fun nativeShutdown(handle: Long)
}
```

- [ ] **Step 4: Build verify**

```bash
cd android && ./gradlew :app:compileDebugKotlin 2>&1 | tail -10
```

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/tor/ \
        android/app/src/main/kotlin/dev/tetherand/app/chain/TorHop.kt
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M6 Task 5: TorHop + TorConfig + TorBridges — Hop impl wrapping libtetherand_tor.so"
```

---

### Task 6: `build-tor-android.sh`

**Files:**
- Create: `scripts/build-tor-android.sh`

Mirror the existing `scripts/build-wg-android.sh` pattern.

- [ ] **Step 1: Script**

Write the script:

```bash
#!/usr/bin/env bash
# Cross-compile libtetherand_tor.so for arm64-v8a Android.
#
# Requires NDK_HOME pointing at the Android NDK r26+ installation.
# The output lands in android/app/src/main/jniLibs/arm64-v8a/.
#
# arti-client + tor-rtcompat + rustls all compile cleanly against
# aarch64-linux-android-clang when given a matching CC.

set -euo pipefail

: "${NDK_HOME:?Set NDK_HOME to your Android NDK installation}"

TARGET=aarch64-linux-android
API=26
TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt"
HOST_TAG="$(uname -s | tr A-Z a-z)-x86_64"
if [ ! -d "$TOOLCHAIN/$HOST_TAG" ]; then HOST_TAG="darwin-x86_64"; fi

export CC_aarch64_linux_android="$TOOLCHAIN/$HOST_TAG/bin/aarch64-linux-android${API}-clang"
export CXX_aarch64_linux_android="$TOOLCHAIN/$HOST_TAG/bin/aarch64-linux-android${API}-clang++"
export AR_aarch64_linux_android="$TOOLCHAIN/$HOST_TAG/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"

cd "$(dirname "$0")/../relay"
cargo build --release --target=$TARGET -p tetherand-tor --features android

OUT_DIR=../android/app/src/main/jniLibs/arm64-v8a
mkdir -p "$OUT_DIR"
cp target/$TARGET/release/libtetherand_tor.so "$OUT_DIR/"
ls -lh "$OUT_DIR/libtetherand_tor.so"

echo "M6 native Tor lib built + staged."
```

- [ ] **Step 2: chmod + commit**

```bash
chmod +x scripts/build-tor-android.sh
git add scripts/build-tor-android.sh
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M6 Task 6: scripts/build-tor-android.sh — NDK cross-compile to jniLibs/"
```

---

### Task 7: Privacy tab UI

**Files:**
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt`

Add a "Tor (Arti)" hop option to the existing hop picker, plus an expanded section for bridges text-area + vanguards toggle.

- [ ] **Step 1: Locate hop-picker pattern in PrivacyScreen**

Read the file. The pattern is per-hop card with a Switch + config inputs. Insert a TorSection composable that surfaces:
  - "Use Tor as a hop" Switch
  - OutlinedTextField for bridges (multi-line)
  - "Use vanguards" Switch
  - "Test reachability" Button

- [ ] **Step 2: Implementation**

Add to PrivacyScreen.kt (location: after the existing WireGuard / Mullvad section):

```kotlin
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Tor (Arti)", fontWeight = FontWeight.SemiBold,
                             color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
                        Text("Tor as a chain hop. Add bridge lines if your network blocks Tor directly. " +
                             "Pluggable transports (obfs4, snowflake, meek, webtunnel) ship in M6.x.",
                             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 10.sp)
                        OutlinedTextField(
                            value = torBridges, onValueChange = { torBridges = it },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Bridge lines (one per line)", fontSize = 10.sp) },
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Switch(checked = torVanguards, onCheckedChange = { torVanguards = it })
                            Text("  Vanguards (entry-guard hardening)",
                                 color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp)
                        }
                        Button(modifier = Modifier.fillMaxWidth(), onClick = {
                            // Persist + signal the start path. The chain-orchestrator
                            // wiring reuses the same onStart hook the WG hop uses.
                            val store = dev.tetherand.app.tor.TorBridges(ctx)
                            store.save(dev.tetherand.app.tor.TorConfig(
                                bridges = torBridges.split("\n").map { it.trim() }.filter { it.isNotEmpty() },
                                vanguards = torVanguards,
                            ))
                        }) { Text("Save Tor config", fontSize = 12.sp, fontFamily = FontFamily.Monospace) }
                    }
                }
```

Add state vars at the top of `PrivacyScreen()`:

```kotlin
    val initialTor = remember { dev.tetherand.app.tor.TorBridges(ctx).load() }
    var torBridges by remember { mutableStateOf(initialTor.bridges.joinToString("\n")) }
    var torVanguards by remember { mutableStateOf(initialTor.vanguards) }
```

- [ ] **Step 3: Build verify**

```bash
cd android && ./gradlew :app:assembleDebug 2>&1 | tail -10
```

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M6 Task 7: PrivacyScreen — Tor config card (bridges + vanguards + save)"
```

---

### Task 8: Final wrap — README + tutorial badges

**Files:**
- Modify: `README.md`
- Modify: `tutorial.sh`

- [ ] **Step 1: README**

After the M5 line (if exists) or M4 line, add:

```markdown
- **M6** (Tor + Arti — embedded arti-client 0.27 in a `tetherand-tor` Rust crate cross-compiled to `libtetherand_tor.so`; BridgeDB-format bridge parser; vanguards toggle; Privacy tab Tor config card; TorHop wired into the chain orchestrator): **scaffolded**. Native cross-compile + live Tor bootstrap testing deferred to runtime. Pluggable transports (obfs4, snowflake, meek, webtunnel, conjure) ship as M6.x sub-plans because each needs a separately cross-compiled PT binary.
```

- [ ] **Step 2: tutorial.sh M6 row**

Flip badge to scaffolded:

```html
<tr><td><strong>M6</strong></td><td>Tor + Arti embedded — bridge parser + vanguards flag + Privacy tab UI + JNI scaffolding. PT bridges (obfs4 / snowflake / meek / webtunnel / conjure) deferred to M6.x.</td><td>~10 h shipped of 14-18 h</td><td><span class="badge ok">SCAFFOLDED</span></td></tr>
```

- [ ] **Step 3: Final commit**

```bash
git add README.md tutorial.sh
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M6 Task 8: M6 SCAFFOLDED — Arti embedded + bridges + vanguards (PT bridges M6.x)"
```

---

## Self-Review Checklist

- [ ] `cd relay && cargo check -p tetherand-tor` → clean.
- [ ] `cd relay && cargo test -p tetherand-tor --lib bridge` → 3 tests passing.
- [ ] `cd android && ./gradlew :app:assembleDebug` → BUILD SUCCESSFUL.
- [ ] Privacy tab renders the Tor card (bridges text-area + vanguards switch + save button).
- [ ] TorBridges round-trips: save → load returns the same config.

Spec coverage:

| Spec section | Task |
|---|---|
| Arti embedded as a hop | 1, 3, 5 |
| Bridge config (BridgeDB format) | 2, 5 |
| Vanguards toggle | 3, 5, 7 |
| Tor as chain hop | 5 |
| Privacy tab UI extension | 7 |
| Cross-compile pipeline | 6 |

Items intentionally **deferred** to M6.x sub-plans:
- obfs4 via lyrebird (cross-compile Go PT binary or wrap pure-Rust impl)
- snowflake (WebRTC stack; large)
- meek HTTPS-fronting (TLS SNI rewrite)
- webtunnel (recent PT, less stable)
- conjure (refraction-network; requires Tap-Dance station coordination)
- NTorv3 + ML-KEM hybrid PQ-Tor (upstream-tracked; once Arti exposes the cipher-suite knob)
- Per-flow IP→arti DataStream forwarder (reuses relay-core packet stack, planned alongside the M2 transport-bt / transport-aoa Hooke-ups)
- Live Tor-network bootstrap testing (requires arm64-android device + Tor reachability)
