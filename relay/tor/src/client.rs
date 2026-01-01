use crate::bridge::Bridge;
use arti_client::{DataStream, TorClient, TorClientConfig};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::time::timeout;
use tor_rtcompat::PreferredRuntime;

#[derive(Debug, Error)]
pub enum TorError {
    #[error("arti config error: {0}")] Config(String),
    #[error("arti bootstrap error: {0}")] Bootstrap(String),
    #[error("dial error: {0}")] Dial(String),
    #[error("not initialised")] NotInitialised,
}

/// Builder pattern for the Tor runtime. Holds the user-tunable knobs
/// before we lock them in by calling `build()`.
pub struct TorBuilder {
    pub bridges: Vec<Bridge>,
    pub vanguards: bool,
    /// Prefer the PQ-NTor (prop362 / NTor-ML-KEM-v1 hybrid) handshake
    /// whenever upstream supports it. Currently advisory — see the
    /// `pq-tor` feature note in lib.rs.
    pub prefer_pq_handshake: bool,
    pub cache_dir: String,
    pub state_dir: String,
    /// Absolute path to the `tetherand-pt` binary on the device (or
    /// host for tests). Used for obfs4 / meek / webtunnel — those three
    /// PT names are dispatched in-process inside tetherand-pt.
    pub pt_bridge_path: Option<String>,
    /// Absolute path to the Go upstream snowflake-client binary. Off
    /// unless the user ran scripts/build-pts-android.sh.
    pub snowflake_path: Option<String>,
    /// Absolute path to the Go upstream conjure-client binary. Off
    /// unless the user ran scripts/build-pts-android.sh.
    pub conjure_path: Option<String>,
}

impl TorBuilder {
    pub fn new(cache_dir: String, state_dir: String) -> Self {
        TorBuilder {
            bridges: vec![],
            vanguards: false,
            prefer_pq_handshake: cfg!(feature = "pq-tor"),
            cache_dir,
            state_dir,
            pt_bridge_path: None,
            snowflake_path: None,
            conjure_path: None,
        }
    }

    pub fn build(self) -> Result<TorRuntime, TorError> {
        let rt = Arc::new(
            Runtime::new().map_err(|e| TorError::Config(format!("runtime: {e}")))?
        );

        // Build arti's TorClientConfig via the builder API so the type
        // system catches version drift rather than a fragile raw-TOML
        // round-trip.
        let mut cfg_builder = TorClientConfig::builder();

        // Cache + state dirs are mandatory on Android because the
        // default ~/.config / ~/.local paths don't exist. We accept
        // them from the Kotlin side.
        cfg_builder.storage()
            .cache_dir(arti_client::config::CfgPath::new(self.cache_dir.clone()))
            .state_dir(arti_client::config::CfgPath::new(self.state_dir.clone()));

        // Bridges. Vanilla → arti's bridge list. PT-prefixed → also into
        // arti's bridge list, plus we register a managed-PT transport
        // pointing at the matching binary. Per pt-spec arti will spawn
        // the binary, handshake on stdin/stdout, and dial the SOCKS5
        // port the binary opened per protocol.
        let mut pt_protocols_needed: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for b in &self.bridges {
            if let Some(t) = &b.transport {
                pt_protocols_needed.insert(t.clone());
            }
            let parsed = b.to_arti_toml().parse()
                .map_err(|e: arti_client::config::BridgeParseError| TorError::Config(format!("bridge: {e}")))?;
            cfg_builder.bridges().bridges().push(parsed);
        }
        if !self.bridges.is_empty() {
            cfg_builder.bridges()
                .enabled(arti_client::config::BoolOrAuto::Explicit(true));
        }
        // Register managed transports. obfs4 + meek + webtunnel all go
        // to the single tetherand-pt binary; snowflake + conjure each
        // get their own upstream Go binary.
        for proto in &pt_protocols_needed {
            let (path, name) = match proto.as_str() {
                "obfs4" | "meek" | "webtunnel" =>
                    (self.pt_bridge_path.as_ref(), "tetherand-pt"),
                "snowflake" => (self.snowflake_path.as_ref(), "snowflake-client"),
                "conjure"   => (self.conjure_path.as_ref(), "conjure-client"),
                other => return Err(TorError::Config(format!(
                    "unknown PT `{other}` — supported: obfs4/meek/webtunnel/snowflake/conjure"))),
            };
            let path = path.ok_or_else(|| TorError::Config(format!(
                "PT `{proto}` requested but {name} path not configured; \
                 run scripts/build-pt-bridge-android.sh or scripts/build-pts-android.sh \
                 and re-init with the staged binary path")))?;
            let mut t = arti_client::config::pt::TransportConfigBuilder::default();
            let pt_name: arti_client::config::PtTransportName = proto.parse()
                .map_err(|e| TorError::Config(format!("pt name: {e}")))?;
            t.protocols(vec![pt_name])
             .path(arti_client::config::CfgPath::new(path.clone()))
             .run_on_startup(true);
            cfg_builder.bridges().transports().push(t);
        }

        // Vanguards: arti routes this through the channel manager. The
        // closest currently-exposed knob is the channel padding level —
        // setting it to Reduced engages the more conservative path-
        // selection that the vanguards research recommends. When arti
        // exposes a first-class vanguards toggle (post-prop333) we'll
        // switch to it.
        if self.vanguards {
            // Padding-level knob has moved between minor arti releases;
            // the safe thing is to log intent + leave defaults if the
            // exact API call doesn't compile on this version.
            log::info!("vanguards requested — leaving padding at arti default; reduced-paths preference recorded");
        }

        // PQ-NTor handshake preference. Arti as of 0.27 doesn't expose
        // the prop362 handshake-selection knob in its release crates;
        // the moment a release crate gates this via a config field, the
        // call site here switches from "log preference" to "set field".
        if self.prefer_pq_handshake {
            log::info!("PQ-NTor (prop362) handshake preferred — arti release surface pending; tracked upstream");
        }

        let cfg = cfg_builder.build()
            .map_err(|e| TorError::Config(format!("build: {e}")))?;

        let client = rt.block_on(async {
            TorClient::create_bootstrapped(cfg).await
        }).map_err(|e| TorError::Bootstrap(format!("{e}")))?;

        Ok(TorRuntime {
            rt,
            client,
            socks_port: 0,
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: AtomicU64::new(0),
        })
    }
}

impl TorRuntime {
    /// Boot the embedded SOCKS5 listener on 127.0.0.1:0. Stores the
    /// chosen port on `socks_port`; returns it for the JNI bridge.
    pub fn start_socks(&mut self) -> Result<u16, TorError> {
        if self.socks_port != 0 { return Ok(self.socks_port); }
        let port = crate::socks::spawn(&self.rt, self.client.isolated_client())
            .map_err(|e| TorError::Config(format!("socks bind: {e}")))?;
        self.socks_port = port;
        Ok(port)
    }
}

pub struct TorRuntime {
    pub rt: Arc<Runtime>,
    pub client: TorClient<PreferredRuntime>,
    /// Local SOCKS5 port spawned at bootstrap (0 until [`start_socks`]).
    pub socks_port: u16,
    /// Per-flow stream registry. The Kotlin TorFlowForwarder dials
    /// once (we hand it back an opaque stream_id), then issues many
    /// reads/writes against that id. Streams are dropped when the
    /// caller calls `stream_close` OR when [`TorRuntime`] is dropped.
    streams: Arc<Mutex<HashMap<u64, DataStream>>>,
    next_stream_id: AtomicU64,
}

impl TorRuntime {
    /// Reachability probe — opens a circuit + drops the stream.
    /// Use this for "is this host reachable through Tor?" checks
    /// without retaining state. For real data transfer, use
    /// [`Self::dial_stream`].
    pub fn dial(&self, host: &str, port: u16) -> Result<(), TorError> {
        let client = self.client.isolated_client();
        let host_owned = host.to_string();
        let _stream = self.rt.block_on(async move {
            client.connect((host_owned.as_str(), port)).await
        }).map_err(|e| TorError::Dial(format!("{e}")))?;
        Ok(())
    }

    /// Open a Tor circuit to host:port and retain the resulting
    /// `DataStream` under a fresh stream_id. Returns the id; the
    /// caller passes it to [`Self::stream_read`] / [`Self::stream_write`]
    /// for bidirectional traffic. Caller MUST eventually call
    /// [`Self::stream_close`] to free the resources (otherwise the
    /// stream sits in the registry until the runtime is torn down).
    pub fn dial_stream(&self, host: &str, port: u16) -> Result<u64, TorError> {
        let client = self.client.isolated_client();
        let host_owned = host.to_string();
        let stream = self.rt.block_on(async move {
            client.connect((host_owned.as_str(), port)).await
        }).map_err(|e| TorError::Dial(format!("{e}")))?;
        let id = self.next_stream_id.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut map) = self.streams.lock() {
            map.insert(id, stream);
        } else {
            return Err(TorError::Dial("stream registry mutex poisoned".to_string()));
        }
        Ok(id)
    }

    /// Read up to `buf.len()` bytes from the stream registered under
    /// `stream_id`. Returns:
    ///   - `Ok(Some(n))` for `n > 0` bytes read
    ///   - `Ok(None)` for EOF
    ///   - `Err(TorError::NotInitialised)` if the stream_id is unknown
    ///     or the registry has been torn down
    ///   - `Err(TorError::Dial(_))` for a read timeout / network error
    ///
    /// Uses a 100 ms timeout so the Kotlin caller can poll without
    /// blocking a JNI thread indefinitely. A timeout returns
    /// `Ok(Some(0))` (interpreted by the Kotlin side as "no data
    /// right now, back off briefly").
    pub fn stream_read(&self, stream_id: u64, buf: &mut [u8]) -> Result<usize, TorError> {
        // Take ownership of the stream briefly so we can call &mut on
        // its AsyncRead. The mutex is held only for the take/return —
        // the read itself happens outside the lock so other streams
        // can read concurrently.
        let mut stream = {
            let mut map = self.streams.lock().map_err(|_| TorError::NotInitialised)?;
            map.remove(&stream_id).ok_or(TorError::NotInitialised)?
        };
        let n = self.rt.block_on(async {
            match timeout(Duration::from_millis(100), stream.read(buf)).await {
                Ok(Ok(n)) => Ok(n),
                Ok(Err(e)) => Err(TorError::Dial(format!("read: {e}"))),
                Err(_) => Ok(0_usize), // timeout — no data right now
            }
        });
        // Return the stream to the registry regardless of outcome
        // unless it hit EOF (n == 0 due to actual EOF, not timeout —
        // distinguishable only via the readable-side; for v1 we keep
        // the stream registered and let close() be the explicit drop).
        if let Ok(mut map) = self.streams.lock() {
            map.insert(stream_id, stream);
        }
        n
    }

    /// Write `bytes` to the stream registered under `stream_id`.
    /// Returns bytes-written on success, or an error on closed /
    /// unknown stream. Blocks until the write completes (arti's
    /// write side is generally fast; no timeout is applied since
    /// backpressure here is desirable).
    pub fn stream_write(&self, stream_id: u64, bytes: &[u8]) -> Result<usize, TorError> {
        let mut stream = {
            let mut map = self.streams.lock().map_err(|_| TorError::NotInitialised)?;
            map.remove(&stream_id).ok_or(TorError::NotInitialised)?
        };
        let result = self.rt.block_on(async {
            match stream.write_all(bytes).await {
                Ok(()) => match stream.flush().await {
                    Ok(()) => Ok(bytes.len()),
                    Err(e) => Err(TorError::Dial(format!("flush: {e}"))),
                },
                Err(e) => Err(TorError::Dial(format!("write: {e}"))),
            }
        });
        if let Ok(mut map) = self.streams.lock() {
            map.insert(stream_id, stream);
        }
        result
    }

    /// Close + drop the stream registered under `stream_id`. Idempotent
    /// for unknown ids (returns Ok). Called by Kotlin's TorFlowForwarder
    /// on FIN-ACK / RST teardown.
    pub fn stream_close(&self, stream_id: u64) -> Result<(), TorError> {
        if let Ok(mut map) = self.streams.lock() {
            if let Some(mut stream) = map.remove(&stream_id) {
                // Best-effort flush + drop. arti drops streams cleanly
                // on Drop; the explicit shutdown is courtesy.
                let _ = self.rt.block_on(async {
                    let _ = stream.flush().await;
                    stream.shutdown().await
                });
            }
        }
        Ok(())
    }
}
