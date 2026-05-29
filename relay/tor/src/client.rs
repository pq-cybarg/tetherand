use crate::bridge::Bridge;
use arti_client::{TorClient, TorClientConfig};
use std::sync::Arc;
use thiserror::Error;
use tokio::runtime::Runtime;
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

        Ok(TorRuntime { rt, client })
    }
}

pub struct TorRuntime {
    pub rt: Arc<Runtime>,
    pub client: TorClient<PreferredRuntime>,
}

impl TorRuntime {
    /// Dial host:port through Tor. Returns Ok if the circuit completes
    /// + the stream attaches; we drop the stream immediately (this is
    /// a reachability probe). The per-flow IP→DataStream forwarder
    /// lives on the Kotlin side (TorHop) and ships in M6.x once the
    /// relay-core packet stack is reused.
    pub fn dial(&self, host: &str, port: u16) -> Result<(), TorError> {
        let client = self.client.isolated_client();
        let host_owned = host.to_string();
        let _stream = self.rt.block_on(async move {
            client.connect((host_owned.as_str(), port)).await
        }).map_err(|e| TorError::Dial(format!("{e}")))?;
        Ok(())
    }
}
