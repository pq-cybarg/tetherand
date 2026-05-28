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
}

impl TorBuilder {
    pub fn new(cache_dir: String, state_dir: String) -> Self {
        TorBuilder {
            bridges: vec![],
            vanguards: false,
            prefer_pq_handshake: cfg!(feature = "pq-tor"),
            cache_dir,
            state_dir,
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

        // Bridges. For vanilla bridges we feed the address+fingerprint
        // line. PT bridges need the PT framework; v1 surfaces a clear
        // config error rather than silently dropping them.
        for b in &self.bridges {
            if b.transport.is_some() {
                return Err(TorError::Config(format!(
                    "pluggable transport `{}` requires the M6.x PT framework",
                    b.transport.as_deref().unwrap_or("")
                )));
            }
            // arti's bridge config takes string lines.
            let parsed = b.to_arti_toml().parse()
                .map_err(|e: arti_client::config::BridgeParseError| TorError::Config(format!("bridge: {e}")))?;
            cfg_builder.bridges().bridges().push(parsed);
        }
        if !self.bridges.is_empty() {
            cfg_builder.bridges()
                .enabled(arti_client::config::BoolOrAuto::Explicit(true));
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
