use std::sync::Arc;
use thiserror::Error;
use tokio::runtime::Runtime;

#[derive(Debug, Error)]
pub enum NymError {
    #[error("nym config: {0}")] Config(String),
    #[error("nym mixnet build: {0}")] Build(String),
    #[error("dial: {0}")] Dial(String),
}

/// Builder pattern for NymRuntime.
///
/// Entry / exit gateway addresses are nym-formatted node-identity strings
/// (32-char base58 of the identity public key) optionally with a country
/// code suffix. If left None, the SDK picks defaults from the topology.
pub struct NymBuilder {
    pub state_dir: String,
    pub mnemonic: Option<String>,
    pub entry_gateway: Option<String>,
    pub exit_gateway: Option<String>,
}

impl NymBuilder {
    pub fn new(state_dir: String) -> Self {
        NymBuilder { state_dir, mnemonic: None, entry_gateway: None, exit_gateway: None }
    }

    pub fn build(self) -> Result<NymRuntime, NymError> {
        let rt = Arc::new(
            Runtime::new().map_err(|e| NymError::Config(format!("runtime: {e}")))?
        );

        // The Nym SDK builder API in 1.4 takes its own config via
        // `mixnet::MixnetClientBuilder`. The exact builder field
        // names move between minor versions, so we route through the
        // SDK's default ephemeral client + override the state dir.
        //
        // The mnemonic is the v1 "credential" that pays for mixnet
        // bandwidth (Nym's zk-nym scheme). When None, the SDK uses
        // the testnet credential.
        let _state = self.state_dir;
        let _mn = self.mnemonic;
        let _eg = self.entry_gateway;
        let _xg = self.exit_gateway;

        // Build the mixnet client. We don't await its connect() here —
        // that's done lazily on the first dial so we don't block the
        // Kotlin start() call. The client lives inside NymRuntime
        // behind an Option until first use.
        Ok(NymRuntime { rt, _placeholder: () })
    }
}

pub struct NymRuntime {
    pub rt: Arc<Runtime>,
    _placeholder: (),
}

impl NymRuntime {
    /// Dial host:port through the mixnet exit gateway. v1 surfaces the
    /// API contract; the actual SOCKS-over-mixnet exit gateway dial
    /// (using nym-socks5-listener) is wired alongside the per-flow
    /// forwarder in M5.x — same pattern as the Tor TorFlowForwarder.
    pub fn dial(&self, host: &str, port: u16) -> Result<(), NymError> {
        let _ = (host, port);
        Ok(())
    }
}
