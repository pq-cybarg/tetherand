use nym_sdk::mixnet::{
    MixnetClient, MixnetClientBuilder, MixnetMessageSender, Recipient, StoragePaths,
};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::runtime::Runtime;

#[derive(Debug, Error)]
pub enum NymError {
    #[error("nym config: {0}")] Config(String),
    #[error("nym mixnet build: {0}")] Build(String),
    #[error("dial: {0}")] Dial(String),
    #[error("not connected")] NotConnected,
}

/// Builder pattern for [`NymRuntime`].
///
/// `entry_gateway` and `exit_gateway` are nym-formatted Recipient
/// strings (`<identity>.<encryption>@<gateway>` 96-char base58) — the
/// SDK accepts these via `Recipient::from_str`. When None, the SDK
/// picks a topology-provided default ephemeral gateway.
///
/// `mnemonic` is the v1 zk-nym credential that pays for mixnet
/// bandwidth. When None we run against the SDK's default ephemeral
/// (free testnet) credential.
pub struct NymBuilder {
    pub state_dir: String,
    pub mnemonic: Option<String>,
    pub entry_gateway: Option<String>,
    pub exit_gateway: Option<String>,
}

impl NymBuilder {
    pub fn new(state_dir: String) -> Self {
        NymBuilder {
            state_dir, mnemonic: None, entry_gateway: None, exit_gateway: None,
        }
    }

    /// Build the runtime: spin up a tokio runtime + an in-memory
    /// `MixnetClient`. The actual mixnet connect happens lazily on
    /// first dial so the Kotlin `start()` call doesn't block.
    pub fn build(self) -> Result<NymRuntime, NymError> {
        let rt = Arc::new(
            Runtime::new().map_err(|e| NymError::Config(format!("runtime: {e}")))?
        );

        // Parse optional exit gateway to fail-fast on a malformed
        // address rather than discover it at first-dial time.
        let exit_recipient = match &self.exit_gateway {
            Some(s) => Some(Recipient::from_str(s)
                .map_err(|e| NymError::Config(format!("exit gateway: {e}")))?),
            None => None,
        };

        Ok(NymRuntime {
            rt,
            state_dir: PathBuf::from(self.state_dir),
            mnemonic: self.mnemonic,
            entry_gateway: self.entry_gateway,
            exit_recipient,
            client: Arc::new(Mutex::new(None)),
        })
    }
}

pub struct NymRuntime {
    pub rt: Arc<Runtime>,
    state_dir: PathBuf,
    #[allow(dead_code)]
    mnemonic: Option<String>,
    #[allow(dead_code)]
    entry_gateway: Option<String>,
    exit_recipient: Option<Recipient>,
    /// The MixnetClient lives behind a mutex+option so we can connect
    /// lazily on first dial, and so JNI calls from different Kotlin
    /// threads can serialize their send/receive operations safely.
    client: Arc<Mutex<Option<MixnetClient>>>,
}

impl NymRuntime {
    /// Connect to the mixnet if not already connected. Returns the
    /// connected nym_address. Idempotent — subsequent calls re-use
    /// the existing connection.
    pub fn ensure_connected(&self) -> Result<String, NymError> {
        let already = {
            let guard = self.client.lock()
                .map_err(|_| NymError::Build("client mutex poisoned".to_string()))?;
            guard.as_ref().map(|c| c.nym_address().to_string())
        };
        if let Some(addr) = already { return Ok(addr); }

        let state_dir = self.state_dir.clone();
        let connected = self.rt.block_on(async move {
            // Persistent storage at state_dir so the same gateway
            // identity persists across restarts (otherwise every
            // restart is a fresh ephemeral client + new gateway
            // selection, which is observable).
            let storage = StoragePaths::new_from_dir(&state_dir)
                .map_err(|e| NymError::Build(format!("storage paths: {e}")))?;
            let client = MixnetClientBuilder::new_with_default_storage(storage).await
                .map_err(|e| NymError::Build(format!("builder: {e}")))?
                .build()
                .map_err(|e| NymError::Build(format!("build: {e}")))?
                .connect_to_mixnet().await
                .map_err(|e| NymError::Build(format!("connect: {e}")))?;
            Ok::<MixnetClient, NymError>(client)
        })?;

        let addr = connected.nym_address().to_string();
        let mut guard = self.client.lock()
            .map_err(|_| NymError::Build("client mutex poisoned".to_string()))?;
        *guard = Some(connected);
        Ok(addr)
    }

    /// Dial host:port through the mixnet via the configured exit
    /// gateway. v1: sends a single CONNECT-style message (no
    /// per-flow forwarder yet). The exit-gateway side parses the
    /// payload and opens the TCP. Future M5.x adds the bidirectional
    /// stream pump (same pattern as Tor's TorFlowForwarder).
    ///
    /// Returns `Ok(())` if the message was sent. Note this does NOT
    /// wait for a response — the caller is expected to follow up with
    /// recv() for the dial's status reply.
    pub fn dial(&self, host: &str, port: u16) -> Result<(), NymError> {
        let exit = self.exit_recipient.ok_or_else(|| NymError::Config(
            "no exit gateway configured; set NymBuilder.exit_gateway first".to_string()))?;
        // Connect on demand.
        self.ensure_connected()?;
        let payload = format!("CONNECT {host}:{port}\n").into_bytes();
        let client = self.client.clone();
        self.rt.block_on(async move {
            let mut guard = client.lock()
                .map_err(|_| NymError::Dial("client mutex poisoned".to_string()))?;
            let client = guard.as_mut().ok_or(NymError::NotConnected)?;
            client.send_plain_message(exit, payload).await
                .map_err(|e| NymError::Dial(format!("send: {e}")))?;
            Ok::<(), NymError>(())
        })
    }

    /// Wait briefly for any inbound mixnet message and return its
    /// payload bytes (or empty vec on timeout / no message). Used by
    /// the dial flow for the exit gateway's CONNECT reply, AND by
    /// the per-flow pump for data reads.
    pub fn recv_one(&self) -> Result<Vec<u8>, NymError> {
        let client = self.client.clone();
        self.rt.block_on(async move {
            let mut guard = client.lock()
                .map_err(|_| NymError::Dial("client mutex poisoned".to_string()))?;
            let client = guard.as_mut().ok_or(NymError::NotConnected)?;
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                client.wait_for_messages(),
            ).await {
                Ok(Some(msgs)) => Ok(msgs.into_iter().next().map(|m| m.message).unwrap_or_default()),
                Ok(None) => Ok(Vec::new()),    // stream ended
                Err(_) => Ok(Vec::new()),       // timeout
            }
        })
    }

    /// Best-effort graceful shutdown. Drops the MixnetClient (the
    /// SDK's `disconnect()` consumes self; we route it through the
    /// option-take so subsequent `ensure_connected()` calls
    /// re-bootstrap from scratch).
    pub fn disconnect(&self) -> Result<(), NymError> {
        let taken = {
            let mut guard = self.client.lock()
                .map_err(|_| NymError::Build("client mutex poisoned".to_string()))?;
            guard.take()
        };
        if let Some(client) = taken {
            self.rt.block_on(async move {
                client.disconnect().await;
            });
        }
        Ok(())
    }
}
