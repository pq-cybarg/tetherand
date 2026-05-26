//! Transport abstraction for Tetherand.

use async_trait::async_trait;
use tetherand_codec::Frame;
use thiserror::Error;

pub use tetherand_codec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransportId {
    UsbAdb,
    UsbAoa,
    Bluetooth,
    Tcp,
}

impl TransportId {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportId::UsbAdb => "usb-adb",
            TransportId::UsbAoa => "usb-aoa",
            TransportId::Bluetooth => "bluetooth",
            TransportId::Tcp => "tcp",
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Capabilities {
    pub id: TransportId,
    pub mtu: u16,
    pub bandwidth_hint_bps: u64,
    pub latency_hint_ms: u32,
}

#[async_trait]
pub trait Transport: Send {
    async fn connect(&mut self) -> Result<Capabilities, TransportError>;
    async fn next_frame(&mut self) -> Result<Frame, TransportError>;
    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError>;
    async fn close(&mut self) -> Result<(), TransportError>;
    fn id(&self) -> TransportId;
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec: {0}")]
    Codec(#[from] tetherand_codec::CodecError),
    #[error("transport closed unexpectedly")]
    Closed,
    #[error("transport not connected")]
    NotConnected,
    #[error("other: {0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_render_to_stable_strings() {
        assert_eq!(TransportId::UsbAdb.as_str(),    "usb-adb");
        assert_eq!(TransportId::UsbAoa.as_str(),    "usb-aoa");
        assert_eq!(TransportId::Bluetooth.as_str(), "bluetooth");
        assert_eq!(TransportId::Tcp.as_str(),       "tcp");
    }
}
