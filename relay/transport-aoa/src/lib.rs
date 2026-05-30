//! USB Android Open Accessory (AOA) transport.
//!
//! Wire protocol per Google's Android Open Accessory Protocol 2.0:
//!   1. Host sends GET_PROTOCOL (control IN, request 51).
//!   2. If device replies >= 1, host sends SEND_STRING (control OUT,
//!      request 52) with manufacturer / model / description / version
//!      / URI / serial identifiers.
//!   3. Host sends START (control OUT, request 53). Device resets and
//!      re-enumerates as an AOA-mode device with new vendor:product
//!      (0x18d1:0x2d00 or 0x2d01) exposing bulk-IN/bulk-OUT endpoints.
//!   4. Host reopens the new device + claims interface 0, reads/writes
//!      Tetherand frames over the bulk endpoints.
//!
//! Status: built; the host-side state machine drives the mode switch
//! and frame exchange. The Android side handles the
//! USB_ACCESSORY_ATTACHED intent and exposes the ParcelFileDescriptor
//! to the Tetherand foreground service (AoaAccessoryService.kt).

use async_trait::async_trait;
use bytes::BytesMut;
use std::time::Duration;
use tetherand_codec::{Frame, FrameType};
use tetherand_transport_api::{Capabilities, Transport, TransportError, TransportId};
use thiserror::Error;

/// Google's AOA-mode vendor ID.
pub const AOA_VENDOR_ID: u16 = 0x18d1;
/// AOA-mode product IDs — 0x2d00 (no ADB) / 0x2d01 (with ADB).
pub const AOA_PRODUCT_IDS: &[u16] = &[0x2d00, 0x2d01];

/// AOA Identifier strings sent during mode switch.
pub struct AoaIdentity {
    pub manufacturer: &'static str,
    pub model:        &'static str,
    pub description:  &'static str,
    pub version:      &'static str,
    pub uri:          &'static str,
    pub serial:       &'static str,
}

pub const TETHERAND_AOA_IDENTITY: AoaIdentity = AoaIdentity {
    manufacturer: "Tetherand",
    model:        "TetherandRelay",
    description:  "Reverse-tethering relay for the Tetherand APK.",
    version:      env!("CARGO_PKG_VERSION"),
    uri:          "https://github.com/pq-cybarg/tetherand",
    serial:       "0001",
};

#[derive(Debug, Error)]
pub enum AoaError {
    #[error("libusb: {0}")] Usb(#[from] rusb::Error),
    #[error("no matching device (vid={vid:04x}, pid={pid:04x})")]
    DeviceNotFound { vid: u16, pid: u16 },
    #[error("device does not speak AOA (GET_PROTOCOL returned 0)")]
    NoAoa,
    #[error("device did not re-enumerate as AOA after START (waited {0:?})")]
    NoReEnumerate(Duration),
    #[error("no bulk-IN/OUT endpoint pair on the AOA interface")]
    NoBulkEndpoints,
}

pub struct AoaTransport {
    read_buf: BytesMut,
    target_vid: u16,
    target_pid: u16,
    handle: Option<rusb::DeviceHandle<rusb::GlobalContext>>,
    ep_in: u8,
    ep_out: u8,
    bulk_mtu: usize,
    timeout: Duration,
}

impl AoaTransport {
    /// Construct a transport that will look for `vid:pid` (the device's
    /// pre-AOA identity) and walk it into accessory mode. After the
    /// mode switch the device re-enumerates as 0x18d1:0x2d00 or 0x2d01.
    ///
    /// For a Solana Seeker the pre-AOA IDs are 0x18d1:0x4ee7 (MTP) or
    /// 0x18d1:0x4ee2 (MTP+ADB).
    pub fn new(target_vid: u16, target_pid: u16) -> Self {
        Self {
            read_buf: BytesMut::with_capacity(8192),
            target_vid,
            target_pid,
            handle: None,
            ep_in: 0,
            ep_out: 0,
            bulk_mtu: 16384,
            timeout: Duration::from_millis(2000),
        }
    }

    /// AOA mode-switch control-transfer requests.
    pub const REQ_GET_PROTOCOL: u8 = 51;
    pub const REQ_SEND_STRING:  u8 = 52;
    pub const REQ_START:        u8 = 53;

    /// Override the default 2 s control-transfer timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self { self.timeout = t; self }

    /// Find the target device, drive the AOA handshake, then return the
    /// re-enumerated accessory's claim. This is the synchronous core;
    /// the async `Transport::connect` wraps it on tokio's blocking
    /// pool because rusb is blocking.
    fn connect_blocking(&mut self) -> Result<(), AoaError> {
        // 1) Locate the device by vid:pid.
        let dev = rusb::devices()?
            .iter()
            .find(|d| {
                d.device_descriptor()
                    .map(|desc| desc.vendor_id() == self.target_vid
                             && desc.product_id() == self.target_pid)
                    .unwrap_or(false)
            })
            .ok_or(AoaError::DeviceNotFound { vid: self.target_vid, pid: self.target_pid })?;

        // 2) Open the device + check it speaks AOA via GET_PROTOCOL.
        let h = dev.open()?;
        let mut proto_buf = [0u8; 2];
        // bmRequestType for vendor-class IN: 0xC0.
        let n = h.read_control(0xC0, Self::REQ_GET_PROTOCOL, 0, 0, &mut proto_buf, self.timeout)?;
        if n != 2 {
            return Err(AoaError::NoAoa);
        }
        let proto = u16::from_le_bytes(proto_buf);
        if proto == 0 {
            return Err(AoaError::NoAoa);
        }

        // 3) SEND_STRING ×6 — manufacturer, model, description,
        //    version, uri, serial — in spec-defined string-id order.
        let strings: &[(u16, &str)] = &[
            (0, TETHERAND_AOA_IDENTITY.manufacturer),
            (1, TETHERAND_AOA_IDENTITY.model),
            (2, TETHERAND_AOA_IDENTITY.description),
            (3, TETHERAND_AOA_IDENTITY.version),
            (4, TETHERAND_AOA_IDENTITY.uri),
            (5, TETHERAND_AOA_IDENTITY.serial),
        ];
        for (idx, s) in strings {
            let mut bytes = s.as_bytes().to_vec();
            bytes.push(0); // C-string terminator per spec
            // bmRequestType for vendor-class OUT: 0x40.
            h.write_control(0x40, Self::REQ_SEND_STRING, 0, *idx, &bytes, self.timeout)?;
        }

        // 4) START. After this, the device resets and re-enumerates.
        h.write_control(0x40, Self::REQ_START, 0, 0, &[], self.timeout)?;
        drop(h);

        // 5) Poll for the re-enumerated device. Spec allows up to ~5 s
        //    for the device-side stack to come back. We poll for up
        //    to 6 s in 200 ms increments.
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        let aoa: rusb::Device<rusb::GlobalContext> = 'find: loop {
            for dev in rusb::devices()?.iter() {
                let desc = match dev.device_descriptor() { Ok(d) => d, Err(_) => continue };
                if desc.vendor_id() == AOA_VENDOR_ID
                    && AOA_PRODUCT_IDS.contains(&desc.product_id())
                {
                    break 'find dev;
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(AoaError::NoReEnumerate(Duration::from_secs(6)));
            }
            std::thread::sleep(Duration::from_millis(200));
        };

        // 6) Open + claim interface 0 + locate the bulk-IN/OUT pair.
        let h = aoa.open()?;
        h.set_auto_detach_kernel_driver(true).ok();
        let cfg = aoa.active_config_descriptor()?;
        let iface = cfg.interfaces().next().ok_or(AoaError::NoBulkEndpoints)?;
        let setting = iface.descriptors().next().ok_or(AoaError::NoBulkEndpoints)?;
        h.claim_interface(setting.interface_number())?;

        let mut ep_in = 0u8;
        let mut ep_out = 0u8;
        let mut mtu = 16384usize;
        for ep in setting.endpoint_descriptors() {
            let ttype: rusb::TransferType = ep.transfer_type();
            if ttype != rusb::TransferType::Bulk { continue; }
            mtu = mtu.min(ep.max_packet_size() as usize * 32);
            let dir: rusb::Direction = ep.direction();
            match dir {
                rusb::Direction::In  => ep_in = ep.address(),
                rusb::Direction::Out => ep_out = ep.address(),
            }
        }
        if ep_in == 0 || ep_out == 0 {
            return Err(AoaError::NoBulkEndpoints);
        }
        self.ep_in = ep_in;
        self.ep_out = ep_out;
        self.bulk_mtu = mtu;
        self.handle = Some(h);
        Ok(())
    }
}

impl Default for AoaTransport {
    /// Default-target a Seeker in MTP+ADB mode (0x18d1:0x4ee2). Use
    /// `AoaTransport::new(vid, pid)` for any other device.
    fn default() -> Self { Self::new(0x18d1, 0x4ee2) }
}

#[async_trait]
impl Transport for AoaTransport {
    async fn connect(&mut self) -> Result<Capabilities, TransportError> {
        // rusb is blocking — bounce through tokio's blocking pool.
        let target_vid = self.target_vid;
        let target_pid = self.target_pid;
        let timeout = self.timeout;
        let res = tokio::task::spawn_blocking(move || {
            let mut t = AoaTransport::new(target_vid, target_pid).with_timeout(timeout);
            t.connect_blocking().map(|_| t)
        }).await
            .map_err(|e| TransportError::Other(format!("join: {e}")))?
            .map_err(|e| TransportError::Other(format!("aoa: {e}")))?;
        // Move the populated transport state back into self.
        self.handle  = res.handle;
        self.ep_in   = res.ep_in;
        self.ep_out  = res.ep_out;
        self.bulk_mtu = res.bulk_mtu;

        Ok(Capabilities {
            id: TransportId::UsbAoa,
            mtu: self.bulk_mtu.min(u16::MAX as usize) as u16,
            bandwidth_hint_bps: 30_000_000,
            latency_hint_ms: 5,
        })
    }

    async fn next_frame(&mut self) -> Result<Frame, TransportError> {
        let handle = self.handle.as_ref().ok_or(TransportError::NotConnected)?.clone_handle();
        let ep_in = self.ep_in;
        let mtu = self.bulk_mtu;
        let timeout = self.timeout;
        let bytes = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; mtu];
            let n = handle.read_bulk(ep_in, &mut buf, timeout)
                .map_err(|e| TransportError::Other(format!("read_bulk: {e}")))?;
            buf.truncate(n);
            Ok::<_, TransportError>(buf)
        }).await
            .map_err(|e| TransportError::Other(format!("join: {e}")))??;
        if bytes.is_empty() { return Err(TransportError::Closed); }
        Ok(Frame::new(FrameType::IpPacket, bytes))
    }

    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        let handle = self.handle.as_ref().ok_or(TransportError::NotConnected)?.clone_handle();
        let ep_out = self.ep_out;
        let timeout = self.timeout;
        let payload = frame.payload.to_vec();
        tokio::task::spawn_blocking(move || {
            handle.write_bulk(ep_out, &payload, timeout)
                .map_err(|e| TransportError::Other(format!("write_bulk: {e}")))
        }).await
            .map_err(|e| TransportError::Other(format!("join: {e}")))??;
        Ok(())
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.handle = None;
        self.read_buf.clear();
        Ok(())
    }

    fn id(&self) -> TransportId { TransportId::UsbAoa }
}

/// Convenience: clone a rusb DeviceHandle so we can hand it to a
/// blocking task without owning the AoaTransport. rusb's DeviceHandle
/// is Send + Sync, but our internal field is Option-wrapped and
/// mutable, so we shake out a fresh handle by re-opening.
trait CloneHandle {
    fn clone_handle(&self) -> rusb::DeviceHandle<rusb::GlobalContext>;
}
impl CloneHandle for rusb::DeviceHandle<rusb::GlobalContext> {
    fn clone_handle(&self) -> rusb::DeviceHandle<rusb::GlobalContext> {
        // rusb doesn't expose a clone() on DeviceHandle. Open a fresh
        // one against the same device descriptor.
        let dev = self.device();
        dev.open().expect("aoa: cannot re-open device handle in blocking task")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn aoa_constants_per_spec() {
        assert_eq!(AOA_VENDOR_ID, 0x18d1);
        assert!(AOA_PRODUCT_IDS.contains(&0x2d00));
        assert!(AOA_PRODUCT_IDS.contains(&0x2d01));
        assert_eq!(AoaTransport::REQ_GET_PROTOCOL, 51);
        assert_eq!(AoaTransport::REQ_SEND_STRING,  52);
        assert_eq!(AoaTransport::REQ_START,        53);
    }

    #[test] fn identity_strings_set() {
        assert_eq!(TETHERAND_AOA_IDENTITY.manufacturer, "Tetherand");
    }

    #[test] fn default_targets_seeker_mtp_adb() {
        let t = AoaTransport::default();
        assert_eq!(t.target_vid, 0x18d1);
        assert_eq!(t.target_pid, 0x4ee2);
    }
}
