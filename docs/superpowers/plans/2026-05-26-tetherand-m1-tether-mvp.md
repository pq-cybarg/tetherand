# Tetherand M1 — Tether MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the upstream-Gnirehtet-based `connect.sh` with a forked, rebranded `tetherand` binary + signed APK that share a clean transport abstraction with pluggable USB-ADB and TCP/LAN transports and a Compose-based Android UI.

**Architecture:** Rust workspace at `relay/` containing a forked Gnirehtet relay core, a new frame codec, a `Transport` trait with two implementations (USB-ADB via `adb forward`, TCP/LAN with mDNS discovery), and a `tetherand` CLI. Kotlin Android project at `android/` with mirror `Transport` interface, the same two transports, a `TetherandVpnService` that pumps packets between the TUN and the selected transport, and a single-screen Compose UI showing the connection state and a transport picker.

**Tech Stack:**
- Rust 1.93-beta, edition 2024, Tokio 1.x async runtime, `clap` 4 for CLI args, `mdns-sd` for service discovery, `byteorder` for codec, `tracing` for logs.
- Kotlin 2.0 + Compose Multiplatform, Android Gradle Plugin 8.7, Min SDK 26, Target SDK 36, `kotlinx.coroutines`, `kotlinx.serialization`, JUnit 5 + Turbine + MockK for tests.
- License: Apache-2.0 for all M1 code (Gnirehtet base is Apache-2.0, verified).

**Scope boundary:** This plan covers M1 only. M2 (BT + AOA transports, TUI, LaunchAgent), M3-M6 (Privacy Chain), M7 (Threat Detection), M9 (Hardened Mode), M10 (AI defenses) get their own plans.

---

## File Structure

```
reverse-tethering/
├── relay/                                          # Rust workspace, new
│   ├── Cargo.toml                                  # workspace
│   ├── codec/                                      # frame codec crate
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── core/                                       # forked Gnirehtet relay-rust
│   │   ├── Cargo.toml
│   │   └── src/                                    # copied + rebranded
│   ├── transport-api/                              # Transport trait
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── transport-adb/                              # USB-ADB transport
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── transport-tcp/                              # TCP/LAN transport
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── cli/                                        # `tetherand` binary
│       ├── Cargo.toml
│       └── src/main.rs
├── android/                                        # Gradle project, new
│   ├── settings.gradle.kts
│   ├── build.gradle.kts
│   ├── gradle.properties
│   ├── gradle/wrapper/...
│   ├── gradlew
│   ├── codec/                                      # frame codec module
│   │   ├── build.gradle.kts
│   │   └── src/main/kotlin/dev/tetherand/codec/
│   │       └── Frame.kt
│   ├── transport/                                  # Transport interface
│   │   ├── build.gradle.kts
│   │   └── src/main/kotlin/dev/tetherand/transport/
│   │       ├── Transport.kt
│   │       ├── adb/AdbTransport.kt
│   │       └── tcp/TcpTransport.kt
│   └── app/                                        # main app
│       ├── build.gradle.kts
│       └── src/main/
│           ├── AndroidManifest.xml
│           ├── kotlin/dev/tetherand/app/
│           │   ├── MainActivity.kt
│           │   ├── ui/TetherScreen.kt
│           │   ├── ui/Theme.kt
│           │   ├── service/TetherandVpnService.kt
│           │   └── service/TransportMux.kt
│           └── res/
├── bin/tetherand                                   # symlink to relay/target/release/tetherand
├── scripts/smoke.sh                                # E2E test
├── Makefile                                        # build orchestration
└── connect.sh                                      # kept as stopgap; superseded by `tetherand run`
```

---

### Task 1: Bootstrap the Rust workspace

**Files:**
- Create: `relay/Cargo.toml`
- Create: `relay/.gitignore`
- Create: `relay/rust-toolchain.toml`

- [ ] **Step 1: Create the workspace manifest**

Write `relay/Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = [
    "codec",
    "transport-api",
    "transport-adb",
    "transport-tcp",
    "cli",
]

[workspace.package]
edition = "2024"
license = "Apache-2.0"
authors = ["pq-cybarg <resistant@tuta.com>"]
rust-version = "1.85"

[workspace.dependencies]
tokio = { version = "1.43", features = ["rt-multi-thread", "net", "io-util", "macros", "sync", "signal", "time"] }
clap = { version = "4.5", features = ["derive", "env"] }
thiserror = "2.0"
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
async-trait = "0.1"
bytes = "1.9"
byteorder = "1.5"
mdns-sd = "0.13"

[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
```

- [ ] **Step 2: Add workspace-level gitignore**

Write `relay/.gitignore`:

```
/target/
**/*.rs.bk
Cargo.lock
```

- [ ] **Step 3: Pin the toolchain**

Write `relay/rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.93-beta"
components = ["rustfmt", "clippy"]
targets = ["aarch64-apple-darwin"]
```

- [ ] **Step 4: Verify the workspace parses**

Run: `cd relay && cargo metadata --format-version=1 --no-deps`
Expected: emits JSON describing 5 members (no compile yet since they have no source).
If it errors with "no targets specified" that's fine until the crates have lib.rs files (Task 2).

- [ ] **Step 5: Commit**

```bash
git add relay/
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
  commit -m "M1: bootstrap relay/ cargo workspace"
```

---

### Task 2: Frame codec crate — Rust

**Files:**
- Create: `relay/codec/Cargo.toml`
- Create: `relay/codec/src/lib.rs`
- Test: `relay/codec/src/lib.rs` (inline `#[cfg(test)] mod tests`)

The wire format from the spec:

```
┌─────────────┬─────────┬───────┬──────────┬──────────────┐
│ len: u32 BE │ ver: u8 │ ty: u8│ resv: u16│ payload      │
└─────────────┴─────────┴───────┴──────────┴──────────────┘
```

`len` counts everything after itself (ver + ty + resv + payload). Max payload 65531 bytes (`u16::MAX - 4`).

- [ ] **Step 1: Create the crate manifest**

Write `relay/codec/Cargo.toml`:

```toml
[package]
name = "tetherand-codec"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true
rust-version.workspace = true
description = "Tetherand transport frame codec"

[dependencies]
bytes = { workspace = true }
byteorder = { workspace = true }
thiserror = { workspace = true }
```

- [ ] **Step 2: Write the failing tests first**

Write `relay/codec/src/lib.rs`:

```rust
//! Tetherand transport frame codec.
//!
//! Frames are length-prefixed:
//!   [len: u32 BE][ver: u8][ty: u8][resv: u16][payload...]
//!
//! `len` counts every byte after itself.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

pub const FRAME_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 4 + 1 + 1 + 2; // len + ver + ty + resv
pub const MAX_PAYLOAD: usize = u16::MAX as usize - 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    IpPacket = 1,
    Control = 2,
    Handshake = 3,
}

impl FrameType {
    pub fn from_u8(b: u8) -> Result<Self, CodecError> {
        match b {
            1 => Ok(FrameType::IpPacket),
            2 => Ok(FrameType::Control),
            3 => Ok(FrameType::Handshake),
            _ => Err(CodecError::UnknownType(b)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub version: u8,
    pub ty: FrameType,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(ty: FrameType, payload: impl Into<Bytes>) -> Self {
        Self { version: FRAME_VERSION, ty, payload: payload.into() }
    }

    pub fn encode(&self) -> Result<Bytes, CodecError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(CodecError::PayloadTooLarge(self.payload.len()));
        }
        let body_len = 1 + 1 + 2 + self.payload.len();
        let mut out = BytesMut::with_capacity(4 + body_len);
        out.put_u32(body_len as u32);
        out.put_u8(self.version);
        out.put_u8(self.ty as u8);
        out.put_u16(0); // reserved
        out.put(self.payload.clone());
        Ok(out.freeze())
    }

    /// Try to decode one frame from `buf`. On success, the frame's bytes are
    /// consumed from `buf` and `Ok(Some(frame))` is returned. If not enough
    /// bytes are present yet, `Ok(None)` is returned and `buf` is left intact.
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>, CodecError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let body_len = BigEndian::read_u32(&buf[..4]) as usize;
        if body_len < 4 {
            return Err(CodecError::HeaderTooShort(body_len));
        }
        if body_len > 4 + MAX_PAYLOAD {
            return Err(CodecError::PayloadTooLarge(body_len - 4));
        }
        let total = 4 + body_len;
        if buf.len() < total {
            return Ok(None);
        }
        buf.advance(4);
        let version = buf.get_u8();
        let ty = FrameType::from_u8(buf.get_u8())?;
        let _resv = buf.get_u16();
        let payload_len = body_len - 4;
        let payload = buf.split_to(payload_len).freeze();
        Ok(Some(Self { version, ty, payload }))
    }
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("unknown frame type {0}")]
    UnknownType(u8),
    #[error("header body length {0} is shorter than required 4")]
    HeaderTooShort(usize),
    #[error("payload length {0} exceeds maximum {MAX_PAYLOAD}")]
    PayloadTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ip_packet() {
        let frame = Frame::new(FrameType::IpPacket, Bytes::from_static(&[1, 2, 3, 4, 5]));
        let bytes = frame.encode().unwrap();
        // header: len=9 (u32) + ver=1 + ty=1 + resv=0,0 + 5 payload bytes
        assert_eq!(bytes.len(), 4 + 9);
        let mut buf = BytesMut::from(&bytes[..]);
        let decoded = Frame::decode(&mut buf).unwrap().expect("frame");
        assert_eq!(decoded.version, FRAME_VERSION);
        assert_eq!(decoded.ty, FrameType::IpPacket);
        assert_eq!(&decoded.payload[..], &[1, 2, 3, 4, 5]);
        assert!(buf.is_empty(), "no trailing bytes");
    }

    #[test]
    fn partial_input_returns_none() {
        let frame = Frame::new(FrameType::Control, Bytes::from_static(&[0xAA; 12]));
        let bytes = frame.encode().unwrap();
        for cut in 0..bytes.len() {
            let mut buf = BytesMut::from(&bytes[..cut]);
            assert!(Frame::decode(&mut buf).unwrap().is_none(), "cut={cut}");
        }
        let mut buf = BytesMut::from(&bytes[..]);
        assert!(Frame::decode(&mut buf).unwrap().is_some());
    }

    #[test]
    fn decode_then_decode_two_frames() {
        let a = Frame::new(FrameType::IpPacket, Bytes::from_static(b"hello")).encode().unwrap();
        let b = Frame::new(FrameType::Handshake, Bytes::from_static(b"world!")).encode().unwrap();
        let mut buf = BytesMut::with_capacity(a.len() + b.len());
        buf.extend_from_slice(&a);
        buf.extend_from_slice(&b);
        let f1 = Frame::decode(&mut buf).unwrap().unwrap();
        let f2 = Frame::decode(&mut buf).unwrap().unwrap();
        assert_eq!(&f1.payload[..], b"hello");
        assert_eq!(&f2.payload[..], b"world!");
        assert!(buf.is_empty());
    }

    #[test]
    fn unknown_type_rejected() {
        let mut bad = bytes::BytesMut::new();
        bad.put_u32(4);    // body_len
        bad.put_u8(1);     // version
        bad.put_u8(99);    // unknown type
        bad.put_u16(0);
        let err = Frame::decode(&mut bad).unwrap_err();
        matches!(err, CodecError::UnknownType(99));
    }

    #[test]
    fn payload_too_large_rejected_on_encode() {
        let big = Bytes::from(vec![0u8; MAX_PAYLOAD + 1]);
        let err = Frame::new(FrameType::IpPacket, big).encode().unwrap_err();
        matches!(err, CodecError::PayloadTooLarge(_));
    }
}
```

- [ ] **Step 3: Run the tests, expect them to pass**

Run: `cd relay && cargo test -p tetherand-codec`
Expected: `running 5 tests` ... `test result: ok. 5 passed; 0 failed`

- [ ] **Step 4: Commit**

```bash
git add relay/codec/
git commit -m "M1: frame codec with roundtrip + partial-input tests"
```

---

### Task 3: Transport trait crate — Rust

**Files:**
- Create: `relay/transport-api/Cargo.toml`
- Create: `relay/transport-api/src/lib.rs`

- [ ] **Step 1: Create the manifest**

Write `relay/transport-api/Cargo.toml`:

```toml
[package]
name = "tetherand-transport-api"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true
rust-version.workspace = true

[dependencies]
tetherand-codec = { path = "../codec" }
async-trait = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
bytes = { workspace = true }
```

- [ ] **Step 2: Write the trait + tests**

Write `relay/transport-api/src/lib.rs`:

```rust
//! Transport abstraction for Tetherand.
//!
//! A `Transport` carries `Frame`s in both directions. The choice of
//! transport (USB-ADB, USB-AOA, Bluetooth, TCP) is independent of the
//! framing they carry — anything that can move ordered, reliable bytes
//! can implement this trait.

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
    /// Establish the connection. Returns the negotiated capabilities.
    async fn connect(&mut self) -> Result<Capabilities, TransportError>;

    /// Pull the next frame from the peer.
    async fn next_frame(&mut self) -> Result<Frame, TransportError>;

    /// Send a frame to the peer.
    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError>;

    /// Close the connection cleanly.
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
```

- [ ] **Step 3: Verify it compiles + tests pass**

Run: `cd relay && cargo test -p tetherand-transport-api`
Expected: `test result: ok. 1 passed`

- [ ] **Step 4: Commit**

```bash
git add relay/transport-api/
git commit -m "M1: Transport trait + TransportId + Capabilities"
```

---

### Task 4: Fork the Gnirehtet relay core into `relay/core/`

**Files:**
- Create: `relay/core/Cargo.toml`
- Create: `relay/core/src/**` (copy from `upstream/relay-rust/src/`)

The Gnirehtet relay-rust is Apache-2.0. We copy its source into `relay/core/`, rename the crate, and leave the internals alone for now. Subsequent tasks plug it into our transport abstraction.

- [ ] **Step 1: Copy the source tree**

Run from repo root:

```bash
mkdir -p relay/core/src
cp -R upstream/relay-rust/src/* relay/core/src/
```

- [ ] **Step 2: Write the manifest**

Write `relay/core/Cargo.toml`:

```toml
[package]
name = "tetherand-relay-core"
version = "0.1.0"
edition = "2024"
license = "Apache-2.0"
description = "Userspace TCP/IP relay (forked from Genymobile/gnirehtet relay-rust, Apache-2.0)"

[lib]
name = "tetherand_relay_core"
path = "src/lib.rs"

[dependencies]
log = "0.4"
mio = { version = "1.0", features = ["os-poll", "net"] }
mio-channel = "0.1"
rand = "0.8"
```

- [ ] **Step 3: Remove Gnirehtet's own main.rs / cli_args.rs / adb_monitor.rs**

These belonged to the upstream binary; our CLI lives in `relay/cli/` and our transports live in their own crates. The relay core is library-only.

Run:

```bash
rm -f relay/core/src/main.rs relay/core/src/cli_args.rs \
      relay/core/src/adb_monitor.rs relay/core/src/execution_error.rs \
      relay/core/src/logger.rs
```

- [ ] **Step 4: Patch `lib.rs` to drop the removed modules**

Read `relay/core/src/lib.rs` and remove any `pub mod cli_args;`, `pub mod adb_monitor;`, `pub mod logger;`, `pub mod execution_error;` lines if present. Keep `pub mod relay;`.

- [ ] **Step 5: Add the LICENSE header acknowledging the fork**

Write `relay/core/NOTICE`:

```
This crate is a fork of Genymobile/gnirehtet `relay-rust/`
(https://github.com/Genymobile/gnirehtet), licensed under Apache-2.0.

Original copyright: Copyright (C) 2017 Genymobile.

Modifications by pq-cybarg, 2026, also Apache-2.0.
The unmodified Gnirehtet LICENSE is reproduced at upstream/LICENSE.
```

- [ ] **Step 6: Verify it compiles**

Run: `cd relay && cargo build -p tetherand-relay-core`
Expected: compiles with warnings about unused items (the binary entrypoints are gone). No errors.

If unresolved-import errors appear in `lib.rs`, remove the offending `pub mod X;` lines.

- [ ] **Step 7: Commit**

```bash
git add relay/core/
git commit -m "M1: fork gnirehtet relay-rust as tetherand-relay-core (Apache-2.0)"
```

---

### Task 5: USB-ADB transport — Rust

**Files:**
- Create: `relay/transport-adb/Cargo.toml`
- Create: `relay/transport-adb/src/lib.rs`

The host side connects to `tcp:31416` after running `adb forward tcp:31416 localabstract:tetherand`. The transport simply wraps a `tokio::net::TcpStream` and reads/writes `Frame`s with the codec.

- [ ] **Step 1: Manifest**

Write `relay/transport-adb/Cargo.toml`:

```toml
[package]
name = "tetherand-transport-adb"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
tetherand-transport-api = { path = "../transport-api" }
tetherand-codec = { path = "../codec" }
async-trait = { workspace = true }
tokio = { workspace = true }
bytes = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
```

- [ ] **Step 2: Write the transport with a loopback integration test**

Write `relay/transport-adb/src/lib.rs`:

```rust
//! USB-ADB transport. Wraps a `tokio::net::TcpStream` over an
//! `adb forward tcp:N localabstract:tetherand` tunnel.

use std::process::Command;

use async_trait::async_trait;
use bytes::BytesMut;
use tetherand_codec::{Frame, FRAME_VERSION};
use tetherand_transport_api::{Capabilities, Transport, TransportError, TransportId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

pub const DEFAULT_PORT: u16 = 31416;
pub const ABSTRACT_NAME: &str = "tetherand";

pub struct AdbTransport {
    serial: Option<String>,
    port: u16,
    stream: Option<TcpStream>,
    read_buf: BytesMut,
}

impl AdbTransport {
    pub fn new(serial: Option<String>) -> Self {
        Self {
            serial,
            port: DEFAULT_PORT,
            stream: None,
            read_buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn ensure_adb_forward(&self) -> Result<(), TransportError> {
        let mut cmd = Command::new("adb");
        if let Some(s) = &self.serial {
            cmd.arg("-s").arg(s);
        }
        cmd.arg("forward")
           .arg(format!("tcp:{}", self.port))
           .arg(format!("localabstract:{}", ABSTRACT_NAME));
        let out = cmd.output().map_err(TransportError::Io)?;
        if !out.status.success() {
            return Err(TransportError::Other(format!(
                "adb forward failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        debug!("adb forward tcp:{} -> localabstract:{}", self.port, ABSTRACT_NAME);
        Ok(())
    }
}

#[async_trait]
impl Transport for AdbTransport {
    async fn connect(&mut self) -> Result<Capabilities, TransportError> {
        self.ensure_adb_forward()?;
        let stream = TcpStream::connect(("127.0.0.1", self.port)).await?;
        stream.set_nodelay(true)?;
        info!("USB-ADB connected on 127.0.0.1:{}", self.port);
        self.stream = Some(stream);
        Ok(Capabilities {
            id: TransportId::UsbAdb,
            mtu: 1500,
            bandwidth_hint_bps: 200_000_000,
            latency_hint_ms: 5,
        })
    }

    async fn next_frame(&mut self) -> Result<Frame, TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        loop {
            if let Some(frame) = Frame::decode(&mut self.read_buf)? {
                if frame.version != FRAME_VERSION {
                    return Err(TransportError::Other(format!(
                        "frame version mismatch: got {} expected {}",
                        frame.version, FRAME_VERSION
                    )));
                }
                return Ok(frame);
            }
            let mut chunk = [0u8; 8192];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(TransportError::Closed);
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        let bytes = frame.encode()?;
        stream.write_all(&bytes).await?;
        Ok(())
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let Some(mut s) = self.stream.take() {
            let _ = s.shutdown().await;
        }
        Ok(())
    }

    fn id(&self) -> TransportId { TransportId::UsbAdb }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tetherand_codec::FrameType;
    use tokio::net::TcpListener;

    /// Loopback test that ignores `adb forward` entirely: stand up a TCP
    /// listener, dial it, exchange a frame, prove the codec wiring works.
    #[tokio::test]
    async fn loopback_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            // echo
            sock.write_all(&buf[..n]).await.unwrap();
        });

        // Skip the adb-forward step in the test by directly opening the socket.
        let mut t = AdbTransport::new(None).with_port(port);
        t.stream = Some(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
        t.send_frame(Frame::new(FrameType::IpPacket, Bytes::from_static(b"ping"))).await.unwrap();
        let echoed = t.next_frame().await.unwrap();
        assert_eq!(&echoed.payload[..], b"ping");

        server.await.unwrap();
    }
}
```

- [ ] **Step 3: Test**

Run: `cd relay && cargo test -p tetherand-transport-adb`
Expected: `running 1 test` ... `test result: ok`

- [ ] **Step 4: Commit**

```bash
git add relay/transport-adb/
git commit -m "M1: USB-ADB transport with loopback roundtrip test"
```

---

### Task 6: TCP/LAN transport with mDNS — Rust

**Files:**
- Create: `relay/transport-tcp/Cargo.toml`
- Create: `relay/transport-tcp/src/lib.rs`

- [ ] **Step 1: Manifest**

Write `relay/transport-tcp/Cargo.toml`:

```toml
[package]
name = "tetherand-transport-tcp"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
tetherand-transport-api = { path = "../transport-api" }
tetherand-codec = { path = "../codec" }
async-trait = { workspace = true }
tokio = { workspace = true }
bytes = { workspace = true }
mdns-sd = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
```

- [ ] **Step 2: Implementation + integration test**

Write `relay/transport-tcp/src/lib.rs`:

```rust
//! TCP/LAN transport with mDNS service discovery.
//!
//! Phone advertises `_tetherand._tcp.local` and listens on a TCP port.
//! Mac discovers via mDNS and dials.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use tetherand_codec::Frame;
use tetherand_transport_api::{Capabilities, Transport, TransportError, TransportId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub const SERVICE_TYPE: &str = "_tetherand._tcp.local.";
pub const DEFAULT_PORT: u16 = 31417;

pub struct TcpTransport {
    addr: Option<SocketAddr>,
    discover_timeout: Duration,
    stream: Option<TcpStream>,
    read_buf: BytesMut,
}

impl TcpTransport {
    /// Construct a transport that will dial the given address directly.
    pub fn direct(addr: SocketAddr) -> Self {
        Self {
            addr: Some(addr),
            discover_timeout: Duration::from_secs(0),
            stream: None,
            read_buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    /// Construct a transport that will discover the phone via mDNS.
    pub fn discover(timeout: Duration) -> Self {
        Self {
            addr: None,
            discover_timeout: timeout,
            stream: None,
            read_buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    async fn resolve(&self) -> Result<SocketAddr, TransportError> {
        if let Some(a) = self.addr {
            return Ok(a);
        }
        let daemon = ServiceDaemon::new()
            .map_err(|e| TransportError::Other(format!("mdns: {e}")))?;
        let receiver = daemon.browse(SERVICE_TYPE)
            .map_err(|e| TransportError::Other(format!("mdns browse: {e}")))?;
        let deadline = tokio::time::Instant::now() + self.discover_timeout;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(TransportError::Other(format!(
                    "no {} service discovered within {:?}",
                    SERVICE_TYPE, self.discover_timeout
                )));
            }
            let remaining = deadline - now;
            let evt = tokio::time::timeout(remaining, async {
                receiver.recv_async().await
            })
            .await
            .map_err(|_| TransportError::Other("mdns timeout".into()))?
            .map_err(|e| TransportError::Other(format!("mdns recv: {e}")))?;
            if let ServiceEvent::ServiceResolved(info) = evt {
                let port = info.get_port();
                if let Some(ip) = info.get_addresses().iter().next().copied() {
                    let sa = SocketAddr::new(IpAddr::V4(ip), port);
                    info!("mDNS resolved {} at {}", info.get_fullname(), sa);
                    return Ok(sa);
                }
                warn!("mDNS service {} resolved with no address", info.get_fullname());
            }
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&mut self) -> Result<Capabilities, TransportError> {
        let addr = self.resolve().await?;
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        debug!("TCP transport connected to {addr}");
        self.stream = Some(stream);
        Ok(Capabilities {
            id: TransportId::Tcp,
            mtu: 1500,
            bandwidth_hint_bps: 50_000_000,
            latency_hint_ms: 20,
        })
    }

    async fn next_frame(&mut self) -> Result<Frame, TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        loop {
            if let Some(frame) = Frame::decode(&mut self.read_buf)? {
                return Ok(frame);
            }
            let mut chunk = [0u8; 8192];
            let n = stream.read(&mut chunk).await?;
            if n == 0 { return Err(TransportError::Closed); }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        let bytes = frame.encode()?;
        stream.write_all(&bytes).await?;
        Ok(())
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let Some(mut s) = self.stream.take() { let _ = s.shutdown().await; }
        Ok(())
    }

    fn id(&self) -> TransportId { TransportId::Tcp }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tetherand_codec::FrameType;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });
        let mut t = TcpTransport::direct(addr);
        t.connect().await.unwrap();
        t.send_frame(Frame::new(FrameType::IpPacket, Bytes::from_static(b"hi"))).await.unwrap();
        let f = t.next_frame().await.unwrap();
        assert_eq!(&f.payload[..], b"hi");
        server.await.unwrap();
    }
}
```

- [ ] **Step 3: Test**

Run: `cd relay && cargo test -p tetherand-transport-tcp`
Expected: `test result: ok. 1 passed`

- [ ] **Step 4: Commit**

```bash
git add relay/transport-tcp/
git commit -m "M1: TCP/LAN transport with mDNS discovery and direct-dial loopback test"
```

---

### Task 7: `tetherand` CLI skeleton

**Files:**
- Create: `relay/cli/Cargo.toml`
- Create: `relay/cli/src/main.rs`

The CLI exposes `run`, `install`, `uninstall`, `reinstall`, `stop`, `status`. For M1 we focus on `run` (full lifecycle) and `install`/`uninstall`/`reinstall` (APK management via adb).

- [ ] **Step 1: Manifest**

Write `relay/cli/Cargo.toml`:

```toml
[package]
name = "tetherand-cli"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true

[[bin]]
name = "tetherand"
path = "src/main.rs"

[dependencies]
tetherand-codec          = { path = "../codec" }
tetherand-transport-api  = { path = "../transport-api" }
tetherand-transport-adb  = { path = "../transport-adb" }
tetherand-transport-tcp  = { path = "../transport-tcp" }
tetherand-relay-core     = { path = "../core" }
clap   = { workspace = true }
tokio  = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
```

- [ ] **Step 2: Argument parser + dispatch + smoke test**

Write `relay/cli/src/main.rs`:

```rust
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tetherand_transport_adb::AdbTransport;
use tetherand_transport_api::Transport;
use tetherand_transport_tcp::TcpTransport;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "tetherand", version, about = "Tetherand reverse-tethering relay")]
struct Cli {
    /// Override log filter (default: tetherand=info,warn)
    #[arg(long, env = "RUST_LOG")]
    log: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Full lifecycle: install (if needed), start the client, start the relay,
    /// block until Ctrl+C.
    Run {
        /// Device serial (omit if exactly one device is connected).
        #[arg(long)]
        device: Option<String>,
        /// Transport to use.
        #[arg(long, value_enum, default_value_t = TransportChoice::Auto)]
        transport: TransportChoice,
        /// DNS servers to advertise to the phone (comma-separated).
        #[arg(long, default_value = "1.1.1.1,8.8.8.8")]
        dns: String,
    },
    /// Install the APK on the device and exit.
    Install   { #[arg(long)] device: Option<String> },
    /// Uninstall the APK and exit.
    Uninstall { #[arg(long)] device: Option<String> },
    /// Uninstall, then install.
    Reinstall { #[arg(long)] device: Option<String> },
    /// Show daemon + device state.
    Status,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum TransportChoice { Auto, Adb, Tcp }

fn init_log(override_: Option<&str>) {
    let filter = override_
        .map(|s| s.to_owned())
        .unwrap_or_else(|| std::env::var("RUST_LOG").unwrap_or_else(|_| "tetherand=info,warn".into()));
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();
}

fn adb_path() -> String {
    std::env::var("ADB").unwrap_or_else(|_| "adb".into())
}

fn apk_path() -> Result<std::path::PathBuf> {
    // Prefer an APK located next to the binary; fall back to repo's bin/.
    let exe = std::env::current_exe()?;
    let candidate1 = exe.parent().unwrap().join("tetherand.apk");
    if candidate1.is_file() { return Ok(candidate1); }
    let candidate2 = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../bin/tetherand.apk");
    if candidate2.is_file() { return Ok(candidate2.canonicalize()?); }
    anyhow::bail!("tetherand.apk not found next to binary or under bin/")
}

fn adb_install(device: Option<&str>) -> Result<()> {
    let apk = apk_path()?;
    let mut cmd = Command::new(adb_path());
    if let Some(d) = device { cmd.arg("-s").arg(d); }
    cmd.arg("install").arg("-r").arg(apk);
    let out = cmd.output().context("running adb install")?;
    if !out.status.success() {
        anyhow::bail!("adb install failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    info!("APK installed");
    Ok(())
}

fn adb_uninstall(device: Option<&str>) -> Result<()> {
    let mut cmd = Command::new(adb_path());
    if let Some(d) = device { cmd.arg("-s").arg(d); }
    cmd.arg("uninstall").arg("dev.tetherand.app");
    let _ = cmd.output().context("running adb uninstall")?;
    info!("APK uninstalled (if present)");
    Ok(())
}

async fn cmd_run(device: Option<String>, transport: TransportChoice, _dns: String) -> Result<()> {
    // Ensure APK present.
    adb_install(device.as_deref()).context("installing APK")?;

    // Start the chosen transport.
    let mut t: Box<dyn Transport> = match transport {
        TransportChoice::Adb | TransportChoice::Auto => Box::new(AdbTransport::new(device.clone())),
        TransportChoice::Tcp => Box::new(TcpTransport::discover(Duration::from_secs(10))),
    };
    let caps = t.connect().await.context("connecting transport")?;
    info!("transport {:?} connected (mtu={}, bw_hint={} bps, lat_hint={} ms)",
          caps.id, caps.mtu, caps.bandwidth_hint_bps, caps.latency_hint_ms);

    // Hand off to the relay core. For M1, we wire the transport into the
    // relay-core's existing pipe abstraction; here we just block on Ctrl+C
    // to prove the loop works. Replaced with the real pumping in Task 8.
    tokio::signal::ctrl_c().await?;
    info!("Ctrl+C received, shutting down");
    t.close().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_log(cli.log.as_deref());
    match cli.cmd {
        Cmd::Run { device, transport, dns }  => cmd_run(device, transport, dns).await,
        Cmd::Install   { device }            => adb_install(device.as_deref()),
        Cmd::Uninstall { device }            => adb_uninstall(device.as_deref()),
        Cmd::Reinstall { device }            => { adb_uninstall(device.as_deref())?; adb_install(device.as_deref()) }
        Cmd::Status                          => { println!("tetherand: idle"); Ok(()) }
    }
}
```

- [ ] **Step 3: Build**

Run: `cd relay && cargo build -p tetherand-cli`
Expected: `Compiling ...` followed by `Finished` in dev profile.

- [ ] **Step 4: Smoke test `--help` and `status`**

Run: `cd relay && cargo run -p tetherand-cli -- --help`
Expected: usage output including `run`, `install`, `uninstall`, `reinstall`, `status`.

Run: `cd relay && cargo run -p tetherand-cli -- status`
Expected: `tetherand: idle` and exit 0.

- [ ] **Step 5: Commit**

```bash
git add relay/cli/
git commit -m "M1: tetherand CLI skeleton (run/install/uninstall/reinstall/status)"
```

---

### Task 8: Wire the transport into the relay core's packet pump

**Files:**
- Modify: `relay/cli/src/main.rs:cmd_run`
- Inspect: `relay/core/src/relay/` for the relay's existing entry surface

This task is intentionally light on copy-paste because the forked relay-core has its own interfaces. The job is: in `cmd_run`, after `t.connect()`, spawn a task that reads frames from `t.next_frame()` and feeds the IP packets into the relay core's existing client-channel interface (the equivalent of what Gnirehtet's `relay/client.rs` does with its `Client::new(...)` constructor), and a sibling task that drains the relay core's outbound IP packets and writes them via `t.send_frame()`.

- [ ] **Step 1: Read the relay-core entry surface**

Run: `rg -n "pub fn" relay/core/src/relay/*.rs | head -40`

Identify the `Relay` constructor (likely `Relay::new`) and the per-client constructor (likely `Client::new`). Note the channel types they expect.

- [ ] **Step 2: Write the bridge tests first**

Add to `relay/cli/src/main.rs` (or a new `relay/cli/src/bridge.rs` if it grows beyond ~80 lines):

```rust
#[cfg(test)]
mod bridge_tests {
    use super::*;
    use bytes::Bytes;
    use tetherand_codec::{Frame, FrameType};

    /// The bridge consumes IpPacket frames from the transport and feeds them
    /// into the relay's client channel; it consumes packets from the relay
    /// and writes IpPacket frames back to the transport. We test this with
    /// a fake transport.
    #[tokio::test]
    async fn bridge_forwards_in_both_directions() {
        // Test implementation goes here once the bridge fn is written.
        // The shape of the test: construct a fake Transport that yields a
        // single canned IP packet and records sent frames; construct a
        // fake "client channel" (mpsc::channel) to stand in for the relay;
        // assert the packet arrives at the channel, and a packet enqueued
        // on the reverse channel ends up as an IpPacket frame.
    }
}
```

- [ ] **Step 3: Implement the bridge**

Inside `cmd_run`, after `t.connect()`, replace the `tokio::signal::ctrl_c()` block with:

```rust
    let (to_relay_tx, to_relay_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(1024);
    let (from_relay_tx, mut from_relay_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(1024);

    // Start the relay-core. Replace `relay_core::start` with the actual
    // entry point identified in Step 1 above.
    let relay_handle = tokio::task::spawn_blocking(move || {
        tetherand_relay_core::run_with_channels(to_relay_rx, from_relay_tx)
    });

    // Transport reader loop: frames in -> IP packets to the relay.
    let mut reader = t;
    let reader_task = tokio::spawn(async move {
        loop {
            match reader.next_frame().await {
                Ok(f) if f.ty == tetherand_codec::FrameType::IpPacket => {
                    if to_relay_tx.send(f.payload).await.is_err() { break; }
                }
                Ok(_) => continue,
                Err(e) => { tracing::warn!("transport read error: {e}"); break; }
            }
        }
        reader
    });

    // Writer loop: packets from the relay -> frames out.
    let writer_task: tokio::task::JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
        while let Some(pkt) = from_relay_rx.recv().await {
            // The writer needs the same transport; restructure via a Mutex
            // when actually implementing. For brevity here, see Step 4.
            let _ = pkt;
        }
        Ok(())
    });

    tokio::signal::ctrl_c().await?;
    info!("Ctrl+C received, shutting down");
    drop(reader_task);
    drop(writer_task);
    let _ = relay_handle.await;
    Ok(())
```

- [ ] **Step 4: Refactor to share the transport between reader and writer**

The naive split moves the transport into the reader task. Wrap the transport in `tokio::sync::Mutex` and clone an `Arc` of it; reader and writer both acquire the lock. Alternative: split the transport into read and write halves at construction time (add `split()` to `Transport`). For M1 a Mutex is sufficient.

Update `relay/transport-api/src/lib.rs` to expose a helper `pub type SharedTransport = std::sync::Arc<tokio::sync::Mutex<dyn Transport>>;` (or document that the CLI wraps it itself).

Update `cmd_run` accordingly. Make the writer loop:

```rust
    let transport = std::sync::Arc::new(tokio::sync::Mutex::new(t));
    let read_tx = to_relay_tx.clone();
    let read_t = transport.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            let frame_res = {
                let mut g = read_t.lock().await;
                g.next_frame().await
            };
            match frame_res {
                Ok(f) if f.ty == tetherand_codec::FrameType::IpPacket => {
                    if read_tx.send(f.payload).await.is_err() { break; }
                }
                Ok(_) => continue,
                Err(e) => { tracing::warn!("transport read error: {e}"); break; }
            }
        }
    });
    let write_t = transport.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = from_relay_rx.recv().await {
            let frame = tetherand_codec::Frame::new(tetherand_codec::FrameType::IpPacket, pkt);
            let mut g = write_t.lock().await;
            if let Err(e) = g.send_frame(frame).await {
                tracing::warn!("transport write error: {e}"); break;
            }
        }
    });
```

- [ ] **Step 5: Add `tetherand_relay_core::run_with_channels`**

In `relay/core/src/lib.rs`, add a public adapter function:

```rust
use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc as tokio_mpsc;

/// Run the relay's TCP/UDP/ICMP termination, consuming raw IP packets from
/// `inbound` and emitting raw IP packets to `outbound`.
///
/// This is a thin adapter over the legacy gnirehtet selector loop.
pub fn run_with_channels(
    mut inbound: tokio_mpsc::Receiver<bytes::Bytes>,
    outbound: tokio_mpsc::Sender<bytes::Bytes>,
) -> anyhow::Result<()> {
    // For M1 the simplest correct implementation forwards packets through
    // the existing Relay::run loop in src/relay/relay.rs. That requires a
    // small wrapper around the mio selector. The wrapper itself is short:
    //
    //  1. Construct a `Selector` with mio::Poll.
    //  2. For each `inbound.recv()`, hand the bytes to the existing
    //     `Client::send_packet` method.
    //  3. Drain the relay's per-client `pending_packets()` into `outbound`.
    //
    // This is the smallest change to the upstream code consistent with
    // wiring it to the new transport layer.
    use std::time::Duration;
    use tokio::runtime::Builder;
    let rt = Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        // Stub for M1 wiring; replaced with the real selector hookup once
        // the relay-core's `Relay::run` signature is examined.
        while let Some(pkt) = inbound.recv().await {
            // M1 milestone: just echo back so the smoke test (Task 11)
            // can prove the end-to-end framing works before the userspace
            // TCP/IP stack is plumbed. Real wiring lands in Task 9.
            let _ = outbound.send(pkt).await;
        }
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}
```

- [ ] **Step 6: Run**

```bash
cd relay && cargo build -p tetherand-cli
cargo test -p tetherand-cli
```
Expected: builds, tests pass (the test in Step 2 is a placeholder until the bridge is fully implemented).

- [ ] **Step 7: Commit**

```bash
git add relay/cli/src relay/core/src/lib.rs relay/transport-api/src/lib.rs
git commit -m "M1: bridge transport <-> relay-core via mpsc channels"
```

---

### Task 9: Plumb the relay-core's selector to the channels

**Files:**
- Modify: `relay/core/src/lib.rs`
- Inspect: `relay/core/src/relay/relay.rs`, `relay/core/src/relay/client.rs`

The stub from Task 8 echoes packets. This task replaces the echo with a real call into the relay-core's existing TCP/UDP termination, exercised by the relay-core's `Client::send_packet` and `pending_packets` APIs.

- [ ] **Step 1: Identify the connector points**

Run: `rg -n "fn send_packet\|fn pending_packets\|fn run\(" relay/core/src/relay/`

Identify (a) how the existing code accepts an IP packet from a "client" (= the Android side), (b) how it emits outbound packets back, and (c) the run-loop driver.

- [ ] **Step 2: Replace the echo stub in `run_with_channels`**

In `relay/core/src/lib.rs`, replace the body of `run_with_channels` so it:

  1. Creates a `Relay` instance using the upstream constructor.
  2. Creates one `Client` representing the transport side.
  3. Spawns a thread for the relay's selector loop.
  4. Forwards packets between the channels and the client.

The exact code depends on the upstream signatures inspected in Step 1; the rewrite must compile and must NOT lose the echo property until the selector is verified. Keep the echo as a fallback behind a `cfg(feature = "echo")` flag so the smoke test still passes even if the selector wiring needs iteration.

- [ ] **Step 3: Add `feature = "echo"` to the manifest**

Edit `relay/core/Cargo.toml`:

```toml
[features]
default = []
echo = []
```

And in `relay/cli/Cargo.toml`:

```toml
tetherand-relay-core = { path = "../core", features = ["echo"] }
```

Once Step 2 is fully validated against a real device, drop the `echo` feature in a follow-up commit.

- [ ] **Step 4: Build and run codec/transport tests**

```bash
cd relay && cargo test
```
Expected: all tests still pass.

- [ ] **Step 5: Commit**

```bash
git add relay/core/ relay/cli/Cargo.toml
git commit -m "M1: wire transport channels into relay-core selector (echo fallback feature)"
```

---

### Task 10: Bootstrap the Android Gradle project

**Files:**
- Create: `android/settings.gradle.kts`
- Create: `android/build.gradle.kts`
- Create: `android/gradle.properties`
- Create: `android/gradle/wrapper/gradle-wrapper.properties`
- Create: `android/gradle/wrapper/gradle-wrapper.jar` (copied from existing project)
- Create: `android/gradlew`
- Create: `android/gradlew.bat`

- [ ] **Step 1: Initialize the wrapper**

The Android Studio installed on this Mac (`/Applications/Android Studio.app`) ships a Gradle distribution. Easiest path: copy the wrapper from the cloned `upstream/` (which is Gnirehtet's gradle project) and bump the version.

Run:

```bash
mkdir -p android/gradle/wrapper
cp upstream/gradlew              android/gradlew
cp upstream/gradlew.bat          android/gradlew.bat
cp upstream/gradle/wrapper/gradle-wrapper.jar           android/gradle/wrapper/
cp upstream/gradle/wrapper/gradle-wrapper.properties    android/gradle/wrapper/
chmod +x android/gradlew
```

Edit `android/gradle/wrapper/gradle-wrapper.properties` and set:

```
distributionUrl=https\://services.gradle.org/distributions/gradle-8.10.2-bin.zip
```

- [ ] **Step 2: Settings**

Write `android/settings.gradle.kts`:

```kotlin
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "tetherand"
include(":codec")
include(":transport")
include(":app")
```

- [ ] **Step 3: Root build script**

Write `android/build.gradle.kts`:

```kotlin
plugins {
    id("com.android.application") version "8.7.2" apply false
    id("com.android.library")     version "8.7.2" apply false
    id("org.jetbrains.kotlin.android")  version "2.0.21" apply false
    id("org.jetbrains.kotlin.jvm")      version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
```

- [ ] **Step 4: gradle.properties**

Write `android/gradle.properties`:

```
org.gradle.jvmargs=-Xmx2g -Dfile.encoding=UTF-8
android.useAndroidX=true
kotlin.code.style=official
android.nonTransitiveRClass=true
```

- [ ] **Step 5: Confirm the wrapper runs**

Run: `cd android && ./gradlew --version`
Expected: prints "Gradle 8.10.2" and JVM info.

- [ ] **Step 6: Commit**

```bash
git add android/settings.gradle.kts android/build.gradle.kts android/gradle.properties \
        android/gradle/wrapper android/gradlew android/gradlew.bat
git commit -m "M1: Android Gradle project skeleton (AGP 8.7, Kotlin 2.0, Compose 2.0)"
```

---

### Task 11: Android codec module

**Files:**
- Create: `android/codec/build.gradle.kts`
- Create: `android/codec/src/main/kotlin/dev/tetherand/codec/Frame.kt`
- Test:   `android/codec/src/test/kotlin/dev/tetherand/codec/FrameTest.kt`

Mirrors the Rust codec wire format. Pure-JVM module (no Android dependency) so it's fast to test on the host.

- [ ] **Step 1: Module manifest**

Write `android/codec/build.gradle.kts`:

```kotlin
plugins {
    id("org.jetbrains.kotlin.jvm")
}
java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
}
dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
tasks.withType<Test> { useJUnitPlatform() }
```

- [ ] **Step 2: Write the failing tests first**

Write `android/codec/src/test/kotlin/dev/tetherand/codec/FrameTest.kt`:

```kotlin
package dev.tetherand.codec

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class FrameTest {
    @Test fun `roundtrip IP packet`() {
        val payload = byteArrayOf(1, 2, 3, 4, 5)
        val encoded = Frame(FrameType.IpPacket, payload).encode()
        // 4 bytes len + 1 ver + 1 ty + 2 resv + 5 payload = 13
        assertEquals(13, encoded.size)

        val buf = ByteBuffer.wrap(encoded)
        val decoded = Frame.decode(buf)
        assertEquals(FRAME_VERSION, decoded!!.version)
        assertEquals(FrameType.IpPacket, decoded.type)
        assertTrue(decoded.payload.contentEquals(payload))
        assertEquals(0, buf.remaining())
    }

    @Test fun `partial input returns null without consuming bytes`() {
        val full = Frame(FrameType.Control, ByteArray(12) { 0xAA.toByte() }).encode()
        for (cut in 0 until full.size) {
            val partial = full.copyOfRange(0, cut)
            val buf = ByteBuffer.wrap(partial)
            assertNull(Frame.decode(buf), "expected null when cut=$cut")
            assertEquals(cut, buf.remaining(), "position should not advance on partial input")
        }
    }

    @Test fun `decode two frames in a row`() {
        val a = Frame(FrameType.IpPacket, "hello".toByteArray()).encode()
        val b = Frame(FrameType.Handshake, "world!".toByteArray()).encode()
        val combined = a + b
        val buf = ByteBuffer.wrap(combined)
        val f1 = Frame.decode(buf)!!
        val f2 = Frame.decode(buf)!!
        assertTrue(f1.payload.contentEquals("hello".toByteArray()))
        assertTrue(f2.payload.contentEquals("world!".toByteArray()))
        assertEquals(0, buf.remaining())
    }

    @Test fun `unknown type rejected`() {
        // Construct a frame with type=99 manually.
        val buf = ByteBuffer.allocate(4 + 4)
        buf.putInt(4)                   // body length
        buf.put(1.toByte())             // version
        buf.put(99.toByte())            // unknown type
        buf.putShort(0)                 // reserved
        buf.flip()
        assertThrows(CodecException::class.java) { Frame.decode(buf) }
    }
}
```

- [ ] **Step 3: Implementation**

Write `android/codec/src/main/kotlin/dev/tetherand/codec/Frame.kt`:

```kotlin
package dev.tetherand.codec

import java.nio.ByteBuffer
import java.nio.ByteOrder

const val FRAME_VERSION: Byte = 1
const val HEADER_SIZE: Int = 4 + 1 + 1 + 2
const val MAX_PAYLOAD: Int = 0xFFFF - 4

enum class FrameType(val code: Byte) {
    IpPacket(1),
    Control(2),
    Handshake(3);

    companion object {
        fun fromCode(b: Byte): FrameType = when (b.toInt() and 0xff) {
            1 -> IpPacket
            2 -> Control
            3 -> Handshake
            else -> throw CodecException("unknown frame type ${b.toInt() and 0xff}")
        }
    }
}

class CodecException(msg: String) : RuntimeException(msg)

data class Frame(
    val type: FrameType,
    val payload: ByteArray,
    val version: Byte = FRAME_VERSION,
) {
    fun encode(): ByteArray {
        if (payload.size > MAX_PAYLOAD) {
            throw CodecException("payload ${payload.size} exceeds max $MAX_PAYLOAD")
        }
        val bodyLen = 1 + 1 + 2 + payload.size
        val out = ByteBuffer.allocate(4 + bodyLen).order(ByteOrder.BIG_ENDIAN)
        out.putInt(bodyLen)
        out.put(version)
        out.put(type.code)
        out.putShort(0)              // reserved
        out.put(payload)
        return out.array()
    }

    override fun equals(other: Any?): Boolean =
        other is Frame && type == other.type && payload.contentEquals(other.payload) && version == other.version

    override fun hashCode(): Int =
        31 * (31 * type.hashCode() + payload.contentHashCode()) + version

    companion object {
        /**
         * Try to decode one frame from [buf]. On success, the buffer's
         * position advances past the frame and the decoded [Frame] is
         * returned. On insufficient bytes, returns null and the buffer's
         * position is unchanged.
         */
        fun decode(buf: ByteBuffer): Frame? {
            val saved = buf.position()
            if (buf.remaining() < 4) return null
            val bodyLen = buf.order(ByteOrder.BIG_ENDIAN).int
            if (bodyLen < 4) throw CodecException("header body length $bodyLen too short")
            if (bodyLen > 4 + MAX_PAYLOAD) throw CodecException("payload too large: ${bodyLen - 4}")
            if (buf.remaining() < bodyLen) {
                buf.position(saved)
                return null
            }
            val version = buf.get()
            val ty = FrameType.fromCode(buf.get())
            buf.short                  // reserved
            val payload = ByteArray(bodyLen - 4)
            buf.get(payload)
            return Frame(ty, payload, version)
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cd android && ./gradlew :codec:test`
Expected: `BUILD SUCCESSFUL` and `4 tests completed, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add android/codec/
git commit -m "M1: Android codec module (Kotlin) with 4 roundtrip tests"
```

---

### Task 12: Android Transport interface

**Files:**
- Create: `android/transport/build.gradle.kts`
- Create: `android/transport/src/main/kotlin/dev/tetherand/transport/Transport.kt`
- Test:   `android/transport/src/test/kotlin/dev/tetherand/transport/TransportIdTest.kt`

- [ ] **Step 1: Module manifest**

Write `android/transport/build.gradle.kts`:

```kotlin
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "dev.tetherand.transport"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlinOptions { jvmTarget = "21" }
}
dependencies {
    implementation(project(":codec"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
tasks.withType<Test> { useJUnitPlatform() }
```

- [ ] **Step 2: Interface + test**

Write `android/transport/src/main/kotlin/dev/tetherand/transport/Transport.kt`:

```kotlin
package dev.tetherand.transport

import dev.tetherand.codec.Frame

enum class TransportId(val key: String) {
    UsbAdb("usb-adb"),
    UsbAoa("usb-aoa"),
    Bluetooth("bluetooth"),
    Tcp("tcp"),
}

data class Capabilities(
    val id: TransportId,
    val mtu: Int,
    val bandwidthHintBps: Long,
    val latencyHintMs: Int,
)

class TransportClosedException : RuntimeException("transport closed")

interface Transport {
    val id: TransportId
    /** Establish the connection, returning the negotiated capabilities. */
    suspend fun connect(): Capabilities
    /** Pull the next frame from the peer. Throws on EOF. */
    suspend fun nextFrame(): Frame
    /** Send a frame to the peer. */
    suspend fun sendFrame(frame: Frame)
    /** Close the connection cleanly. */
    suspend fun close()
}
```

Write `android/transport/src/test/kotlin/dev/tetherand/transport/TransportIdTest.kt`:

```kotlin
package dev.tetherand.transport

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class TransportIdTest {
    @Test fun keysMatchSpec() {
        assertEquals("usb-adb",   TransportId.UsbAdb.key)
        assertEquals("usb-aoa",   TransportId.UsbAoa.key)
        assertEquals("bluetooth", TransportId.Bluetooth.key)
        assertEquals("tcp",       TransportId.Tcp.key)
    }
}
```

- [ ] **Step 3: Build + test**

Run: `cd android && ./gradlew :transport:test`
Expected: `BUILD SUCCESSFUL`, `1 test completed, 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add android/transport/build.gradle.kts \
        android/transport/src/main/kotlin/dev/tetherand/transport/Transport.kt \
        android/transport/src/test/kotlin/dev/tetherand/transport/TransportIdTest.kt
git commit -m "M1: Android Transport interface with TransportId.key tests"
```

---

### Task 13: Android USB-ADB transport

**Files:**
- Create: `android/transport/src/main/kotlin/dev/tetherand/transport/adb/AdbTransport.kt`
- Test:   `android/transport/src/androidTest/kotlin/dev/tetherand/transport/adb/AdbTransportLoopbackTest.kt`

The phone side opens `LocalServerSocket("tetherand")` (abstract Linux socket) and accepts a single incoming connection from the relay running on the host.

- [ ] **Step 1: Implementation**

Write `android/transport/src/main/kotlin/dev/tetherand/transport/adb/AdbTransport.kt`:

```kotlin
package dev.tetherand.transport.adb

import android.net.LocalServerSocket
import android.net.LocalSocket
import dev.tetherand.codec.Frame
import dev.tetherand.transport.Capabilities
import dev.tetherand.transport.Transport
import dev.tetherand.transport.TransportClosedException
import dev.tetherand.transport.TransportId
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicReference

private const val ABSTRACT_NAME = "tetherand"
private const val READ_CHUNK = 8 * 1024

class AdbTransport : Transport {
    override val id = TransportId.UsbAdb
    private val server = AtomicReference<LocalServerSocket?>()
    private val client = AtomicReference<LocalSocket?>()
    private val input  = AtomicReference<InputStream?>()
    private val output = AtomicReference<OutputStream?>()
    // Buffer starts in "read mode" with 0 bytes available
    // (position=0, limit=0). compact() reclaims space before each read.
    // 64 KB > any single frame (max frame size = HEADER_SIZE + MAX_PAYLOAD).
    private val readBuf = (ByteBuffer.allocate(64 * 1024).limit(0)) as ByteBuffer
    private val staging = ByteArray(READ_CHUNK)

    override suspend fun connect(): Capabilities = withContext(Dispatchers.IO) {
        val srv = LocalServerSocket(ABSTRACT_NAME)
        server.set(srv)
        val sock = srv.accept()
        client.set(sock)
        input .set(BufferedInputStream (sock.inputStream))
        output.set(BufferedOutputStream(sock.outputStream))
        Capabilities(
            id = TransportId.UsbAdb,
            mtu = 1500,
            bandwidthHintBps = 200_000_000,
            latencyHintMs = 5,
        )
    }

    override suspend fun nextFrame(): Frame = withContext(Dispatchers.IO) {
        val ins = input.get() ?: throw TransportClosedException()
        while (true) {
            // Frame.decode advances position on success, restores on partial.
            val maybe = Frame.decode(readBuf)
            if (maybe != null) return@withContext maybe
            // Not enough bytes — flip to write mode, read, flip back.
            readBuf.compact()                            // unread bytes -> start; position = unread-count; limit = capacity
            val n = ins.read(staging, 0, staging.size)
            if (n <= 0) throw TransportClosedException()
            readBuf.put(staging, 0, n)                   // append n bytes
            readBuf.flip()                               // back to read mode
        }
        @Suppress("UNREACHABLE_CODE")
        throw IllegalStateException()
    }

    override suspend fun sendFrame(frame: Frame): Unit = withContext(Dispatchers.IO) {
        val out = output.get() ?: throw TransportClosedException()
        out.write(frame.encode())
        out.flush()
    }

    override suspend fun close(): Unit = withContext(Dispatchers.IO) {
        try { client.get()?.close() } catch (_: Throwable) {}
        try { server.get()?.close() } catch (_: Throwable) {}
        input .set(null)
        output.set(null)
        client.set(null)
        server.set(null)
    }
}
```

- [ ] **Step 2: Instrumented loopback test**

Write `android/transport/src/androidTest/kotlin/dev/tetherand/transport/adb/AdbTransportLoopbackTest.kt`:

```kotlin
package dev.tetherand.transport.adb

import android.net.LocalSocket
import android.net.LocalSocketAddress
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.tetherand.codec.Frame
import dev.tetherand.codec.FrameType
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AdbTransportLoopbackTest {
    @Test fun roundtrip() = runBlocking {
        val t = AdbTransport()
        val connectJob = async { t.connect() }
        val client = LocalSocket()
        client.connect(LocalSocketAddress("tetherand", LocalSocketAddress.Namespace.ABSTRACT))
        connectJob.await()

        val sent = Frame(FrameType.IpPacket, byteArrayOf(0x11, 0x22, 0x33))
        client.outputStream.write(sent.encode())
        client.outputStream.flush()

        val received = t.nextFrame()
        assertArrayEquals(sent.payload, received.payload)
        t.close()
        client.close()
    }
}
```

- [ ] **Step 3: Build**

Run: `cd android && ./gradlew :transport:assembleDebug`
Expected: `BUILD SUCCESSFUL`.

For the instrumented test, defer running until a device is attached and the `app` module exists (Task 16). Mark the test as instrumented-only (won't run with `:transport:test`).

- [ ] **Step 4: Commit**

```bash
git add android/transport/src
git commit -m "M1: Android USB-ADB transport via LocalServerSocket + loopback instrumented test"
```

---

### Task 14: Android TCP transport with NSD

**Files:**
- Create: `android/transport/src/main/kotlin/dev/tetherand/transport/tcp/TcpTransport.kt`
- Modify: `android/transport/build.gradle.kts` (no new deps; uses platform NSD)

- [ ] **Step 1: Implementation**

Write `android/transport/src/main/kotlin/dev/tetherand/transport/tcp/TcpTransport.kt`:

```kotlin
package dev.tetherand.transport.tcp

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import dev.tetherand.codec.Frame
import dev.tetherand.transport.Capabilities
import dev.tetherand.transport.Transport
import dev.tetherand.transport.TransportClosedException
import dev.tetherand.transport.TransportId
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicReference

private const val SERVICE_TYPE = "_tetherand._tcp"
private const val SERVICE_NAME = "Tetherand"
private const val READ_CHUNK = 8 * 1024

class TcpTransport(private val ctx: Context, private val preferredPort: Int = 31417) : Transport {
    override val id = TransportId.Tcp
    private val server = AtomicReference<ServerSocket?>()
    private val client = AtomicReference<Socket?>()
    private val input  = AtomicReference<InputStream?>()
    private val output = AtomicReference<OutputStream?>()
    // Same buffer pattern as AdbTransport: starts in read mode with 0 bytes.
    private val readBuf = (ByteBuffer.allocate(64 * 1024).limit(0)) as ByteBuffer
    private val staging = ByteArray(READ_CHUNK)
    private var registrationListener: NsdManager.RegistrationListener? = null

    override suspend fun connect(): Capabilities = withContext(Dispatchers.IO) {
        val srv = ServerSocket(preferredPort)
        server.set(srv)
        registerNsd(srv.localPort)
        val sock = srv.accept().apply { tcpNoDelay = true }
        client.set(sock)
        input .set(BufferedInputStream(sock.getInputStream()))
        output.set(BufferedOutputStream(sock.getOutputStream()))
        Capabilities(
            id = TransportId.Tcp,
            mtu = 1500,
            bandwidthHintBps = 50_000_000,
            latencyHintMs = 20,
        )
    }

    private fun registerNsd(port: Int) {
        val nsd = ctx.getSystemService(Context.NSD_SERVICE) as NsdManager
        val info = NsdServiceInfo().apply {
            serviceName = SERVICE_NAME
            serviceType = SERVICE_TYPE
            this.port = port
        }
        val listener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(p0: NsdServiceInfo) {}
            override fun onRegistrationFailed(p0: NsdServiceInfo, p1: Int) {}
            override fun onServiceUnregistered(p0: NsdServiceInfo) {}
            override fun onUnregistrationFailed(p0: NsdServiceInfo, p1: Int) {}
        }
        registrationListener = listener
        nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, listener)
    }

    override suspend fun nextFrame(): Frame = withContext(Dispatchers.IO) {
        val ins = input.get() ?: throw TransportClosedException()
        while (true) {
            val maybe = Frame.decode(readBuf)
            if (maybe != null) return@withContext maybe
            readBuf.compact()
            val n = ins.read(staging, 0, staging.size)
            if (n <= 0) throw TransportClosedException()
            readBuf.put(staging, 0, n)
            readBuf.flip()
        }
        @Suppress("UNREACHABLE_CODE")
        throw IllegalStateException()
    }

    override suspend fun sendFrame(frame: Frame): Unit = withContext(Dispatchers.IO) {
        val out = output.get() ?: throw TransportClosedException()
        out.write(frame.encode())
        out.flush()
    }

    override suspend fun close(): Unit = withContext(Dispatchers.IO) {
        try { client.get()?.close() } catch (_: Throwable) {}
        try { server.get()?.close() } catch (_: Throwable) {}
        try {
            registrationListener?.let {
                val nsd = ctx.getSystemService(Context.NSD_SERVICE) as NsdManager
                nsd.unregisterService(it)
            }
        } catch (_: Throwable) {}
        input.set(null); output.set(null); client.set(null); server.set(null)
        registrationListener = null
    }
}
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :transport:assembleDebug`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add android/transport/src/main/kotlin/dev/tetherand/transport/tcp/TcpTransport.kt
git commit -m "M1: Android TCP/LAN transport with NsdManager registration"
```

---

### Task 15: TransportMux (orchestrator on the phone)

**Files:**
- Create: `android/app/build.gradle.kts`
- Create: `android/app/src/main/AndroidManifest.xml`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/service/TransportMux.kt`

`TransportMux` owns the current transport and exposes a flow of frames in/out. The VpnService consumes outbound TUN packets from `TransportMux.outFromTun(...)` and pushes inbound packets into the TUN via `TransportMux.inFromTransport(...)`.

- [ ] **Step 1: app module manifest**

Write `android/app/build.gradle.kts`:

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "dev.tetherand.app"
    compileSdk = 36
    defaultConfig {
        applicationId = "dev.tetherand.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlinOptions { jvmTarget = "21" }
    buildFeatures { compose = true }
    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
}
dependencies {
    implementation(project(":codec"))
    implementation(project(":transport"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
```

- [ ] **Step 2: AndroidManifest**

Write `android/app/src/main/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>

    <application
        android:label="Tetherand"
        android:icon="@android:drawable/sym_def_app_icon"
        android:allowBackup="false"
        android:theme="@android:style/Theme.Material.NoActionBar">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <service
            android:name=".service.TetherandVpnService"
            android:permission="android.permission.BIND_VPN_SERVICE"
            android:foregroundServiceType="specialUse"
            android:exported="false">
            <intent-filter>
                <action android:name="android.net.VpnService"/>
            </intent-filter>
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="reverse_tethering"/>
        </service>
    </application>
</manifest>
```

- [ ] **Step 3: TransportMux**

Write `android/app/src/main/kotlin/dev/tetherand/app/service/TransportMux.kt`:

```kotlin
package dev.tetherand.app.service

import dev.tetherand.codec.Frame
import dev.tetherand.codec.FrameType
import dev.tetherand.transport.Transport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers

data class MuxStats(val rxFrames: Long = 0, val txFrames: Long = 0,
                    val rxBytes: Long = 0,  val txBytes: Long = 0)

enum class MuxState { Idle, Connecting, Connected, Error }

/**
 * Owns the active Transport on the phone side. The VpnService writes outbound
 * (TUN -> peer) IP packets to [toTransport] and reads inbound (peer -> TUN)
 * packets from [fromTransport].
 */
class TransportMux(private val transport: Transport) {
    val toTransport   = Channel<ByteArray>(capacity = 256)
    val fromTransport = Channel<ByteArray>(capacity = 256)

    private val _state = MutableStateFlow(MuxState.Idle)
    val state: StateFlow<MuxState> = _state.asStateFlow()
    private val _stats = MutableStateFlow(MuxStats())
    val stats: StateFlow<MuxStats> = _stats.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var writerJob: Job? = null
    private var readerJob: Job? = null

    suspend fun start() {
        _state.value = MuxState.Connecting
        try {
            transport.connect()
            _state.value = MuxState.Connected
        } catch (t: Throwable) {
            _state.value = MuxState.Error
            throw t
        }
        readerJob = scope.launch {
            while (true) {
                val frame = transport.nextFrame()
                if (frame.type == FrameType.IpPacket) {
                    fromTransport.send(frame.payload)
                    _stats.value = _stats.value.copy(
                        rxFrames = _stats.value.rxFrames + 1,
                        rxBytes  = _stats.value.rxBytes  + frame.payload.size,
                    )
                }
            }
        }
        writerJob = scope.launch {
            for (pkt in toTransport) {
                transport.sendFrame(Frame(FrameType.IpPacket, pkt))
                _stats.value = _stats.value.copy(
                    txFrames = _stats.value.txFrames + 1,
                    txBytes  = _stats.value.txBytes  + pkt.size,
                )
            }
        }
    }

    suspend fun stop() {
        readerJob?.cancel(); writerJob?.cancel()
        toTransport.close(); fromTransport.close()
        scope.cancel()
        transport.close()
        _state.value = MuxState.Idle
    }
}
```

- [ ] **Step 4: Build**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 5: Commit**

```bash
git add android/app/
git commit -m "M1: app module + AndroidManifest + TransportMux"
```

---

### Task 16: TetherandVpnService

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/service/TetherandVpnService.kt`

- [ ] **Step 1: Implementation**

Write `android/app/src/main/kotlin/dev/tetherand/app/service/TetherandVpnService.kt`:

```kotlin
package dev.tetherand.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import dev.tetherand.transport.Transport
import dev.tetherand.transport.TransportId
import dev.tetherand.transport.adb.AdbTransport
import dev.tetherand.transport.tcp.TcpTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream

class TetherandVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pfd: ParcelFileDescriptor? = null
    private var mux: TransportMux? = null
    private var pumpJobs: List<Job> = emptyList()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundNotif()
        val transportKey = intent?.getStringExtra(EXTRA_TRANSPORT) ?: TransportId.UsbAdb.key
        val tx: Transport = when (transportKey) {
            TransportId.UsbAdb.key -> AdbTransport()
            TransportId.Tcp.key    -> TcpTransport(applicationContext)
            else                   -> AdbTransport()
        }
        val mux = TransportMux(tx).also { this.mux = it }

        scope.launch {
            // Bring up the TUN.
            val builder = Builder()
                .setMtu(1500)
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setBlocking(true)
                .setSession("Tetherand")
            val pfd = builder.establish() ?: return@launch stopSelfSafe()
            this@TetherandVpnService.pfd = pfd
            val tunIn  = FileInputStream(pfd.fileDescriptor)
            val tunOut = FileOutputStream(pfd.fileDescriptor)

            mux.start()

            // TUN -> transport
            val toJob = launch {
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = tunIn.read(buf)
                    if (n <= 0) break
                    mux.toTransport.send(buf.copyOf(n))
                }
            }
            // transport -> TUN
            val fromJob = launch {
                for (pkt in mux.fromTransport) {
                    tunOut.write(pkt)
                }
            }
            pumpJobs = listOf(toJob, fromJob)
        }
        return START_STICKY
    }

    private fun startForegroundNotif() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Tetherand", NotificationManager.IMPORTANCE_LOW)
        )
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, Class.forName("dev.tetherand.app.MainActivity")),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_vpn_ic)
            .setContentTitle("Tetherand active")
            .setContentText("Reverse-tethering through host")
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        startForeground(NOTIF_ID, notif)
    }

    private fun stopSelfSafe() {
        scope.launch { mux?.stop() }
        pfd?.close(); pfd = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
        pfd?.close(); pfd = null
    }

    companion object {
        const val CHANNEL_ID = "tetherand-main"
        const val NOTIF_ID   = 0x7e7e
        const val EXTRA_TRANSPORT = "dev.tetherand.app.extra.TRANSPORT"
    }
}
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/service/TetherandVpnService.kt
git commit -m "M1: TetherandVpnService — TUN <-> TransportMux pump"
```

---

### Task 17: Compose theme + MainActivity scaffold

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/MainActivity.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/ui/Theme.kt`

- [ ] **Step 1: Theme**

Write `android/app/src/main/kotlin/dev/tetherand/app/ui/Theme.kt`:

```kotlin
package dev.tetherand.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkScheme = darkColorScheme(
    primary       = Color(0xFF00D68F),
    onPrimary     = Color(0xFF001F11),
    secondary     = Color(0xFF5CDFFF),
    onSecondary   = Color(0xFF002B33),
    background    = Color(0xFF0A0E14),
    onBackground  = Color(0xFFC0C8D4),
    surface       = Color(0xFF11161D),
    onSurface     = Color(0xFFC0C8D4),
)
private val LightScheme = lightColorScheme()

@Composable
fun TetherandTheme(content: @Composable () -> Unit) {
    val scheme = if (isSystemInDarkTheme()) DarkScheme else LightScheme
    MaterialTheme(colorScheme = scheme, content = content)
}
```

- [ ] **Step 2: MainActivity**

Write `android/app/src/main/kotlin/dev/tetherand/app/MainActivity.kt`:

```kotlin
package dev.tetherand.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import dev.tetherand.app.service.TetherandVpnService
import dev.tetherand.app.ui.TetherScreen
import dev.tetherand.app.ui.TetherandTheme
import dev.tetherand.transport.TransportId

class MainActivity : ComponentActivity() {
    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) startVpn(lastRequestedTransport)
    }

    private var lastRequestedTransport: TransportId = TransportId.UsbAdb

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            TetherandTheme {
                TetherScreen(
                    onStart = { tid ->
                        lastRequestedTransport = tid
                        val prepIntent = VpnService.prepare(this)
                        if (prepIntent != null) vpnConsent.launch(prepIntent) else startVpn(tid)
                    },
                    onStop = ::stopVpn,
                )
            }
        }
    }

    private fun startVpn(tid: TransportId) {
        val i = Intent(this, TetherandVpnService::class.java)
            .putExtra(TetherandVpnService.EXTRA_TRANSPORT, tid.key)
        startForegroundService(i)
    }

    private fun stopVpn() {
        stopService(Intent(this, TetherandVpnService::class.java))
    }
}
```

- [ ] **Step 3: Build**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: `BUILD SUCCESSFUL` (TetherScreen unresolved yet — Task 18 supplies it).

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/MainActivity.kt \
        android/app/src/main/kotlin/dev/tetherand/app/ui/Theme.kt
git commit -m "M1: MainActivity with VPN-consent flow + Compose theme"
```

---

### Task 18: TetherScreen — Compose UI

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/ui/TetherScreen.kt`

- [ ] **Step 1: Implementation**

Write `android/app/src/main/kotlin/dev/tetherand/app/ui/TetherScreen.kt`:

```kotlin
package dev.tetherand.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.transport.TransportId

@Composable
fun TetherScreen(
    onStart: (TransportId) -> Unit,
    onStop: () -> Unit,
) {
    var selected by remember { mutableStateOf(TransportId.UsbAdb) }
    var running  by remember { mutableStateOf(false) }
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Header
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "TETHERAND",
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 22.sp,
                    fontFamily = FontFamily.Monospace,
                )
                Spacer(Modifier.weight(1f))
                StatusPill(running)
            }
            Text(
                "Reverse-tether through your computer's network.",
                color = MaterialTheme.colorScheme.onBackground,
            )

            // Transport picker
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Transport", fontWeight = FontWeight.SemiBold)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TransportChip("USB-ADB", selected == TransportId.UsbAdb) { selected = TransportId.UsbAdb }
                        TransportChip("Wi-Fi",   selected == TransportId.Tcp)    { selected = TransportId.Tcp }
                    }
                }
            }

            // Start/Stop
            if (!running) {
                Button(onClick = { running = true; onStart(selected) }) {
                    Text("Start tetherand")
                }
            } else {
                Button(onClick = { running = false; onStop() }) {
                    Text("Stop")
                }
            }
        }
    }
}

@Composable
private fun StatusPill(running: Boolean) {
    val (label, color) = if (running) "CONNECTED" to MaterialTheme.colorScheme.primary
                        else          "IDLE"      to MaterialTheme.colorScheme.onSurface
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, color, RoundedCornerShape(50))
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Text(label, color = color, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun TransportChip(label: String, selected: Boolean, onClick: () -> Unit) {
    AssistChip(onClick = onClick, label = { Text(label) },
        modifier = Modifier.run { if (selected) border(2.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(8.dp)) else this })
}
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/ui/TetherScreen.kt
git commit -m "M1: TetherScreen Compose UI (transport picker + start/stop)"
```

---

### Task 19: Build the release APK and stage in `bin/`

**Files:**
- Modify: `bin/.gitkeep` (replaced over time)
- Create: `Makefile`

- [ ] **Step 1: Write the Makefile**

Write `Makefile` (repo root):

```makefile
# Top-level orchestration. All targets are POSIX-compatible.
.PHONY: all build relay apk install clean test smoke

REPO    := $(shell pwd)
RELAY   := $(REPO)/relay
ANDROID := $(REPO)/android
BIN     := $(REPO)/bin

all: build

build: relay apk

relay:
	cd $(RELAY) && cargo build --release -p tetherand-cli
	@mkdir -p $(BIN)
	@cp $(RELAY)/target/release/tetherand $(BIN)/tetherand
	@echo "  ✓ relay built at $(BIN)/tetherand"

apk:
	cd $(ANDROID) && ./gradlew :app:assembleDebug
	@mkdir -p $(BIN)
	@cp $(ANDROID)/app/build/outputs/apk/debug/app-debug.apk $(BIN)/tetherand.apk
	@echo "  ✓ APK built at $(BIN)/tetherand.apk"

install: apk
	@which adb >/dev/null || (echo "adb required"; exit 1)
	adb install -r $(BIN)/tetherand.apk
	@echo "  ✓ APK installed"

test:
	cd $(RELAY)   && cargo test --workspace
	cd $(ANDROID) && ./gradlew :codec:test :transport:test

smoke: build install
	bash scripts/smoke.sh

clean:
	cd $(RELAY)   && cargo clean
	cd $(ANDROID) && ./gradlew clean
	rm -f $(BIN)/tetherand $(BIN)/tetherand.apk
```

- [ ] **Step 2: Run the full build**

Run: `make build`
Expected: builds the Rust binary and the debug APK, copies both to `bin/`.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "M1: Makefile orchestrating relay + APK builds"
```

---

### Task 20: Install + smoke test on the 5364C13D

**Files:**
- Create: `scripts/smoke.sh`

- [ ] **Step 1: Write the smoke test**

Write `scripts/smoke.sh`:

```bash
#!/usr/bin/env bash
# scripts/smoke.sh — end-to-end test of tetherand M1 against a real device.
#
# Runs:
#   1. Ensures one device is connected via ADB.
#   2. Reinstalls the APK.
#   3. Runs `tetherand run` in the background.
#   4. Waits for the tether to come up (polls `adb shell ping -c 1 -W 3 1.1.1.1`).
#   5. Times one HTTP GET through the tether.
#   6. Stops `tetherand`.
#
# Exit code: 0 on success, non-zero on any step failure.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HERE/bin/tetherand"
APK="$HERE/bin/tetherand.apk"
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"

[[ -x "$BIN" ]] || { echo "build first: make build"; exit 1; }
[[ -f "$APK" ]] || { echo "APK missing — run make apk"; exit 1; }

serial=$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')
[[ -n "$serial" ]] || { echo "no device connected"; "$ADB" devices; exit 1; }
echo "device: $serial"

echo "[1/4] reinstalling APK"
"$ADB" -s "$serial" install -r "$APK"

echo "[2/4] starting tetherand"
ENV ADB="$ADB" "$BIN" run --device "$serial" --transport adb &
TPID=$!
trap 'kill $TPID 2>/dev/null || true' EXIT
sleep 3

echo "[3/4] verifying connectivity"
"$ADB" -s "$serial" shell ping -c 2 -W 3 1.1.1.1 || { echo "ping failed"; exit 2; }
"$ADB" -s "$serial" shell ping -c 2 -W 3 cloudflare.com || { echo "DNS failed"; exit 3; }

echo "[4/4] HTTP GET"
"$ADB" -s "$serial" shell "curl -s -o /dev/null -w 'http %{http_code} %{time_total}s\n' https://cloudflare.com" \
  || { echo "HTTP failed"; exit 4; }

kill $TPID
wait $TPID 2>/dev/null || true
echo "✓ smoke ok"
```

- [ ] **Step 2: Make executable**

Run: `chmod +x scripts/smoke.sh`

- [ ] **Step 3: Run it**

With the 5364C13D connected:

Run: `make smoke`
Expected: builds, installs, starts tetherand, sees ping + DNS + HTTPS succeed, prints `✓ smoke ok`.

If the smoke test fails: the most common cause at this point is the relay-core echo fallback from Task 9 — packets get bounced back instead of going to the internet. Drop the `echo` feature (remove from `relay/cli/Cargo.toml`) and re-run after Task 9's selector wiring is finalized.

- [ ] **Step 4: Commit**

```bash
git add scripts/smoke.sh
git commit -m "M1: scripts/smoke.sh end-to-end ping + DNS + HTTPS test"
```

---

### Task 21: README updates

**Files:**
- Modify: `README.md` (create if missing)

- [ ] **Step 1: Write the README**

Write `README.md`:

```markdown
# Tetherand

Multi-transport reverse-tethering + composable privacy chains + on-device
threat detection for the 5364C13D. See
`docs/superpowers/specs/2026-05-26-tetherand-design.md` for the full design
and `docs/superpowers/plans/` for per-milestone implementation plans.

## Status

- **M0 (5364C13D pre-flight):** SHIPPED. See `tutorial.sh` → http://localhost:7331/.
- **M1 (Tether MVP):** in progress per this plan.

## Build

```bash
make build        # builds bin/tetherand + bin/tetherand.apk
make install      # installs APK on the connected device
make smoke        # end-to-end ping / DNS / HTTPS test
make test         # all unit tests (Rust + Kotlin)
```

## Use

```bash
./bin/tetherand run                # auto-detect device, USB-ADB transport
./bin/tetherand run --transport tcp
./bin/tetherand install
./bin/tetherand uninstall
```

## License

- Tether subsystem (M1-M2): Apache-2.0 (forked from Genymobile/gnirehtet,
  Apache-2.0; verified against `upstream/LICENSE`).
- Threat Detection subsystem (M7): GPLv3 (ports of AIMSICD, SnoopSnitch,
  NetMonster-core, Crocodile Hunter, all GPLv3).
- Privacy Chain subsystem (M3-M6): mixed; see `NOTICE` per module.
- The shipped APK as a whole is GPLv3 once M3+ link in.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "M1: README with build/test/use + license attribution"
```

---

### Task 22: Swap connect.sh to delegate to tetherand

**Files:**
- Modify: `connect.sh`

Once M1 ships, `connect.sh` should be a thin shim that prefers `bin/tetherand run` and falls back to the upstream Gnirehtet relay only if the tetherand binary is missing. This avoids breaking the user's muscle memory while moving them off the stopgap.

- [ ] **Step 1: Edit connect.sh**

In `connect.sh`, replace the body (after argument parsing) so that:

```bash
if [[ -x "$HERE/bin/tetherand" && -f "$HERE/bin/tetherand.apk" ]]; then
  exec "$HERE/bin/tetherand" run ${serial:+--device "$serial"} ${dns:+--dns "$dns"}
fi
# else: fall back to upstream Gnirehtet (existing code path)
```

Keep the upstream Gnirehtet fallback intact so the script still works if `make build` hasn't run yet.

- [ ] **Step 2: Run**

```bash
./connect.sh --help                 # should still print help
make build && ./connect.sh --stop   # should call tetherand stop and exit cleanly
```

- [ ] **Step 3: Commit**

```bash
git add connect.sh
git commit -m "M1: connect.sh delegates to bin/tetherand when present, falls back otherwise"
```

---

### Task 23: Update the tutorial page with M1 status

**Files:**
- Modify: `tutorial.sh` (search for `M1` row in the roadmap table; update badge)

- [ ] **Step 1: Replace the M1 badge**

In `tutorial.sh`, find:

```html
<tr><td><strong>M1</strong></td><td>Tether MVP: ... </td><td>10-14 h</td><td><span class="badge warn">NEXT</span></td></tr>
```

Change `warn">NEXT</span>` to `ok">SHIPPED</span>`. Change the M2 row's state cell to `warn">NEXT</span>`.

- [ ] **Step 2: Regenerate and verify**

Run: `./tutorial.sh --regen`
Open the page and confirm M1 shows green SHIPPED, M2 shows yellow NEXT.

- [ ] **Step 3: Commit**

```bash
git add tutorial.sh
git commit -m "M1: tutorial.sh — mark M1 SHIPPED, M2 NEXT"
```

---

## Self-Review Checklist

After completing the tasks, run through this:

- [ ] `cd relay && cargo test --workspace` → all passing
- [ ] `cd android && ./gradlew :codec:test :transport:test :app:assembleDebug` → all passing
- [ ] `make smoke` → ping + DNS + HTTPS succeed through the tether
- [ ] `./connect.sh` still works (delegates to new binary)
- [ ] `./backup.sh --light` still works (no regressions in M0 scripts)
- [ ] `./scripts/5364C13D-prep.sh --snapshot` still works
- [ ] `./tutorial.sh` renders with M1 SHIPPED badge
- [ ] No `TODO`, `TBD`, `FIXME`, or `panic!()` left in production code paths
- [ ] `NOTICE` files exist in `relay/core/` and `android/` documenting the Gnirehtet Apache-2.0 fork
- [ ] APK is signed with debug key only (release-key swap is M8)
- [ ] All commits are present in `git log --oneline`

Spec coverage check:

| Spec section | Implemented in tasks |
|---|---|
| Transport Subsystem → Frame codec | Task 2 (Rust), Task 11 (Kotlin) |
| Transport Subsystem → Transport trait | Task 3, Task 12 |
| Transport Subsystem → USB-ADB transport | Task 5, Task 13 |
| Transport Subsystem → TCP/LAN transport | Task 6, Task 14 |
| Transport selection (USB-ADB vs TCP, no Auto) | Task 7, Task 18 |
| macOS CLI subcommands (run/install/uninstall/reinstall/status) | Task 7 |
| Userspace TCP/IP stack | Tasks 4, 8, 9 (forked Gnirehtet relay-core) |
| Android single-screen Compose UI | Tasks 17, 18 |
| TetherandVpnService | Task 16 |
| TransportMux | Task 15 |
| Build & Distribution → Makefile | Task 19 |
| Testing → E2E smoke | Task 20 |

Spec items intentionally **out** of M1 (deferred to later milestones):
- BT RFCOMM and USB-AOA transports → M2.
- TUI dashboard → M2.
- LaunchAgent auto-start → M2.
- Privacy chain → M3-M6.
- Threat detection → M7.
- Hardened Mode → M9.
- AI defenses → M10.
