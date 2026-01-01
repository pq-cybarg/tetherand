# Tetherand — Multi-Transport Reverse-Tethering, Composable VPN Chains, and On-Device Threat Detection

**Status:** Approved design, pending plan.
**Author:** pq-cybarg
**Date:** 2026-05-26
**Target device:** Solana Seeker (Android 16 / SDK 36 / arm64-v8a / MediaTek)
**Host:** macOS (arm64-darwin)

## Goals

Build a single Android APK ("Tetherand") and companion macOS CLI that together provide:

1. **Reverse tethering** — share the Mac's internet to the phone over USB-C (ADB or AOA), Bluetooth RFCOMM, or LAN TCP.
2. **Composable privacy chains** — route phone traffic through user-composed sequences of Mullvad / WireGuard / NymVPN / Tor hops, each independently configured, with a visible live chain diagram in the app.
3. **On-device threat detection** — detect IMSI catchers, evil-twin Wi-Fi, suspicious app installs, and other local attacks, regardless of whether the phone is tethered.

All three subsystems are independently shippable and testable.

## Non-Goals

- Linux/Windows host support in v1 (Mac only; CLI is Rust so porting is mostly transport-impl work).
- IPv6 in v1 (Gnirehtet's stack is IPv4-only; smoltcp migration is a follow-up).
- Rooting or unlocking the bootloader.
- Detection of attacks that fundamentally require baseband access on MediaTek (full Qualcomm-style `/dev/diag` analysis is out of scope; we use what `TelephonyManager` exposes plus heuristics).
- Cloud sync, telemetry, or any data leaving the device.

## Base Approach

Fork Gnirehtet (Genymobile, GPL-3) for the tether subsystem — its Java VpnService client + Rust userspace TCP/IP relay are battle-tested. Rebrand under `dev.tetherand.*`. Wrap a transport-abstraction layer around the existing USB-ADB transport, then add USB-AOA / Bluetooth RFCOMM / TCP siblings. Replace the Android client with a modern Kotlin + Compose app. The privacy and threat subsystems are net-new.

License inherited: GPL-3 for code derived from Gnirehtet (relay core + initial Android service shell). New code (Compose UI, threat detector, privacy chain orchestrator) starts as GPL-3-compatible (MPL-2 candidate) until/unless the relay core is rewritten clean-room post-launch.

## Architecture

```
┌──────────────────────── Seeker (Tetherand app) ─────────────────────────┐
│                                                                          │
│  Compose UI:                                                             │
│    Tether tab │ Privacy tab (chain editor) │ Threat tab                  │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │              TetherandVpnService (single VpnService)            │    │
│  │                                                                  │    │
│  │   Apps → TUN (10.0.0.2/24) → Privacy Chain → Transport Mux →    │    │
│  │                                                                  │    │
│  │                  ┌─────┐  ┌─────┐  ┌─────┐                      │    │
│  │   Privacy Chain: │ Hop │→ │ Hop │→ │ Hop │ → out                │    │
│  │                  └─────┘  └─────┘  └─────┘                      │    │
│  │                    wg     tor      nym                          │    │
│  │                                                                  │    │
│  │   Transport Mux: USB-ADB | USB-AOA | BT-RFCOMM | TCP | direct   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  ThreatDetectionService (independent foreground service)         │    │
│  │  Telephony + WiFi + BT + App audit → Heuristics → Alerts → UI   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘

                          (over selected transport)

┌──────────────────────────── Mac (tetherand) ─────────────────────────────┐
│                                                                           │
│   tetherand daemon (LaunchAgent)                                          │
│       │                                                                   │
│       ├── Userspace TCP/IP stack (Gnirehtet-derived, Rust)                │
│       ├── Transport endpoints: adb-forward, libusb (AOA),                 │
│       │      IOBluetooth (RFCOMM), TCP listener (+mDNS)                   │
│       ├── IOKit USB watcher (auto-attach on Seeker plug-in)               │
│       └── Local IPC socket                                                │
│                                                                           │
│   tetherand CLI / tetherand dashboard (TUI)                               │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

Critical orthogonality: **transports** carry packets to the Mac; **chains** transform packets before they leave the device. Either subsystem can be used without the other. A chain plus a tether means the chain encrypts on-device first and the Mac only ever forwards opaque encrypted frames.

## Repository Layout

```
reverse-tethering/
├── android/                          # Gradle project, Kotlin + Compose
│   ├── app/
│   │   └── src/main/kotlin/dev/tetherand/app/
│   │       ├── ui/                   # Compose screens: Tether, Privacy, Threat
│   │       ├── service/              # TetherandVpnService, ThreatDetectionService
│   │       ├── tile/                 # QS tile
│   │       └── receiver/             # USB attach, boot completed
│   ├── chain/                        # Privacy chain runtime
│   │   └── src/main/kotlin/dev/tetherand/chain/
│   │       ├── Hop.kt                # Hop trait
│   │       ├── hops/{wg,mullvad,nym,tor,direct}/
│   │       └── Orchestrator.kt
│   ├── transports/                   # Phone-side transport impls
│   │   └── src/main/kotlin/dev/tetherand/transports/{adb,aoa,bt,tcp}/
│   ├── threat/                       # Threat detection engine
│   │   └── src/main/kotlin/dev/tetherand/threat/
│   └── native/                       # Rust → JNI shared codec + WG hooks
├── relay/                            # Cargo workspace (Mac side)
│   ├── core/                         # Userspace TCP/IP (forked Gnirehtet relay-rust)
│   ├── transports/{adb,aoa,bt,tcp}/
│   ├── cli/                          # `tetherand` binary
│   ├── tui/                          # ratatui dashboard
│   ├── daemon/                       # Long-running daemon
│   └── codec/                        # Frame codec (shared with android/native)
├── launchd/                          # dev.tetherand.daemon.plist + installer
├── bin/                              # Built artifacts: APK + arm64-darwin binary
├── keys/                             # Signing keys (gitignored except pub)
├── scripts/                          # smoke.sh, package.sh, sign-release.sh
├── docs/superpowers/specs/           # Design + plan
├── connect.sh                        # Stopgap (upstream Gnirehtet) until v1 lands
└── tetherand → bin/tetherand         # Convenience symlink
```

## Transport Subsystem

### Frame Codec

Every transport is a bidirectional, ordered, reliable byte stream. The codec frames messages:

```
┌─────────────┬─────────┬───────┬──────────┬──────────────┐
│ len: u32 BE │ ver: u8 │ ty: u8│ resv: u16│ payload      │
└─────────────┴─────────┴───────┴──────────┴──────────────┘
```

`ty=1` IP packet (raw IPv4), `ty=2` control message (keepalive, stats), `ty=3` handshake (version + capabilities). Frames ≤ 65535 bytes. The same codec library compiles to a Rust crate (Mac) and a JNI library (`libtetherand-codec.so`, Android).

### Transport Trait

```rust
#[async_trait]
pub trait Transport: Send {
    async fn connect(&mut self) -> Result<Capabilities>;
    async fn next_frame(&mut self) -> Result<Frame>;
    async fn send_frame(&mut self, frame: Frame) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
}

pub struct Capabilities {
    pub mtu: u16,
    pub bandwidth_hint_bps: u64,
    pub latency_hint_ms: u32,
    pub reliability: Reliability,    // always Reliable in v1
}
```

### Per-Transport Details

**USB-ADB.** Phone-side: `LocalServerSocket("tetherand")` (Linux abstract socket). Mac-side: `adb forward tcp:31416 localabstract:tetherand` then connect to `127.0.0.1:31416`. Effectively identical to Gnirehtet's existing transport, just renamed and wrapped in the new trait.

**USB-AOA.** Phone-side: declares accessory filter in `AndroidManifest.xml`; service receives `UsbManager.ACTION_USB_ACCESSORY_ATTACHED`. Mac-side: `rusb` (libusb-rs); send the AOA v2 protocol bytes (`51` get protocol, `52`/`53` set strings, `55` start accessory) to move phone into accessory mode, then bulk-transfer over the two endpoints. Solana Mobile VID = `0x2D95` (verify on first build). USB-AOA does not require ADB to be enabled.

**Bluetooth RFCOMM.** Phone-side: `BluetoothServerSocket.listenUsingRfcommWithServiceRecord("Tetherand", UUID("...tetherand..."))`. Mac-side: IOBluetooth via a small Swift wrapper (`TetherandBluetooth.framework`) FFI'd into Rust. Pairing flows through the system UI on both sides. We register an L2CAP fallback for higher throughput on supported stacks.

**TCP / LAN.** Phone-side: `ServerSocket` on configurable port; advertised via NSD as `_tetherand._tcp.local`. Mac-side: `mdns-sd` discovers, then connects out. Useful when the phone has bad/expensive cellular but can still hit the Mac's LAN (captive-portal Wi-Fi without trusting it for full traffic).

### Transport Selection

Phone UI: 4 chips plus an Auto chip. Auto picks by capability ranking (USB-ADB > USB-AOA > TCP > BT) and current availability. The selected transport is announced via a control frame; the Mac daemon mirrors selection state.

## Privacy Chain Subsystem

### Hop Interface

```kotlin
interface Hop {
    val id: String
    val displayName: String
    val capabilities: HopCaps   // pq, multihop, anti-censor, etc.
    suspend fun start(input: PacketChannel): PacketChannel  // returns output stream
    suspend fun stop()
    fun stateFlow(): StateFlow<HopState>   // status, latency, throughput
}
```

A chain is `List<Hop>` plus a terminal exit (direct internet, or the transport mux for tethered exit). The orchestrator wires `apps → tun → hop[0] → hop[1] → ... → exit`. Hops can be added/removed/reordered live; the orchestrator drains in-flight packets before swap.

### Hop Implementations

| Hop | Lib | Configuration |
|-----|-----|---------------|
| **WireGuard (generic)** | `wireguard-android` (wg-go) | Standard WG config text or QR code import; peer endpoint, keys, allowed IPs, DNS |
| **Mullvad** | WG core + `mullvad-api` REST client (Kotlin port of `mullvad-types`) | Login with Mullvad account number; auto-fetch server list; toggles for PQ, multihop entry/exit, DAITA, QUIC/Shadowsocks/UDP-over-TCP obfuscation, kill-switch, split-tunnel by app |
| **NymVPN** | `nym-vpn-client` (Rust, JNI'd in) | Mnemonic-based login; entry + exit gateway selection; Sphinx mixnet 2-hop |
| **Tor** | Bundled `tor` (cross-compiled arm64-android, ~3 MB) + `obfs4proxy` + `snowflake-client` + `lyrebird` (meek/webtunnel) + `conjure-client` | Default 3-hop circuit; PT bridges with auto-fetch from BridgeDB; toggles for ML-KEM hybridization (when stable), vanguards-lite, ConnectionPadding, IsolateDestAddr; custom bridges paste; configurable guards; control-port for live circuit inspection |
| **Direct** | n/a | Pass-through; terminal element |

### Post-Quantum Stack

- **Mullvad PQ tunnel:** implements Mullvad's spec — Kyber/ML-KEM exchanges a 32-byte PSK during handshake, used as WG's `PresharedKey`. Re-handshake on a timer matching Mullvad's app.
- **WireGuard generic PQ:** BoringTun fork with the same ML-KEM-PSK design exposed as an opt-in flag; documented as experimental.
- **Tor PQ (per current guidance):** when running against a Tor patch supporting `HSv4-PQHybrid` and circuit ML-KEM, expose these as opt-in flags. UI links to current Tor Project post-quantum guidance. Until those land in stable, default to classical with a "PQ when available" toggle pre-checked.

### Anti-Censorship

Tor PT bridges: `obfs4`, `meek-azure`, `snowflake`, `webtunnel`, `conjure`, plus custom bridge lines. Mullvad obfuscation: QUIC, Shadowsocks, UDP-over-TCP. Hop-level "censorship resilient" toggle prefers anti-censorship transports when on.

### Visualization

Privacy tab: a horizontal scrollable strip of hop cards.

```
[ Apps ]──→[ Mullvad SE (PQ, multihop) ]──→[ Tor (snowflake bridge) ]──→[ Exit ]
              42 ms · 18 MB/s                  410 ms · 1.2 MB/s
              ▓▓▓▓▓░░░░░ pq                    ▓░░░░░░░░░ tor circuit ok
              [ configure ]    [ × ]            [ configure ]    [ × ]              [ + add hop ]
```

Drag to reorder, tap `×` to remove, tap `+` to add. Long-press shows a hop's recent latency / throughput sparkline. Card colors reflect status: green ok, yellow connecting, red error, gray bypassed.

### Failure Behavior

Chain failure modes are user-configurable per chain: `block` (kill-switch, no traffic until chain repairs), `bypass` (fall back to direct, with banner), or `retry-and-block` (try N times then block). Default is `block`.

## Threat Detection Subsystem

### Service

`ThreatDetectionService` — foreground service, independent of `TetherandVpnService`. Survives tether on/off. Notification persistence required by Android.

### Signal Sources

| Source | API | Frequency |
|--------|-----|-----------|
| Cell info | `TelephonyManager.getAllCellInfo()` + `requestCellInfoUpdate()` | every 5s + on event |
| Network type | `TelephonyCallback.ServiceStateListener` (R+ API) | on change |
| Signal strength | `TelephonyCallback.SignalStrengthsListener` | on change |
| Wi-Fi scan | `WifiManager.startScan()` | every 30s when screen on |
| Bluetooth scan | `BluetoothLeScanner` low-power | continuous |
| Motion | `Sensor.TYPE_LINEAR_ACCELERATION` | 1 Hz |
| App audit | `PackageManager.getInstalledPackages()` + permission diff | every 60s + on install/uninstall broadcast |
| Cert audit | system trust store snapshot | every 60s |
| MDM / Accessibility | `DevicePolicyManager.getActiveAdmins()`, `AccessibilityManager.getEnabledAccessibilityServiceList()` | every 60s |

### Heuristics (alert ≥ threshold)

- **Stingray fallback**: RAT downgrades from 5G/LTE to UMTS/GSM in an area baseline-recorded as 4G/5G covered. Confidence increases with sudden + stationary (low accel) + new cell ID.
- **Fake BTS**: previously unseen `CID/LAC` with anomalously high signal AND zero `neighboringCellInfo` AND not on operator's published cell DB (optional offline DB).
- **TA jump**: Timing Advance > N rings change in < 5 s without motion (Linear Accel below threshold) → suggests cell location forgery or sudden cell switch.
- **Cell flapping**: > 4 cell-ID handovers in 60 s while stationary.
- **Evil twin**: scan result with SSID matching a recently-connected SSID but BSSID OUI from a different vendor; bonus if RSSI suddenly very high. Detect deauth flood by counting `WifiManager.startScan()` interruptions / `EXTRA_RESULTS_UPDATED` false events.
- **Karma attack**: probe-request response from networks the phone hasn't broadcast (requires monitor mode → skip without root; substitute: spike in unknown-SSID auto-joins).
- **Trust store change**: new root CA installed not in last snapshot.
- **MDM appears**: `DevicePolicyManager.isDeviceOwnerApp` becomes true or a profile is newly enrolled.
- **Suspicious app**: app gains accessibility service, device-admin, system-alert-window, or `MANAGE_EXTERNAL_STORAGE` within 1 h of install.
- **VPN profile injected**: new `VpnService`-capable package + always-on enabled without user toggle in our UI.

Each heuristic produces a typed `Alert(severity, kind, evidence, recommendations)`. Per-location baseline learned over 7-day rolling window keyed by `geohash6` (lat/lng rounded; never leaves device).

### UI

Threat tab:
- **Risk score 0-100** — weighted aggregate of last-24-h alert severity.
- **Live signal map** — 5 sparklines (RAT, RSSI, neighbors, TA, cell flaps), color-coded.
- **Alert feed** — most recent 50 alerts, expandable evidence, "dismiss" / "snooze 1 h" / "always alert".
- **Threat detail** — per-alert page explaining the heuristic, the evidence, and recommended actions.
- **Panic button** — "Airplane Mode + activate Privacy Chain on Tor only"; one tap.

### Privacy of the Threat Service

No data leaves the device. Baselines stored in `EncryptedSharedPreferences` with hardware-backed keystore. Alerts stored in a local Room database, auto-pruned > 30 days unless the user pins them. Export-on-demand only.

## macOS CLI / TUI / Daemon

`tetherand` is a single Rust binary, ~5 MB stripped.

Subcommands:
- `tetherand run [--transport=auto|adb|aoa|bt|tcp] [--device=SERIAL]` — install (if needed), start, block until Ctrl+C.
- `tetherand install / uninstall / reinstall`
- `tetherand stop`
- `tetherand status` — JSON of daemon + device state.
- `tetherand dashboard` — ratatui: per-flow table (5-tuple, bytes, packets, age), throughput chart, transport state, error log.
- `tetherand daemon` — long-running daemon used by LaunchAgent.

CLI talks to daemon over `$HOME/Library/Application Support/Tetherand/sock` via JSON-over-unix-socket. Daemon mediates exclusive ADB / USB / Bluetooth access.

The userspace TCP/IP stack is forked from Gnirehtet's `relay-rust` initially. A follow-up migration to `smoltcp` would unlock IPv6 and reduce maintenance.

## Auto-Start

**Mac:** `dev.tetherand.daemon.plist` LaunchAgent runs `tetherand daemon` at login. Daemon uses IOKit `IOServiceAddMatchingNotification` matching the Solana Mobile VID. On attach, brings up the configured transport (defaults to ADB) and signals the phone to start the VPN service. On detach, tears down state.

**Phone:** `USB_DEVICE_ATTACHED` and `USB_ACCESSORY_ATTACHED` broadcasts wake `TetherandVpnService` if the user has opted in. Boot-completed receiver re-starts `ThreatDetectionService` always. The privacy chain auto-resumes its last active configuration if "remember chain" is on.

## Testing

- **Rust:** unit tests for codec, packet parsing, TCP state machine edges, transport-cap negotiation, hop orchestrator state machine.
- **Kotlin:** unit tests for chain orchestration, threat heuristics on canned signal sequences.
- **Instrumented Android tests** (Espresso + UI Automator): VpnService permission gating, transport selection state machine, foreground-notification lifecycle, QS tile, chain hot-reload.
- **End-to-end:** `scripts/smoke.sh` runs ping / DNS / HTTP / 10 MB throughput over each transport, with optional `--chain mullvad-pq+tor` to also exercise the chain.
- **Gnirehtet regression:** identical workload on USB-ADB, expect ≤ 10% throughput delta vs. upstream Gnirehtet.
- **Heuristic replay:** record real cell-info / Wi-Fi traces, replay them through the threat engine in tests; ship known IMSI-catcher and evil-twin recordings as fixtures.

## Build & Distribution

- `make build` → signed-release APK + arm64-darwin `tetherand` binary in `bin/`.
- `make install` → installs APK to connected device, prompts to register the LaunchAgent.
- `make package` → tarball with binary, plist, README, and APK.
- APK signed by `keys/release.jks` (initial key generated locally; replace with a hardware-backed key before any public distribution).

## Milestones

| | Scope | Effort | Cumulatively functional |
|---|---|---|---|
| **M1** Tether MVP | Fork + rebrand, transport abstraction, USB-ADB transport, TCP transport, Compose Tether tab, `tetherand run` CLI | 10-14 h | Replaces `connect.sh` |
| **M2** More transports | BT RFCOMM transport, USB-AOA transport, ratatui dashboard, LaunchAgent + IOKit USB watcher | 10-14 h | All 4 transports |
| **M3** Privacy chain core | Hop interface, WireGuard generic hop, chain orchestrator, Privacy tab with chain visualizer | 14-18 h | WG-only chains |
| **M4** Mullvad + PQ | Mullvad API client, account login, PQ tunnel, multihop, DAITA, obfuscation toggles, kill-switch, split-tunnel | 8-12 h | + Mullvad |
| **M5** NymVPN | `nym-vpn-client` embedded via JNI, mnemonic login, entry/exit selection | 6-10 h | + Nym |
| **M6** Tor + bridges + PQ | Cross-compile `tor` and PTs for arm64-android, configure as a hop, BridgeDB integration, control-port wrapper, PQ flags | 14-18 h | Full chain library |
| **M7** Threat detection | All signal sources, heuristic engine, per-location baselining, Threat tab + alert feed + panic button | 16-20 h | Threat subsystem live |
| **M8** Polish & release | Smoke tests, signed release APK, install scripts, README, performance tuning | 6-8 h | Shippable |

**Total: ~85-115 h of focused work.**

Three independently shippable subsystems:
- **Tether (M1–M2)** — works alone, ships first; this is the immediate `connect.sh` replacement.
- **Privacy Chain (M3–M6)** — works on cellular alone; pairs with the tether for extra privacy.
- **Threat Detection (M7)** — runs entirely standalone, always on.

Parallelization opportunities within M2 (BT, AOA, TUI, LaunchAgent are largely independent), within M4–M6 (different hop types, no inter-dep), and within M7 (signal sources independent).

## Risks & Mitigations

- **Userspace TCP/IP correctness.** Gnirehtet's stack has been in the field since 2017; we inherit its correctness. Subtle edges (window scaling, SACK) tracked as known issues.
- **AOA on Solana Seeker.** USB Accessory protocol is occasionally finicky on OEM USB stacks. Mitigation: ship USB-ADB as default; mark AOA as opt-in until validated.
- **Bluetooth throughput.** Realistic RFCOMM ceiling on Android is 1-3 Mbps; advertise this in UI so users don't expect USB speeds.
- **Tor PQ flag stability.** Tor's PQ rollout is still in progress as of design date. Spec includes the toggle but defaults to whatever Tor's recommended stable configuration is at build time. If PQ flags are unstable, the toggle is greyed-out with a "not yet available" tooltip.
- **MediaTek baseband visibility.** No `/dev/diag` means our threat detection is heuristic, not deterministic. We document this clearly in the Threat tab and recommend cross-checking with hardware-level tools (Crocodile Hunter, etc.) when in high-threat environments.
- **Mullvad / Nym API changes.** Both vendors version their public APIs; we pin and add CI canaries that exercise the documented endpoints monthly.
- **Single-VPN constraint on Android.** Android only allows one active `VpnService`; we are that one. Conflicting apps (e.g. Mullvad's own app, Mullvad already installed on the user's Seeker) are detected on pre-flight and the UI guides the user to disable them.
- **License pollution.** GPL-3 from Gnirehtet propagates to the relay core. Acceptable for v1; document clearly in `LICENSE` and `NOTICE`. Future relay rewrite can relicense.

## Open Decisions Deferred to Implementation

- Exact Bluetooth UUID for the Tetherand SDP record (will register one).
- Frame codec versioning policy (1 byte version; bump strategy TBD).
- Whether to ship a Mullvad / Nym credential vault on top of EncryptedSharedPreferences or use a more involved hardware-key strategy. Default: EncryptedSharedPreferences for v1.
- Whether to ship pre-bundled Tor PT binaries vs. download-on-first-use. Default: pre-bundled (smaller blast radius, larger APK).

## Appendix A — Frame Codec Reference (Rust)

```rust
pub const FRAME_VERSION: u8 = 1;

#[repr(u8)]
pub enum FrameType {
    IpPacket = 1,
    Control  = 2,
    Handshake = 3,
}

pub struct Frame {
    pub ty: FrameType,
    pub payload: Bytes,
}

// Wire format:
//   len: u32 BE (total bytes including version+type+reserved+payload)
//   ver: u8
//   ty:  u8
//   res: u16
//   payload: [u8; len-4]
```

## Appendix B — Chain Hop State Diagram

```
       ┌──────────────────────────────────────┐
       │                                      ▼
   ┌─────────┐    start    ┌──────────┐    success   ┌────────┐
   │  Idle   │────────────►│Connecting│─────────────►│ Active │
   └─────────┘             └──────────┘              └────────┘
       ▲                        │                        │
       │                        │ failure                │ drop / stop
       │                        ▼                        ▼
       │                   ┌──────────┐              ┌────────┐
       └───────────────────│  Error   │◄─────────────│Stopping│
                           └──────────┘              └────────┘
```

## Appendix C — Threat Severity Scale

| Severity | Examples | UI behavior |
|---|---|---|
| Critical | Active MDM enrollment, root CA installed, persistent IMSI catcher confirmed | Full-screen alert, panic button surfaced |
| High | Stingray fallback pattern, evil-twin near a previously trusted network | Notification + Threat tab badge |
| Medium | Unusual TA jump, single anomalous cell | Quiet badge, listed in feed |
| Low | New Wi-Fi network in area, expected events | Logged only |
