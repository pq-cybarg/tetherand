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

- Linux/Windows host support before DEFCON (Mac only; CLI is Rust so porting is mostly transport-impl work — open after the conference).
- Rooting or unlocking the bootloader (Tier 2 root-only detection paths are architected and auto-engage if the user later roots).
- Cloud sync, telemetry, or any data leaving the device — period.
- Any defence that requires breaking another app's TLS (we inspect handshakes at the IP layer; we do not MITM).

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
│   │       ├── collector/{netmonster,telephony,wifi,bt,app,adbtier,mtktier2}/
│   │       ├── heuristic/{aimsicd,snoopsnitch,crocodile,ours}/
│   │       ├── tower/                # OpenCellID Room DB + EARFCN allocations
│   │       └── sdr/                  # JNI to libtetherand-sdr.so (rtl-sdr / hackrf)
│   ├── aiguard/                      # AI-era defences (M10)
│   │   └── src/main/kotlin/dev/tetherand/aiguard/
│   │       ├── runtime/              # LiteRT + NNAPI delegate, MediaTek NPU
│   │       ├── classifier/{phi,voice,text,qr}/
│   │       ├── voiceprint/           # trusted-contact voiceprint vault
│   │       ├── clipboard/            # prompt-injection scrubber
│   │       ├── provenance/           # C2PA / SynthID / Content Credentials
│   │       └── osint/                # exposure dashboard via Privacy Chain
│   ├── ai-models/                    # Quantised model assets, in-APK
│   │   ├── phi-tetherand-3b-q4.litertmodel
│   │   ├── voiceguard-v1.litertmodel
│   │   ├── textguard-v1.litertmodel
│   │   └── qrguard-v1.litertmodel
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

### Prior Art

This subsystem builds on four existing GPL-3 projects whose code we can port directly:

- **AIMSICD** (Android IMSI-Catcher Detector) — github.com/CellularPrivacy/Android-IMSI-Catcher-Detector. Mostly inactive since ~2017 but the canonical reference for non-root, TelephonyManager-based IMSI-catcher detection. Heuristics we port: `BTSAlgorithm` (cell-tower consistency vs. OpenCellID), LAC/CID consistency, neighbor-cell consistency, femtocell pattern, encryption-status capture where carriers expose it, silent-SMS heuristic (binary SMS arrival to phantom port).
- **SnoopSnitch** — opensource.srlabs.de/projects/snoopsnitch. The Qualcomm `/dev/diag` path does not apply to the Seeker (MediaTek), but we port the higher-level subset: silent-paging analysis, cell-tower fingerprinting design, RAT-downgrade severity scoring, encryption-indicator algorithm (A5/0 etc. when exposed via `cell_info` or `service_state` extras). The Qualcomm-diag pathway is preserved in the codebase but gated to `Build.HARDWARE` matching Qualcomm SoCs — it will not activate on the Seeker but the architecture is portable to Qualcomm phones (your next device, a passenger's Pixel, etc.).
- **NetMonster-core** — github.com/mroczis/netmonster-core. Actively maintained (2024+), GPL-3, and crucially **MediaTek-aware**: uses reflection against MTK-specific framework classes to surface neighbor cells, secondary serving cells, EARFCN/PCI/TAC/eNB-ID/RSRP-Q, NR-side-info, carrier-aggregation state, and the "subsidiary" fields that `TelephonyManager.getAllCellInfo()` silently drops on MediaTek. This is the bridge that gives us baseband-grade visibility on the Seeker without root.
- **Crocodile Hunter** (EFF) — github.com/EFForg/crocodilehunter. Phone-side data collector (Java) plus server-side ML analysis (Python) plus optional SDR (Airspy/RTL-SDR) capture. We port the phone-side collector and *all* heuristics that don't require an SDR; we also support **optional RTL-SDR-via-USB-C-OTG mode** for the full pipeline (see "Crocodile Hunter Integration" below).

All four projects are GPL-3 — compatible with our Gnirehtet-derived relay base.

The runtime is therefore layered: **NetMonster-core for MediaTek-aware data collection on the Seeker**, AIMSICD's `BTSAlgorithm` + tower DB for non-root heuristic scoring, SnoopSnitch's higher-level heuristics for paging/encryption analysis, and Crocodile Hunter's TAC/EARFCN/GPS-cross-check heuristics. Plus our additions (Wi-Fi/BT/app-audit + SDR mode).

Tower database: bundle a quarterly OpenCellID snapshot in-APK (~80 MB compressed for global). Room + an `mcc_mnc_index` partial-load strategy so DB lookups stay sub-millisecond on-device. In-app updater for fresh pulls, opt-in, runs through the user's selected Privacy Chain if one is active.

### MediaTek-Specific Detection Path

The Seeker is `arm64-v8a` with a MediaTek SoC. There is no Qualcomm `/dev/diag` — but MediaTek exposes equivalent information through different surfaces. The strategy is layered by privilege:

**Tier 0 — Unprivileged (Seeker default, no root):**
- **NetMonster-core** as the primary collector. Pulls full LTE/NR cell info via MTK reflection (EARFCN, TAC, eNB-ID, PCI, RSRP/RSRQ/SINR, NR-NSA/SA mode, neighbors, secondary cells, CA bands). This is the data SnoopSnitch reads from `/dev/diag` on Qualcomm; NetMonster reads it from MTK framework internals via reflection.
- `TelephonyManager.requestCellInfoUpdate()` + `TelephonyCallback.{CellInfoListener, ServiceStateListener, SignalStrengthsListener, DisplayInfoListener}`. The `DisplayInfo` callback exposes the carrier's display capability (5G/LTE+/LTE) which often diverges from actual RAT under attack.
- Engineering Mode broadcast probes — MediaTek devices respond to `Intent.ACTION_DIAL` with `*#*#3646633#*#*` (Engineering Mode) and `*#*#83781#*#*` (Field Trial). We programmatically launch the dialer with these codes only when the user explicitly opts in from the Threat tab ("Open MediaTek diagnostic"). We do not require this for default operation, but it is the user's fallback for deep modem state.

**Tier 1 — Optional adb-shell access (no root, but USB debugging enabled — fits our existing setup):**
- `adb shell dumpsys telephony.registry` — exposes per-subscription state including extras the Java API hides (cipher state on some MTK builds, registered TAC history).
- `adb shell service call iphonesubinfo …` — returns IMEI/IMSI history for re-attach detection.
- `adb shell getprop | grep -iE 'gsm|ril|modem|mtk'` — MediaTek RIL properties expose `gsm.network.type`, `ril.cipher.algorithm`, `vendor.mtk.signal.report.mode`. Polled by a small background poller in the Mac daemon when the device is tethered; results pushed back to the phone via the existing transport's control frames.

**Tier 2 — Root (not assumed; if user roots their Seeker later):**
- `/proc/ccci_md1_*` — MediaTek's Cross-Core Communication Interface. Contains modem state machine transitions. Equivalent in spirit to Qualcomm's diag.
- `/sys/class/ccci_md1_*` — modem firmware version, capability bitmap.
- `mdlog` (MTKLogger) dumps when enabled — full modem trace; matches what SnoopSnitch's Qualcomm pipeline ingests.
- AT command channel via `/dev/ttyMT*` (alias varies): supports `AT+CSQ`, `AT+CREG?`, MTK proprietary `AT+EHSR`, `AT+EPSB` for service state.

We implement the architecture for all three tiers. Tier 0 is what activates on a stock Seeker today. Tier 1 activates whenever the phone is tethered to the Mac (we already have the ADB channel open). Tier 2 is dormant unless `/proc/ccci_md1_*` is readable, automatically engaging if the user roots later.

Detection-depth indicator in the Threat tab UI: "Mode: MediaTek (Tier 0 + Tier 1 active)" so the user knows what coverage they have.

### Crocodile Hunter Integration

Two-mode integration:

**Software-only mode (default, always on):** port the EFF Crocodile Hunter Android client's data collector and Python heuristics to Kotlin / Rust.

Ported heuristics from Crocodile Hunter:
- **TAC anomaly with GPS cross-check**: TAC change without geographic movement (cross-checked against `FusedLocationProviderClient` + linear acceleration). The strongest CH signal: stingrays often announce a new TAC to force re-attach (and re-leak IMSI).
- **EARFCN out of allocation**: LTE channel outside the user's MCC/MNC operator's published EARFCN allocation. CH bundles operator allocations; we port the table and update via the same in-APK quarterly bundle as OpenCellID.
- **Suspicious eNB-ID / sector count**: CH's "tower fingerprint" — an eNB legitimately operates a small number of sectors; an attacker often runs a single sector. Cross-references the tower DB.
- **Cell Found Rate (CFR) anomaly**: > N distinct PCI / cell-ID observations in T seconds while stationary.
- **Re-attach storm**: > N `EVENT_TAC_CHANGE` + `EVENT_CELL_CHANGE` in M seconds — characteristic of forced re-attach.
- **TMSI churn (when exposed)**: TMSI cycling faster than carrier baseline.

**SDR mode (optional, USB-C OTG):** Seeker's USB-C supports OTG with bus-power-budget for an RTL-SDR (~$30) or HackRF. When user plugs in a supported SDR, we detect the VID/PID and enable SDR mode.

- Driver: bundle `librtlsdr-android` (Marto Lazo's port, GPL-2; we link dynamically and document the license boundary). HackRF support via `hackrf_android` (likewise dynamic-link, license preserved).
- Scanner: a Rust component (compiled to `libtetherand-sdr.so`) tunes through the operator's LTE bands, decodes MIB/SIB1/SIB2/SIB3 broadcast control messages via a stripped-down `srsRAN`-derived decoder, captures Random Access channel events.
- Heuristics gated on SDR mode (CH-derived):
  - SIB content mismatch — the SIB advertised on PCI X differs from what we've previously seen on that PCI (likely fake cell).
  - SIB cell-barring flag flipping on/off rapidly.
  - Master Information Block (MIB) bandwidth mismatch with EARFCN expectation.
  - Persistent Random Access bursts (paging storms preceding silent SMS).
- Storage: PCAP-like binary log to `app-internal-storage/sdr-captures/`, viewable from Threat tab, exportable on demand (opt-in only).

**Server-side correlation (deliberately not adopted):** EFF Crocodile Hunter syncs cell observations to a community server. We **do not** sync by default. We include an opt-in toggle "Share anonymized observations with the EFF Crocodile Hunter community" — off by default, behind a clear consent screen, and the data flows only through the user's currently-active Privacy Chain if one is on.

UI surface for CH features:
- Threat tab gets a "Cellular details" panel showing live TAC, PCI, EARFCN, eNB-ID, neighbors.
- An "SDR" sub-tab appears only if an SDR is connected; shows live SIB decode and the MIB/SIB sparkline.
- Settings → "Community" page hosts the opt-in for EFF server sync.

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

Cellular — Tier 0 / Tier 1 (no root, software-only):

- **Stingray fallback** (SnoopSnitch-derived): RAT downgrades from 5G/LTE to UMTS/GSM in an area baseline-recorded as 4G/5G covered. Confidence increases with sudden + stationary (low accel) + new cell ID. Severity scored on AIMSICD's `BTSAlgorithm` weights.
- **Fake BTS** (AIMSICD `BTSAlgorithm`): cell `CID/LAC/MCC/MNC` not present in OpenCellID snapshot for the user's area, AND anomalously high signal, AND zero `neighboringCellInfo`. Tower-DB lookup is local.
- **LAC change anomaly** (AIMSICD): LAC changes more than threshold/hour while stationary; LAC value outside known carrier LAC ranges.
- **Femtocell pattern** (AIMSICD): CID values in vendor-known femtocell ranges, with `getCellLocation()` GPS inconsistency.
- **Silent SMS** (SnoopSnitch-derived, best-effort): binary SMS arrivals to phantom ports detected via `SmsManager` broadcast inspection; full coverage limited by Android 12+ permissions, but stalking-grade silent SMS is still partly visible.
- **Encryption indicator** (SnoopSnitch-derived): when carrier `service_state` extras expose cipher info, alert on A5/0 (no encryption). Some carriers expose this via `TelephonyManager` extras; many don't — flag is presented as "data available" / "not exposed by carrier". On Tier 1 we additionally poll the MediaTek RIL prop `ril.cipher.algorithm` via the tethered ADB channel.
- **Cell fingerprint mismatch** (SnoopSnitch-derived): persistent cell IDs whose signal/neighbor fingerprint changes day-over-day.
- **TAC change without movement** (Crocodile Hunter): TAC change while GPS + accel show the user is stationary. Strongest CH signal — characteristic of a re-attach attack.
- **EARFCN out of allocation** (Crocodile Hunter): LTE EARFCN outside the user's operator's published allocation table.
- **Suspicious eNB sector count** (Crocodile Hunter): a tower DB entry with a single sector when the operator's typical eNB runs ≥ 3.
- **Cell Found Rate anomaly** (Crocodile Hunter): > N distinct PCI / cell-ID observations in T seconds while stationary.
- **Re-attach storm** (Crocodile Hunter): > N TAC-change + cell-change events in M seconds.
- **TMSI churn** (Crocodile Hunter, when TMSI exposed): TMSI cycling faster than carrier baseline.
- **TA jump** (our addition): Timing Advance > N rings change in < 5 s without motion (Linear Accel below threshold) → suggests cell location forgery or sudden cell switch.
- **Cell flapping** (our addition): > 4 cell-ID handovers in 60 s while stationary.
- **MediaTek extras** (NetMonster-core): NR-NSA / NR-SA mode inconsistency (e.g. NSA reported but no LTE anchor); secondary serving cell suddenly disappearing; carrier-aggregation bands collapsing while signal nominally strong.

Cellular — SDR mode (optional, RTL-SDR / HackRF via USB-C OTG):

- **SIB content mismatch** (Crocodile Hunter SDR): SIB1/SIB2/SIB3 broadcast on a given PCI differs from previous observations on that PCI.
- **Cell-barring flag flapping** (Crocodile Hunter SDR): SIB1 `cellBarred` flag toggles rapidly.
- **MIB bandwidth mismatch** (Crocodile Hunter SDR): Master Information Block bandwidth advertised inconsistent with EARFCN expectation.
- **Paging-storm pattern** (Crocodile Hunter SDR): persistent bursts of paging messages preceding silent-SMS-style stalking.

Cellular — Tier 2 (root, dormant on stock Seeker; auto-activates if user roots):

- **Modem state transitions** (MediaTek `/proc/ccci_md1_*`): RRC connection releases without legitimate cause; service interruptions while signal is nominal — these are the events SnoopSnitch reads from Qualcomm `/dev/diag`, equivalents read from MTK's CCCI.
- **`mdlog` trace anomalies**: when MTKLogger is enabled, parse the dumps for RRC + NAS-layer messages indicating active attacks.

Wi-Fi / Bluetooth / App-audit (our additions, not in AIMSICD or SnoopSnitch):

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
- **Detection-depth pill** — "Mode: MediaTek Tier 0+1 (NetMonster reflection 8/12, ADB-tier active)" so the user always knows what coverage is live.
- **Cellular details panel** — live TAC, PCI, EARFCN, eNB-ID, neighbor count, encryption indicator, NR/LTE mode.
- **Live signal map** — sparklines for RAT, RSSI, neighbors, TA, cell flaps, TAC churn, EARFCN, color-coded.
- **Alert feed** — most recent 50 alerts, expandable evidence, "dismiss" / "snooze 1 h" / "always alert".
- **Threat detail** — per-alert page explaining the heuristic, the evidence (incl. the raw NetMonster / CH fields that triggered it), and recommended actions.
- **SDR sub-tab** — appears only when an RTL-SDR or HackRF is connected; live SIB1/SIB2/SIB3 decode, MIB sparkline, raw PCAP-style capture viewer, export.
- **MediaTek diagnostics** — explicit button "Open Engineering Mode (`*#*#3646633#*#*`)" for user-driven inspection.
- **Panic button** — "Airplane Mode + activate Privacy Chain on Tor only"; one tap.

### Privacy of the Threat Service

No data leaves the device. Baselines stored in `EncryptedSharedPreferences` with hardware-backed keystore. Alerts stored in a local Room database, auto-pruned > 30 days unless the user pins them. Export-on-demand only.

## Hardened Mode (DEFCON Profile)

DEFCON's network is famously the most hostile WiFi/cellular environment in the world: Stingrays, Wi-Fi Pineapples on drones, KARMA, deauth floods, evil twins, juice-jacking cables in the hotel, hostile USB drops in vendor village, BLE trackers attached to bags, and an audience explicitly trying to find unpatched things. The Solana Seeker adds a crypto-wallet target on top.

The defaults the rest of the spec describes are good for everyday use. Hardened Mode is a one-tap profile that turns the volume to 11 on every defense and adds capabilities only relevant in adversarial environments.

### Activation

One tile in Quick Settings + a slider on the Threat tab. Toggling on:
1. Captures a **pre-conference attestation snapshot** (see below) — required first time.
2. Applies all hardening actions atomically — partial activation is not allowed; if any required step fails, rolls back.
3. Persistent foreground notification with "DEFCON Mode active — X defenses live" plus a 1-tap deactivate.

Toggling off:
1. Captures a **post-conference attestation snapshot**.
2. Diff against pre-snapshot; shows changes (new apps, new admins, new CAs, hardware-attestation drift, boot count delta, etc.).
3. Restores prior settings (with confirmation).

### Defenses Engaged

**Network — kill switch and chain enforcement**
- **Always-on VPN through Privacy Chain**, with Android's `alwaysOn` + `lockdown` flags set programmatically (we are the active VpnService, so this is just our own config). Lockdown means *zero* traffic leaves the device when the VPN is down — no leaks, no DNS punch-through, no captive-portal exception.
- **Forced Tor chain**: Hardened Mode replaces whatever the active chain was with `wg(mullvad-pq, multihop, far-from-vegas) → tor(snowflake+conjure bridges, vanguards, isolate-by-destination)`.
- **Per-app firewall**: all non-essential apps lose `INTERNET` capability via per-UID blackhole rules in our VpnService. User picks the allowlist before entering DEFCON; defaults to: Tetherand, Signal, system clock sync. Everything else is offline.
- **Block cleartext traffic**: VpnService inspects and drops plaintext HTTP/IMAP/POP3 attempts and surfaces the offending app.
- **DNS hardening**: DNS-over-HTTPS through the chain's exit, with system DNS blackholed. Local DNS sinkhole bundled — blocks ad/tracker/known-malicious domains (`StevenBlack/hosts` list, periodically refreshed through chain).
- **RFC1918 leak detector**: alerts on any traffic destined for `10/8`, `172.16/12`, `192.168/16` that's not the captive-portal probe (which is also disabled).
- **Outbound port allowlist**: blocks ports < 1024 outside 53/80/443 unless explicitly permitted.

**Network — honeypots and probes**
- **Decoy listeners**: bind unprivileged decoy ports (8080, 8443, 8000, 9000, 1080, 3128) and log every connection attempt with peer IP + ASN + reverse-DNS-via-chain. Scans light up the Threat tab in red.
- **Honeytokens**: ship 3 baited files in `Downloads/` (`backup.pdf`, `keys.txt`, `seed-phrase.txt`) with `FileObserver` watching for access. Anything touching them = compromise.
- **Pineapple signatures**: known Wi-Fi Pineapple firmware OUI list + behavior signatures (mass-PNL responses to probe requests). Updated quarterly with the EARFCN/OpenCellID bundle.

**Cellular hardening**
- **Force LTE-only (no 2G/3G fallback)**: writes `Settings.Global.PREFERRED_NETWORK_MODE` to LTE-only via system intent; if denied, prompts user to do it in Settings. 2G is where IMSI catchers live; refusing 2G removes most attack value.
- **SIM PIN required**: prompts user to enable.
- **Operator change alert**: alerts if `TelephonyManager.getSimOperator()` deviates from baseline.
- **IMSI/IMEI/TMSI watch**: alerts if `SubscriberId` or `DeviceId` (where exposed) deviates; logs every TMSI cycle.
- **Carrier-config-change alert**: snapshots `CarrierConfigManager.getConfig()` and diffs each hour. Hostile carrier-config push is a known attack vector.
- **Pre-conference cell-baseline capture**: drives around campus / hotel and logs the cell environment so the threat engine has ground truth; runs in background during the drive.

**Wi-Fi defenses**
- **Forget all saved networks** (with backup): no network in the saved list = no KARMA attack value.
- **Auto-join disabled globally.**
- **MAC randomization forced** even for the rare networks you do join.
- **Pineapple / evil-twin / deauth / beacon-flood detection**: heuristics from Threat Detection, with severity inflated in Hardened Mode.
- **Probe-request minimization**: where Android exposes it (some OEMs do, MTK partially does via reflection), disable active probing — only passive scan.

**Bluetooth defenses**
- **Off by default** in Hardened Mode. Allowlist of paired devices (your YubiKey, your watch) can be re-enabled per-device.
- **BLE tracker scan on demand**: tap a "Scan for trackers" button — runs `BluetoothLeScanner` looking for AirTag (Apple Find My), Tile, Samsung SmartTag, Pebblebee, Chipolo, generic AltBeacon stalkerware patterns. Surfaces RSSI-vs-time graphs to show if something's been near you for a long time.
- **Name randomization**: device name set to a random alphanumeric on entry to Hardened Mode (and restored on exit).
- **BlueBorne / pairing-request flood detection**: count rejected pairing requests.

**NFC**
- **NFC off** in Hardened Mode. (DEFCON has had NFC-malware demos.)

**USB defenses**
- **Data block when locked**: USB switches to charge-only mode when screen is locked. Achieved by toggling `setting global development_settings_enabled` and the USB-data sysprop via our (Mac-tethered, ADB-channel) helper; if not available, alerts user to manually verify.
- **VID/PID allowlist**: only enumerated, known-good USB devices (your Mac, your SDR, your YubiKey) trigger any handler. Unknown VID/PID → log + alert + ignore.
- **Power-trace anomaly detection**: `BatteryManager.BATTERY_PROPERTY_CURRENT_NOW` polled at 1 Hz; alert on charging current spikes inconsistent with the negotiated PD profile (data-line activity often correlates).
- **Charge-port watcher**: detect plug/unplug events while screen is locked → photo via front camera (see Physical below).
- **ADB authorization audit**: enumerate authorized ADB host keys (`/data/misc/adb/adb_keys` is root-only; alternative is `Settings.Global.ADB_ALLOWED_CONNECTION_TIME` + manual review on each new prompt).

**App / process defenses**
- **Snapshot + diff** of every installed package, version, signature hash, and granted permission on entry to Hardened Mode. Diff on every screen unlock thereafter. New app = critical alert. New permission = high alert.
- **Accessibility-service freeze**: alert + block any change to the accessibility-service list (a common malware persistence mechanism).
- **Device-admin freeze**: same for `DevicePolicyManager.getActiveAdmins()`.
- **System-trust-store freeze**: any new root CA = critical alert.
- **Battery-usage anomaly**: `UsageStatsManager` snapshot diff — apps drawing significantly more battery than baseline get flagged.
- **Background-process scan**: list everything Android lets us see via `ActivityManager.getRunningAppProcesses()` (limited on Android 11+) and `UsageStatsManager.queryEvents()`; flag novel processes.

**Sensor / IO defenses**
- **Mic / cam persistent indicator**: foreground notification showing the live list of apps with mic / cam access. Android 12+ already surfaces this in the status bar; we duplicate it in the persistent Hardened-Mode notification.
- **Auto-revoke mic/cam from unused apps** the moment they go background.
- **Location off** except for Tetherand's own threat detector.
- **Clipboard scrub**: clipboard cleared every 30 s of inactivity; alert on any clipboard read by an app other than what the user just pasted into.
- **Screenshot watch**: detect screenshot events (via `FileObserver` on `Pictures/Screenshots/`) and confirm they were user-initiated (via `KeyguardManager` and recent touch state).

**Physical / anti-evil-maid**
- **Front-cam selfie on failed unlock**: after N failed unlock attempts in Hardened Mode, take a photo via front cam and save with timestamp + location. If you weren't there, you'll know who tried.
- **Front-cam selfie on USB-data plug while locked**: same trigger; juice-jacker selfie.
- **Accelerometer-tamper**: when device has been still for > 5 minutes (placed down), monitor accelerometer for pickup. On pickup-while-locked → log event + take selfie + require PIN (no biometric).
- **Biometrics disabled in Hardened Mode**: PIN/password only. Biometrics can be physically compelled in many jurisdictions; passwords usually cannot.
- **Lockdown mode**: invoke Android's built-in `KeyguardManager`-level lockdown which disables biometric unlock, notification preview, and Smart Lock until the next password unlock.
- **Show-on-lockscreen disabled**: notifications redact contents on the lock screen.

**Crypto wallet (Solana Seeker-specific)**
- **Pre-DEFCON wallet migration prompt**: surfaces in Hardened Mode toggle — "Move your Solana keys off-device before the conference." Walks user through Seed Vault export to a Saga / hardware wallet, or a fresh paper-only mnemonic stored offsite.
- **Seed Vault freeze**: monitors the Solana Mobile Stack Seed Vault for any access attempt; alerts on unsolicited reads.
- **dApp store monitor**: snapshots installed Solana dApps; new install = critical (high targeted-malware risk in this audience).
- **Transaction firewall**: any transaction signing request while Hardened Mode is on requires a 30-second cool-down and explicit re-PIN. Blocks 0-click drains.
- **Recommend: leave the Seeker's primary keys at home.** Bring a freshly-flashed device with empty Seed Vault if you must transact.

**Counter-surveillance**
- **Ultrasonic-beacon listener**: 1-second mic samples every 5 minutes, FFT for tones in 18-22 kHz band (common ad-network ultrasonic beacon range); alert on detected tones. Listen only — never record speech.
- **BLE proximity-tracker**: continuously scan for BLE devices that follow you across location bins (geohash6 changes); a persistent BLE MAC across many geohashes = likely tracker.
- **Wi-Fi probe-request leakage detector**: as noted; if Android exposes outbound probes via reflection, log and alert.
- **TLS-cert pinning audit**: known sites (Mullvad, Signal, GitHub, your bank) have pinned cert fingerprints; alert on any change. (Functions only for traffic going through our VpnService; we can inspect TLS handshakes by parsing TLS-ClientHello / Server SNI / cert chain — without breaking TLS — at the IP layer.)

**Power / battery**
- **Battery health snapshot** before/after.
- **Charge-cycle audit**: too many cycles overnight = device-was-plugged-in-untrusted-cable.
- **Only-when-screen-on charging**: optional — refuse to charge while screen is off in Hardened Mode (we can fake-discharge via `BatteryManager` userspace tricks; limited effect, but visible).

**Recovery / resilience**
- **Encrypted pre-DEFCON backup to Mac**: full local backup over the tether — all settings (global/secure/system), every installed APK, all user storage (Pictures/DCIM/Movies/Music/Documents/Download), permission grants, signing-cert fingerprints, device fingerprint and baseband — packaged into one `.tar.gz.enc` (AES-256-CBC, PBKDF2 600k iterations, user passphrase). SHA-256 manifest of every file inside. Available **today** via `./backup.sh`. Restore via `./restore.sh <archive>` with mode-restricted variants (`--settings-only`, `--apks-only`, `--media-only`) and a `--undo` flag that captures the pre-restore state so the restore itself is reversible. Documented limits: hardware-keystore-backed keys and apps that refuse `adb backup` (most modern privacy apps) are not in scope — those follow their own backup procedures.
- **Dead-man's switch (optional)**: if user doesn't check in within N hours, send a Signal message to a chosen contact / trigger remote wipe / trigger Solana-key revoke. Off by default; configured explicitly.
- **Hardware-key unlock fallback**: support YubiKey (USB-C) for unlock challenge — even if face/PIN are compelled, the YubiKey isn't on you.
- **Multi-factor escape mode**: a hidden second profile with decoy data; specific PIN unlocks it instead of the real one. Useful at borders / under coercion.

### Pre / Post Conference Attestation

A snapshot taken on Hardened Mode entry and again on exit:

| Field | How |
|---|---|
| Hardware attestation | `KeyStore.getInstance("AndroidKeyStore")` + `KeyAttestation` chain; root key signed by Google attestation root |
| Boot counter / verified boot state | `KeyAttestation.getVerifiedBootState()` |
| Bootloader version | `Build.BOOTLOADER` |
| System properties (modem firmware, baseband, fingerprint) | `Build.*` + `getprop` whitelist |
| Installed package list + signature hashes | `PackageManager.getInstalledPackages(GET_SIGNATURES)` |
| Granted permissions per app | `PackageManager.getPackageInfo(GET_PERMISSIONS)` |
| Root CA store hash | enumerate + SHA-256 |
| Device admins, accessibility services, VPN profiles | `DevicePolicyManager`, `AccessibilityManager` |
| Settings.Secure / Settings.Global whitelist | filtered get |
| Cell-environment baseline | last 7 days of cell observations, hashed |
| Wi-Fi network preferences | hash |
| App data sizes (proxy for tampered data) | `UsageStatsManager` |

Diff is computed via `git diff`-style unified view, surfaced in the Threat tab post-DEFCON. Anything weird → guided incident response runbook.

### Incident Response Runbook (in-app)

If a critical alert fires during DEFCON, Hardened Mode walks the user through:

1. Verify the alert via at least one independent signal (cross-check across heuristics).
2. Decide between four responses, presented as buttons with clear consequences:
   - **Acknowledge** — log + continue (low confidence alert).
   - **Isolate** — switch to airplane mode, kill all running apps except Tetherand, surface the live signal panel.
   - **Evacuate** — full backup to Mac, then factory reset on a defined trigger phrase.
   - **Burn** — secure-wipe the device immediately (`DevicePolicyManager.wipeData(WIPE_RESET_PROTECTION)` with optional `WIPE_EXTERNAL_STORAGE`). Confirmation required.

### Quick Wins Available Today (Pre-APK)

Hardened Mode is fully realized only with the M7+ app, but the high-value subset is achievable **right now** using only:

- This Mac, `adb`, the Seeker, and one shell script.
- ~$70 of hardware (USB data blocker, Faraday pouch, RTL-SDR if you want SDR mode early).
- Existing apps (Mullvad, Orbot, Signal).

We ship a `scripts/defcon-prep.sh` that runs through everything below.

The runnable checklist (script does these or prompts for them):

1. **Capture attestation snapshot** — `adb shell` enumerations of installed packages + permissions + root CAs + bootloader/baseband versions + cell-env baseline, stored locally on the Mac under `attestation/pre/`.
2. **Enable always-on VPN + lockdown** through Mullvad app (instructs user to set up Mullvad PQ multihop with a non-Vegas entry; verifies via `adb shell settings get global always_on_vpn_lockdown`).
3. **Enable Orbot** with Snowflake bridge as a secondary chain (configure manually; script verifies the package is installed and configured).
4. **Force LTE-only**: writes `Settings.Global` preferred-network-mode where allowed; otherwise opens the carrier-settings screen and prompts the user.
5. **SIM PIN** prompt + verification.
6. **Forget all saved Wi-Fi networks** (script lists them and asks; deletes with `adb shell cmd wifi forget-network`).
7. **Disable NFC** via `adb shell svc nfc disable`.
8. **Bluetooth off** via `adb shell svc bluetooth disable`.
9. **Disable USB debugging in untrusted contexts**: cycle ADB authorization (clear `~/.android/adbkey` on Mac after final config, generate fresh keys, single-Mac authorize).
10. **Permission audit** — script dumps every dangerous permission grant and surfaces the diff vs. a clean device baseline.
11. **Install signing-key snapshot** — `adb shell pm list packages -f -i` + sha256 every APK signing cert; baseline for tamper detection.
12. **Migrate Solana keys**: script does **not** touch the Seed Vault; it walks the user through a Seed Vault export to an offline device, then verifies the on-device vault is empty.
13. **Battery / charge baseline** — capture `dumpsys battery` + thermal sensors snapshot.
14. **Cell baseline drive**: script starts a 30-minute logger via `adb shell` that captures `dumpsys telephony.registry` + `getAllCellInfo` every 30 s while the user walks the conference perimeter; saves to `attestation/cell-baseline.jsonl`.
15. **Hardware buy list**: prints recommended hardware items not yet acquired (data blocker, Faraday pouch, YubiKey 5C NFC, RTL-SDR + USB-C OTG dongle, throwaway power bank).
16. **Operational reminders**: prints the OPSEC checklist (use cash, don't pick up USB drives, no biometric unlock, don't connect to "DEFCON-Open", keep phone in Faraday pouch when sleeping, etc.).
17. **Post-conference re-run**: script's `--post` mode captures the post-snapshot and diffs against pre.

This pre-flight script ships as **M0** — buildable and runnable today, no Kotlin involved. See updated milestones.

### AI-Era Threats (first DEFCON of the LLM-mass-market era)

The 2026 DEFCON is operating in a fundamentally different threat landscape than any prior year. Attackers now have:

- Real-time voice synthesis good enough to impersonate trusted contacts after a few seconds of training audio (RVC, ElevenLabs, OpenVoice).
- Real-time speech-to-text + LLM + TTS pipelines fast enough to hold a coherent two-way conversation while wearing a fake identity.
- Personalised phishing generated from your scraped OSINT (LinkedIn, GitHub, X, scraped breach data) with a copy quality indistinguishable from a real colleague.
- Multimodal vision models that can read your screen from a meters-away camera and generate context-aware lures in seconds.
- Adversarial-ML inputs (poisoned QR codes, prompt-injection stickers, model-confusing visual patterns) carried by any vendor swag or badge artwork.
- LLM-augmented social engineering during in-person chat that drafts the next reply on a hidden earpiece in under a second.

Tetherand counters with on-device, model-driven defences. None of these phone home; all classifiers run locally on the Seeker's NPU.

**On-device classifier stack (M10)**

A small ensemble of locally-running models, bundled in-APK and updated via in-APK delta updates (delivered through the active Privacy Chain only, never out-of-band):

- **`phi-tetherand-3b-q4`** — distilled Phi-3.5-mini variant fine-tuned on a corpus of phishing / social-engineering / scam messages. INT4 quantised, ~1.8 GB, runs on the Seeker's NPU via LiteRT (formerly TFLite) + GpuDelegate / NNAPI. ~120 ms per message classification.
- **`voiceguard-v1`** — speech-synthesis-detection model. Trained on the WaveFake + ASVspoof2024 corpora. Mel-spectrogram + ConvNeXt-tiny backbone. ~40 ms per second of audio. Inputs: live mic stream + inbound call audio (via Telephony `IncallService`).
- **`textguard-v1`** — LLM-generated-text detection. Lightweight classifier (binoculars-style) using two different LLM perplexity surfaces. Surfaces "AI-likely" badge on incoming SMS/IM. ~60 ms per message.
- **`qrguard-v1`** — adversarial-image detector for QR codes / general visual lures. Detects perturbation patterns from `RobustBench` adversarial families. ~30 ms per image.

**Defences engaged in Hardened Mode (AI-era)**

- **Inbound-message AI screen.** Every incoming SMS, RCS, Signal-relay (via accessibility hook, opt-in), email-preview-notification is classified by `phi-tetherand-3b-q4` for: phishing intent, social engineering, prompt injection (in case any app feeds the message to an LLM agent the user runs), urgency-manipulation, financial-asks. Verdict shown as a banner; high-risk messages can be auto-quarantined.
- **Voice-deepfake detection on inbound calls.** `voiceguard-v1` runs on the call audio (via `InCallService.onAudioStateChanged`). Surfaces a notification banner if the voice is likely synthetic. Includes a "voiceprint vault" of your trusted contacts — fingerprint stored locally on first authenticated call; subsequent calls cross-check.
- **Vishing pattern detection.** Conversation-state classifier looks for known vishing scaffolds (urgency + authority + secrecy + financial-action + abnormal channel). Independent of voiceprint.
- **LLM-generated text badge.** `textguard-v1` flags inbound text that scores as machine-generated. Not an automatic block — just an awareness signal: a tiny "AI?" badge in the notification, plus the verdict in the Threat tab feed.
- **QR-code / image lure inspector.** A share-target intent so any QR scan or shared image first passes through `qrguard-v1`. Adversarial-perturbation pattern → red banner + URL preview behind a click-through.
- **Prompt-injection-resistant clipboard.** Clipboard contents are scanned for known prompt-injection scaffolds ("ignore previous instructions", "system:", "[INST]", `<|im_start|>`, common jailbreak prefixes). Scaffolds get stripped or quarantined before any app reads the clipboard. (Implemented via `ClipboardManager.OnPrimaryClipChangedListener` + a one-shot transform.)
- **Synthetic-content provenance check.** Inspect inbound images / video for C2PA manifest, SynthID watermark, or Microsoft Content Credentials. Surface "Genuine / Synthetic / Unknown provenance" badge.
- **Real-time microphone-use awareness.** Persistent banner when mic is in use, with the using-app's name and AI-pipeline-detection (heuristic on the using-app's process behaviour — e.g. high egress + high CPU during mic capture = likely real-time STT pipeline running against the user's voice).
- **OSINT exposure dashboard.** Pulls (through the active Privacy Chain) from `haveibeenpwned`, `intelligence-x`, public LinkedIn / GitHub for the user's accounts. Surfaces "your AI-targetable surface area" — leaks visible to a targeted attacker. Off by default; opt-in.
- **AI-augmented social engineering field guide.** Threat tab "field guide" page with current attacker tactics: deepfake-on-call, fake-AirDrop conference-app, fake-Reddit-link clickbait, QR-poison badge stickers, etc. Updated through the chain.
- **NPU/AI-accelerator side-channel monitoring.** Watch `/sys/devices/.../mtk_apu*` (MediaTek's NPU sysfs) for unexpected usage from non-user-foreground apps — a covert on-device model running while you sleep is a real risk. Surface in Threat tab.
- **Adversarial-input quarantine for our own models.** If `qrguard-v1` itself reports a confidence-instability pattern (high logit variance under tiny input perturbation), the input is flagged as adversarial regardless of class verdict — protects against attacker-crafted inputs designed to fool our defences.
- **Conference-mode contact verification.** A "verify caller" button that initiates a Signal-Voice or in-app voiceprint handshake before the conversation continues. Prevents real-time deepfake takeover of phone calls.
- **Deepfake-resistant 2FA fallback.** Any 2FA prompt during Hardened Mode requires the YubiKey (USB-C touch). No SMS, no voice-call confirmation, no email — all of those are AI-spoofable now.
- **Conference live threat feed.** Pull (through Privacy Chain only) curated threat intel from DEFCON's own security operations Mastodon, the Wall of Sheep team's IRC, and EFF Crocodile Hunter's community feed. Surface active campaigns as Threat tab cards.
- **Egress LLM-API watch.** Inspect outbound TLS handshakes for SNI patterns matching `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, etc. If an app is talking to LLM APIs without the user's awareness, surface it — this catches both AI-supercharged malware *and* well-intentioned apps secretly forwarding your data to model providers.

**Storage & footprint**

The four-model bundle is ~2.4 GB compressed in-APK as a separate downloadable feature module (Play Asset Delivery's `install-time` policy) or sideloaded from `dist/` for direct-install distribution. INT4 quantisation keeps inference under 200 ms per event on the Seeker's NPU and well within battery budget for continuous mic + message classification.

**Update path**

Models update via in-APK delta updates served from our distribution URL, fetched through the active Privacy Chain, verified by signature against a pinned cosign public key shipped in the APK. No model update ever bypasses the chain. No telemetry returns to us.

### Hardened Mode Threat Coverage Matrix

| Threat | Mitigation in Hardened Mode |
|---|---|
| IMSI catcher / Stingray | LTE-only + NetMonster Tier 0 + CH heuristics + (opt) SDR mode + drive baseline |
| Wi-Fi Pineapple / evil twin | Forget networks + Pineapple sigs + deauth detection + always-on VPN lockdown |
| Juice jacking | Data block when locked + VID/PID allowlist + power-trace + charge-port selfie |
| BLE / AirTag tracker | BLE scan + proximity persistence detection |
| Hostile USB drop | Won't enumerate without VID/PID + no auto-run on Android anyway |
| Karma / probe leakage | All saved networks forgotten + probe-request minimization |
| App impersonation / signing | Signing-cert sha snapshot + diff |
| Persistence: accessibility service | Service-list freeze + alert |
| Persistence: device admin | Admin-list freeze + alert |
| Persistence: rogue CA | Trust-store freeze + alert |
| Persistence: rogue VPN | Single-VPN constraint (we are it) + scan for `VpnService`-capable packages |
| Cellular cipher downgrade (A5/0) | Encryption-indicator + MTK-RIL prop poll (Tier 1) |
| Silent SMS stalking | Silent-SMS heuristic + SDR paging-storm |
| DNS hijack | DoH-through-chain + DNS sinkhole |
| TLS MITM | TLS-ClientHello/SNI/cert-chain inspection at IP layer + cert pinning audit |
| Captive portal coercion | Lockdown VPN refuses captive-portal exception |
| Ultrasonic ad-network tracking | Listener + FFT detection |
| RAM-disk forensics | Encrypted backup option, no plaintext at rest |
| Evil maid (physical access while away) | Accelerometer tamper + selfie + boot-count attestation |
| Coercion / compulsion | Decoy profile + YubiKey unlock + biometrics-off |
| Wallet drain | Tx firewall cool-down + Seed Vault freeze + recommend off-device keys |
| AI voice deepfake on call | `voiceguard-v1` on-device detector + voiceprint vault of trusted contacts |
| Real-time AI-impersonation conversation | Conversation scaffold classifier + Signal-handshake verify-caller flow |
| LLM-personalised phishing | `phi-tetherand-3b` inbound-message screen + urgency-manipulation classifier |
| Adversarial QR / lure imagery | `qrguard-v1` perturbation detector + URL-preview gate |
| Prompt-injection-poisoned clipboard | Clipboard scanner strips known injection scaffolds before any app reads |
| Synthetic media (deepfake images/video) | C2PA / SynthID / Content Credentials provenance check + classifier |
| LLM-supercharged spyware (calls home to LLM APIs) | Outbound SNI watch for `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, etc. |
| Covert NPU use by background app | MTK NPU sysfs watcher (`/sys/devices/.../mtk_apu*`) |
| AI-driven 2FA spoofing (voice / SMS / email) | YubiKey-only 2FA required in Hardened Mode |
| Targeted-OSINT attacker prep | OSINT exposure dashboard surfaces your scraped surface area pre-DEFCON |

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
| **M0** DEFCON pre-flight (shippable today) | `connect.sh` (reverse-tether via upstream Gnirehtet), `backup.sh` + `restore.sh` (local encrypted full backup with `--undo`), `scripts/defcon-prep.sh` + `--post` mode (attestation snapshot, ADB-driven hardening: LTE-only, SIM-PIN prompt, NFC off, BT off, network forget, permission audit, signing-cert snapshot, cell-baseline driver, OPSEC checklist, hardware buy list, Solana Seed Vault migration walkthrough). | 4-6 h | High-value Hardened Mode subset usable **before any APK ships**, fully reversible |
| **M1** Tether MVP | Fork + rebrand, transport abstraction, USB-ADB transport, TCP transport, Compose Tether tab, `tetherand run` CLI | 10-14 h | Replaces `connect.sh` |
| **M2** More transports | BT RFCOMM transport, USB-AOA transport, ratatui dashboard, LaunchAgent + IOKit USB watcher | 10-14 h | All 4 transports |
| **M3** Privacy chain core | Hop interface, WireGuard generic hop, chain orchestrator, Privacy tab with chain visualizer | 14-18 h | WG-only chains |
| **M4** Mullvad + PQ | Mullvad API client, account login, PQ tunnel, multihop, DAITA, obfuscation toggles, kill-switch, split-tunnel | 8-12 h | + Mullvad |
| **M5** NymVPN | `nym-vpn-client` embedded via JNI, mnemonic login, entry/exit selection | 6-10 h | + Nym |
| **M6** Tor + bridges + PQ | Cross-compile `tor` and PTs for arm64-android, configure as a hop, BridgeDB integration, control-port wrapper, PQ flags | 14-18 h | Full chain library |
| **M7a** Threat MVP (no SDR) | NetMonster-core integration (Tier 0), AIMSICD `BTSAlgorithm` + bundled OpenCellID, SnoopSnitch high-level heuristics, Crocodile Hunter phone-side heuristics (TAC / EARFCN / GPS / CFR), Tier 1 ADB-channel collector in Mac daemon, Wi-Fi/BT/app-audit, per-location baseline, Threat tab + alert feed + panic button | 20-26 h | Cellular + Wi-Fi + app threat detection live on Seeker |
| **M7b** SDR mode (optional) | librtlsdr-android + hackrf_android dynamic-link, USB-C OTG SDR detection, `libtetherand-sdr.so` LTE control-channel decoder (srsRAN-derived), CH SDR heuristics, PCAP capture, SDR sub-tab | 12-16 h | SDR mode for users with $30 RTL-SDR |
| **M7c** Tier 2 (root, dormant) | `/proc/ccci_md1_*` reader, `mdlog` parser, AT-command channel via `/dev/ttyMT*`, capability-gating so it's a no-op on un-rooted devices | 4-6 h | Auto-activates if user roots later |
| **M8** Polish & release | Smoke tests, signed release APK, install scripts, README, performance tuning | 6-8 h | Shippable |
| **M9** Hardened Mode (in-app) | DEFCON Mode toggle + Quick Settings tile, kill-switch + per-app firewall, attestation snapshot + diff UI, decoy listeners + honeytokens, BLE tracker scan UI, USB data-block + selfie traps, accelerometer tamper, wallet firewall (Solana), ultrasonic listener, TLS-pinning audit, decoy-profile + YubiKey unlock fallback, incident-response runbook | 22-30 h | Full DEFCON-grade physical / network / cellular defense in the app |
| **M10** AI-era defenses | Bundle 4-model classifier stack (`phi-tetherand-3b-q4`, `voiceguard-v1`, `textguard-v1`, `qrguard-v1`); NPU runtime via LiteRT + NNAPI; inbound-message AI screen; voice-deepfake detection on calls; vishing scaffold classifier; LLM-text "AI?" badge; QR-image lure inspector; prompt-injection-resistant clipboard; C2PA / SynthID provenance check; mic-use awareness; OSINT exposure dashboard; NPU sysfs watcher; egress-LLM-API SNI watch; YubiKey-only 2FA in Hardened Mode; conference live threat feed | 26-34 h | Full AI-era threat coverage |

**Total: ~157-215 h of focused work** (M7 expanded into a/b/c; M0, M9, and M10 added; all milestones are required scope).

This is the first DEFCON since the AI capability boom went mass-market; the attacker side has scaled, automated, and personalised in ways previous years didn't see. No defences deferred, no partial coverage. M0 ships today to lock the perimeter while M1-M10 land in order. Parallelizable bands within the work: {M2 transports}, {M4, M5, M6 hops}, {M7b, M7c}, {M9 sub-defenses}, {M10 four classifiers} can all be split across worktrees once M1 + M3 + M7a are in place.

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
- **MediaTek baseband visibility.** No Qualcomm `/dev/diag` is available on the Seeker. We compensate with a three-tier strategy (Tier 0 NetMonster-core reflection + AIMSICD/SnoopSnitch high-level heuristics + Crocodile Hunter; Tier 1 over the tethered ADB channel; Tier 2 dormant root path for if/when the user roots). The Threat tab surfaces the active tier so the user always knows their detection depth. Optional RTL-SDR-via-USB-C-OTG mode (M7b) restores the broadcast-control-channel visibility that diag mode would otherwise give us — and arguably exceeds it, since SDR captures the air interface directly.
- **AIMSICD/SnoopSnitch staleness.** Both projects target older Android versions and APIs (`PhoneStateListener` instead of `TelephonyCallback`; pre-scoped-storage I/O; pre-permission-revamp). Porting is a partial rewrite, not a copy-paste; we keep the algorithms and rewrite the plumbing for Android 16. Each ported heuristic gets a unit test against canned signal fixtures so we know the algorithm survived the port.
- **NetMonster-core MTK reflection brittleness.** Reflection into MediaTek's framework internals can break across vendor builds. NetMonster-core abstracts much of this, but our Seeker build (Solana Mobile's Android 16 customisation) may need patches. Mitigation: every Tier 0 collector has a `try/catch (ReflectiveOperationException)` fallback to `TelephonyManager.getAllCellInfo()` so degraded reflection turns into shallower data, never crashes. Surface "Reflection coverage: 8/12 fields available" diagnostic in the Threat tab so the user can see and we can fix.
- **SDR driver licensing.** `librtlsdr-android` is GPL-2; our distribution is GPL-3; GPL-2-or-later upgrades fine to GPL-3. `hackrf_android` is also GPL-2-or-later. Both are dynamic-linked and we ship the source / linkage instructions in `NOTICE`.
- **SDR battery / thermal.** Running an SDR over OTG draws ~250-400 mA and heats. Mitigation: SDR mode auto-suspends below 20% battery and after 10 minutes without an interesting event; user can override.
- **Engineering Mode dialer codes.** MTK Engineering Mode (`*#*#3646633#*#*`) opens a system app; we cannot read its output programmatically. We only use the dialer codes as a *user-driven* fallback presented in the UI; the automated path is NetMonster-core + ADB-tier polls.
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
