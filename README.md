# Tetherand

Multi-transport reverse-tethering + composable privacy chains + on-device
threat detection for the Solana Seeker (Android 16, MediaTek). See
`docs/superpowers/specs/2026-05-26-tetherand-design.md` for the full design
and `docs/superpowers/plans/` for per-milestone implementation plans.

## Status

- **M0** (DEFCON pre-flight playbook + scripts): **shipped**. Run `./tutorial.sh` → http://localhost:7331/.
- **M1** (Tether MVP — Apache-2.0 forked relay + custom-branded APK): **shipped**.
- **M3** (Privacy Chain core + WireGuard hop via BoringTun JNI): **shipped**.
- **M4** (Mullvad full stack: classic WG + PQ tunnel ML-KEM-1024 + kill-switch + multihop + DAITA + obfuscation transports + split-tunnel): **shipped**.
- **M7a** (Threat Detection MVP — 8 heuristics, Room-backed alerts + per-geohash6 baseline, Compose Threat tab, panic button): **shipped**. APK is now GPLv3-converged.
- **M9** (Hardened Mode — one-tap DEFCON profile: pre/post attestation snapshot + frozen app-audit baseline + 6-port honeypot + accelerometer tamper-watcher + 12-item user-action checklist + Acknowledge/Isolate/Evacuate/Burn incident-response runbook + Quick Settings tile): **shipped**.
- **M10** (AI-era defenses — local-only, contributory: clipboard prompt-injection scrubber, pseudo-perplexity AI-text scorer, phishing-rule message classifier, C2PA/SynthID provenance check, egress-LLM-API SNI watch (18 exact + 10 suffix entries), MTK NPU sysfs watcher, voiceprint-vault safe-word handshake, HIBP OSINT exposure, 8-entry DEFCON-34 field guide, LiteRT runtime scaffold for the 4-model contributory bundle, AI tab UI): **shipped**. Model bundle (~2.4 GB) ships via the M10.x delta-update mechanism — deterministic primaries function fully without it per spec.
- **M6** (Tor + Arti — embedded arti-client 0.27 in `tetherand-tor` Rust crate, BridgeDB-format bridge parser (3/3 tests), vanguards toggle, PQ-NTor (prop362 / NTor-ML-KEM-v1) handshake preference, Privacy tab Tor config card, TorHop wired into the chain orchestrator scaffolding, `scripts/build-tor-android.sh` for NDK cross-compile): **shipped**.
- **M6.x** (PT bridges + per-flow forwarder + live probe — `tetherand-pt` Rust binary implementing obfs4 + meek + webtunnel inline (5/5 tests, ntor handshake, ChaCha20-Poly1305 AEAD frames, HTTPS POST tunneling, WS upgrade), arti managed-PT wiring via `TransportConfigBuilder`, `TorFlowForwarder` per-flow IP→arti DataStream forwarder reusing relay-core packet stack, `PtBinaryStager` extracting bundled PTs from nativeLibraryDir, `scripts/build-pt-bridge-android.sh` + `scripts/build-pts-android.sh` for NDK + Go cross-compile of snowflake-client + conjure-client, live-probe integration tests (`cargo test --test live_probe -- --ignored`) for clearnet + .onion): **shipped**.
- **M2** (BT-RFCOMM + USB-AOA transports — `tetherand-transport-bt` crate with btleplug 0.11 + Tetherand-private SPP-derived UUID `7e7ae72d-…`, `tetherand-transport-aoa` crate with rusb 0.9 + AOA-protocol-2.0 mode-switch sequence, `BtRfcommServer` Android server-mode RFCOMM listener, `AoaAccessoryService` USB-accessory receiver with manifest filter, ratatui dashboard at `tetherand tui` (4-panel: transports / traffic-sparkline / devices / events), `scripts/com.tetherand.launcher.plist` + `scripts/usb-watcher.sh` macOS LaunchAgent auto-starting `tetherand run` on Seeker attach via IOKit polling): **shipped**.
- **M5** (NymVPN mixnet hop — `tetherand-nym` Rust crate wrapping nym-sdk 1.4 behind a `with-sdk` feature gate (upstream nym-noise 1.20.4 has a type-inference issue on rustc 1.83+), JNI surface (init/dial/close/shutdown), `NymHop` Sphinx-3-hop mixnet hop with mnemonic + entry/exit gateway config, `NymCredentials` EncryptedSharedPreferences persistence, Privacy tab Nym card, `scripts/build-nym-android.sh` NDK cross-compile): **shipped**.
- **M7b** (SDR mode — `SdrDetector` USB-OTG scanner for RTL-SDR / HackRF One / Nuand bladeRF / LimeSDR variants, `SdrSection` threat-tab presence card, `scripts/build-rtlsdr-android.sh` cross-compiles libusb + librtlsdr + libhackrf for arm64-android via cmake + NDK toolchain): **shipped**.
- **M7c** (Root-tier MTK modem readers — `RootCheck` 3-signal vote, `CcciMd1Reader` reading `/proc/ccci_md1_status` + `_ic_intr` via `su`, `MdlogParser` for the MTK modem binary log format with magic-resync, `AtCommandChannel` over `/dev/ttyMT0` for 3GPP TS 27.007 + MTK `AT+EMRSS` queries, `RootSection` threat-tab card surfacing dormant/active state; every reader returns Dormant on un-rooted devices): **shipped**.
- **M8** (Release polish — `make native-all` cross-compiles all five native libs (wg / tor / nym / pt-bridge / rtlsdr-stack), `make release-signed` builds + zipalign + apksigner-signs a release APK via `scripts/release-sign.sh` with a PII-DN allow-list gate, `make smoke-device` walks every tab via UiAutomator + asserts the threat-detection foreground service is up, `make hashes` + `scripts/hash-artifacts.sh` emit SHA-256 + SHA3-256 sidecars + `bin/SHASUMS.txt` index for every artefact, `make launcher` installs the macOS LaunchAgent for auto-tether on Seeker attach): **shipped**.

## Build

```bash
make build        # builds bin/tetherand + bin/tetherand.apk (cross-compiles libtetherand_wg.so for the chain)
make native-wg    # just rebuild the WireGuard native lib for arm64-android
make install      # installs APK on the connected device + pre-grants VPN consent
make smoke        # end-to-end test (ping + DNS through the tether)
make chain        # alias of build (chain ships in the same APK)
make test         # all Rust unit tests (codec, relay-core, wg + parser/handshake tests)
make release      # signed-release APK (debug key for now; production key in M8)
make clean        # cargo clean + gradle clean + remove bin/ artifacts
```

## Use

```bash
./bin/tetherand run                       # USB-ADB transport (default)
./bin/tetherand run --transport tcp       # LAN TCP transport
./bin/tetherand run --device <SERIAL>     # specific device
./bin/tetherand install                   # install APK only
./bin/tetherand uninstall                 # uninstall APK only
./bin/tetherand status                    # connected devices + version

# Stopgap convenience wrapper (delegates to bin/tetherand if present,
# falls back to upstream Gnirehtet otherwise):
./connect.sh
./connect.sh --stop
./connect.sh --reinstall

# DEFCON pre-flight + tutorial:
./tutorial.sh                             # browser playbook on :7331
./backup.sh                               # local encrypted backup of the phone
./restore.sh                              # restore from backup
./scripts/defcon-prep.sh                  # pre-conference hardening
```

## Architecture (M1)

```
┌──────── Seeker (dev.tetherand.app APK) ────────┐
│  Compose UI (MainActivity)                      │
│       │ Start                                    │
│       ▼                                          │
│  TetherandService (VpnService)                   │
│       │ TUN (10.0.0.2)                           │
│       ▼                                          │
│  PersistentRelayTunnel ───►  LocalSocket         │
│                              "tetherand"         │
└─────────────────────────────────┬────────────────┘
                                  │ adb reverse
                                  ▼
┌──────── Mac (bin/tetherand) ──────────────────────┐
│  tetherand-cli  ── runs `adb reverse                │
│       │           localabstract:tetherand tcp:N`,   │
│       │           starts the relay, blocks on Ctrl+C│
│       ▼                                              │
│  tetherand-relay-core (forked from Genymobile/      │
│       gnirehtet relay-rust, Apache-2.0)              │
│       │  userspace TCP/UDP/ICMP stack                │
│       ▼                                              │
│  Real internet (host Wi-Fi/Ethernet)                 │
└──────────────────────────────────────────────────────┘
```

The Rust workspace at `relay/` also contains `tetherand-codec`,
`tetherand-transport-api`, `tetherand-transport-adb`, and
`tetherand-transport-tcp` — built but unused by M1's CLI (it talks to
the relay-core's TCP socket directly via `adb reverse`). They exist
ready-to-wire for M2's Bluetooth and USB-AOA transports where stream
framing matters.

## License

Multi-module, in line with what each subsystem is derived from:

- **Tether (M1-M2):** Apache-2.0. Forked from Genymobile/gnirehtet
  `relay-rust/` and `app/` (both Apache-2.0, verified against
  `upstream/LICENSE`). New code in this subsystem is Apache-2.0.
- **Privacy Chain (M3-M6):** mixed. WireGuard userspace is MIT/Apache-2.0;
  Mullvad libraries are GPLv3; NymVPN client is GPLv3; Tor is BSD-3.
- **Threat Detection (M7):** GPLv3. Ports of AIMSICD, SnoopSnitch,
  NetMonster-core, and Crocodile Hunter — all GPLv3.
- **Whole APK once M3+ links in:** GPLv3.

`NOTICE` files in `relay/core/` and (as M7+ lands) elsewhere document
each subcomponent's origin and license.

## Repo Layout

```
.
├── android/                          # Gradle project (AGP 8.7, Kotlin 2.0, Compose)
│   ├── app/
│   │   ├── build.gradle.kts
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/dev/tetherand/app/   # forked Apache-2.0 Java sources
│   │       ├── kotlin/dev/tetherand/app/ # Compose MainActivity
│   │       └── res/                       # rebranded resources
│   └── ...
├── relay/                            # Rust workspace
│   ├── Cargo.toml                    # workspace manifest
│   ├── codec/                        # frame codec (reserved for M2+)
│   ├── transport-api/                # Transport trait
│   ├── transport-adb/                # USB-ADB transport (M2+ wiring)
│   ├── transport-tcp/                # TCP transport (M2+ wiring)
│   ├── core/                         # forked Gnirehtet relay-rust
│   └── cli/                          # tetherand binary
├── upstream/                         # vendored Gnirehtet for license + reference
├── bin/                              # built artifacts: tetherand + tetherand.apk
├── backups/                          # local encrypted backups (gitignored)
├── attestation/                      # device snapshots (gitignored)
├── scripts/
│   ├── defcon-prep.sh
│   └── smoke.sh
├── docs/superpowers/
│   ├── specs/  ← design
│   └── plans/  ← per-milestone TDD plans
├── backup.sh           restore.sh    tutorial.sh    connect.sh    Makefile
└── README.md
```

## Privacy Posture (Hard Constraints)

These are non-negotiable per the spec:

1. **Deterministic core, contributory AI.** Every defense has a deterministic
   primary rule. LLM classifiers (M10) are advisory only — never the sole
   trigger for a destructive action.
2. **Local-only AI.** Every model runs on the Seeker's MediaTek NPU via
   LiteRT + NNAPI. No prompt, classification, or telemetry ever reaches
   a cloud LLM API. The egress-LLM-API SNI watch defense (M10) enforces
   this for other apps too.
3. **No telemetry.** Tetherand never phones home. Models update only
   through the user's active Privacy Chain.

## Contributing

This is currently a single-developer project preparing for DEFCON. See the
spec and the per-milestone plans for what's coming. PRs welcome after M8.
