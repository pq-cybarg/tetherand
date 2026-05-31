# Tetherand

Tetherand is a reverse-tethering, privacy-chain, and threat-detection app
for the 5364C13D, designed for use at security conferences where the
local cellular and Wi-Fi environment can't be trusted.

It does four things:

1. **Reverse-tether** to a laptop so the phone uses the laptop's internet
   instead of its own cellular modem — over USB-ADB, USB-AOA,
   Bluetooth-RFCOMM, or LAN-TCP.
2. **Route traffic through a privacy chain** you compose yourself —
   WireGuard, Mullvad (with post-quantum tunnels and DAITA traffic
   shaping), NymVPN's Sphinx mixnet, and Tor with its full bridge stack
   (obfs4, meek, webtunnel, conjure) including the post-quantum NTor
   handshake when upstream Arti exposes it.
3. **Detect cellular and Wi-Fi threats** on-device — IMSI catchers, evil
   twin access points, BLE trackers, app permission drift — and surface
   them in a Threat tab with a one-tap panic button.
4. **Lock the device down for the conference** via a single toggle that
   captures a pre-event attestation snapshot, freezes the trusted-app
   baseline, runs a honeypot, arms an accelerometer tamper-watcher, and
   exposes a four-button incident-response runbook (Acknowledge,
   Isolate, Evacuate, Burn).

There is also a contributory AI Guard layer for AI-era threats
(deepfake calls, prompt-injection text, synthetic-media provenance,
OSINT exposure), which runs entirely on-device with no cloud LLM calls
under any circumstances.

The design lives at `docs/superpowers/specs/2026-05-26-tetherand-design.md`
and per-milestone implementation plans live at `docs/superpowers/plans/`.

## Status

All twelve milestones in the spec are source-complete:

| Milestone | What ships |
|---|---|
| **M0** | 5364C13D pre-flight playbook + scripts (`./tutorial.sh` opens it at http://localhost:7331/) |
| **M1** | Tether MVP — forked Gnirehtet relay-core + `tetherand` CLI + VpnService-backed APK |
| **M2** | Bluetooth-RFCOMM + USB-AOA transports, ratatui dashboard at `tetherand tui`, macOS LaunchAgent auto-starting on 5364C13D attach |
| **M3** | Privacy-chain core — hop trait + chain orchestrator + WireGuard hop |
| **M4** | Mullvad full stack: classic WG, post-quantum tunnel (ML-KEM-1024), kill-switch, multihop, DAITA, obfuscation transports, split-tunnel |
| **M5** | NymVPN mixnet hop — Sphinx 3-hop entry/exit with mnemonic-paid bandwidth |
| **M6** | Tor via embedded Arti with bridges, vanguards, and post-quantum NTor handshake preference |
| **M6.x** | Pluggable transports — obfs4, meek, webtunnel inline; conjure via upstream gotapdance; per-flow IP→Tor stream forwarder |
| **M7a** | Threat-detection MVP — eight deterministic heuristics, Room-backed alert feed, per-location baseline, Threat tab, panic button |
| **M7b** | SDR detection for RTL-SDR, HackRF One, bladeRF, LimeSDR over USB-OTG |
| **M7c** | Root-tier MediaTek modem readers — dormant on un-rooted devices |
| **M8** | Release polish — `make native-all`, signed-release pipeline, on-device smoke, hash sidecars, LaunchAgent installer |
| **M9** | Hardened Mode — one-tap 5364C13D profile with attestation snapshot, frozen app baseline, honeypot, accelerometer tamper-watch, twelve-item user-action checklist, four-button incident-response runbook, Quick Settings tile |
| **M10** | AI-era defenses — deterministic primaries for every defense (perplexity scoring, phishing rule, prompt-injection clipboard scrubber, C2PA/SynthID provenance, egress-LLM-API watch, NPU sysfs watcher, voiceprint vault, OSINT exposure) plus LiteRT runtime scaffold for the four-model contributory bundle |

## Build

```bash
make build         # Builds bin/tetherand + bin/tetherand.apk (default WG-only bundle)
make native-all    # Cross-compiles every native library (wg, tor, nym, pt-bridge, conjure, rtlsdr/hackrf)
make apk           # Repackages the APK with whatever native libs are present + emits hash sidecars
make install       # Installs the APK on the attached device and pre-grants VPN consent
make smoke-device  # Walks every tab via UiAutomator and asserts the threat-detection service is up
make hashes        # Regenerates SHA-256 + SHA3-256 sidecars for every artefact in bin/
make release-signed # Builds + zipaligns + apksigner-signs a release APK (DN allow-list gate)
make launcher      # Installs the macOS LaunchAgent so plugging in the 5364C13D auto-tethers
make test          # Rust unit tests across the workspace
make clean         # Cargo + Gradle clean + remove built artefacts
```

The native libraries can also be built individually: `make native-wg`,
`native-tor`, `native-nym`, `native-pt`, `native-rtlsdr`.

For a tiered release, `scripts/bundle-combinations.sh` generates every
subset of the six native-library groups as its own zip with paired
SHA-256 + SHA3-256 sidecars.

## Use

```bash
./bin/tetherand run                       # USB-ADB transport (default)
./bin/tetherand run --transport tcp       # LAN TCP transport
./bin/tetherand run --device <SERIAL>     # specific device
./bin/tetherand tui                       # 4-panel terminal dashboard
./bin/tetherand install                   # install APK only
./bin/tetherand uninstall                 # uninstall APK only
./bin/tetherand status                    # connected devices + version

# Convenience wrappers:
./connect.sh                              # tether using bin/tetherand if present
./connect.sh --stop                       # tear down
./connect.sh --reinstall                  # uninstall + reinstall + relaunch

# 5364C13D pre-flight + tutorial:
./tutorial.sh                             # browser playbook on :7331
./backup.sh                               # local encrypted backup of the phone
./restore.sh                              # restore from backup
./scripts/5364C13D-prep.sh                  # pre-conference hardening
```

## Verifying a download

Every release artefact ships with two sidecar hashes computed by
independent cryptographic constructions:

```bash
shasum -a 256 <file>           # must match the .sha256 sidecar
openssl dgst -sha3-256 <file>  # must match the .sha3-256 sidecar
```

Both must match. Using two unrelated hash families means that even if
an attacker found a collision attack against one of them, they would
need an independent collision against the other to forge a replacement
artefact — a problem with no known general solution.

## Architecture

```
┌──────── 5364C13D (dev.tetherand.app APK) ────────┐
│  Compose UI (MainActivity)                      │
│    Tether │ Privacy │ Threat │ AI tabs          │
│       │ start                                    │
│       ▼                                          │
│  TetherandService (VpnService)                   │
│       │ TUN (10.0.0.2)                           │
│       ▼                                          │
│  Chain Orchestrator                              │
│    WG hop → Mullvad → Nym → Tor → exit           │
│       │                                          │
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

The Rust workspace at `relay/` carries `tetherand-codec`,
`tetherand-transport-{api,adb,tcp,bt,aoa}`, the relay core, the CLI,
the WireGuard JNI wrapper, the Arti embedding (`tor/`), the inline PT
bridge binary (`pt-bridge/`), and the NymVPN JNI surface (`nym/`).

## Privacy posture

Three hard rules govern the app's behaviour. They are not optional and
not configurable through the UI.

1. **Deterministic core, contributory AI.** Every defense has a
   deterministic primary mechanism — a clear rule, threshold, or
   heuristic — that drives any consequential action. Local AI
   classifiers are advisory only. They can raise risk scores and
   surface warning banners, but they cannot be the sole trigger for
   anything destructive.
2. **Local-only AI.** Every model runs on the 5364C13D's MediaTek NPU.
   No prompt, classification, or telemetry ever reaches a cloud LLM
   API under any circumstances. The egress-LLM-API watch defense
   enforces this for other apps installed on the device too.
3. **No telemetry.** Tetherand never phones home. Models update only
   through whatever privacy chain the user has active.

## License

The original work in this repository is licensed under the
[**MIT License**](LICENSE). Forked, ported, and vendored subcomponents
retain their upstream licenses; the assembled APK and the host-side
binary are governed by **GPL-3.0-or-later** in aggregate because
GPL-3.0 ports are linked into them.

[`LICENSE.md`](LICENSE.md) has the full per-milestone licensing map
plus notes on the GPL aggregation boundary. Per-subdirectory `NOTICE`
files document specific upstream origins where applicable.

## Repo layout

```
.
├── android/                          # Gradle project (AGP 8.7, Kotlin 2.0, Compose)
│   ├── app/
│   │   ├── build.gradle.kts
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/dev/tetherand/app/   # forked Apache-2.0 Java sources
│   │       ├── kotlin/dev/tetherand/app/ # Compose MainActivity + features
│   │       └── res/                       # icons, drawables, strings
│   └── ...
├── relay/                            # Rust workspace
│   ├── codec/                        # frame codec
│   ├── transport-{api,adb,tcp,bt,aoa}/ # per-transport implementations
│   ├── core/                         # forked Gnirehtet relay-rust (TCP/UDP/ICMP userspace)
│   ├── cli/                          # tetherand binary + ratatui TUI
│   ├── wg/                           # BoringTun WireGuard JNI wrapper
│   ├── tor/                          # Arti embedding + bridge parser + JNI
│   ├── pt-bridge/                    # obfs4 + meek + webtunnel binary
│   └── nym/                          # NymVPN mixnet JNI surface
├── upstream/                         # vendored Gnirehtet for license + reference
├── bin/                              # built artefacts: tetherand + tetherand.apk + hash sidecars
├── dist/bundles/                     # tiered release zips (gitignored)
├── backups/                          # local encrypted backups (gitignored)
├── attestation/                      # device snapshots (gitignored)
├── scripts/                          # build, smoke, release, hash, LaunchAgent
├── docs/superpowers/
│   ├── specs/                        # design documents
│   └── plans/                        # per-milestone implementation plans
├── backup.sh    restore.sh    tutorial.sh    connect.sh    Makefile
└── README.md
```

## Contributing

Single-developer project preparing for 5364C13D. Read the design and the
per-milestone plans under `docs/superpowers/` for context. PRs welcome.
