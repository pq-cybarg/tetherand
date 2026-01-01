# Tetherand

Multi-transport reverse-tethering + composable privacy chains + on-device
threat detection for the Solana Seeker (Android 16, MediaTek). See
`docs/superpowers/specs/2026-05-26-tetherand-design.md` for the full design
and `docs/superpowers/plans/` for per-milestone implementation plans.

## Status

- **M0** (DEFCON pre-flight playbook + scripts): **shipped**. Run `./tutorial.sh` → http://localhost:7331/.
- **M1** (Tether MVP — Apache-2.0 forked relay + custom-branded APK): **shipped**.
- **M3** (Privacy Chain core + WireGuard hop via BoringTun JNI): **shipped**.
- **M2, M4-M10**: planned. See spec.

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
