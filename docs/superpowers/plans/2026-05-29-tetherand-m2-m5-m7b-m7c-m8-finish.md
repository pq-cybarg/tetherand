# Tetherand M2 + M5 + M7b + M7c + M8 — Finish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every outstanding spec milestone. M2 ships Bluetooth-RFCOMM + USB-AOA transports + ratatui TUI dashboard + macOS LaunchAgent + IOKit USB watcher. M5 ships a NymVPN hop wrapping the upstream `nym-vpn-client` via SOCKS5 (cross-compile-script delivered, same mechanism as M6.x). M7b ships SDR-mode (RTL-SDR / HackRF detection + sub-tab + librtlsdr stub). M7c ships the root-tier MTK modem readers (`/proc/ccci_md1_*` + `mdlog` parser + AT-command channel) capability-gated so they're no-ops without root. M8 ships smoke tests + signed release APK + install scripts + README polish + final on-device verification on the 5364C13D.

**Architecture:** Each milestone slots into the existing module layout — M2 adds two new Rust transport crates + a TUI subcommand, M5 adds `chain/NymHop.kt`, M7b adds `threat/sdr/`, M7c adds `threat/root/`, M8 is repo-level polish. Every Kotlin file ships behind feature-detection (BT permission absent → BtTransport surfaces a clear "ungranted" state; root absent → M7c no-ops). The final on-device step installs the APK and exercises each tab via `monkey` + `dumpsys` checks.

**Tech Stack:**
- M2: `btleplug` (Mac BLE/RFCOMM), `ratatui` 0.28, `crossterm`, `launchctl` plists, `IOKit` polling via `osascript` shell helpers.
- M5: `nym-vpn-client` 1.4 (cross-compile via script, same pattern as snowflake/conjure).
- M7b: `rtlsdr-android` placeholder, USB descriptor matcher.
- M7c: `java.io.File` + `Runtime.exec("su -c …")` capability-gated read paths.
- M8: existing `scripts/smoke.sh` + new `make release` target + signed-APK doc.

**License:** All new code GPLv3 to match M7a/M9/M10/M6 convergence.

**Hard constraint:** Every milestone surfaces "feature absent" state honestly. No hidden no-ops.

**Scope:** This plan closes ALL remaining items the spec lists. The user explicitly directed (in earlier conversation) "defer none" — same standard applies here. Where an external SDK is required (NymVPN's `nym-vpn-client`, RTL-SDR's `librtlsdr`), we ship the cross-compile script + integration wiring + UI surface so the system is fully assembled once the user runs the script.

---

## File Structure

```
relay/transport-bt/                          # M2 — already exists as scaffold; flesh out
relay/transport-aoa/                         # M2 — new
relay/cli/src/tui.rs                         # M2 — ratatui dashboard
scripts/com.tetherand.launcher.plist         # M2 — LaunchAgent
scripts/usb-watcher.sh                       # M2 — IOKit polling helper

relay/nym/                                   # M5 — Rust crate wrapping nym-vpn-client
android/app/src/main/kotlin/dev/tetherand/app/chain/NymHop.kt
android/app/src/main/kotlin/dev/tetherand/app/nym/NymConfig.kt
scripts/build-nym-android.sh                 # M5 — cross-compile script

android/app/src/main/kotlin/dev/tetherand/app/threat/sdr/SdrDetector.kt
android/app/src/main/kotlin/dev/tetherand/app/threat/sdr/SdrSubTab.kt
android/app/src/main/kotlin/dev/tetherand/app/threat/ui/ThreatScreen.kt  # +SDR section

android/app/src/main/kotlin/dev/tetherand/app/threat/root/
├── RootCheck.kt
├── CcciMd1Reader.kt
├── MdlogParser.kt
└── AtCommandChannel.kt
android/app/src/main/kotlin/dev/tetherand/app/threat/ui/ThreatScreen.kt  # +Root tier section

scripts/smoke-device.sh                      # M8 — on-device smoke test
scripts/release-sign.sh                      # M8 — signed-release recipe
Makefile                                     # M8 — `make release` target
README.md                                    # M8 — milestone-complete sweep
tutorial.sh                                  # M8 — badge sweep
```

---

### Task 1: M2 — Bluetooth RFCOMM transport (Rust + Android)

**Files:**
- Create: `relay/transport-bt/src/lib.rs` (the existing crate is empty)
- Create: `android/app/src/main/kotlin/dev/tetherand/app/transport/BtRfcommServer.kt`
- Modify: `android/app/src/main/AndroidManifest.xml` (BLUETOOTH_CONNECT scope)

The Android side opens a server-mode RFCOMM socket on a known UUID. The Mac side connects via `btleplug`. The standard SPP UUID `00001101-0000-1000-8000-00805F9B34FB` is what most BT-to-serial adapters use; we use a Tetherand-private UUID derived from the SPP base.

[implementation steps — short, like prior plans]

---

### Task 2: M2 — USB-AOA transport (Rust + Android)

**Files:**
- Create: `relay/transport-aoa/src/lib.rs`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/transport/AoaAccessoryService.kt`
- Modify: `android/app/src/main/AndroidManifest.xml` (USB-ACCESSORY intent filter)

Android Open Accessory protocol — the host switches the device into "accessory mode" via USB control transfers, then the device exposes a serial-like endpoint. Implemented on Android via the `UsbManager.USB_ACCESSORY_ATTACHED` intent and the `UsbAccessory.ParcelFileDescriptor` API.

---

### Task 3: M2 — ratatui TUI dashboard in `tetherand-cli`

**Files:**
- Create: `relay/cli/src/tui.rs`
- Modify: `relay/cli/src/main.rs` (`tetherand tui` subcommand)
- Modify: `relay/cli/Cargo.toml` (+ratatui, +crossterm)

Live dashboard showing each transport's connection state, byte counts, last error, and recent traffic histogram. Run as `tetherand tui`.

---

### Task 4: M2 — macOS LaunchAgent + IOKit USB watcher

**Files:**
- Create: `scripts/com.tetherand.launcher.plist`
- Create: `scripts/usb-watcher.sh`
- Create: `scripts/install-launchagent.sh`

LaunchAgent watches for USB device-attach events matching the 5364C13D's vendor:product ID and auto-starts `tetherand run`.

---

### Task 5: M5 — `relay/nym/` Rust crate + JNI

**Files:**
- Create: `relay/nym/Cargo.toml`
- Create: `relay/nym/src/{lib,client,jni}.rs`
- Modify: `relay/Cargo.toml` (members += "nym")

Embeds `nym-vpn-client` 1.4 — same pattern as the `tetherand-tor` crate. Exposes 4 JNI methods (init/dial/close/shutdown). Mnemonic-login + entry/exit-server selection via the upstream client's config. Cross-compile via `scripts/build-nym-android.sh` (same NDK pattern as build-tor/build-wg).

---

### Task 6: M5 — `NymHop.kt` + UI integration

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/chain/NymHop.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/nym/{NymConfig,NymCredentials}.kt`
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt` (+Nym section)

NymHop implements `Hop`. UI section accepts mnemonic + picks entry/exit server. Same encryption-at-rest pattern as TorBridges.

---

### Task 7: M7b — SDR detection + sub-tab

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/threat/sdr/SdrDetector.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/threat/sdr/SdrSubTab.kt`
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/threat/ui/ThreatScreen.kt` (+SDR row)
- Create: `scripts/build-rtlsdr-android.sh`

`SdrDetector` scans `UsbManager.deviceList` for the RTL-SDR (vendor 0x0bda product 0x2832/2838) and HackRF (vendor 0x1d50 product 0x6089) USB IDs. Surfaces "absent / detected / active" state. Live decoder defers to upstream librtlsdr's Android port (`librtlsdr-android` build script).

---

### Task 8: M7c — Root-tier MTK modem readers

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/threat/root/RootCheck.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/threat/root/CcciMd1Reader.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/threat/root/MdlogParser.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/threat/root/AtCommandChannel.kt`
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/threat/ui/ThreatScreen.kt` (+Root tier badge)

`RootCheck.isRooted()` looks for `/system/xbin/su` / `/system/bin/su` and tries `Runtime.exec("su -c id")`. If true, the readers go active; else surface "Dormant — un-rooted" in the UI. The MTK modem buffer at `/proc/ccci_md1_*` is normally root-only on stock Android; the mdlog parser handles the binary log format; AT commands ship over `/dev/ttyMT0`.

---

### Task 9: M8 — Smoke tests + signed release recipe + Makefile

**Files:**
- Create: `scripts/smoke-device.sh`
- Create: `scripts/release-sign.sh`
- Modify: `Makefile` (+`release` target)

`smoke-device.sh` runs `adb install`, walks each tab via `monkey`, verifies via `dumpsys` that the threat-detection foreground service is up.

---

### Task 10: M8 — README + tutorial badge sweep

**Files:**
- Modify: `README.md`
- Modify: `tutorial.sh`

Flip every remaining milestone to SHIPPED.

---

### Task 11: Final on-device install + smoke

**Files:** none (device-side verification).

Install the APK, exercise the golden path, report which surfaces light up.
