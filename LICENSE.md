# Licensing

Tetherand is a composite project. Different subdirectories ship under
different licenses depending on what they fork, port, or link.

This document maps every subcomponent to its license. The headline is:

- **Original work in this repository** — code, scripts, configuration,
  and documentation written for Tetherand — is licensed under the
  **MIT License**. See [`LICENSE`](LICENSE) for the canonical text.
- **Forked, ported, and vendored code** retains its upstream license.
  The applicable license is stated in the per-subdirectory `NOTICE`
  file alongside the code, and summarised below.
- **The assembled APK and the host-side `tetherand` binary** are
  governed by **GPL-3.0-or-later** in aggregate, because GPL-3.0 ports
  (NetMonster reflection, AIMSICD `BTSAlgorithm`, SnoopSnitch
  heuristics, Crocodile Hunter heuristics, Mullvad client libraries,
  parts of `gotapdance`) are linked into the shipped binaries. Source
  distributions still carry the per-file licenses above.

If you reuse only the MIT-licensed subset (for example, the build
scripts, the documentation, the deterministic-AI Guard heuristics in
isolation), MIT terms apply.

If you redistribute the shipped APK or binary, GPL-3.0-or-later terms
apply to the combined work.

## Summary by spec milestone

| Milestone | Primary source location | License of new code | License of forked code | Effective license of compiled output |
|---|---|---|---|---|
| **M0** Pre-flight scripts | `connect.sh`, `backup.sh`, `restore.sh`, `tutorial.sh`, `scripts/5364C13D-prep.sh` | MIT | — | MIT |
| **M1** Tether MVP | `android/app/src/main/java/dev/tetherand/app/`, `relay/core/`, `relay/cli/` | Apache-2.0 (matching upstream) | Apache-2.0 (Genymobile/gnirehtet) | Apache-2.0 |
| **M2** BT + AOA transports | `relay/transport-bt/`, `relay/transport-aoa/`, `android/app/src/main/kotlin/dev/tetherand/app/transport/` | MIT | — | MIT |
| **M3** Privacy chain core | `android/app/src/main/kotlin/dev/tetherand/app/chain/`, `relay/wg/` | MIT | BSD-3-Clause (BoringTun) | MIT-compatible |
| **M4** Mullvad full stack | `android/app/src/main/kotlin/dev/tetherand/app/mullvad/`, `android/app/src/main/kotlin/dev/tetherand/app/splittunnel/` | MIT (wrapper) | GPL-3.0-or-later (Mullvad client libraries) | **GPL-3.0-or-later** |
| **M5** NymVPN hop | `relay/nym/`, `android/app/src/main/kotlin/dev/tetherand/app/nym/` | MIT (wrapper) | Apache-2.0 / GPL-3.0 (nym-sdk components when `with-sdk` feature is enabled) | Apache-2.0 / GPL-3.0-or-later depending on feature set |
| **M6** Tor + Arti | `relay/tor/`, `android/app/src/main/kotlin/dev/tetherand/app/tor/`, `android/app/src/main/kotlin/dev/tetherand/app/chain/TorHop.kt` | MIT (wrapper) | MIT OR Apache-2.0 (arti-client, tor-rtcompat) | MIT |
| **M6.x** Pluggable transports | `relay/pt-bridge/` (obfs4/meek/webtunnel) | MIT (clean-room implementations from public specs) | Apache-2.0 (`gotapdance` conjure client when bundled) | MIT or Apache-2.0 depending on bundled binaries |
| **M7a** Threat-detection MVP | `android/app/src/main/kotlin/dev/tetherand/app/threat/` | GPL-3.0-or-later | GPL-3.0 (AIMSICD `BTSAlgorithm`, SnoopSnitch heuristics, Crocodile Hunter heuristics, NetMonster-core) | **GPL-3.0-or-later** |
| **M7b** SDR detection + libs | `android/app/src/main/kotlin/dev/tetherand/app/threat/sdr/`, `scripts/build-rtlsdr-android.sh` | MIT (our code) | GPL-2.0-or-later (librtlsdr, libhackrf), LGPL-2.1-or-later (libusb) | GPL-2.0-or-later when shipped with the SDR libs |
| **M7c** Root-tier MTK readers | `android/app/src/main/kotlin/dev/tetherand/app/threat/root/` | MIT | — | MIT |
| **M8** Release polish | `scripts/release-sign.sh`, `scripts/hash-artifacts.sh`, `scripts/bundle-combinations.sh`, `scripts/smoke-device.sh`, `Makefile` | MIT | — | MIT |
| **M9** Hardened Mode | `android/app/src/main/kotlin/dev/tetherand/app/hardened/` | MIT | — | MIT (subject to APK aggregation) |
| **M10** AI Guard | `android/app/src/main/kotlin/dev/tetherand/app/aiguard/` | MIT | Apache-2.0 (LiteRT / TensorFlow Lite at link time) | MIT (subject to APK aggregation) |

## License texts referenced

- **MIT License** — [`LICENSE`](LICENSE) in the repo root. Covers every
  subcomponent marked MIT above.
- **Apache License 2.0** — [`upstream/LICENSE`](upstream/LICENSE) is
  the canonical Apache-2.0 text vendored from Gnirehtet.
- **GPL-3.0-or-later** — applies to M4 (Mullvad), M7a (threat
  detection), and the aggregated APK once M3+ links in. Use the
  upstream's published text; GNU's canonical copy lives at
  `https://www.gnu.org/licenses/gpl-3.0.txt`.
- **GPL-2.0-or-later** — applies to M7b's bundled `librtlsdr` and
  `libhackrf`. Each ships its own `COPYING` file inside its source
  tree under `.sdr-build/`.
- **LGPL-2.1-or-later** — applies to `libusb`. See its `COPYING` in
  `.sdr-build/libusb/`.
- **BSD-3-Clause** — applies to BoringTun (Cloudflare). The full text
  is reproduced in BoringTun's own crate metadata.
- **MIT OR Apache-2.0** — Arti and the entire `tor-*` crate family
  are dual-licensed; we pick MIT here for the M6 wrapper.

## Per-subdirectory `NOTICE` files

The following `NOTICE` files document specific upstream origins and
modifications. Each is authoritative for its directory:

- [`relay/core/NOTICE`](relay/core/NOTICE) — relay-rust fork from
  Genymobile/gnirehtet.
- Additional `NOTICE` files will be added under
  `android/app/src/main/kotlin/dev/tetherand/app/threat/` when the
  individual GPL-3.0 port subdirectories are factored out per
  upstream attribution requirements.

## Notes on the GPL aggregation boundary

Several spec milestones (M3, M5, M6, M6.x, M9, M10) carry MIT or
Apache-2.0 source on their own, but get linked into a single APK
alongside GPL-3.0 ports (M4, M7a). Under GPL-3.0 the **combined work**
falls under GPL-3.0-or-later for distribution purposes, even though
the individual files remain under their declared licenses for the
purposes of reuse and reattribution.

In practical terms:

- **You can freely extract and reuse** any MIT-licensed file from
  this repo without GPL obligations attaching. The MIT terms travel
  with the file.
- **You cannot redistribute the assembled APK** under MIT-only terms
  once M4 or M7a are included — the GPL-3.0 sources demand GPL-3.0
  redistribution of the whole binary.
- **You can build a "thin" APK** that omits M4 and M7a entirely (drop
  the relevant native libraries from `jniLibs/` and the Mullvad and
  threat-detection Kotlin packages from the build inputs); that
  variant can ship under MIT terms.

This is identical to how many composite Android projects handle
license-blending (mixing Apache-2.0 AndroidX with GPL-3.0 forks); it
follows the FSF's published guidance on aggregation versus
combination.

## Trademarks and attribution

"Tetherand" is the project name. The bold-ampersand icon
(`android/app/src/main/res/mipmap-*/ic_launcher*.png`) is the project
wordmark. Both are released under the same MIT terms as the rest of
the original work in this repo — feel free to fork the name and the
icon for non-impersonating derivatives.

If you fork the project and run a separate community, please pick a
different name and icon for clarity.

## Reporting license issues

If you believe code in this repo is mis-licensed, please open a
GitHub issue with the file path and the specific license concern.
For sensitive issues (for example, a fork you maintain has been
mis-attributed in this repo), the author's email is published as
the committer identity on every commit on `main`.
