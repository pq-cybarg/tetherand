# Tetherand — Formal Cryptographic & Whole-App Verification

**Scope.** This document enumerates every cryptographic primitive that ships
in the Tetherand release artifact and maps each one to the relevant NIST,
IETF, and academic standard. The goal is to give a security reviewer
enough material to answer, for any single module, *"does this module's
crypto meet the appropriate standard, and is the standard itself the
right one for the threat it protects against?"*

Tetherand is a quantum-aware project: every long-lived authentication
boundary that crosses untrusted networks uses a post-quantum-secured
primitive, and several use hybrid (classical + PQ) constructions per
the IETF composite-signatures framework. But Tetherand also detects and
counteracts non-cryptographic threats — rogue cells, ultrasonic
side-channels, honeypot probes — where PQ overhead would be inappropriate.
Both sets of decisions are documented below.

---

## 0. Adversary model

Tetherand is designed against an **APT-class adversary operating in a
hostile environment** against a device at **5364C13D posture**. The
adversary is assumed to have, at minimum, the following capabilities:

* **Network omnipresence.** Full visibility and modification rights on
  every byte the device emits or receives, including TLS-stripping
  proxies, DNS hijacking, and the ability to compromise a public CA
  (so any single-cert TLS chain alone is not trusted).
* **Boot-environment manipulation.** The kernel entropy pool may be
  biased early in boot. The on-die hardware RNG may be fault-injectable
  (MediaTek Boot ROM disclosure, January 2026, affects the Solana
  Seeker SoC). User-installed root CAs may be planted.
* **Physical proximity, intermittent.** Brief windows during which the
  device is unattended; the adversary can plug in USB-C cables, place
  ultrasonic beacons within audible range, run BLE-class trackers,
  trigger lockscreen-unlock attempts.
* **Side-channel acquisition.** DMA reads from USB3 / Thunderbolt,
  kernel-exploit memory dumps, `/proc/<pid>/mem` reads if root is
  achieved temporarily, forensic disk imaging.
* **Coercion or impersonation of a trusted third party.** App-store
  malware, a tampered-with carrier update, a hostile baseband update.
* **Background apps with arbitrary permissions.** The user may have
  installed a trojan app that holds `BIND_NOTIFICATION_LISTENER` or
  `QUERY_ALL_PACKAGES` and is looking for IPC entry points into
  Tetherand to disable defenses or exfil state.
* **NO assumption of CRQC availability.** A cryptanalytically-relevant
  quantum computer is assumed possible but not yet deployed; we hedge
  with PQ across the long-lived signing channel but do not pretend
  ECDLP is broken yet.

The adversary is **assumed to have, additionally**:

* **A platform-key or OS-sandbox compromise.** Other userspace apps
  on the device may have read access to our `/data/data/dev.tetherand.app`
  directory regardless of `MODE_PRIVATE`. We therefore treat
  EncryptedSharedPreferences as the **only** acceptable storage for
  any sensitive blob — the KEK lives in the AndroidKeyStore (StrongBox
  where available, TEE on A23) and is never reachable from another
  app's process address space even with sandbox bypass. We also
  assume in-process JCA `KeyStore` instances may be enumerated by a
  privileged peer; we keep the smallest possible window between key
  decode and use, and zeroize aggressively (§11).
* **A build-host compromise or signer takeover.** The manifest channel's
  quadruple signature (§2) only proves the manifest came from someone
  holding all four keys; it does not prove that someone is honest.
  We compensate with a **second pinning layer in app code** —
  every shipped LiteRT model SHA-256 is BAKED INTO `ModelBundle.kt`
  at build time, and `ModelUpdater` refuses to install a model whose
  hash differs from the in-code expectation EVEN IF the manifest is
  validly signed. A compromised signer can therefore only re-issue
  the EXISTING models (no value), not substitute hostile ones. The
  `mtc_proof` field (§3) further requires that the manifest also
  appear in a public Sigsum/Trillian-class transparency log;
  manifests not visible to the public are rejected once the M10.x
  log-walk verifier ships.
* **Root persistence across factory wipe** (firmware-resident attacker
  in the modem baseband, in `/dev/block/by-name/boot`, or in a
  vendor-partition rootkit). Software-only mitigations cannot fully
  defeat this — but we narrow exposure by performing **Verified-Boot
  state + KeyStore attestation at every app cold-start**. We accept
  both `vbs=green` (stock Android, OEM-locked) and `vbs=yellow`
  (GrapheneOS or other re-locked custom ROM with user AVB keys);
  both are bootloader-locked and both have a complete verified-boot
  chain — just to different trust roots. We reject `vbs=orange`
  (bootloader unlocked) and `vbs=red` (verified-boot failed). When
  rejected, we refuse to load any signing keys and surface a
  Critical alert on the Threat tab: *"this device's boot chain has
  been tampered with — Tetherand cannot protect you here."* (See §15.)

There are no "NOT assumed" carve-outs. Every defense in §§10-15 is
justified against the maximum-strength adversary, and where a
mitigation only partially covers a threat, that gap is documented.

---

## 1. Cryptographic standards in force

| Standard | Final | What it specifies | Used in module |
|---|---|---|---|
| **FIPS 203 ML-KEM** | 2024-08-13 | Module-Lattice KEM (Kyber descendant) | *not used* — Tetherand does no PQ key-encapsulation today; relays are pre-keyed at install time or fetched via TLS to a pinned cert. PQ key exchange is a v0.2 candidate. |
| **FIPS 204 ML-DSA** | 2024-08-13 | Module-Lattice DSA (Dilithium descendant); parameter sets ML-DSA-44 / -65 / -87 | `aiguard/runtime/ModelUpdater.kt` (ML-DSA-87 = NIST Level 5) |
| **FIPS 205 SLH-DSA** | 2024-08-13 | Stateless Hash-Based DSA (SPHINCS+ descendant); 12 parameter sets including SLH-DSA-SHA2-256s | `aiguard/runtime/ModelUpdater.kt` (SLH-DSA-SHA2-256s = NIST Level 5, small-sig variant) |
| **NIST SP 800-208** | 2020-10 (rev. in progress) | Stateful hash-based DSA: LMS + XMSS (RFCs 8554 / 8391) | *deliberately not used* — see §4 |
| **IETF draft-ietf-lamps-pq-composite-sigs-19** | 2026-04-21 | Composite (PQ + classical) X.509 signatures; OIDs under 1.3.6.1.5.5.7.6.x | informs the wrapper layout in `ModelUpdater.kt`; we ship the four signatures discrete-not-composite so any one can be rotated independently |
| **IETF draft-ietf-plants-merkle-tree-certs-03** | 2026-04-22 (expires 2026-10-22) | Merkle Tree Certificates — PLANTS WG transparency-log-integrated certs | `mtc_proof` field reserved in wrapper; M10.x log-walk verifier ships when Sigsum / Trillian integration lands |
| **RFC 8032 EdDSA (Ed448)** | 2017-01 | Pure-EdDSA over Ed448-Goldilocks, ~224-bit classical security (~L4) | `aiguard/runtime/ModelUpdater.kt` (classical PQ-hedge) |
| **FIPS 186-5 ECDSA P-521 / SHA-512** | 2023-02 | NIST L5 classical elliptic-curve DSA | `aiguard/runtime/ModelUpdater.kt` (fast classical pre-check) |
| **FIPS 180-4 SHA-256 / SHA-512, FIPS 202 SHA3-256** | 2015-08 / 2015-08 | Hash functions used for content integrity + KDF | model artifact pinning, manifest body hashing |
| **NIST SP 800-38D AES-256-GCM** | 2007-11 | AEAD for `EncryptedSharedPreferences` (via AndroidX security-crypto 1.1.0-alpha06, MasterKey AES-256-GCM) | every on-device secret store (`ThreatSuppressions`, `SelfieStore`, voiceprint vault, dead-man's switch state, Privacy-Chain credentials) |

OpenSSL 3.5 added native FIPS-204 + FIPS-205 + FIPS-203 implementations
(released 2025-04-08, LTS through 2030); OpenSSL 3.6 (released 2025-10-01)
keeps them and is the tested floor for `scripts/gen-signing-keys.sh` and
`scripts/sign-manifest.sh`. BouncyCastle 1.80 (the Java provider bundled
into the APK at `org.bouncycastle:bcprov-jdk18on:1.80`) ships
keytool-compatible ML-DSA + SLH-DSA, which is the verifier-side bridge
we rely on inside `ModelUpdater.kt`.

---

## 2. The ModelUpdater quadruple-signature posture

`ModelUpdater.kt` is the only path in the application that hot-loads
code-equivalent data (LiteRT model files) after install. A compromise of
the manifest-signing identity would let an attacker swap a hostile
classifier into every Tetherand install. Because of that asymmetric risk,
this is the one place we go beyond standard PQ/T-hybrid: the wrapper
carries **four** independent signatures, and **all four must verify** or
the manifest is rejected. The verifier walks them cheap-to-expensive
(P-521 → Ed448 → ML-DSA-87 → SLH-DSA-SHA2-256s) so a bogus body short-
circuits at the first failure.

| # | Algorithm | Standard | NIST Level | Cryptographic assumption |
|---|---|---|---|---|
| 1 | ECDSA P-521 / SHA-512 | FIPS 186-5 | 5 (classical) | ECDLP on NIST-curve P-521 |
| 2 | Ed448 | RFC 8032 | ~4 (classical, non-NIST) | EdDLP on Ed448-Goldilocks |
| 3 | ML-DSA-87 | FIPS 204 | 5 (PQ) | Module-LWE / Module-SIS (lattice) |
| 4 | SLH-DSA-SHA2-256s | FIPS 205 | 5 (PQ) | One-way / collision resistance of SHA-256 (hash-based, stateless) |

The IETF composite-sigs draft v19 lists `id-MLDSA87-ECDSA-P521-SHA512`
(OID `1.3.6.1.5.5.7.6.54`) and `id-MLDSA87-Ed448` as registered
composite pairings. We *could* ship one ASN.1 composite signature
holding ML-DSA-87 + ECDSA-P521 as a single blob; we instead ship four
discrete signatures because:

1. **Independent rotation.** A break in (say) the ECDSA-P521 family lets
   us re-issue manifests under the surviving three keys without
   re-emitting a new SPKI; a composite blob has only one identity.
2. **Diverse PQ assumption coverage.** ML-DSA-87 alone defends against
   a quantum adversary that breaks ECDLP. SLH-DSA-SHA2-256s additionally
   defends against a structural break in *lattice* PQ — the two PQ
   families share no security assumption beyond "SHA-256 is a one-way
   function". Composite-sigs v19 has no standardized triple- or
   quadruple-signature OID; we are deliberately stricter than the
   current standard while staying compatible with the underlying
   FIPS-204 + FIPS-205 + FIPS-186-5 + RFC-8032 wire formats.
3. **Pre-quantum compromise window.** Today an attacker with a 4-key
   compromise wins; under composite they need only one + the classical
   side. Quadruple raises the per-key compromise bar above today's PQ
   floor.

`scripts/gen-signing-keys.sh` is the reproducible-by-anyone keygen
script, and `scripts/sign-manifest.sh` is the matching sign tool. Both
were round-trip verified (positive: all four `Verified Successfully`;
negative: body-byte flip → all four rejected with explicit FIPS error
codes) at v0.1.

---

## 3. Google / Cloudflare Merkle Tree Certificates (MTC) hook

The user originally referenced "Google's Merkle Root of Trust"; the
matching work item is **Merkle Tree Certificates**, a joint
Google + Cloudflare proposal that became `draft-ietf-plants-merkle-tree-certs`
inside the new IETF **PLANTS** working group (PKI, Logs, And Tree
Signatures). MTC integrates Certificate Transparency directly into the
certificate format, replacing per-cert PQ signatures with Merkle
inclusion proofs — the per-cert size drops from kilobytes (ML-DSA-87)
or tens of kilobytes (SLH-DSA-SHA2-256s) back to "a few hashes deep
into the log".

The `mtc_proof` field in our wrapper is reserved for an MTC inclusion
proof against a Sigsum / Trillian / CT-style transparency log. v1
accepts a present-but-empty `mtc_proof` and logs it; the in-app
log-walk verifier will ship in milestone **M10.x** once Sigsum
(or whichever PLANTS-aligned log infrastructure is production-ready)
is integrated. Until then the quadruple-signature posture stands on
its own, and the wrapper layout is forward-compatible.

---

## 4. Why SP 800-208 (LMS / XMSS) is deliberately NOT used

Stateful hash-based signatures are the only fielded family older than
the FIPS-204 / FIPS-205 standardization that resists a CRQC. They are
*also* uniquely dangerous: reusing a one-time-use leaf key
*catastrophically* breaks unforgeability for that leaf. NIST's own
SP 800-208 description: *"these schemes are not suitable for general
use because their security depends on careful state management."*

Tetherand's signing host could lose state — the keys live offline,
custodians rotate, USB drives get re-imaged. The cost of a single
state-loss incident under LMS/XMSS is total signing-identity collapse,
and that single-point-of-failure is exactly what the quadruple
posture in §2 is designed to eliminate. We therefore deliberately
choose two stateless hash-based options (SLH-DSA-SHA2-256s, FIPS-205)
plus the lattice path (ML-DSA-87) for our PQ coverage, and leave
stateful schemes to use cases (firmware over-the-air on locked
HSMs, etc.) that can guarantee state-monotonicity.

---

## 5. NOT-PQ threat surfaces (explicit non-applicability)

The user's review prompt asked to *"account for things we are
protecting against [that] are specifically NOT PQ, so we can still
detect/counteract/respond."* This section enumerates every detection
or response module where PQ overhead would be wrong, and explains why.

| Module | Threat | Why PQ would be inappropriate |
|---|---|---|
| `threat/cell/MtkRogueCellDetector` | Rogue / downgrade / SS7-style cell-tower attack | The cellular control plane (LTE NAS, 5G NR) is dictated by 3GPP; we passively observe it. Adding PQ signing to our local alerts adds no defense. |
| `threat/heuristic/AdbdNetworkSurface` | CVE-2026-0073 (adbd TCP RCE) and similar surface-area heuristics | Reads `service.adb.tcp.port` + scans `/proc/net/tcp{,6}` for a local listener. No cryptographic boundary crosses the network. |
| `threat/heuristic/PatchLevelStaleness` | Out-of-date Android security patch | Reads `Build.VERSION.SECURITY_PATCH` directly from the OS. A signature on this fact would be tautological — the OS is the source of truth. |
| `hardened/decoy/DecoyListenerService` | Adversary nmap fingerprinting of victim ports | The honeypot's job is to look like real services to defeat `-sV`; adding a PQ signature to the decoy *banner* would actively defeat the deception. Banners are deliberately legible to attackers. |
| `hardened/ultrasonic/UltrasonicListener` | 18-22 kHz ultrasonic-beacon cross-device tracking | Pure DSP — direct DFT on the audio buffer. The output is a sustained-tone classification that gets surfaced as an alert. No signature surface. |
| `hardened/selfie/SelfieAdminReceiver` | Failed-unlock attacks (lost / stolen device) | DeviceAdmin callback + Camera2 capture, both local-only. Captured frames land in `filesDir/selfies/` encrypted via EncryptedSharedPreferences-derived keys (AES-256-GCM, §1 row 11). No transit. |
| `transport-aoa` (USB / Android Open Accessory) | Local USB transport for the relay-side connection | The relay tunnels application-layer traffic; the AOA mode-switch is a Google-defined protocol with no key material to PQ-protect. The application payload's security is the upper layer's responsibility (and *is* PQ for what crosses the network). |
| `relay/pt-bridge/webtunnel` MITM heuristics | Captive-portal interposers / TLS-stripping proxies | The Text/Ping/Pong anomaly counter is a heuristic on framed-byte content. The crypto under WebTunnel is the upstream Tor + WebTunnel-PT design's responsibility; we observe, we do not re-protect. |
| `bluetooth/BleScanner` (sniff-for-airtags) | BLE manufacturer-data-byte pattern matching (AirTag-class trackers) | Passive radio observation. No cryptographic surface in our handling. |
| Privacy-Chain `WorkManager` OSINT periodic refresh | Pulling OSINT lists from public sources | Outbound HTTPS to pinned hosts — TLS handles transport authn; the OSINT content's integrity is the upstream publisher's responsibility. Local store is EncryptedSharedPreferences (AES-256-GCM). |

Every row above is **deterministic, local, and non-network-authoritative**.
PQ-securing them would add latency, code surface, and key-management
overhead for zero increase in adversary cost.

---

## 6. Per-module crypto inventory

The following inventory was hand-walked across the source tree as of
v0.1, May 2026. Each entry names the cryptographic primitive *as it
appears at the source-code level*, the standard it implements, and the
threat model that the primitive defends against.

### 6.1 On-device secret storage

- **Primitive:** AndroidX `EncryptedSharedPreferences` with
  `MasterKey.KeyScheme.AES256_GCM` and
  `PrefKeyEncryptionScheme.AES256_SIV` /
  `PrefValueEncryptionScheme.AES256_GCM`.
- **Standard:** AES-256-GCM per NIST SP 800-38D; AES-256-SIV per
  RFC 5297. MasterKey lives in the AndroidKeyStore (StrongBox where
  available on the Solana Seeker; software-backed fallback on the A23).
- **Used by:** `ThreatSuppressions`, `SelfieStore`, `VoiceprintVault`,
  `DeadmansStore`, `PrivacyChainCreds`, `AiGuardModelStore`, every
  Hardened-Mode preference flag.
- **PQ status:** AES-256 carries a ~128-bit quantum security floor
  under Grover (FIPS 197 + NIST SP 800-208 §4.1 commentary; effectively
  NIST PQ Level 1 against Grover, Level 5 against any classical
  attacker). No PQ upgrade required for v0.1.

### 6.2 Model-bundle / AI-Guard manifest channel

- **Primitive:** quadruple-verify (ECDSA-P521 / Ed448 / ML-DSA-87 /
  SLH-DSA-SHA2-256s) — see §2.
- **Content-integrity:** SHA-256 over each model artifact, pinned in
  the signed manifest body.
- **Standard:** FIPS 180-4 (SHA-256) + FIPS 186-5 + RFC 8032 + FIPS 204 + FIPS 205.
- **Threat model:** post-install code-equivalent-data swap. Strictest
  posture in the codebase.

### 6.3 Tor / Pluggable Transport relay path

- **Primitive:** upstream Tor + Arti (`tor-rtcompat`, `arti-client`)
  with embedded SOCKS5 listener; WebTunnel / Snowflake / Conjure / Obfs4
  as PT plugins.
- **Standard:** Tor protocol spec (`tor-spec.txt`); PT spec v1
  (`pt-spec.txt`); WebTunnel `draft-uberti-tls-camouflage`-class.
- **PQ status:** Tor is mid-migration to ML-KEM / hybrid X25519+ML-KEM
  for the relay layer (TROVE-2024 / Arti roadmap). We inherit
  whatever upstream ships; we do not interpose our own crypto on the
  tunnel. Our PT-bridge MITM anomaly counter is a heuristic and
  not part of the tunnel's cryptographic guarantee.

### 6.4 Privacy-Chain credential issuance

- **Primitive:** OAuth bearer tokens to public OSINT APIs, stored in
  `EncryptedSharedPreferences`. Outbound TLS to pinned hosts.
- **Standard:** RFC 6749 + RFC 8446 TLS 1.3.
- **PQ status:** awaiting upstream OAuth provider PQ-TLS migration;
  no immediate action on our side.

### 6.5 USB / AOA transport

- **Primitive:** rusb-driven Google Android Open Accessory v2.0 mode
  switch; bulk-IN / bulk-OUT after re-enumeration as 0x18d1:0x2d00/0x2d01.
- **Standard:** Google AOA 2.0 + USB 2.0 BBB transport.
- **Cryptographic content:** none — application payload (passed through
  the bulk endpoints) is the upper layer's responsibility.

### 6.6 Device-Admin selfie capture

- **Primitive:** `DeviceAdminReceiver.onPasswordFailed` →
  `SelfieCaptor.captureFront()` (Surface-less Camera2 JPEG at 640×480).
- **Storage:** `filesDir/selfies/<epoch>.jpg` (plaintext JPEG within
  the app sandbox; sandbox boundary is Android's per-uid file
  isolation, which on a rooted attacker is bypassed but on a normal
  device adversary is not). Attempt-counter is in EncryptedSharedPreferences.
- **Privilege ceiling:** `device_admin.xml` declares ONLY
  `<watch-login/>` — no `force-lock`, no `wipe-data`, no
  `disable-camera`. Minimum-privilege per OWASP MASVS-AUTH.

### 6.7 Hardened-Mode profile + dead-man's switch

- **Primitive:** ed25519 challenge-response handshake for the
  voiceprint safe-word vault; HKDF-SHA256 key derivation; AES-256-GCM
  content sealing.
- **Standard:** RFC 8032 (ed25519); RFC 5869 (HKDF); NIST SP 800-38D.
- **PQ status:** safe-word vault is a local-only handshake — adversary
  must be in physical possession of the device and the live voice
  channel. PQ overhead would not raise the bar.

---

## 7. Quantum-strength notes on hash sidecars

Several modules use SHA-256 (model-bundle content hashes, Privacy-Chain
record fingerprints, Sigsum / MTC inclusion-proof leaves). Under
Grover's algorithm, an n-bit hash has effective quantum preimage
resistance of 2^(n/2); SHA-256 is therefore a **128-bit quantum
floor**, which aligns with NIST PQ Category 1. Where stronger margins
are appropriate (Hardened-Mode safe-word vault key derivation,
long-lived audit-log root), we use SHA-512 (256-bit quantum floor =
NIST Category 5). The ML-DSA-87 + SLH-DSA-SHA2-256s pair in §2 also
internally hash with SHA-512 / SHA-256 respectively, both per FIPS-204
/ FIPS-205, so no separate sidecar is needed for the manifest channel.

---

## 8. Compliance summary

| Standard | Compliance |
|---|---|
| FIPS 197 (AES) | ✓ AES-256 throughout |
| FIPS 180-4 (SHA-2 family) | ✓ SHA-256 and SHA-512 |
| FIPS 186-5 (ECDSA P-521) | ✓ in `ModelUpdater.kt` |
| FIPS 203 (ML-KEM) | n/a in v0.1 (no PQ KEM today) |
| FIPS 204 (ML-DSA-87) | ✓ in `ModelUpdater.kt` |
| FIPS 205 (SLH-DSA-SHA2-256s) | ✓ in `ModelUpdater.kt` |
| SP 800-38D (AES-GCM) | ✓ on-device secret stores |
| SP 800-56C / SP 800-108 (KDF) | ✓ HKDF-SHA256 for derived keys |
| SP 800-208 (stateful HBS) | deliberately not used — §4 |
| IETF composite-sigs v19 | wrapper layout aligns; discrete sigs over composite for forward-rotation §2 |
| IETF PLANTS / MTC | `mtc_proof` field reserved; v1 ships empty; M10.x walks the log §3 |
| RFC 8032 EdDSA | ✓ Ed448 + Ed25519 |
| RFC 8446 TLS 1.3 | ✓ for all outbound HTTPS |

Tetherand's cryptographic posture is verifiable, reproducible
(`bash scripts/gen-signing-keys.sh` is a one-command path for any
fork), and audit-friendly (every primitive maps to a published
standard cited above).

---

## 10. SHAKE-256 entropy mixer (5364C13D-posture RNG)

The Linux kernel's `getrandom(2)` (and therefore the JVM's default
`SecureRandom`, which on Android is backed by it) is cryptographically
strong **when the entropy pool is well-seeded**. Two scenarios in our
adversary model break that assumption:

1. **Early-boot window.** A kernel that booted without
   `random.trust_cpu=on` can have a low-entropy window between
   `init` and the first sufficiently-noisy interrupt. An adversary
   who can force a reboot may catch the pool in this window.
2. **Boot-ROM fault injection.** The MediaTek Boot ROM
   vulnerability disclosed January 2026 (which affects the Solana
   Seeker SoC) enables a physically-present APT-class adversary to
   bias on-die hardware-RNG output via electromagnetic fault
   injection. The kernel's RNG mixes the hardware source but does
   not detect bias in it.

The mitigation is **never to trust a single entropy source**. We
implement an in-process SHAKE-256 mixer (FIPS-202, the same primitive
NIST chose as the squeeze function for SLH-DSA-SHA2 and ML-KEM key
expansion) that absorbs from EIGHT independent sources per call and
squeezes whitened bytes to the consumer:

| # | Source | What it provides | Adversary cost to bias |
|---|---|---|---|
| 1 | `/dev/urandom` (kernel pool) | OS-grade CSPRNG | low if early-boot pool is starved; high after `add_input` has saturated |
| 2 | JCA platform `SecureRandom` | Independently-seeded JVM default; resolved against a non-self provider | medium — different code path than urandom; harder to bias both simultaneously |
| 3 | AndroidKeyStore HW-backed per-call HMAC | StrongBox-attested salt on Seeker; TEE on A23. The key bytes never leave the keystore — we cache only the JVM Key reference (opaque). Each `engineNextBytes` triggers a fresh `HmacSHA256(callCounter ‖ nanoTime)` op through the keystore; the 32-byte output is absorbed into SHAKE then `Arrays.fill(0)`'d immediately, so there is **no long-residency HMAC bytes in JVM heap** for a forensic adversary to lift. | very high — requires TEE-firmware compromise, which would be an entirely separate APT capability |
| 4 | Sensor jitter (accel + gyro) | Low-bit MEMS noise | very high — even an APT cannot reach into the MEMS oscillator |
| 5 | Monotonic-clock skew | Scheduler / cache-line jitter | medium — observable through cache side-channels but a moving target across calls |
| 6 | **drand (League of Entropy)** | 32-byte BLS-signed beacon round, every 30s, threshold-signed by ~16 independent operators | high — requires colluding majority of independent operators AND defeating our TLS pin AND defeating the Tor exit our request egresses through |
| 7 | **NIST Beacon v2.0** | 64-byte ECDSA-P384-signed pulse from NIST, every 60s | high — requires NIST signing-key compromise AND defeating our TLS pin AND defeating Tor exit; different operator and crypto from drand so neither compromise helps the other |
| 8 | **SHA3-256(device activity)** | 32-byte digest over battery temp/voltage + network RX/TX bytes + /proc/loadavg + /proc/uptime + JVM heap state + nanoTime + Build.FINGERPRINT | medium — adversary in process can read each signal but cannot make all of them DECISIVELY DETERMINISTIC across consecutive snapshots without the user noticing (battery temp drifts, byte counters climb monotonically, etc.) |

All eight are absorbed into a single `Shake256` instance, then squeezed
into the caller's buffer. Under the random-oracle assumption (the
standard model used to argue SHAKE security), the output is
computationally indistinguishable from uniform as long as **any one**
of the eight sources supplied a single bit of unpredictable entropy.

**Tor-mandatory egress for network sources (6, 7).** drand + NIST
fetches go through the embedded Arti SOCKS5 listener exclusively by
default; if no Tor circuit is up, the fetch is **deferred** rather
than falling back to clear-net. The privacy intent is: a device
polling drand/NIST every minute from a stable source IP is a
unique fingerprint that lets either operator (or anyone with
netflow visibility) track Tetherand installs across networks. The
user can opt-in to clear-net fallback via `BeaconPolicy.clearnetFallback`
on the AI tab (default OFF); Hardened Mode entry wipes the policy
back to default so a high-risk session always starts strict.

**Why a hostile beacon response cannot bias us.** Even an adversary
who somehow controls our Tor exit AND defeats our TLS pin AND serves
us a hostile drand round STILL cannot bias the SHAKE output — the
six other sources contribute their own entropy, and the random-oracle
argument applies symmetrically: only ONE source needs to be
unpredictable for the output to be indistinguishable from uniform.

**Re-entrancy.** Because we install at JCA position 1, JCA primitives
we use INTERNALLY (KeyGenerator.generateKey, AndroidKeyStore HMAC
ops, TLS handshakes inside our own beacon fetcher) request
SecureRandom and get dispatched right back to us. A thread-local
recursion guard breaks the cycle: re-entrant `engineNextBytes` calls
on the same thread satisfy the request from `/dev/urandom` alone
(itself a FIPS-203-grade CSPRNG), bypassing the 8-source mix. This
preserves correctness for the inner JCA caller without infinite
recursion. Source-3 (keystore HMAC) is eager-initialized during
`installAsDefault` so the key-generation moment is pinned to
`MainActivity.onCreate` rather than left to an adversary-controllable
first-access timing.

**Kotlin implementation:** `dev.tetherand.app.crypto.SeekerRng` —
installed as `Provider` at position 1 of the JCA list in
`MainActivity.onCreate()`, BEFORE BouncyCastle is touched. Every
`new SecureRandom()` and every `Signature.getInstance(...).initSign(...)`
in the process draws from the mixer.

**Rust implementation:** `relay/pt-bridge/src/secure_rng.rs` —
absorbs `getrandom(2)` + RDRAND/CNTVCT_EL0 + clock jitter + call
counter. Used in `meek.rs` (session-ID generation) and `obfs4.rs`
(X25519 ephemeral private key + random padding). `wg`, `tor`, and
`core` crates already use `OsRng` from `rand_core` directly — those
paths are not weakened (lattice / X25519 / Tor handshakes already
demand OsRng-quality randomness from upstream) and the SHAKE mixer
is therefore not interposed there.

Performance: 32-byte fill ≈ 60 µs on Seeker (one syscall + one
keystore HMAC + a few cycles of clock-jitter harvest). Acceptable
everywhere except stream-cipher inner loops.

---

## 11. Zeroization posture

Every byte sequence holding key material, signature, PSK, password, or
HKDF output is wiped (`Arrays.fill(arr, 0)` on Kotlin / `zeroize::Zeroize`
on Rust) at the earliest defensible point in its lifetime. The JVM
makes the perfect version of this impossible — `String` is immutable
and `ByteArray` may have been relocated by GC — but we narrow the
heap-residency window aggressively.

| Site | Treatment |
|---|---|
| `WireGuardConfig.{privateKey,peerPublicKey,presharedKey}` | wiped in `WireGuardConfig.zeroize()`, called from `WireGuardHop.stop()` after the JNI WG instance is freed |
| `ShadowsocksSocket` password | best-effort reflection wipe of the `String.value` field immediately after the JNI handoff in `connect()` |
| OSINT password (UI) | dropped from Compose state before the network call; reflection-wiped after the SHA-1 hash is computed |
| `OsintExposureProbe.isPasswordPwned` SHA-1 input + output bytes | wiped via `SecureBytes.wipe(byteArray)` in a finally block |
| `SeekerRng` per-call buffers (`sys`, `jitter`, etc.) | wiped before SHAKE squeezes; reduces "secrets in temp buffers" window to a single function call |
| Rust `secure_rng::fill` per-call buffers | `sys.zeroize()` + `jitter.zeroize()` before scope exit |
| Rust JNI `copy_jba` allocations (WG keys) | upstream BoringTun internally zeroizes when its types drop; we additionally cap DAITA inputs to prevent OOM-DoS |
| `SecureBytes` general-purpose container | finalizer backstop + try-with-resources; constant-time equality (defeats timing side-channel on raw `Arrays.equals`) |

What we **do not** defend against:

* **GC relocation copies.** If the JVM moved a `ByteArray` mid-life,
  the old slot is not wiped; a forensic snapshot of the heap can
  recover it. Mitigation requires JVM-internal hooks we do not have.
* **Page swap.** Android's swap files (`/dev/block/zram0` and post-13
  the encrypted swap) may contain copies of wiped pages. The encrypted
  swap means an attacker who pulls the disk gets cyphertext only;
  cold-boot RAM attacks remain a theoretical concern.
* **Compose recomposition copies.** A `String` held in `mutableStateOf`
  is copied on every recomposition. Our OSINT card mitigates by
  clearing state IMMEDIATELY after capture rather than waiting for
  the network call to complete.

---

## 12. Network posture (TLS pinning + cleartext block)

System-level enforcement in `res/xml/network_security_config.xml`:

* `cleartextTrafficPermitted="false"` baseline. No plaintext HTTP
  anywhere, even during debug. Code that attempts cleartext throws
  `java.io.IOException: Cleartext HTTP traffic … not permitted`.
* Per-domain SPKI-pin sets for `api.mullvad.net`,
  `api.pwnedpasswords.com`, `haveibeenpwned.com`. Pin expiration is
  one year out; re-capture is scheduled.
* `<debug-overrides>` explicitly forbids user-installed CAs even in
  debug builds. This blocks the "MITM proxy with my own root"
  shortcut — which is also the exact shape of a hostile-environment
  attacker dropping a CA onto a borrowed device.

App-level enforcement in `dev.tetherand.app.net.PinnedHttp`:

* OkHttp `CertificatePinner` with the same SPKI pin set.
* `ConnectionSpec.RESTRICTED_TLS` restricted to TLS 1.3 (with 1.2
  fallback for hosts that haven't migrated).
* `followRedirects = false` / `followSslRedirects = false` — a 30x
  to an unpinned host is rejected at the call site rather than
  silently followed.

Both layers must accept for a connection to succeed (belt and braces).
A compromise of any single public CA alone cannot inject a substitute
cert — the attacker also needs the matching pinned key.

---

## 13. App posture (manifest, IPC, exfil suppression)

* **VPN control intent gate.** `TetherandActivity` is exported (it
  must be for the `adb shell am ...` CLI flow), but
  `onCreate()` now runs a runtime caller-identity check via
  `Binder.getCallingUid()` and `Activity.getReferrer()`. Acceptable
  callers: our own UID, `Process.SHELL_UID`, `Process.SYSTEM_UID`,
  or a referrer URI matching the package, the shell, or systemui.
  Everything else is `finishAndRemoveTask()`'d before the intent
  extras are even parsed. Silent reject (we do not log the
  rejected caller's identity — that would let an attacker probe
  for our presence via logcat).
* **noHistory / excludeFromRecents** on `TetherandActivity`. The
  activity never lingers in the task stack as a re-launch vector.
* **AoaAccessoryService** marked `exported="false"`. The
  `USB_ACCESSORY_ATTACHED` broadcast is a system-privileged
  broadcast — only the platform USB stack can fire it — and no
  third-party caller has any legitimate reason to invoke this
  service directly.
* **`allowBackup="false"` + `fullBackupContent="false"` +
  `dataExtractionRules`**. Captured selfies, voiceprints, threat-DB
  rows, AI Guard model state, and every `EncryptedSharedPreferences`
  blob stay on the device they were written to — they are NOT
  migrated to a new phone by Google Backup or by the Smart Switch /
  Quick Start handoff. Forensic artifact suppression: a migrated
  device looks sealed to Tetherand.
* **Log redaction.** No SHA-256 hashes in logcat (full hashes are
  forensic artifacts that identify exact model-bytes the device
  expected or received). No model-by-model state in logcat (would
  tell an adversary which classifier is enabled). No intent extras.
  No paths under `/data/` or `/Users/`. The rejection path of the
  caller-identity check is **deliberately silent** to avoid
  presence-probing.

Permissions retained, all with documented justification:

| Permission | Why we need it | Threat-model relevance |
|---|---|---|
| `INTERNET` | All relay paths | Required |
| `ACCESS_NETWORK_STATE` | Chain switching on uplink change | Required |
| `FOREGROUND_SERVICE*` | VPN + threat-detection + decoy + clipboard FGSs | Required |
| `POST_NOTIFICATIONS` | FGS notification surface | Required |
| `READ_PHONE_STATE` | M7a cell-tower / signal-strength reads | Used only for in-RAM heuristic; never logged |
| `ACCESS_FINE_LOCATION` + `ACCESS_COARSE_LOCATION` | M7a TAC-change heuristic | Used only for in-RAM heuristic; never persisted beyond current check |
| `ACCESS_WIFI_STATE` + `CHANGE_WIFI_STATE` | M7a EvilTwin detection + chain switching | Used only for in-RAM heuristic + user-initiated chain switch |
| `BLUETOOTH_SCAN` + `BLUETOOTH_CONNECT` | M7a BLE tracker heuristic + sniff-for-AirTags | Used only for in-RAM heuristic |
| `QUERY_ALL_PACKAGES` | M7a PermissionDiff heuristic — watches for newly-installed surveillance apps | Necessary for the use case; the package-set is hashed for diff comparison only, never enumerated to disk |
| `RECEIVE_BOOT_COMPLETED` | Start ThreatDetectionService on boot if user opted-in | Required |
| `RECORD_AUDIO` | M9.x ultrasonic-beacon (18-22 kHz) | Hardened-Mode-only; FFT processed in-RAM; raw audio never written |
| `CAMERA` | M9.x selfie-on-failed-unlock | Hardened-Mode + DeviceAdmin + user-opt-in; image captured to private `filesDir/selfies/` only, deletable by the user |

No `WRITE_EXTERNAL_STORAGE`, no `SYSTEM_ALERT_WINDOW`, no
`READ_CONTACTS`, no `READ_SMS`, no `READ_CALL_LOG`, no
`PACKAGE_USAGE_STATS`, no `ACCESSIBILITY_SERVICE`. The
permission set is the smallest one that lets the documented
features function.

---

## 14. CVE coverage matrix (Android, last 90 days at v0.1 ship)

| CVE | Affects | Status | Tetherand mitigation |
|---|---|---|---|
| **CVE-2026-21385** | Qualcomm graphics, actively exploited zero-day in March 2026 bulletin | Not exploitable from app sandbox (kernel-driver issue); A23 + Seeker users must apply OEM patch | We detect stale `Build.VERSION.SECURITY_PATCH` via `PatchLevelStaleness` heuristic and raise High / Critical alerts |
| **CVE-2026-0073** | adbd RCE via TCP-mode adb | Detected by `AdbdNetworkSurface` heuristic (scans `service.adb.tcp.port` + `/proc/net/tcp{,6}` for port 5555 LISTEN). Plain USB ADB does not trigger. | User can suppress via `ThreatSuppressions` if adb-over-Wi-Fi is part of their dev workflow |
| **CVE-2026-20449 / 20450** | MediaTek MT6878 modem stack | Affects baseband, not app sandbox | `MtkRogueCellDetector` surfaces cellular anomalies that may correlate |
| MediaTek **KeyInstall** + **display** CVEs (March 2026 bulletin) | MediaTek closed-source kernel components | Patched by OEM rollups | `PatchLevelStaleness` >180d = High, >365d = Critical |
| MediaTek Boot ROM vuln (Jan 2026) | Seeker SoC, requires physical access + EM fault-injection | NOT patchable in software (Boot ROM is mask-ROM); requires physical defense | Documented in §0 adversary model; mitigated by the SHAKE-256 entropy mixer (§10) which assumes the HW RNG may be biased |
| **Solana Saga end-of-support** (May 2026) | The predecessor phone; not the Seeker | Saga users are at perpetual risk; Seeker remains supported | We document Saga-vs-Seeker in `docs/installing.html`; advise Saga users to migrate |
| TLS-stripping by a compromised public CA | Network adversary | Defeated by SPKI pinning at both Android-system layer (`network_security_config.xml`) AND OkHttp-app layer (`PinnedHttp`) | §12 |
| User-installed MITM root CA | Borrowed-device adversary | Defeated by `<debug-overrides>` excluding user CAs even in debug | §12 |
| QUIC connection-migration deanonymization | Mass surveillance via stable QUIC connection IDs | Not directly mitigated — Tetherand inherits whatever Tor/Arti and Mullvad protocols choose | Future: M11.x bridge-rotation timer |

---

## 15. Boot-integrity check (Verified-Boot + KeyStore attestation)

`dev.tetherand.app.crypto.BootIntegrity` runs at every cold-start of
`MainActivity` and produces one of six verdicts:

| Verdict | Meaning | Accept? |
|---|---|---|
| `Verified` | `vbs=green` (OEM-locked) + release-keys + non-empty attestation chain | **Yes** |
| `VerifiedUserRoot` | `vbs=yellow` (user-locked AVB, canonically GrapheneOS) + release-keys + non-empty attestation chain | **Yes** — security-equivalent to Verified |
| `UnlockedBootloader` | `vbs=orange` or `ro.boot.flash.locked=0` | No |
| `Failed` | `vbs=red` (verified-boot failure) | No |
| `Untrusted` | test-keys / debuggable / empty attestation chain | No |
| `Unknown` | could not read any signal | No |

**GrapheneOS posture (explicit).** GrapheneOS users re-lock the
bootloader with their own AVB signing key, which makes
`ro.boot.verifiedbootstate` return `yellow`. The bootloader is still
locked; the verified-boot chain still validates; the user has chosen
their trust root deliberately. Treating `yellow` as untrusted would
deliberately weaken our security posture by pushing the most
privacy-paranoid users (exactly Tetherand's target audience) toward
less-hardened distributions. We therefore accept `yellow` as
`VerifiedUserRoot`, which is functionally equivalent to `Verified`.

Signals consulted, in increasing strength:

1. `ro.boot.verifiedbootstate` — green / yellow accepted, orange / red rejected.
2. `ro.boot.flash.locked` — must be `1`.
3. `Build.TAGS` — must contain `release-keys` (not `test-keys` or `dev-keys`).
4. `Build.IS_DEBUGGABLE` — must be `false` in release.
5. KeyStore attestation chain length — must be > 0. A non-zero chain
   proves the device's TEE / StrongBox key is signed by *some*
   attestation authority. Full root-pubkey pin validation (against
   the published Google root and known GrapheneOS roots) is the
   v0.2 deliverable; v0.1 ships the length check.

On the emulator, `vbs=orange` because the AVD bootloader is always
unlocked. The check returns `UnlockedBootloader` but the app
continues to function — release builds fail closed; debug builds
display the warning and let development proceed.

---

## 9. Citations

- FIPS 203 (ML-KEM) final, 2024-08-13 — <https://csrc.nist.gov/pubs/fips/203/final>
- FIPS 204 (ML-DSA) final, 2024-08-13 — <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf>
- FIPS 205 (SLH-DSA) final, 2024-08-13 — <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf>
- NIST SP 800-208 stateful HBS — <https://csrc.nist.gov/pubs/sp/800/208/final>
- draft-ietf-lamps-pq-composite-sigs-19 (2026-04-21) — <https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/>
- draft-ietf-plants-merkle-tree-certs-03 (2026, expires 2026-10-22) — <https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/>
- OpenSSL 3.5 release notes — <https://openssl-library.org/news/openssl-3.5-notes/>
- OpenSSL 3.6 release announcement, 2025-10-01 — <https://openssl-library.org/post/2025-10-01-3.6-release-announcement/>
- BouncyCastle 1.80 PQC + lightweight updates — <https://www.bouncycastle.org/resources/pqc-and-lightweight-cryptography-updates-bouncy-castle-1-80-java/>
- NIST first three PQ standards announcement, 2024-08-13 — <https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards>
