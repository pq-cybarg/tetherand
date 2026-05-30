# Tetherand — Formal Cryptographic Verification

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
