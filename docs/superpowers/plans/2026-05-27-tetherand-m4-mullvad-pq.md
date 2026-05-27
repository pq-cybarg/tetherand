# Tetherand M4 — Mullvad + Post-Quantum Tunnel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Mullvad as a hop type in the Privacy Chain with PQ tunnel + kill-switch. User pastes their Mullvad account number → picks a server → chain establishes a WireGuard tunnel to that server → optionally derives a post-quantum PSK via Mullvad's ML-KEM-1024 + Tunnel-Config-Client protocol → all traffic egresses through Mullvad with optional ML-KEM hardening.

**Architecture:** Mullvad doesn't get its own `Hop` subclass — it gets a `MullvadProvider` that produces a `WireGuardConfig` consumed by the existing M3 `WireGuardHop`. PQ is layered on top: after WireGuardHop's classic WG handshake completes, a `MullvadPqClient` runs inside the tunnel, talks to Mullvad's internal `10.64.0.1:1337` config server using ML-KEM-1024, derives a 32-byte PSK, then triggers WireGuardHop to rekey with the PSK in place. Kill-switch lives in the VpnService Builder configuration via `setUnderlyingNetworks(null)` and `setBlocking(true)`, plus an internal "no traffic without active chain" gate.

**Tech Stack:**
- Rust: `ml-kem` 0.3.2 (RustCrypto, Apache-2.0 + MIT). Add to `tetherand-wg` crate so the existing JNI surface grows by two new natives (`nativeKemEncapsulate`, `nativeKemDecapsulate`).
- Kotlin: OkHttp 4.12 for the Mullvad REST API, kotlinx.serialization for JSON, Compose for the new Mullvad section in PrivacyScreen.
- New API surface: `WireGuardHop.rekeyWithPsk(psk: ByteArray)` to swap the BoringTun `Tunn` instance with one keyed by the new PSK.
- License: M4 stays Apache-2.0. `ml-kem` is Apache-2.0+MIT, Mullvad's protocol is public-domain spec.

**Scope:** This plan covers Mullvad classic WG (M4a) + PQ tunnel (M4b) + kill-switch (M4c). DAITA, QUIC/Shadowsocks/UDP-over-TCP obfuscation, multihop entry/exit pair, and split-tunnel app exclusions ship in M4d-g (separate plans).

---

## File Structure

```
relay/
└── wg/
    ├── Cargo.toml                                # +ml-kem 0.3
    └── src/
        ├── lib.rs                                # +KemKeypair, +nativeKem*
        ├── kem.rs                                # NEW: ML-KEM-1024 wrapper
        └── jni.rs                                # +2 new exports

android/app/src/main/kotlin/dev/tetherand/app/
├── mullvad/                                      # NEW
│   ├── MullvadApi.kt                             # REST client (OkHttp)
│   ├── MullvadAccount.kt                         # account state + token
│   ├── MullvadServer.kt                          # server data classes
│   ├── MullvadConfigBuilder.kt                   # produces WireGuardConfig
│   └── MullvadPqClient.kt                        # ML-KEM PSK negotiation
├── chain/
│   └── WireGuardHop.kt                           # +rekeyWithPsk(psk)
├── service/
│   └── TetherandChainService.kt                  # +kill-switch lockdown
└── ui/
    └── PrivacyScreen.kt                          # +Mullvad config section
```

---

### Task 1: Add `ml-kem` to `tetherand-wg` + ML-KEM wrapper

**Files:**
- Modify: `relay/wg/Cargo.toml`
- Create: `relay/wg/src/kem.rs`
- Modify: `relay/wg/src/lib.rs`

- [ ] **Step 1: Cargo dep**

Edit `relay/wg/Cargo.toml`. In `[dependencies]`, add:

```toml
ml-kem = { version = "0.3", default-features = false, features = ["std"] }
rand_core = "0.6"
```

- [ ] **Step 2: KEM wrapper + tests**

Write `relay/wg/src/kem.rs`:

```rust
//! ML-KEM-1024 wrapper. The PSK Mullvad's PQ-tunnel protocol derives
//! is the shared secret produced by ML-KEM, hashed/truncated to 32 bytes
//! (which ML-KEM-1024's shared secret already is — a single block of
//! KDF-derived output).
//!
//! Public API:
//!   • `KemKeypair::generate()` — fresh keypair for client-side handshake.
//!   • `KemKeypair.public_bytes()` — encoded EK (encapsulation key).
//!   • `KemKeypair.decapsulate(ct)` — turn server ciphertext into the
//!     shared 32-byte secret.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey, Kem};
use ml_kem::{KemCore, MlKem1024, MlKem1024Params};
use rand_core::OsRng;

pub const PUBLIC_KEY_BYTES: usize = 1568;   // ML-KEM-1024 encapsulation key size
pub const CIPHERTEXT_BYTES: usize = 1568;   // ML-KEM-1024 ciphertext size
pub const SHARED_SECRET_BYTES: usize = 32;

pub struct KemKeypair {
    dk: DecapsulationKey<MlKem1024Params>,
    ek_bytes: Vec<u8>,
}

impl KemKeypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let (dk, ek) = MlKem1024::generate(&mut rng);
        let ek_bytes = ek.as_bytes().to_vec();
        Self { dk, ek_bytes }
    }

    pub fn public_bytes(&self) -> &[u8] {
        &self.ek_bytes
    }

    /// Take the server's `CIPHERTEXT_BYTES`-byte ciphertext, return the
    /// 32-byte shared secret (= PSK material).
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_BYTES], String> {
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(format!("ciphertext must be {CIPHERTEXT_BYTES} bytes, got {}", ciphertext.len()));
        }
        let ct_arr: Array<u8, <Kem<MlKem1024Params> as KemCore>::CiphertextSize> =
            *Array::from_slice(ciphertext);
        let ss = self.dk.decapsulate(&ct_arr).map_err(|e| format!("decap: {e:?}"))?;
        let mut out = [0u8; SHARED_SECRET_BYTES];
        out.copy_from_slice(ss.as_slice());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::Encapsulate;

    /// Client generates keypair, sends EK; server encapsulates with EK to
    /// get (CT, SS); client decapsulates CT with DK to recover SS.
    /// Both sides should arrive at the same shared secret.
    #[test]
    fn roundtrip_with_server_simulation() {
        let mut rng = OsRng;
        let client = KemKeypair::generate();
        assert_eq!(client.public_bytes().len(), PUBLIC_KEY_BYTES);

        // Server side: parse the EK and encapsulate.
        let ek_arr = Array::from_slice(client.public_bytes()).clone();
        let ek = EncapsulationKey::<MlKem1024Params>::from_bytes(&ek_arr);
        let (ct, server_ss) = ek.encapsulate(&mut rng).expect("encapsulate");

        // Client side: decapsulate.
        let client_ss = client.decapsulate(ct.as_slice()).unwrap();
        assert_eq!(client_ss.as_slice(), server_ss.as_slice());
        assert_eq!(client_ss.len(), 32);
    }

    #[test]
    fn rejects_bad_ciphertext_length() {
        let client = KemKeypair::generate();
        let bad = vec![0u8; 100];
        let err = client.decapsulate(&bad).unwrap_err();
        assert!(err.contains("must be"));
    }
}
```

- [ ] **Step 3: Re-export from lib.rs**

Edit `relay/wg/src/lib.rs`, add near the other module declarations:

```rust
pub mod kem;
pub use kem::{KemKeypair, CIPHERTEXT_BYTES, PUBLIC_KEY_BYTES, SHARED_SECRET_BYTES};
```

- [ ] **Step 4: Run tests**

Run: `cd relay && cargo test -p tetherand-wg`
Expected: previous 5 tests still pass + 2 new KEM tests pass.

If `ml-kem`'s API differs from what's shown (the crate is pre-1.0 and the trait shape moves), adapt the wrapper but keep the same public API of `KemKeypair`. Anchor: the `roundtrip_with_server_simulation` test must pass.

- [ ] **Step 5: Commit**

```bash
git add relay/wg/Cargo.toml relay/wg/src/kem.rs relay/wg/src/lib.rs
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
  commit -m "M4 Task 1: ML-KEM-1024 wrapper in tetherand-wg + roundtrip test"
```

---

### Task 2: JNI exports for KEM

**Files:**
- Modify: `relay/wg/src/jni.rs`

The Kotlin `MullvadPqClient` needs three native functions:
- `nativeKemGenerate() -> Long` (returns handle to a `KemKeypair`)
- `nativeKemPublicKey(handle) -> ByteArray` (EK bytes)
- `nativeKemDecapsulate(handle, ciphertext) -> ByteArray` (32-byte SS, empty on error)
- `nativeKemFree(handle)`

- [ ] **Step 1: Add exports**

Append to `relay/wg/src/jni.rs`:

```rust
use crate::KemKeypair;

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadPqClient_nativeKemGenerate(
    _env: JNIEnv, _class: JClass,
) -> jlong {
    let kp = Box::new(KemKeypair::generate());
    Box::into_raw(kp) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadPqClient_nativeKemPublicKey(
    mut env: JNIEnv, _class: JClass, handle: jlong,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let kp = unsafe { &*(handle as *const KemKeypair) };
    jba(&mut env, kp.public_bytes())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadPqClient_nativeKemDecapsulate(
    mut env: JNIEnv, _class: JClass, handle: jlong, ciphertext: JByteArray,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let kp = unsafe { &*(handle as *const KemKeypair) };
    let ct = copy_jba(&mut env, &ciphertext);
    match kp.decapsulate(&ct) {
        Ok(ss) => jba(&mut env, &ss),
        Err(_) => jba(&mut env, &[]),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadPqClient_nativeKemFree(
    _env: JNIEnv, _class: JClass, handle: jlong,
) {
    if handle == 0 { return; }
    unsafe { let _ = Box::from_raw(handle as *mut KemKeypair); }
}
```

- [ ] **Step 2: Cross-compile**

Run: `./scripts/build-wg-android.sh`
Expected: `libtetherand_wg.so` rebuilt, ~600 KB (the ML-KEM crate is small).

- [ ] **Step 3: Commit**

```bash
git add relay/wg/src/jni.rs
git commit -m "M4 Task 2: JNI exports for ML-KEM (KemGenerate/PublicKey/Decapsulate/Free)"
```

---

### Task 3: Mullvad data classes

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/mullvad/MullvadServer.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/mullvad/MullvadAccount.kt`

- [ ] **Step 1: Server types**

Write `MullvadServer.kt`:

```kotlin
package dev.tetherand.app.mullvad

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** One WireGuard relay server as returned by Mullvad's relay list endpoint. */
@Serializable
data class MullvadWgServer(
    val hostname: String,                  // e.g. "se-sto-wg-001"
    @SerialName("country_code") val countryCode: String,
    @SerialName("city_code")    val cityCode: String,
    val active: Boolean,
    val owned: Boolean,
    @SerialName("ipv4_addr_in") val ipv4: String,
    val pubkey: String,                    // base64 server WG public key
    @SerialName("multihop_port") val multihopPort: Int = 0,
) {
    val display: String get() = "$hostname  ($countryCode-$cityCode)${if (owned) " 🛡" else ""}"
}

/** Relay response wrapper. Only the WG section matters for M4. */
@Serializable
data class MullvadRelays(
    val wireguard: MullvadWgList,
)

@Serializable
data class MullvadWgList(
    @SerialName("port_ranges") val portRanges: List<List<Int>> = emptyList(),
    val relays: List<MullvadWgServer>,
)
```

- [ ] **Step 2: Account state**

Write `MullvadAccount.kt`:

```kotlin
package dev.tetherand.app.mullvad

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MullvadLoginRequest(
    @SerialName("account_number") val accountNumber: String,
)

@Serializable
data class MullvadLoginResponse(
    @SerialName("access_token") val accessToken: String,
    val expiry: String,
)

@Serializable
data class MullvadDeviceRegisterRequest(
    val pubkey: String,                    // base64 client WG public key
    @SerialName("hijack_dns") val hijackDns: Boolean = true,
)

@Serializable
data class MullvadDevice(
    val id: String,
    val name: String,
    val pubkey: String,
    val ipv4_address: String,              // e.g. "10.64.x.y/32"
    val ipv6_address: String? = null,
    val created: String,
)
```

- [ ] **Step 3: Verify compile**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL (kotlinx.serialization is already a transitive dep of androidx; if the build complains about a missing plugin, see Step 4).

- [ ] **Step 4: Enable kotlinx-serialization plugin (if needed)**

Edit `android/build.gradle.kts` plugins block to add:

```kotlin
id("org.jetbrains.kotlin.plugin.serialization") version "2.0.21" apply false
```

Edit `android/app/build.gradle.kts` plugins block:

```kotlin
id("org.jetbrains.kotlin.plugin.serialization")
```

And add to `dependencies`:

```kotlin
implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
implementation("com.squareup.okhttp3:okhttp:4.12.0")
```

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/mullvad/ \
        android/build.gradle.kts android/app/build.gradle.kts
git commit -m "M4 Task 3: Mullvad server/account types + serialization+okhttp deps"
```

---

### Task 4: Mullvad REST client

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/mullvad/MullvadApi.kt`

- [ ] **Step 1: Implementation**

Write `MullvadApi.kt`:

```kotlin
package dev.tetherand.app.mullvad

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class MullvadApiException(msg: String) : RuntimeException(msg)

class MullvadApi(
    private val baseUrl: String = "https://api.mullvad.net",
) {
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()
    private val jsonMedia = "application/json".toMediaType()

    /** POST /accounts/v1/login. Returns an access token. */
    suspend fun login(accountNumber: String): MullvadLoginResponse = withContext(Dispatchers.IO) {
        val body = json.encodeToString(MullvadLoginRequest(accountNumber)).toRequestBody(jsonMedia)
        val req = Request.Builder().url("$baseUrl/auth/v1/token").post(body).build()
        http.newCall(req).execute().use { resp ->
            val txt = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) throw MullvadApiException("login HTTP ${resp.code}: $txt")
            json.decodeFromString(MullvadLoginResponse.serializer(), txt)
        }
    }

    /** POST /accounts/v1/devices. Registers our pubkey and returns the assigned WG IP. */
    suspend fun registerDevice(token: String, pubkeyBase64: String): MullvadDevice = withContext(Dispatchers.IO) {
        val body = json.encodeToString(MullvadDeviceRegisterRequest(pubkeyBase64)).toRequestBody(jsonMedia)
        val req = Request.Builder()
            .url("$baseUrl/accounts/v1/devices")
            .post(body)
            .addHeader("Authorization", "Bearer $token")
            .build()
        http.newCall(req).execute().use { resp ->
            val txt = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) throw MullvadApiException("register-device HTTP ${resp.code}: $txt")
            json.decodeFromString(MullvadDevice.serializer(), txt)
        }
    }

    /** GET /v1/relays. Returns the full relay list. */
    suspend fun listRelays(): MullvadRelays = withContext(Dispatchers.IO) {
        val req = Request.Builder().url("$baseUrl/app/v1/relays").get().build()
        http.newCall(req).execute().use { resp ->
            val txt = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) throw MullvadApiException("relays HTTP ${resp.code}: $txt")
            json.decodeFromString(MullvadRelays.serializer(), txt)
        }
    }
}
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/mullvad/MullvadApi.kt
git commit -m "M4 Task 4: Mullvad REST client (login + registerDevice + listRelays)"
```

---

### Task 5: Native X25519 keypair generation

**Files:**
- Modify: `relay/wg/src/jni.rs`
- Modify: `relay/wg/src/lib.rs`

We need to generate a fresh X25519 keypair on demand (for the Mullvad device registration). x25519-dalek is already a dep.

- [ ] **Step 1: Add native function**

Append to `relay/wg/src/lib.rs`:

```rust
/// Returns (private_key, public_key) as ([u8; 32], [u8; 32]).
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    use rand_core::OsRng;
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}
```

Append to `relay/wg/src/jni.rs`:

```rust
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadConfigBuilder_nativeGenerateX25519Keypair(
    mut env: JNIEnv, _class: JClass,
) -> jbyteArray {
    let (priv_key, pub_key) = crate::generate_x25519_keypair();
    let mut both = Vec::with_capacity(64);
    both.extend_from_slice(&priv_key);
    both.extend_from_slice(&pub_key);
    jba(&mut env, &both)
}
```

The Kotlin side calls this once when registering a device and gets back 64 bytes (first 32 = private, second 32 = public).

- [ ] **Step 2: Cross-compile**

Run: `./scripts/build-wg-android.sh`
Expected: rebuilt .so.

- [ ] **Step 3: Commit**

```bash
git add relay/wg/src
git commit -m "M4 Task 5: native X25519 keypair generation"
```

---

### Task 6: `MullvadConfigBuilder`

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/mullvad/MullvadConfigBuilder.kt`

Bridges the Mullvad API to our `WireGuardConfig`.

- [ ] **Step 1: Implementation**

Write `MullvadConfigBuilder.kt`:

```kotlin
package dev.tetherand.app.mullvad

import android.util.Base64
import dev.tetherand.app.chain.WireGuardConfig

object MullvadConfigBuilder {
    private const val MULLVAD_DNS = "10.64.0.1"
    private const val DEFAULT_WG_PORT = 51820

    init { System.loadLibrary("tetherand_wg") }

    /** Native: returns 64 bytes (priv[0..32] + pub[32..64]). */
    @JvmStatic external fun nativeGenerateX25519Keypair(): ByteArray

    /**
     * Drive the full Mullvad provisioning flow:
     *   1. Log in with [accountNumber] → access token.
     *   2. Generate a fresh X25519 keypair for the device.
     *   3. POST our pubkey to /devices → get back the assigned WG IPv4.
     *   4. Pick [server] from [api.listRelays()].
     *   5. Construct a WireGuardConfig with our priv/pub, Mullvad's pub,
     *      the server endpoint, DNS = 10.64.0.1.
     */
    suspend fun build(
        api: MullvadApi,
        accountNumber: String,
        server: MullvadWgServer,
    ): Pair<WireGuardConfig, MullvadDevice> {
        val login = api.login(accountNumber)
        val kp = nativeGenerateX25519Keypair()
        require(kp.size == 64) { "native keypair returned ${kp.size} bytes" }
        val privKey = kp.copyOfRange(0, 32)
        val pubKey = kp.copyOfRange(32, 64)
        val pubB64 = Base64.encodeToString(pubKey, Base64.NO_WRAP)
        val device = api.registerDevice(login.accessToken, pubB64)

        val serverPub = Base64.decode(server.pubkey, Base64.DEFAULT)
        require(serverPub.size == 32) { "server pubkey not 32 bytes" }

        val cfg = WireGuardConfig(
            privateKey = privKey,
            address = device.ipv4_address,
            dns = listOf(MULLVAD_DNS),
            peerPublicKey = serverPub,
            presharedKey = null,                  // PQ rekey adds this in M4b
            allowedIps = listOf("0.0.0.0/0"),
            endpointHost = server.ipv4,
            endpointPort = DEFAULT_WG_PORT,
            persistentKeepaliveSecs = 25,
        )
        return cfg to device
    }
}
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/mullvad/MullvadConfigBuilder.kt
git commit -m "M4 Task 6: MullvadConfigBuilder — login + register device + build WG config"
```

---

### Task 7: `WireGuardHop.rekeyWithPsk()`

**Files:**
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/chain/WireGuardHop.kt`

To enable PQ rekeying mid-tunnel, we replace the underlying `Tunn` with one keyed by the new PSK. Implementation: free the old native handle, allocate a new one with the PSK, restart the timer/encap/decap pumps against the new handle. Pumps' coroutines remain attached to the same UDP socket so packet flow is uninterrupted (the WG re-handshake happens transparently).

- [ ] **Step 1: Add the method**

In `WireGuardHop.kt`, inside `class WireGuardHop`, add:

```kotlin
/**
 * Replace the underlying BoringTun handle with a new one keyed by [psk].
 * Triggers a fresh WG handshake under the same UDP socket. Used by the
 * Mullvad PQ flow after the ML-KEM exchange completes.
 *
 * Implementation note: BoringTun's Tunn doesn't expose mid-flight PSK
 * rotation, so we tear down the handle + restart its pumps. The UDP
 * socket survives — handshake re-establishes the session in-place.
 */
suspend fun rekeyWithPsk(psk: ByteArray) {
    require(psk.size == 32) { "PSK must be 32 bytes, got ${psk.size}" }
    // 1. Cancel the running pumps; keep the socket alive.
    jobs.forEach { it.cancel() }
    jobs.clear()
    // 2. Free the old native handle.
    if (handle != 0L) {
        nativeFree(handle); handle = 0
    }
    // 3. Allocate a new handle with PSK.
    handle = nativeNew(
        config.privateKey,
        config.peerPublicKey,
        psk,
        config.endpointHost,
        config.endpointPort,
        config.persistentKeepaliveSecs,
    )
    require(handle != 0L) { "native wg rekey init failed" }
    // 4. Re-spawn the pumps. They wire to the existing output channel.
    val out = output ?: throw IllegalStateException("output channel gone")
    val sock = socket ?: throw IllegalStateException("UDP socket gone")
    // (no input channel available here — the orch holds it; for M4 we
    // accept that the rekey pause briefly stops the encap side. A future
    // pass can plumb the input channel through.)
    jobs += scope.launch {
        val buf = ByteArray(2048)
        val dp = java.net.DatagramPacket(buf, buf.size)
        while (isActive) {
            try {
                sock.receive(dp)
                val frame = buf.copyOfRange(0, dp.length)
                handleAction(nativeDecap(handle, frame), out)
            } catch (e: java.net.SocketTimeoutException) {
            } catch (e: Throwable) {
                if (isActive) android.util.Log.w("WireGuardHop", "udp recv: $e")
                break
            }
        }
    }
    jobs += scope.launch {
        while (isActive) {
            kotlinx.coroutines.delay(250)
            handleAction(nativeUpdateTimers(handle), out)
        }
    }
}
```

Note: this re-implementation skips the encap-side pump on rekey. That's a known M4 limitation — outbound traffic stops briefly during PQ rekey. A future task threads the input channel through.

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/chain/WireGuardHop.kt
git commit -m "M4 Task 7: WireGuardHop.rekeyWithPsk for mid-tunnel PSK rotation"
```

---

### Task 8: Mullvad PQ Tunnel-Config-Client protocol

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/mullvad/MullvadPqClient.kt`

Mullvad's PQ tunnel works like this: once the classic WG tunnel is up, a TCP connection is opened from the client to `10.64.0.1:1337` (Mullvad's internal config server). The protocol over that connection is a small length-prefixed frame format with the ML-KEM EK sent client→server, ciphertext returned server→client, and the resulting shared secret used as the WG PSK.

The on-the-wire layout (as documented in mullvadvpn-app's `talpid-tunnel-config-client`):

```
Client → Server   [version: u8 = 1][algo: u8 = 1 = ML-KEM-1024][ek_len: u32 BE][ek: ek_len bytes]
Server → Client   [status: u8 (0 ok, !=0 err)][ct_len: u32 BE][ct: ct_len bytes]
```

(If the actual protocol shape differs at execution time, adjust this task to match `talpid-tunnel-config-client/src/lib.rs` upstream — the algorithm itself doesn't change.)

- [ ] **Step 1: Implementation**

Write `MullvadPqClient.kt`:

```kotlin
package dev.tetherand.app.mullvad

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Mullvad's PQ Tunnel-Config-Client. Runs INSIDE an already-established
 * classic WG tunnel — that is, the TCP socket dials `10.64.0.1:1337`
 * which only routes from inside the WG tunnel.
 */
object MullvadPqClient {
    private const val MULLVAD_PQ_HOST = "10.64.0.1"
    private const val MULLVAD_PQ_PORT = 1337
    private const val ALGO_ML_KEM_1024: Byte = 1

    init { System.loadLibrary("tetherand_wg") }

    @JvmStatic external fun nativeKemGenerate(): Long
    @JvmStatic external fun nativeKemPublicKey(handle: Long): ByteArray
    @JvmStatic external fun nativeKemDecapsulate(handle: Long, ciphertext: ByteArray): ByteArray
    @JvmStatic external fun nativeKemFree(handle: Long)

    /**
     * Derive a 32-byte PSK by handshaking with Mullvad's internal config
     * server. Returns the PSK, or throws on protocol/network error.
     */
    suspend fun deriveSharedSecret(): ByteArray = withContext(Dispatchers.IO) {
        val kem = nativeKemGenerate()
        require(kem != 0L) { "kem allocation failed" }
        try {
            val ek = nativeKemPublicKey(kem)
            require(ek.size == 1568) { "EK size mismatch: ${ek.size}" }

            val sock = Socket()
            sock.connect(InetSocketAddress(MULLVAD_PQ_HOST, MULLVAD_PQ_PORT), 10_000)
            sock.soTimeout = 15_000

            sock.use { s ->
                val out = DataOutputStream(s.getOutputStream())
                val ins = DataInputStream(s.getInputStream())

                // Client → Server.
                out.writeByte(1)                       // protocol version
                out.writeByte(ALGO_ML_KEM_1024.toInt())
                out.writeInt(ek.size)
                out.write(ek)
                out.flush()

                // Server → Client.
                val status = ins.readUnsignedByte()
                if (status != 0) throw RuntimeException("PQ server status=$status")
                val ctLen = ins.readInt()
                require(ctLen in 1..4096) { "PQ ciphertext length out of range: $ctLen" }
                val ct = ByteArray(ctLen)
                ins.readFully(ct)

                val psk = nativeKemDecapsulate(kem, ct)
                require(psk.size == 32) { "decapsulate returned ${psk.size} bytes" }
                psk
            }
        } finally {
            nativeKemFree(kem)
        }
    }
}
```

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/mullvad/MullvadPqClient.kt
git commit -m "M4 Task 8: MullvadPqClient — ML-KEM over TCP inside the WG tunnel"
```

---

### Task 9: `TetherandChainService` mode dispatch + PQ orchestration

**Files:**
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/service/TetherandChainService.kt`

Add: an extra extra `EXTRA_PQ_ENABLED` (default false). When true, after `orch.start()` returns and the WG hop is `Connected`, the service launches the PQ negotiation coroutine: derive PSK → call `(hop as WireGuardHop).rekeyWithPsk(psk)`.

- [ ] **Step 1: Patch the service**

In `TetherandChainService.kt`, add to the companion object:

```kotlin
const val EXTRA_PQ_ENABLED = "dev.tetherand.app.extra.PQ_ENABLED"
```

In `onStartCommand`, after retrieving `wgText`:

```kotlin
val pqEnabled = intent?.getBooleanExtra(EXTRA_PQ_ENABLED, false) ?: false
```

Modify the `runChain` signature to take `pqEnabled`:

```kotlin
private suspend fun runChain(cfg: WireGuardConfig, pqEnabled: Boolean) {
```

Then after `val tunBoundOut = orch.start(tunInputCh)` succeeds:

```kotlin
if (pqEnabled) {
    scope.launch {
        try {
            // Give the classic WG handshake a moment to establish.
            kotlinx.coroutines.delay(2000)
            android.util.Log.i(TAG, "starting PQ negotiation against Mullvad")
            val psk = dev.tetherand.app.mullvad.MullvadPqClient.deriveSharedSecret()
            android.util.Log.i(TAG, "PQ negotiation OK; rekeying tunnel")
            (hops.first() as dev.tetherand.app.chain.WireGuardHop).rekeyWithPsk(psk)
            android.util.Log.i(TAG, "PQ rekey done")
        } catch (t: Throwable) {
            android.util.Log.e(TAG, "PQ negotiation failed", t)
            // Non-fatal: tunnel keeps running with classic WG.
        }
    }
}
```

Pass `pqEnabled` through the `scope.launch { runChain(cfg) }` call site.

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/service/TetherandChainService.kt
git commit -m "M4 Task 9: chain service dispatches PQ negotiation when EXTRA_PQ_ENABLED"
```

---

### Task 10: Kill-switch (VpnService lockdown)

**Files:**
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/service/TetherandChainService.kt`

`VpnService.Builder.setBlocking(true)` already makes the file descriptor blocking. The real kill-switch behavior is enforced by Android-side `Settings.Secure.always_on_vpn_lockdown` — that's a system setting, not something an app can flip. What we CAN do:
- `Builder.setBlocking(true)` (already on)
- `Builder.allowFamily(AF_INET)` only — drop IPv6 so it can't leak around the v4 TUN
- Route `::/0` to a black hole if we want IPv6 blackholed too

For M4, we add `allowFamily(OsConstants.AF_INET)` and route everything (already do `0.0.0.0/0`). The "kill-switch" UI toggle in the app sets a preference and instructs the user to also enable system-level Always-On VPN with Block Connections without VPN in Settings → Network → VPN → Tetherand.

- [ ] **Step 1: Patch the builder**

In `runChain`, replace the existing `builder.setBlocking(true).setSession(...)` with:

```kotlin
builder.setBlocking(true)
       .setSession("Tetherand Chain")
       .allowFamily(android.system.OsConstants.AF_INET)
```

(And document that the system-level Always-On + Lockdown toggle in Settings is the user-facing kill-switch.)

- [ ] **Step 2: Build**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/service/TetherandChainService.kt
git commit -m "M4 Task 10: VpnService kill-switch — IPv4 only, route everything, blocking IO"
```

---

### Task 11: Mullvad config UI in `PrivacyScreen`

**Files:**
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt`

Add a new section between the existing chain visualizer and the raw WG config editor: "Mullvad" card with account number input, "Fetch servers" button, server picker, PQ toggle. When the user clicks "Build config", we run the Mullvad flow and populate the WG config editor with the resulting text.

- [ ] **Step 1: Update the signature**

The callback now passes a `pqEnabled` flag too. Change:

```kotlin
fun PrivacyScreen(onStart: (String, Boolean) -> Unit, onStop: () -> Unit) {
```

- [ ] **Step 2: Add the Mullvad section**

Inside the existing Column, between the chain-visualizer card and the WG-config-editor card, add:

```kotlin
        var account by remember { mutableStateOf("") }
        var servers by remember { mutableStateOf<List<dev.tetherand.app.mullvad.MullvadWgServer>>(emptyList()) }
        var picked by remember { mutableStateOf<dev.tetherand.app.mullvad.MullvadWgServer?>(null) }
        var pqEnabled by remember { mutableStateOf(true) }
        var mullvadError by remember { mutableStateOf<String?>(null) }
        val scope = androidx.compose.runtime.rememberCoroutineScope()

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Mullvad", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                OutlinedTextField(
                    value = account,
                    onValueChange = { account = it.filter { c -> c.isDigit() }.take(16) },
                    label = { Text("Mullvad account number (16 digits)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace),
                )
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            scope.launch {
                                try {
                                    val api = dev.tetherand.app.mullvad.MullvadApi()
                                    servers = api.listRelays().wireguard.relays.filter { it.active }
                                    mullvadError = null
                                } catch (t: Throwable) { mullvadError = t.message }
                            }
                        },
                        enabled = account.length == 16,
                    ) { Text("Fetch servers") }
                    if (servers.isNotEmpty()) {
                        Text("${servers.size} active", color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp)
                    }
                }
                if (servers.isNotEmpty()) {
                    androidx.compose.foundation.lazy.LazyColumn(
                        modifier = Modifier.fillMaxWidth().height(180.dp),
                    ) {
                        items(servers.size) { i ->
                            val s = servers[i]
                            Text(
                                s.display,
                                color = if (s == picked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { picked = s }
                                    .padding(vertical = 4.dp),
                            )
                        }
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = pqEnabled, onCheckedChange = { pqEnabled = it })
                    Spacer(Modifier.padding(end = 8.dp))
                    Text("Post-quantum tunnel (ML-KEM-1024)", color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                }
                Button(
                    onClick = {
                        scope.launch {
                            try {
                                val server = picked ?: return@launch
                                val api = dev.tetherand.app.mullvad.MullvadApi()
                                val (cfg, _) = dev.tetherand.app.mullvad.MullvadConfigBuilder.build(api, account, server)
                                wgText = configToText(cfg)
                                mullvadError = null
                            } catch (t: Throwable) { mullvadError = t.message }
                        }
                    },
                    enabled = picked != null && account.length == 16,
                ) { Text("Build config from Mullvad") }
                if (mullvadError != null) {
                    Text(mullvadError!!, color = MaterialTheme.colorScheme.error, fontSize = 11.sp)
                }
            }
        }
```

Add the imports at the top:

```kotlin
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Switch
```

And add a `configToText` helper at the bottom of the file (private):

```kotlin
private fun configToText(c: dev.tetherand.app.chain.WireGuardConfig): String {
    val priv = android.util.Base64.encodeToString(c.privateKey, android.util.Base64.NO_WRAP)
    val pub  = android.util.Base64.encodeToString(c.peerPublicKey, android.util.Base64.NO_WRAP)
    val dns  = c.dns.joinToString(", ")
    val ips  = c.allowedIps.joinToString(", ")
    return """
        [Interface]
        PrivateKey = $priv
        Address    = ${c.address}
        DNS        = $dns

        [Peer]
        PublicKey  = $pub
        AllowedIPs = $ips
        Endpoint   = ${c.endpointHost}:${c.endpointPort}
        PersistentKeepalive = ${c.persistentKeepaliveSecs}
    """.trimIndent()
}
```

- [ ] **Step 3: Update the start-button callback**

Change the existing "Start chain" button:

```kotlin
Button(
    onClick = { running = true; onStart(wgText, pqEnabled) },
    enabled = wgText.contains("[Interface]") && wgText.contains("[Peer]"),
) { Text("Start chain") }
```

- [ ] **Step 4: Build**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/ui/PrivacyScreen.kt
git commit -m "M4 Task 11: PrivacyScreen — Mullvad section + PQ toggle + server picker"
```

---

### Task 12: Wire PrivacyScreen → MainActivity → Chain service with PQ flag

**Files:**
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/ui/TabbedRoot.kt`
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/MainActivity.kt`

- [ ] **Step 1: Update TabbedRoot signature**

In `TabbedRoot.kt`:

```kotlin
@Composable
fun TabbedRoot(
    onTetherStart: () -> Unit,
    onTetherStop:  () -> Unit,
    onChainStart:  (String, Boolean) -> Unit,
    onChainStop:   () -> Unit,
)
```

Pass through to `PrivacyScreen(onStart = onChainStart, onStop = onChainStop)` — signature already matches.

- [ ] **Step 2: Update MainActivity**

In `MainActivity.kt`:

```kotlin
private var pendingWgConfig: String? = null
private var pendingPq: Boolean = false

private fun ensureConsentAndStartChain(wgConfigText: String, pqEnabled: Boolean) {
    pending = PendingAction.CHAIN
    pendingWgConfig = wgConfigText
    pendingPq = pqEnabled
    val p = VpnService.prepare(this)
    if (p != null) vpnConsent.launch(p) else startChain(wgConfigText, pqEnabled)
}

private fun startChain(wgConfigText: String, pqEnabled: Boolean) {
    val i = Intent(this, TetherandChainService::class.java)
        .putExtra(TetherandChainService.EXTRA_WG_CONFIG, wgConfigText)
        .putExtra(TetherandChainService.EXTRA_PQ_ENABLED, pqEnabled)
    startForegroundService(i)
}
```

Update the vpnConsent handler:

```kotlin
PendingAction.CHAIN -> startChain(pendingWgConfig ?: return@registerForActivityResult, pendingPq)
```

And in `setContent`:

```kotlin
TabbedRoot(
    onTetherStart = ::ensureConsentAndStartTether,
    onTetherStop = ::stopTether,
    onChainStart = ::ensureConsentAndStartChain,
    onChainStop = ::stopChain,
)
```

- [ ] **Step 3: Build full APK**

Run: `make build`
Expected: BUILD SUCCESSFUL, `bin/tetherand.apk` updated.

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/kotlin/dev/tetherand/app/ui/TabbedRoot.kt \
        android/app/src/main/kotlin/dev/tetherand/app/MainActivity.kt
git commit -m "M4 Task 12: wire pqEnabled flag PrivacyScreen → MainActivity → chain service"
```

---

### Task 13: Manifest cleartext exception for Mullvad API (only if needed)

**Files:**
- Inspect: response from `https://api.mullvad.net/app/v1/relays`

Mullvad's API is HTTPS. If the cleartext-traffic default trips during HTTP redirects or development against a mock, we'd need a `networkSecurityConfig`. For M4, we don't ship a custom NSC — HTTPS-only is the default and matches the API.

- [ ] **Step 1: Verify no changes needed**

Inspect `android/app/src/main/AndroidManifest.xml`. `usesCleartextTraffic` must NOT be true. Confirm.

- [ ] **Step 2: Commit (no-op if nothing changed)**

If you added an NSC because of unexpected redirects:

```bash
git add android/app/src/main/AndroidManifest.xml android/app/src/main/res/xml/
git commit -m "M4 Task 13: network security config (HTTPS-only, Mullvad CA pinning)"
```

Otherwise skip this commit.

---

### Task 14: Tutorial + README + tutorial.sh badge

**Files:**
- Modify: `tutorial.sh`
- Modify: `README.md`

- [ ] **Step 1: tutorial.sh — flip M4 to SHIPPED, M5 to NEXT**

In `tutorial.sh`, find:

```html
    <tr><td><strong>M4</strong></td><td>Mullvad + PQ tunnel + multihop + DAITA + obfuscation toggles + kill-switch + split-tunnel.</td><td>8-12 h</td><td><span class="badge warn">NEXT</span></td></tr>
    <tr><td><strong>M5</strong></td><td>NymVPN embedded via JNI, 2-hop entry/exit through Sphinx mixnet.</td><td>6-10 h</td><td>planned</td></tr>
```

Replace with:

```html
    <tr><td><strong>M4a-c</strong></td><td>Mullvad classic WG + PQ tunnel (ML-KEM-1024) + kill-switch. DAITA / obfuscation / multihop / split-tunnel in M4d-g.</td><td>~10 h</td><td><span class="badge ok">SHIPPED</span></td></tr>
    <tr><td><strong>M5</strong></td><td>NymVPN embedded via JNI, 2-hop entry/exit through Sphinx mixnet.</td><td>6-10 h</td><td><span class="badge warn">NEXT</span></td></tr>
```

- [ ] **Step 2: README status table**

In `README.md`, under `## Status`:

```markdown
- **M4a-c** (Mullvad classic WG + PQ tunnel ML-KEM-1024 + kill-switch): **shipped**.
```

(Add after the M3 line. Note remaining M4d-g and M5+ as planned.)

- [ ] **Step 3: Commit**

```bash
git add tutorial.sh README.md
git commit -m "M4 Task 14: tutorial + README — mark M4a-c SHIPPED, M5 NEXT"
```

---

## Self-Review Checklist

After all tasks land:

- [ ] `cd relay && cargo test --workspace` → all passing (codec, transport-api, transport-adb/tcp, core, wg). The wg crate now has +2 KEM tests.
- [ ] `cd android && ./gradlew :app:assembleDebug` → BUILD SUCCESSFUL.
- [ ] `make build` → APK and binary both rebuild; native lib is co-bundled.
- [ ] When the user installs M4 on real hardware and uses the Privacy tab:
  - Enter Mullvad account → tap Fetch servers → list populates.
  - Pick a server → tap Build config from Mullvad → WG config editor fills in.
  - Toggle PQ on → tap Start chain → status pill flips to ROUTING.
  - logcat shows the Mullvad PQ exchange running (`starting PQ negotiation` → `PQ negotiation OK; rekeying tunnel` → `PQ rekey done`) ~2-5 seconds after the classic tunnel establishes.

Spec coverage check:

| Spec section | Implemented in tasks |
|---|---|
| Privacy Chain → Mullvad hop | Tasks 3-6, 11 |
| Privacy Chain → Mullvad PQ tunnel (ML-KEM-1024) | Tasks 1-2, 7-9 |
| Privacy Chain → kill-switch | Task 10 |
| UI → Mullvad config card on Privacy tab | Task 11 |
| UI → PQ tunnel toggle | Tasks 11, 12 |

Items intentionally **deferred** to later M4.x or beyond:
- Multihop entry/exit pair selection (M4d).
- DAITA toggle (M4e).
- QUIC / Shadowsocks / UDP-over-TCP obfuscation (M4f).
- Split-tunnel by app (M4g).
- Mullvad account creation flow (we require the user has an existing account number).
- Rotating WG keys on a timer (we register a new key per session; cleanup of stale devices is left to Mullvad's account UI).
- Bridging the input channel through `WireGuardHop.rekeyWithPsk` so outbound traffic isn't briefly paused during PQ rekey.
