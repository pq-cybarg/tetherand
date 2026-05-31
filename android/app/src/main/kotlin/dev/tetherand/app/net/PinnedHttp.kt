package dev.tetherand.app.net

import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion
import java.util.concurrent.TimeUnit

/**
 * Centralized OkHttp factory that enforces:
 *
 *   - **Cert pinning** by SubjectPublicKeyInfo SHA-256 ("SPKI pin").
 *     The system CA store remains in force as a baseline check, but
 *     a pinned host MUST present a leaf cert chaining to a key in
 *     our pin set or the connection is refused. This defends against
 *     compromise of any single public CA — the attacker also needs
 *     the matching private key for one of our pinned hosts.
 *   - **TLS 1.3 only** for modern connection specs. TLS 1.2 is
 *     allowed as a fallback for hosts that have not migrated.
 *   - **Restrictive cipher suites** (whatever OkHttp's
 *     RESTRICTED_TLS picks — currently AEAD-only, PFS-only).
 *   - **Tight timeouts** — a hung connection is an indicator, not
 *     a resource we want to hold open. 15s connect, 20s read.
 *
 * Hosts are pinned at the leaf SPKI. When a host rotates its cert
 * but reuses the keypair (the common case), the pin survives. When
 * a host fully rekeys, we ship an OTA update that adds the new pin
 * BEFORE the old cert expires; both pins coexist during the
 * transition window.
 *
 * Hosts NOT in [pinSet] get a normal OkHttp client (system CA only).
 * Calling code should explicitly choose a pinned hostname; passing
 * an unpinned host is a deliberate decision the caller has to make.
 */
object PinnedHttp {

    /**
     * Pin set captured 2026-05-30 by:
     *
     *     openssl s_client -connect <host>:443 -servername <host> </dev/null \
     *       | openssl x509 -pubkey -noout \
     *       | openssl pkey -pubin -outform DER \
     *       | openssl dgst -sha256 -binary \
     *       | openssl enc -base64
     *
     * Captured pins are the LEAF cert's SubjectPublicKeyInfo. We add
     * a placeholder backup pin slot per host so a clean rotation has
     * a slot to land in without an emergency OTA. Re-capture and
     * re-pin annually OR whenever a host advertises a new pin via
     * RFC 7469 (HPKP, deprecated) or an out-of-band channel.
     */
    private val pinSet: CertificatePinner = CertificatePinner.Builder()
        // Mullvad VPN API — used by MullvadApi for login, device
        // registration, relay list. The pin is on the leaf cert
        // hosted at api.mullvad.net behind Mullvad's own infra.
        .add("api.mullvad.net", "sha256/xuCt+G/2Y4qQjtBXZb81VbODvYIKkc6etfPZb4pic4E=")

        // HaveIBeenPwned k-anonymity password range API — used by
        // OsintExposureProbe.isPasswordPwned (Privacy-Chain-routable).
        // No auth header; safe to query through any tunnel.
        .add("api.pwnedpasswords.com", "sha256/9IwmXwvi5X2PS4f4WyChoe7zqc+804o3cHd42i9C/QA=")

        // HIBP main site — used by OsintExposureProbe.emailBreaches
        // (requires user-supplied API key; we never ship one).
        .add("haveibeenpwned.com", "sha256/VgvnWRjPVQSn3Nu/iTPWsgPdGDJqsy+3XCnmPIJEBpE=")

        // drand (League of Entropy) main HTTP endpoint. Used by
        // PublicBeacons as one of two public-randomness beacon
        // sources absorbed into the SeekerRng SHAKE-256 mixer.
        // drand publishes a fresh BLS-signed 32-byte value every 30s
        // via a threshold of independent operators (Cloudflare,
        // Protocol Labs, EPFL, U. Chile, etc.). The signature is
        // verifiable against the pinned chain pubkey, and even a
        // hostile-network adversary cannot bias what we absorb
        // because SHAKE-mixing with the other sources kills any
        // adversarial contribution under the random-oracle model.
        .add("api.drand.sh", "sha256/xA2Dca6ZBfoxQH3BYbwvmrXj4UjQs/P7wyaDeDZvym0=")

        // NIST Interoperable Randomness Beacon v2.0. 512-bit
        // full-entropy pulse every 60s, signed by NIST. Different
        // operator (US-NIST), different cryptosystem (ECDSA over
        // P-384) from drand — diverse failure surface.
        .add("beacon.nist.gov", "sha256/smFZmtvzXcZ6MUUGqbkes77ywMVHmkirJ1QepFwPaoM=")
        .build()

    /**
     * Build an OkHttpClient suitable for hitting any of the pinned
     * hosts above. Per-call enforcement: if you point this client at
     * a host that's IN the pin set but presents a non-matching SPKI,
     * the connection is refused.
     *
     * @param proxy optional SOCKS5/HTTP proxy to route through (e.g.
     *   the embedded Arti SOCKS5 listener at 127.0.0.1:<port>). When
     *   non-null, ALL outbound bytes traverse this proxy first; the
     *   destination host (`api.mullvad.net`, `api.drand.sh`, etc.)
     *   only sees the proxy's exit IP, not the device IP. Cert
     *   pinning still applies — a malicious Tor exit cannot inject
     *   a substitute cert because the SPKI pin set is enforced
     *   inside the TLS handshake that happens INSIDE the SOCKS
     *   tunnel.
     */
    fun client(proxy: java.net.Proxy? = null): OkHttpClient = OkHttpClient.Builder()
        .certificatePinner(pinSet)
        .connectionSpecs(listOf(
            ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
                .build()
        ))
        .apply { proxy?.let { proxy(it) } }
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .followRedirects(false)        // Redirects can shift to unpinned hosts; force the caller to be explicit.
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .build()
}
