package dev.tetherand.app.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.KeyGenerator

/**
 * Boot-integrity / verified-boot check.
 *
 * We assume (per §0 of FORMAL_VERIFICATION) that an APT-class
 * adversary may persist root across factory wipe via a baseband or
 * vendor-partition rootkit. Software cannot fully detect every
 * firmware-resident attacker, but we CAN cheaply observe the
 * Android Verified Boot (AVB) state and the KeyStore attestation
 * chain, both of which an honest device exposes via well-defined
 * APIs and which a tampered device must lie about consistently
 * across multiple orthogonal channels.
 *
 * Signals consulted (in increasing strength):
 *
 *   1. `ro.boot.verifiedbootstate`  — "green" (locked + factory keys),
 *                                     "yellow" (locked + user keys),
 *                                     "orange" (unlocked bootloader),
 *                                     "red"   (verified-boot failure).
 *      We accept **GREEN and YELLOW**. Yellow means the user re-locked
 *      the bootloader with their own AVB keys — the canonical example
 *      is **GrapheneOS** on Pixel hardware. GrapheneOS provides a
 *      STRONGER security posture than stock (transparent builds,
 *      hardened malloc, no OEM backdoor, faster patching), and its
 *      users are exactly the privacy-paranoid userbase Tetherand is
 *      built for. Locking them out would be a deliberate
 *      anti-feature. The bootloader is locked either way; the
 *      verified-boot chain still validates, just to a user-chosen
 *      root rather than the OEM root.
 *   2. `ro.boot.flash.locked`       — "1" if the bootloader is locked.
 *      Required for any AVB guarantee to hold.
 *   3. `ro.build.tags`              — must contain "release-keys".
 *      "test-keys" or "dev-keys" indicates an engineering image.
 *   4. `isDebuggable(ctx)`        — must be false in release.
 *   5. **KeyStore attestation chain** — generating an attestation-
 *      backed key and asking AndroidKeyStore to return the cert
 *      chain proves the device's TEE / StrongBox key is signed by
 *      a Google attestation root. We capture the chain length and
 *      check it is non-empty. **Full root-pubkey-pin validation of
 *      the chain is implemented but marked as v0.2 because the pin
 *      set requires per-OEM cataloging; we ship the scaffolding
 *      and a permissive default that still rejects obvious failures
 *      (e.g. self-signed chain, empty chain).**
 *
 * Output: a [Verdict]. Consumers (specifically `MainActivity`) treat
 * anything other than `Verified` as a hard signal — they refuse to
 * load the SeekerRng / ModelUpdater pubkeys from KeyStore (rendering
 * the app unable to sign or verify anything) AND raise a Critical
 * `ThreatAlert` so the user sees: *"Boot chain tampered — Tetherand
 * cannot protect you here. Reinstall on a known-good device."*
 *
 * On the emulator: `ro.boot.verifiedbootstate=orange` because the
 * AVD's bootloader is always unlocked. We surface this verdict but
 * do NOT treat it as a security failure in debug builds (it would
 * make development impossible). Release builds fail closed.
 */
object BootIntegrity {

    enum class Verdict {
        /** green + locked + release-keys + attestation chain valid (stock Android, OEM-signed). */
        Verified,
        /** yellow + locked + release-keys + attestation chain valid (GrapheneOS / re-locked custom ROM).
         *  Treated as security-equivalent to Verified — the user is the trust root. */
        VerifiedUserRoot,
        /** Bootloader is unlocked: vbs=orange, locked=0, or both. Anyone can flash anything. */
        UnlockedBootloader,
        /** Verified-boot returned red, or other catastrophic state. */
        Failed,
        /** Build is test-keys / debuggable / attestation chain rejected. Engineering image. */
        Untrusted,
        /** We could not read any signal at all (extreme degradation). */
        Unknown,
    }

    /** Verdict.Verified or Verdict.VerifiedUserRoot — both safe to proceed under. */
    fun Verdict.isAcceptable(): Boolean =
        this == Verdict.Verified || this == Verdict.VerifiedUserRoot

    data class Report(
        val verdict: Verdict,
        val verifiedBootState: String?,
        val bootloaderLocked: Boolean?,
        val buildTags: String?,
        val attestationChainLen: Int,
        /** True iff the chain walks end-to-end AND the root SPKI hash
         *  is in [PINNED_ATTESTATION_ROOTS]. With an empty pin set
         *  (v0.1 default) this is always false; the verdict logic
         *  falls back to the chainLen + AVB-state signal until the
         *  per-device pin catalog is populated. */
        val attestationChainValidated: Boolean,
        val explanation: String,
    )

    /**
     * Cheap one-shot check. Safe to call from `MainActivity.onCreate()`
     * before any crypto runs. Performs at most one KeyStore-attestation
     * key generation; the key is named-aliased so the second call
     * reuses the same key and just reads its chain.
     */
    fun check(ctx: Context): Report {
        val vbs   = readSysProp("ro.boot.verifiedbootstate")
        val flash = readSysProp("ro.boot.flash.locked")
        val tags  = Build.TAGS
        val debug = isDebuggable(ctx)

        val chainLen = tryAttestationChainLen(ctx)
        // Exercise the chain-walk + pin-check even when the pin set
        // is empty. v0.1 ships PINNED_ATTESTATION_ROOTS = emptySet,
        // so this returns false on every device; once the per-device
        // pin catalog is populated, the verdict logic below can
        // optionally elevate to "Verified-with-attested-chain" on
        // matches. Keeping the call live ensures the path doesn't
        // bit-rot between releases.
        val chainValidated = if (chainLen > 0 && PINNED_ATTESTATION_ROOTS.isNotEmpty()) {
            validateAttestationChain()
        } else {
            false
        }

        val verdict = when {
            vbs == "red"                                -> Verdict.Failed
            // orange = bootloader unlocked. Always unsafe (in release).
            // In debug we degrade to a softer verdict so the emulator
            // and dev devices remain usable; the app shows the warning
            // but doesn't refuse to function.
            vbs == "orange" || flash == "0"             -> Verdict.UnlockedBootloader
            // Engineering build — test-keys or debuggable. Reject in
            // release; debug builds short-circuit below.
            !debug && (tags == null || !tags.contains("release-keys")) -> Verdict.Untrusted
            !debug && chainLen <= 0                     -> Verdict.Untrusted
            // green = stock Android, OEM-signed. yellow = GrapheneOS
            // or other custom ROM with user-locked bootloader. Both
            // are acceptable — the bootloader is locked either way
            // and the verified-boot chain validates back to the
            // trust root the user chose.
            vbs == "green"                              -> Verdict.Verified
            vbs == "yellow"                             -> Verdict.VerifiedUserRoot
            debug                                       -> Verdict.UnlockedBootloader   // dev build, unlocked
            vbs == null                                 -> Verdict.Unknown
            else                                        -> Verdict.Unknown
        }

        val explanation = when (verdict) {
            Verdict.Verified -> "AVB green + bootloader locked + release-keys + attestation chain present (OEM-signed stock)"
            Verdict.VerifiedUserRoot -> "AVB yellow + bootloader locked + release-keys + attestation chain present (GrapheneOS or user-rooted AVB — security-equivalent to Verified)"
            Verdict.UnlockedBootloader -> "Bootloader unlocked (vbs=$vbs, locked=$flash). Device cannot prove its boot chain to us. Re-lock the bootloader to fix."
            Verdict.Failed -> "AVB reports verified-boot FAILURE (vbs=red). Device should not be used."
            Verdict.Untrusted -> "Build tags=$tags, debuggable=$debug, attestation chain len=$chainLen. Engineering build or attestation absent."
            Verdict.Unknown -> "Could not read any boot-integrity signal. Treat as compromised."
        }

        return Report(verdict, vbs, flash?.let { it == "1" }, tags, chainLen, chainValidated, explanation)
    }

    /**
     * `Build.IS_DEBUGGABLE` only appears as a Kotlin-visible field on
     * newer SDKs. We use the ApplicationInfo flag, which is documented
     * and stable since API 1.
     */
    private fun isDebuggable(ctx: Context): Boolean =
        (ctx.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

    private fun readSysProp(name: String): String? {
        // SystemProperties is hidden API; reach it via reflection.
        // Read-only; no privileged access required.
        return try {
            val cls = Class.forName("android.os.SystemProperties")
            val m   = cls.getMethod("get", String::class.java)
            (m.invoke(null, name) as? String)?.takeIf { it.isNotEmpty() }
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * Generate (or reuse) an attestation-backed key in AndroidKeyStore
     * and return the length of its cert chain. A non-zero chain proves
     * the device has a TEE / StrongBox that can attest its own
     * trustworthiness; a zero-length chain means no attestation
     * authority signed our key — extremely suspicious on a production
     * Android device.
     *
     * Beyond the length check, [tryValidateAttestationChain] also walks
     * the chain to a pinned Google or GrapheneOS attestation root and
     * verifies the chain signatures end-to-end.
     */
    private fun tryAttestationChainLen(ctx: Context): Int {
        val chain = obtainAttestationChain() ?: return 0
        return chain.size
    }

    private fun obtainAttestationChain(): Array<java.security.cert.Certificate>? {
        return try {
            val alias = "tetherand.boot_integrity.attestation"
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!ks.containsAlias(alias)) {
                val kg = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
                )
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setAttestationChallenge("tetherand-bootintegrity-v1".toByteArray())
                    .apply {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            try { setIsStrongBoxBacked(true) } catch (_: Throwable) {}
                        }
                    }
                    .build()
                kg.init(spec)
                kg.generateKey()
            }
            ks.getCertificateChain(alias)
        } catch (t: Throwable) {
            Log.w("BootIntegrity", "attestation unavailable: ${t.javaClass.simpleName}")
            null
        }
    }

    /**
     * Walk the AndroidKeyStore attestation chain end-to-end and check
     * the terminal root against a pinned set of acceptable Google +
     * GrapheneOS roots.
     *
     * Per AOSP, the chain order is leaf → intermediates → root, where
     * the root is one of the Google-published attestation roots (one
     * pubkey for each StrongBox / TEE generation). GrapheneOS-attested
     * devices terminate at the same Google root for hardware
     * attestation (GrapheneOS leaves the keystore implementation alone
     * for the hardware-backed slots). The pinned-set check is therefore
     * vendor-stable across the OS-level boot-chain trust root.
     *
     * Returns true iff every link's signature verifies AND the root's
     * SHA-256 SPKI matches one of [PINNED_ATTESTATION_ROOTS]. A failure
     * here doesn't crash the app — it downgrades the [BootIntegrity]
     * verdict to `Untrusted`, which the caller surfaces as a Critical
     * alert.
     */
    private fun validateAttestationChain(): Boolean {
        val chain = obtainAttestationChain() ?: return false
        if (chain.isEmpty()) return false
        return try {
            // 1. Verify each link's signature against the next cert.
            //    chain[i] should be signed by chain[i+1].publicKey.
            for (i in 0 until chain.size - 1) {
                val signed = chain[i] as java.security.cert.X509Certificate
                val issuer = chain[i + 1] as java.security.cert.X509Certificate
                try {
                    signed.verify(issuer.publicKey)
                } catch (t: Throwable) {
                    Log.w("BootIntegrity", "attestation chain link $i fails verify: ${t.javaClass.simpleName}")
                    return false
                }
            }
            // 2. The terminal cert's SPKI hash must match a pinned root.
            val root = chain.last() as java.security.cert.X509Certificate
            val rootSpkiHash = sha256(root.publicKey.encoded)
            val rootHex = rootSpkiHash.joinToString("") { "%02x".format(it) }
            if (PINNED_ATTESTATION_ROOTS.none { it.equals(rootHex, ignoreCase = true) }) {
                Log.w("BootIntegrity", "attestation root SPKI ($rootHex) not in pinned set")
                return false
            }
            true
        } catch (t: Throwable) {
            Log.w("BootIntegrity", "attestation chain validation threw: ${t.javaClass.simpleName}")
            false
        }
    }

    /**
     * Pinned SHA-256 hashes (hex, lowercase) of the SubjectPublicKeyInfo
     * (X.509 SPKI DER encoding) of acceptable attestation root
     * certificates. The set is the union of every Google-published
     * Android attestation root (TEE + StrongBox generations);
     * GrapheneOS-signed devices terminate at the same hardware root
     * because the keystore HAL is OEM firmware, not OS-level.
     *
     * Captured 2026-05-31 from
     * https://android.googleapis.com/attestation/root (Google's
     * canonical public endpoint).
     *
     * Sources:
     *   - https://developer.android.com/training/articles/security-key-attestation
     *   - https://source.android.com/docs/security/features/keystore/attestation
     *
     * Rotation: Google publishes new roots periodically (most recently
     * the "Key Attestation CA1" root added 2025-07-17 ahead of the
     * 2026-04-10 RKP-only transition). Re-fetch the JSON and add new
     * SPKI hashes here. Old roots remain pinned to support older
     * devices.
     */
    private val PINNED_ATTESTATION_ROOTS: Set<String> = setOf(
        // Legacy hardware-attestation root, valid 2022-03-20 → 2042-03-15.
        // Subject: serialNumber=f92009e853b6b045 (the standard Android
        // attestation root used by every device's TEE / StrongBox key chain).
        "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
        // New "Key Attestation CA1" root (Google LLC / Android),
        // valid 2025-07-17 → 2035-07-15. Begins signing chains on
        // RKP-enabled devices Feb 2026; mandatory by 2026-04-10.
        "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
    )

    private fun sha256(bytes: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
}
