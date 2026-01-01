package dev.tetherand.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import android.util.Log
import dev.tetherand.app.crypto.BootIntegrity
import dev.tetherand.app.crypto.SeekerRng
import dev.tetherand.app.service.TetherandChainService
import dev.tetherand.app.ui.TabbedRoot
import dev.tetherand.app.ui.TetherandTheme

class MainActivity : ComponentActivity() {
    enum class PendingAction { TETHER, CHAIN }
    private var pending: PendingAction = PendingAction.TETHER
    private var pendingWgConfig: String? = null
    private var pendingPq: Boolean = false

    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) when (pending) {
            PendingAction.TETHER -> startTether()
            PendingAction.CHAIN -> startChain(pendingWgConfig ?: return@registerForActivityResult, pendingPq)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Install the SHAKE-256 entropy mixer as the JVM-default
        // SecureRandom for the process BEFORE any code that touches
        // crypto (BouncyCastle init, key generation, JCA Signature
        // instantiation, OkHttp TLS handshake nonces, etc.). This
        // call is idempotent and survives configuration changes.
        SeekerRng.installAsDefault(this)
        // Boot-integrity / AVB check. We accept stock OEM-signed
        // (vbs=green) AND GrapheneOS-style user-rooted (vbs=yellow)
        // — both are bootloader-locked. The verdict is surfaced as
        // a Critical alert on the Threat tab if it indicates a
        // tampered or unlocked device. We log the verdict at startup
        // for support; the explanation field is one line and
        // contains no PII.
        try {
            val r = BootIntegrity.check(this)
            Log.i("BootIntegrity", "verdict=${r.verdict} (${r.explanation})")
        } catch (t: Throwable) {
            // Never let a failed boot-integrity check crash startup;
            // the threat-tab surface remains visible to the user.
            Log.w("BootIntegrity", "check failed: ${t.javaClass.simpleName}")
        }
        enableEdgeToEdge()
        // M7a: kick the threat-detection foreground service. Idempotent —
        // Android handles "already running" by routing to onStartCommand
        // with a fresh START intent. The service decides whether to no-op.
        try {
            startForegroundService(
                Intent(this, dev.tetherand.app.threat.service.ThreatDetectionService::class.java)
            )
        } catch (_: Throwable) {
            // Foreground service may be rejected if the user hasn't granted
            // POST_NOTIFICATIONS on first launch. The Threat tab still works
            // (Room flow), just without live collection until permission lands.
        }
        setContent {
            TetherandTheme {
                TabbedRoot(
                    onTetherStart = ::ensureConsentAndStartTether,
                    onTetherStop = ::stopTether,
                    onChainStart = ::ensureConsentAndStartChain,
                    onChainStop = ::stopChain,
                )
            }
        }
    }

    private fun ensureConsentAndStartTether() {
        pending = PendingAction.TETHER
        val p = VpnService.prepare(this)
        if (p != null) vpnConsent.launch(p) else startTether()
    }

    private fun ensureConsentAndStartChain(wgConfigText: String, pqEnabled: Boolean) {
        pending = PendingAction.CHAIN
        pendingWgConfig = wgConfigText
        pendingPq = pqEnabled
        val p = VpnService.prepare(this)
        if (p != null) vpnConsent.launch(p) else startChain(wgConfigText, pqEnabled)
    }

    private fun startTether() {
        TetherandService.start(this, VpnConfiguration())
    }
    private fun stopTether() {
        TetherandService.stop(this)
    }
    private fun startChain(wgConfigText: String, pqEnabled: Boolean) {
        val i = Intent(this, TetherandChainService::class.java)
            .putExtra(TetherandChainService.EXTRA_WG_CONFIG, wgConfigText)
            .putExtra(TetherandChainService.EXTRA_PQ_ENABLED, pqEnabled)
        startForegroundService(i)
    }
    private fun stopChain() {
        val i = Intent(this, TetherandChainService::class.java)
            .setAction(TetherandChainService.ACTION_STOP)
        startService(i)
    }
}
