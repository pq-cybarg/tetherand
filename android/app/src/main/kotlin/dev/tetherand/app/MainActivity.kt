package dev.tetherand.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import dev.tetherand.app.service.TetherandChainService
import dev.tetherand.app.ui.TabbedRoot
import dev.tetherand.app.ui.TetherandTheme

class MainActivity : ComponentActivity() {
    enum class PendingAction { TETHER, CHAIN }
    private var pending: PendingAction = PendingAction.TETHER
    private var pendingWgConfig: String? = null

    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) when (pending) {
            PendingAction.TETHER -> startTether()
            PendingAction.CHAIN -> startChain(pendingWgConfig ?: return@registerForActivityResult)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
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

    private fun ensureConsentAndStartChain(wgConfigText: String) {
        pending = PendingAction.CHAIN
        pendingWgConfig = wgConfigText
        val p = VpnService.prepare(this)
        if (p != null) vpnConsent.launch(p) else startChain(wgConfigText)
    }

    private fun startTether() {
        TetherandService.start(this, VpnConfiguration())
    }
    private fun stopTether() {
        TetherandService.stop(this)
    }
    private fun startChain(wgConfigText: String) {
        val i = Intent(this, TetherandChainService::class.java)
            .putExtra(TetherandChainService.EXTRA_WG_CONFIG, wgConfigText)
        startForegroundService(i)
    }
    private fun stopChain() {
        val i = Intent(this, TetherandChainService::class.java)
            .setAction(TetherandChainService.ACTION_STOP)
        startService(i)
    }
}
