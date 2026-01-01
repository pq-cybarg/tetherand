package dev.tetherand.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.tetherand.app.chain.ChainOrchestrator
import dev.tetherand.app.chain.Hop
import dev.tetherand.app.chain.WireGuardConfig
import dev.tetherand.app.chain.WireGuardHop
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream

class TetherandChainService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pfd: ParcelFileDescriptor? = null
    private var orch: ChainOrchestrator? = null
    private var pumpJobs: List<Job> = emptyList()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP) {
            stopChain(); return START_NOT_STICKY
        }
        startForegroundNotif()

        val wgText = intent?.getStringExtra(EXTRA_WG_CONFIG)
            ?: return run { stopSelf(); START_NOT_STICKY }
        val cfg = try { WireGuardConfig.parse(wgText) }
                  catch (e: Exception) { Log.e(TAG, "bad WG config: $e"); stopSelf(); return START_NOT_STICKY }

        val pqEnabled = intent?.getBooleanExtra(EXTRA_PQ_ENABLED, false) ?: false
        scope.launch { runChain(cfg, pqEnabled) }
        return START_STICKY
    }

    private suspend fun runChain(cfg: WireGuardConfig, pqEnabled: Boolean) {
        try {
            // 1. Bring up the TUN with the WG-provided address + routes + DNS.
            val (addr, prefix) = cfg.address.split("/").let { it[0] to (it.getOrNull(1)?.toInt() ?: 32) }
            val builder = Builder()
                .setMtu(1280)
                .addAddress(addr, prefix)
            cfg.dns.forEach { builder.addDnsServer(it) }
            cfg.allowedIps.forEach {
                val parts = it.split("/")
                val net = parts[0]
                val p = parts.getOrNull(1)?.toInt() ?: 32
                builder.addRoute(net, p)
            }
            // Kill-switch: blocking I/O + IPv4-only family so traffic can't
            // sneak around the v4 TUN over v6. The user-facing "Always-on
            // VPN + Block connections without VPN" is set in Android
            // system Settings → Network → VPN → Tetherand (one-time).
            builder.setBlocking(true)
                .setSession("Tetherand Chain")
                .allowFamily(android.system.OsConstants.AF_INET)
            val pfd = builder.establish() ?: return run { Log.e(TAG, "establish() returned null"); stopSelf() }
            this.pfd = pfd

            val tunIn = FileInputStream(pfd.fileDescriptor)
            val tunOut = FileOutputStream(pfd.fileDescriptor)

            // 2. Single WG hop for M3.
            val hops: List<Hop> = listOf(
                WireGuardHop(id = "wg-1", displayName = "WireGuard", config = cfg, vpnService = this)
            )
            val orch = ChainOrchestrator(hops).also { this.orch = it }

            val tunInputCh = Channel<ByteArray>(capacity = 256)
            val tunBoundOut = orch.start(tunInputCh)

            // 3. Pump TUN → chain.
            val toChain = scope.launch {
                val buf = ByteArray(2048)
                while (isActive) {
                    val n = tunIn.read(buf)
                    if (n <= 0) break
                    tunInputCh.send(buf.copyOf(n))
                }
            }
            // 4. Pump chain → TUN.
            val fromChain = scope.launch {
                for (pkt in tunBoundOut) {
                    tunOut.write(pkt)
                }
            }
            pumpJobs = listOf(toChain, fromChain)

            // 5. PQ negotiation (optional, runs after classic WG handshake settles).
            if (pqEnabled) {
                scope.launch {
                    try {
                        kotlinx.coroutines.delay(2000)  // let classic handshake establish
                        Log.i(TAG, "starting PQ negotiation against Mullvad")
                        val psk = dev.tetherand.app.mullvad.MullvadPqClient.deriveSharedSecret()
                        Log.i(TAG, "PQ negotiation OK; rekeying tunnel")
                        (hops.first() as dev.tetherand.app.chain.WireGuardHop).rekeyWithPsk(psk)
                        Log.i(TAG, "PQ rekey done")
                    } catch (t: Throwable) {
                        Log.e(TAG, "PQ negotiation failed; tunnel keeps running with classic WG", t)
                    }
                }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "chain failed", t)
            stopChain()
        }
    }

    private fun stopChain() {
        scope.launch {
            pumpJobs.forEach { it.cancel() }
            pumpJobs = emptyList()
            orch?.stop(); orch = null
            try { pfd?.close() } catch (_: Throwable) {}
            pfd = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
        try { pfd?.close() } catch (_: Throwable) {}
    }

    private fun startForegroundNotif() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Tetherand Chain", NotificationManager.IMPORTANCE_LOW)
        )
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, Class.forName("dev.tetherand.app.MainActivity")),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(dev.tetherand.app.R.drawable.ic_usb_24dp)
            .setContentTitle("Tetherand Chain active")
            .setContentText("Routing through privacy chain")
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    companion object {
        private const val TAG = "TetherandChain"
        const val CHANNEL_ID = "tetherand-chain"
        const val NOTIF_ID = 0x7e7f
        const val EXTRA_WG_CONFIG = "dev.tetherand.app.extra.WG_CONFIG"
        const val EXTRA_PQ_ENABLED = "dev.tetherand.app.extra.PQ_ENABLED"
        const val ACTION_STOP = "dev.tetherand.app.action.CHAIN_STOP"
    }
}
