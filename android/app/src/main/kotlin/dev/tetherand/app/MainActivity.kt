package dev.tetherand.app

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Visible Compose entry point for Tetherand. The invisible
 * [TetherandActivity] handles CLI-driven START/STOP intents.
 */
class MainActivity : ComponentActivity() {
    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) startVpn()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()                       // opt into edge-to-edge (Android 15+ default)
        setContent {
            TetherandTheme {
                TetherScreen(
                    onStart = ::ensureConsentAndStart,
                    onStop = ::stopVpn,
                )
            }
        }
    }

    private fun ensureConsentAndStart() {
        val prep = VpnService.prepare(this)
        if (prep != null) vpnConsent.launch(prep) else startVpn()
    }

    /** Use the legacy Java helper so the EXTRA_VPN_CONFIGURATION parcel + correct
     *  startForegroundService dispatch land identically to the CLI path. */
    private fun startVpn() {
        TetherandService.start(this, VpnConfiguration())
    }

    private fun stopVpn() {
        TetherandService.stop(this)
    }
}

@Composable
private fun TetherandTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary       = Color(0xFF00D68F),
            onPrimary     = Color(0xFF001F11),
            secondary     = Color(0xFF5CDFFF),
            onSecondary   = Color(0xFF002B33),
            background    = Color(0xFF0A0E14),
            onBackground  = Color(0xFFC0C8D4),
            surface       = Color(0xFF11161D),
            onSurface     = Color(0xFFC0C8D4),
        ),
        content = content,
    )
}

@Composable
private fun TetherScreen(onStart: () -> Unit, onStop: () -> Unit) {
    var running by remember { mutableStateOf(false) }
    var selectedUsb by remember { mutableStateOf(true) }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "TETHERAND",
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 22.sp,
                    fontFamily = FontFamily.Monospace,
                )
                Spacer(Modifier.weight(1f))
                StatusPill(running)
            }
            Text(
                "Reverse-tether through your computer's network.",
                color = MaterialTheme.colorScheme.onBackground,
            )

            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Transport", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TransportChip("USB-ADB", selectedUsb) { selectedUsb = true }
                        TransportChip("Wi-Fi",  !selectedUsb) { selectedUsb = false }
                    }
                    Text(
                        if (selectedUsb) "Phone listens on abstract socket 'tetherand'; host runs `adb forward` and connects."
                        else             "Phone listens on TCP and advertises via mDNS as _tetherand._tcp.local.",
                        color = MaterialTheme.colorScheme.onSurface,
                        fontSize = 11.sp,
                    )
                }
            }

            if (!running) {
                Button(onClick = { running = true; onStart() }) {
                    Text("Start Tetherand")
                }
            } else {
                Button(onClick = { running = false; onStop() }) {
                    Text("Stop")
                }
            }

            Spacer(Modifier.weight(1f))
            Text(
                "M1 release · uses the forked Gnirehtet relay (Apache-2.0). " +
                "Privacy chains (Mullvad PQ + WireGuard + NymVPN + Tor) arrive in M3-M6. " +
                "Threat detection in M7. Hardened Mode in M9. Local-only AI defenses in M10.",
                color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.6f),
                fontSize = 10.sp,
            )
        }
    }
}

@Composable
private fun StatusPill(running: Boolean) {
    val color = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
    val label = if (running) "CONNECTED" else "IDLE"
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, color, RoundedCornerShape(50))
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Text(label, color = color, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun TransportChip(label: String, selected: Boolean, onClick: () -> Unit) {
    AssistChip(
        onClick = onClick,
        label = { Text(label) },
        modifier = if (selected) Modifier.border(2.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(8.dp))
                   else Modifier,
    )
}
