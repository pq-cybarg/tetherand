package dev.tetherand.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
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

@Composable
fun PrivacyScreen(onStart: (String) -> Unit, onStop: () -> Unit) {
    var running by remember { mutableStateOf(false) }
    var wgText by remember { mutableStateOf(SAMPLE_WG_CONFIG) }
    val scroll = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "PRIVACY CHAIN",
                color = MaterialTheme.colorScheme.secondary,
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp,
                fontFamily = FontFamily.Monospace,
            )
            Spacer(Modifier.weight(1f))
            ChainStatusPill(running)
        }
        Text(
            "Compose hops the phone's traffic flows through before reaching the internet.",
            color = MaterialTheme.colorScheme.onBackground,
        )

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Chain", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    HopCard("Apps")
                    Arrow()
                    HopCard("WireGuard", active = running, accent = MaterialTheme.colorScheme.primary)
                    Arrow()
                    HopCard("Internet")
                }
                Text(
                    "M3: single WireGuard hop. Mullvad PQ (M4), NymVPN (M5), and Tor (M6) join the picker as their hop types ship.",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("WireGuard config", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "Paste a standard [Interface]/[Peer] config. Mullvad classic-WG configs work out of the box.",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
                OutlinedTextField(
                    value = wgText,
                    onValueChange = { wgText = it },
                    modifier = Modifier.fillMaxWidth().height(260.dp),
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
                    label = { Text("conf") },
                )
            }
        }

        if (!running) {
            Button(
                onClick = { running = true; onStart(wgText) },
                enabled = wgText.contains("[Interface]") && wgText.contains("[Peer]"),
            ) { Text("Start chain") }
        } else {
            Button(onClick = { running = false; onStop() }) { Text("Stop chain") }
        }
    }
}

@Composable
private fun ChainStatusPill(active: Boolean) {
    val color = if (active) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.onSurface
    val label = if (active) "ROUTING" else "OFFLINE"
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
private fun HopCard(label: String, active: Boolean = false, accent: Color = MaterialTheme.colorScheme.onSurface) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.background)
            .border(1.dp, if (active) accent else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Text(label, color = if (active) accent else MaterialTheme.colorScheme.onSurface, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
}

@Composable
private fun Arrow() {
    Text("→", color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f), fontFamily = FontFamily.Monospace)
}

private val SAMPLE_WG_CONFIG = """
[Interface]
PrivateKey = <paste your WireGuard private key here, base64>
Address    = 10.66.0.2/32
DNS        = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey  = <paste the peer's public key here, base64>
AllowedIPs = 0.0.0.0/0
Endpoint   = your.wg.endpoint:51820
PersistentKeepalive = 25
""".trimIndent()
