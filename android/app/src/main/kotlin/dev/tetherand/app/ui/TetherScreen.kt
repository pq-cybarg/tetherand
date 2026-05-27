package dev.tetherand.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun TetherScreen(onStart: () -> Unit, onStop: () -> Unit) {
    var running by remember { mutableStateOf(false) }
    var selectedUsb by remember { mutableStateOf(true) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
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
                    TransportChip("Wi-Fi", !selectedUsb) { selectedUsb = false }
                }
                Text(
                    if (selectedUsb) "Phone listens on abstract socket 'tetherand'; host runs `adb reverse` and connects."
                    else "Phone listens on TCP and advertises via mDNS as _tetherand._tcp.local.",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
            }
        }

        if (!running) {
            Button(onClick = { running = true; onStart() }) { Text("Start Tetherand") }
        } else {
            Button(onClick = { running = false; onStop() }) { Text("Stop") }
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
        modifier = if (selected) Modifier.border(2.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(8.dp)) else Modifier,
    )
}
