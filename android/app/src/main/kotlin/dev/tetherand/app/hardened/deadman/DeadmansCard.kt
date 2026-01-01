package dev.tetherand.app.hardened.deadman

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.hardened.HardenedModeManager

/**
 * Hardened-Mode card that exposes the dead-man's switch configuration
 * and surfaces the "still alive?" prompt when armed.
 *
 * The prompt's "I'm OK" button is the only thing standing between the
 * configured action (Alert / Isolate / Burn) and execution, so it
 * gets a prominent placement at the top of the card whenever the
 * switch is armed.
 */
@Composable
fun DeadmansCard() {
    val ctx = LocalContext.current
    val manager = remember { HardenedModeManager(ctx) }
    val deadman = manager.deadman
    val initial = remember { deadman.load() }

    var enabled by remember { mutableStateOf(initial.enabled) }
    var interval by remember { mutableStateOf(initial.intervalMinutes.toString()) }
    var grace by remember { mutableStateOf(initial.graceMinutes.toString()) }
    var action by remember { mutableStateOf(initial.action) }
    var status by remember { mutableStateOf<String?>(null) }

    val armedSince by deadman.armedSince.collectAsState()
    val lastFire by deadman.lastFire.collectAsState()

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Dead-man's switch",
                     fontWeight = FontWeight.SemiBold,
                     color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
                Spacer(Modifier.weight(1f))
                Switch(checked = enabled, onCheckedChange = {
                    enabled = it
                    deadman.save(deadman.load().copy(enabled = it))
                    if (it) deadman.start() else deadman.stop()
                })
            }
            Text("Every interval, a prompt fires. If you don't acknowledge within the grace window, the configured action runs. Always logs a Critical alert; destructive actions (Burn) still require system-Settings confirmation.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 11.sp)

            // The armed prompt — the whole reason this card exists.
            if (armedSince != null) {
                val ackColor = Color(0xFFFFC857)
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.background)) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("● STILL ALIVE?", color = ackColor,
                             fontFamily = FontFamily.Monospace,
                             fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Text("Tap within ${grace} minutes or ${action.name} fires.",
                             color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp)
                        Button(modifier = Modifier.fillMaxWidth(),
                               colors = ButtonDefaults.buttonColors(containerColor = ackColor),
                               onClick = { deadman.acknowledge() }) {
                            Text("I'm OK", fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }

            // Config inputs.
            OutlinedTextField(
                value = interval,
                onValueChange = { interval = it.filter { c -> c.isDigit() }.take(4) },
                label = { Text("Interval (minutes)", fontSize = 10.sp) },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = grace,
                onValueChange = { grace = it.filter { c -> c.isDigit() }.take(3) },
                label = { Text("Grace window (minutes)", fontSize = 10.sp) },
                modifier = Modifier.fillMaxWidth(),
            )
            Text("Action on timeout", fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                for (a in DeadmansSwitch.Action.values()) {
                    AssistChip(
                        onClick = { action = a },
                        label = { Text(a.name, fontSize = 10.sp) },
                    )
                }
            }
            Button(modifier = Modifier.fillMaxWidth(), onClick = {
                deadman.save(DeadmansSwitch.Config(
                    enabled = enabled,
                    intervalMinutes = interval.toIntOrNull()?.coerceAtLeast(1) ?: 30,
                    graceMinutes = grace.toIntOrNull()?.coerceAtLeast(1) ?: 5,
                    action = action,
                ))
                status = "Saved (${if (enabled) "armed" else "disabled"})."
            }) { Text("Save config", fontSize = 12.sp, fontFamily = FontFamily.Monospace) }
            if (lastFire != null) {
                Text("Last fire: ${lastFire}",
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                     fontSize = 10.sp, fontFamily = FontFamily.Monospace)
            }
            if (status != null) {
                Text(status!!, fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                     color = MaterialTheme.colorScheme.primary)
            }
        }
    }
}
