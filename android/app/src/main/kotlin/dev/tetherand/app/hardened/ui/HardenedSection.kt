package dev.tetherand.app.hardened.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
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
import dev.tetherand.app.hardened.HardenedDefense
import dev.tetherand.app.hardened.HardenedModeManager

/**
 * Hardened Mode section on the Threat tab. Renders:
 *   - The DEFCON / off banner + master Switch (delegates to HardenedModeManager).
 *   - The full defenses manifest with green ● (active), amber ▲ (needs user
 *     action), grey ✕ (unavailable) markers per spec. User-action items
 *     prompt the user out-of-band (system Settings) because they can't be
 *     driven without DEVICE_OWNER / root.
 *   - Post-snapshot diff (rendered monospace) once the user toggles back
 *     off — that's the post-conference attestation comparison the spec
 *     describes for spotting tampering after DEFCON.
 */
@Composable
fun HardenedSection() {
    val ctx = LocalContext.current
    val manager = remember { HardenedModeManager(ctx) }
    val active by manager.active.collectAsState()
    // defenses is reactive on toggle: recomputed when the user flips the
    // switch so the markers update (honeypot/tamper flip from amber to
    // green on enter, and back to amber on exit).
    var defenses by remember { mutableStateOf(manager.defenses()) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (active) "DEFCON MODE — ACTIVE" else "Hardened Mode",
                    fontWeight = FontWeight.Bold,
                    color = if (active) Color(0xFF00D68F) else MaterialTheme.colorScheme.onSurface,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                )
                Spacer(Modifier.weight(1f))
                Switch(checked = active, onCheckedChange = {
                    if (it) manager.enter() else manager.exit()
                    defenses = manager.defenses()
                })
            }
            Text(
                if (active)
                    "Honeypot + tamper watcher armed. Pre-conference snapshot captured. Follow the user-action items below."
                else
                    "Activate to lock down the device for DEFCON: capture an attestation snapshot, start the honeypot, arm the tamper watcher, and surface the user-action checklist.",
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f),
                fontSize = 11.sp,
            )
            for (d in defenses) {
                DefenseRow(d)
            }
            // Post-snapshot diff only renders after the user has toggled
            // off (postDiff returns null until both pre and post exist).
            // remember(active) re-keys the diff on every toggle so it
            // updates without recomposition jank.
            val diff = remember(active) { manager.postDiff() }
            if (diff != null) {
                Text(
                    "Post-snapshot diff vs. pre:",
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
                Text(
                    diff,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}

@Composable
private fun DefenseRow(d: HardenedDefense) {
    val color = when (d.state) {
        HardenedDefense.State.Active           -> Color(0xFF00D68F)
        HardenedDefense.State.NeedsUserAction  -> Color(0xFFFFC857)
        HardenedDefense.State.Unavailable      -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f)
    }
    val marker = when (d.state) {
        HardenedDefense.State.Active           -> "●"
        HardenedDefense.State.NeedsUserAction  -> "▲"
        HardenedDefense.State.Unavailable      -> "✕"
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(marker, color = color, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        Spacer(Modifier.padding(end = 6.dp))
        Text(d.displayName, color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp)
    }
}
