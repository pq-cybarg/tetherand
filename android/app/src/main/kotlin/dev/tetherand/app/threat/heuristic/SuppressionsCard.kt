package dev.tetherand.app.threat.heuristic

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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * A small "I know what I'm doing" panel for security heuristics whose
 * default Critical/High firing conflicts with a known-acceptable
 * developer workflow on this specific device.
 *
 * Use sparingly. Each toggle is the user explicitly accepting a real
 * risk for a real reason (dev workflow, known-EoS hardware, etc).
 */
@Composable
fun SuppressionsCard() {
    val ctx = LocalContext.current
    val store = remember { ThreatSuppressions(ctx) }

    var adbdOff by remember { mutableStateOf(store.isSuppressed(ThreatSuppressions.KEY_ADBD_NETWORK)) }
    var patchOff by remember { mutableStateOf(store.isSuppressed(ThreatSuppressions.KEY_PATCH_STALE)) }

    val fmt = remember { SimpleDateFormat("yyyy-MM-dd", Locale.ROOT) }
    fun sinceLabel(key: String): String {
        val ts = store.suppressedSinceMs(key)
        return if (ts > 0) " (since ${fmt.format(Date(ts))})" else ""
    }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Heuristic suppressions",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            Text("Acknowledge a known-acceptable risk on this device. Each toggle ON stops one detector from firing. The underlying risk does not disappear — the device just stops nagging you.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 11.sp)

            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = adbdOff, onCheckedChange = {
                    adbdOff = it
                    if (it) store.suppress(ThreatSuppressions.KEY_ADBD_NETWORK)
                    else store.unsuppress(ThreatSuppressions.KEY_ADBD_NETWORK)
                })
                Spacer(Modifier.padding(end = 8.dp))
                Column {
                    Text("adb-over-Wi-Fi is my dev workflow${if (adbdOff) sinceLabel(ThreatSuppressions.KEY_ADBD_NETWORK) else ""}",
                         color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                    Text("Suppresses the CVE-2026-0073 detector. Re-enable before going to a hostile network.",
                         color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f), fontSize = 10.sp,
                         fontFamily = FontFamily.Monospace)
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = patchOff, onCheckedChange = {
                    patchOff = it
                    if (it) store.suppress(ThreatSuppressions.KEY_PATCH_STALE)
                    else store.unsuppress(ThreatSuppressions.KEY_PATCH_STALE)
                })
                Spacer(Modifier.padding(end = 8.dp))
                Column {
                    Text("I accept the patch-level on this device${if (patchOff) sinceLabel(ThreatSuppressions.KEY_PATCH_STALE) else ""}",
                         color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                    Text("Suppresses the patch-staleness detector. Sensible for known-EoS hardware (e.g. Galaxy A23 post-May-2026).",
                         color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f), fontSize = 10.sp,
                         fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}
