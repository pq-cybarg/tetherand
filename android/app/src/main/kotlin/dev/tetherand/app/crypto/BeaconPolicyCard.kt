package dev.tetherand.app.crypto

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

/**
 * Card on the AI tab letting the user opt-in to clear-net fallback
 * for public-randomness beacon fetches (drand + NIST). Default is
 * **off** — beacons fetch only when a Tor circuit is up, otherwise
 * deferred.
 *
 * The trade-off is explicit: leaving the toggle OFF protects against
 * the IP-fingerprint leak that polling drand/NIST every minute would
 * cause; turning it ON ensures the mixer always has fresh beacon
 * bytes even when Tor is unavailable. Either choice is legitimate —
 * we just want the user to make it deliberately.
 *
 * Hardened Mode wipes this toggle back to default-off on entry so a
 * conference session always starts at strict posture.
 */
@Composable
fun BeaconPolicyCard() {
    val ctx = LocalContext.current
    val policy = remember { BeaconPolicy.get(ctx) }
    var clearnet by remember { mutableStateOf(policy.clearnetFallback) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Public-beacon egress",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            Text("SeekerRng absorbs drand + NIST randomness as two of its eight entropy sources. By default these fetches go through Tor only — if Tor isn't up, they wait. Toggle ON to allow a direct clear-net fetch when Tor is unavailable.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 11.sp)

            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = clearnet, onCheckedChange = {
                    clearnet = it
                    policy.clearnetFallback = it
                })
                Spacer(Modifier.padding(end = 8.dp))
                Column {
                    Text(
                        if (clearnet) "Clear-net fallback ALLOWED"
                        else "Tor-only (recommended)",
                        color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp,
                    )
                    Text(
                        if (clearnet)
                            "Drand + NIST will see this device's source IP when Tor is down. Tracking risk: an observer with netflow access can confirm Tetherand is installed."
                        else
                            "Beacon fetches deferred when no Tor circuit. SeekerRng still produces strong output from its other six local sources.",
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f), fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }
}
