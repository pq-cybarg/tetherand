package dev.tetherand.app.chain

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Hardened-Mode card surfacing the periodic Tor bridge rotation.
 *
 * Shows:
 *   * The bridge currently in use (redacted to a fingerprint prefix
 *     so screenshots of this card don't leak the full bridge line).
 *   * Time-since-last-rotation (the actual next-rotation eta isn't
 *     exposed by [BridgeRotation] today because intervals are
 *     jittered per-iteration — we show "rotates every 60-90 min,
 *     jittered" instead).
 *   * A Rotate Now button that calls [BridgeRotation.rotateNow]
 *     synchronously (uses a coroutine + the user-visible Material 3
 *     Button enabled state to prevent double-press).
 *
 * The card no-ops gracefully when [bridgeRotation] is null — typical
 * when the user hasn't started a Privacy Chain with a Tor hop yet.
 */
@Composable
fun BridgeRotationCard(bridgeRotation: BridgeRotation?) {
    if (bridgeRotation == null) return    // No Tor hop running — no card.

    val scope = rememberCoroutineScope()
    var rotatingNow by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("ready") }
    var lastRotatedAtMs by remember { mutableStateOf<Long?>(null) }
    var nowMs by remember { mutableStateOf(System.currentTimeMillis()) }

    // Tick once per minute so the "X min ago" label stays fresh.
    LaunchedEffect(Unit) {
        while (true) {
            nowMs = System.currentTimeMillis()
            delay(60_000)
        }
    }

    val ago = lastRotatedAtMs?.let { ((nowMs - it) / 60_000).coerceAtLeast(0L) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Tor bridge rotation",
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            Text("Rotates the active bridge every 60-90 min (jittered) to break QUIC connection-migration fingerprints. The auto-rotator runs in the background; this button forces an immediate rotation.",
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 11.sp)

            Text(
                if (ago != null) "Last rotation: ${ago} min ago"
                else "Last rotation: never (since this app start)",
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f),
                fontSize = 11.sp, fontFamily = FontFamily.Monospace,
            )

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !rotatingNow,
                    onClick = {
                        rotatingNow = true
                        status = "rotating…"
                        scope.launch {
                            try {
                                bridgeRotation.rotateNow()
                                lastRotatedAtMs = System.currentTimeMillis()
                                status = "rotated"
                            } catch (t: Throwable) {
                                status = "rotation failed: ${t.javaClass.simpleName}"
                            } finally {
                                rotatingNow = false
                            }
                        }
                    },
                ) {
                    Text(if (rotatingNow) "Rotating…" else "Rotate now",
                        fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                }
            }

            Spacer(Modifier.padding(0.dp))
            Text("status: $status",
                color = MaterialTheme.colorScheme.primary, fontSize = 10.sp,
                fontFamily = FontFamily.Monospace)
        }
    }
}
