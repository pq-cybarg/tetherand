package dev.tetherand.app.hardened.selfie

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
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
 * Hardened-Mode card for the selfie-on-failed-unlock feature.
 *
 * Two pieces of state need to align before the feature actually fires:
 *   1. The in-app toggle (SelfieStore.enabled) is on.
 *   2. The app is enabled as a Device Admin in system Settings.
 *
 * The card surfaces both, with a one-tap shortcut to the Device-Admin
 * settings screen if it's not already enabled.
 */
@Composable
fun SelfieCard() {
    val ctx = LocalContext.current
    val store = remember { SelfieStore(ctx) }
    val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager

    var enabled by remember { mutableStateOf(store.enabled) }
    val isAdmin = dpm?.isAdminActive(SelfieAdminReceiver.component(ctx)) == true
    var galleryCount by remember { mutableStateOf(store.list().size) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Selfie on failed unlock",
                     fontWeight = FontWeight.SemiBold,
                     color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
                Spacer(Modifier.weight(1f))
                Switch(checked = enabled, onCheckedChange = {
                    enabled = it
                    store.enabled = it
                })
            }
            Text("When the keyguard reports a failed PIN/pattern/biometric, fire a single front-camera capture and save it to app-private storage. Captures persist across attempts and are cleared only by the Reset button below.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 11.sp)

            // Two-piece readiness state.
            Text(if (enabled && isAdmin) "● Ready — captures will fire on next failed unlock"
                 else if (enabled && !isAdmin) "▲ Toggle is on, but device-admin not granted yet"
                 else "○ Disabled",
                 color = MaterialTheme.colorScheme.onSurface,
                 fontFamily = FontFamily.Monospace, fontSize = 11.sp)

            if (!isAdmin) {
                Button(modifier = Modifier.fillMaxWidth(), onClick = {
                    val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                        putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN,
                                 SelfieAdminReceiver.component(ctx))
                        putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                                 "Tetherand uses watch-login only — to capture a front-camera image when someone enters the wrong unlock credential. We do not request force-lock, wipe, or any other elevated capability.")
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    try { ctx.startActivity(intent) } catch (_: Throwable) {}
                }) {
                    Text("Grant device-admin (watch-login only)",
                         fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                }
            }

            Text("Captures on disk: $galleryCount",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                 fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            if (galleryCount > 0) {
                Button(modifier = Modifier.fillMaxWidth(), onClick = {
                    store.clearAll()
                    galleryCount = 0
                }) {
                    Text("Reset (delete all captures + counter)",
                         fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}
