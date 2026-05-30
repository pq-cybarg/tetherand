package dev.tetherand.app.aiguard.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.aiguard.runtime.ModelUpdater
import kotlinx.coroutines.launch

/**
 * AI-tab card that drives [ModelUpdater].
 *
 * The actual fetch goes through whatever HTTP path the system has
 * active, which means whatever VpnService the user has up — so the
 * model download travels the privacy chain by default and never the
 * bare cellular / Wi-Fi link.
 */
@Composable
fun ModelUpdaterCard() {
    val ctx = LocalContext.current
    val updater = remember { ModelUpdater(ctx) }
    val scope = rememberCoroutineScope()
    val state by updater.state.collectAsState()

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Model bundle updates",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            Text("Fetches the latest 4-model bundle through the active privacy chain. Manifest is ECDSA-P256 signed; each model is SHA-256 verified before it lands. Until a real release-time signing key is pinned, this checks compile-time placeholder state and aborts safely.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 11.sp)

            if (state.running) {
                Text("● ${state.progress}", color = MaterialTheme.colorScheme.primary,
                     fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            }
            if (state.lastResult != null) {
                Text("Last run: ${state.lastResult}",
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                     fontFamily = FontFamily.Monospace, fontSize = 10.sp)
            }

            Button(
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.running,
                onClick = { scope.launch { updater.checkAndUpdate() } },
            ) {
                Text(if (state.running) "Checking…" else "Check for updates",
                     fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            }
            Button(
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.running,
                onClick = { updater.clear() },
            ) {
                Text("Clear downloaded models",
                     fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            }
        }
    }
}
