package dev.tetherand.app.aiguard.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.aiguard.egress.EgressLlmApiWatch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Paste DNS-log lines or hostnames; classify each against the watchlist. */
@Composable
fun EgressWatchCard() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var input by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<String?>(null) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Egress LLM-API scan",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            Text("Paste DNS query history or hostnames; we'll flag any hits.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 10.sp)
            OutlinedTextField(value = input, onValueChange = { input = it },
                              modifier = Modifier.fillMaxWidth(),
                              label = { Text("hostnames, one per line", fontSize = 10.sp) })
            Button(modifier = Modifier.fillMaxWidth(), onClick = {
                scope.launch {
                    val lines = input.split("\n", "\r").map { it.trim() }.filter { it.isNotEmpty() }
                    val hits = withContext(Dispatchers.IO) { EgressLlmApiWatch.scanAndAlert(ctx, lines) }
                    result = if (hits.isEmpty()) "No LLM-API SNI hits."
                             else "Hits:\n" + hits.joinToString("\n") { "  ${it.host}  (${it.matchedBy})" }
                }
            }) { Text("Scan", fontSize = 12.sp, fontFamily = FontFamily.Monospace) }
            if (result != null) {
                Text(result!!, fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                     color = MaterialTheme.colorScheme.primary)
            }
        }
    }
}
