package dev.tetherand.app.threat.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.threat.model.ThreatDb

@Composable
fun ThreatScreen() {
    val ctx = LocalContext.current
    val db = remember { ThreatDb.get(ctx) }
    val alerts by db.alerts().observeRecent(50).collectAsState(initial = emptyList())
    val risk = run {
        // Last-24h alert severity sum, capped at 100. Recomputed on every
        // alerts change because remember(alerts) {…} captures the list.
        val cutoff = System.currentTimeMillis() - 24L * 3600 * 1000
        alerts.filter { it.tsMs >= cutoff }.sumOf { it.severity.score }.coerceAtMost(100)
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "THREAT", color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.Bold, fontSize = 22.sp,
                fontFamily = FontFamily.Monospace,
            )
            Spacer(Modifier.weight(1f))
            Text(
                "risk $risk/100", fontFamily = FontFamily.Monospace, fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    "Detection mode", fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp,
                )
                Text(
                    "MediaTek Tier 0 — NetMonster reflection + AIMSICD / SnoopSnitch / CH heuristics",
                    color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }

        // M9 Hardened Mode — DEFCON profile + incident-response runbook.
        // Inserted between detection-mode and the panic-button so the
        // user-action checklist sits above the kill-switch.
        dev.tetherand.app.hardened.ui.HardenedSection()
        dev.tetherand.app.hardened.ui.IncidentResponseCard()

        PanicButton()

        Text(
            "Recent alerts", fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground, fontSize = 13.sp,
        )
        if (alerts.isEmpty()) {
            Text(
                "No alerts recorded yet.",
                color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.6f),
                fontSize = 11.sp,
            )
        } else {
            for (a in alerts) AlertRow(a)
        }
    }
}
