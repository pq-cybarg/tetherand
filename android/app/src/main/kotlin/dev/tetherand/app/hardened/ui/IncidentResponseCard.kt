package dev.tetherand.app.hardened.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.hardened.ir.IncidentAction
import dev.tetherand.app.hardened.ir.IncidentResponse

/**
 * Incident-response runbook surfaced as a Compose Card on the Threat tab.
 * Four deterministic actions per spec: Acknowledge / Isolate / Evacuate /
 * Burn. The Burn button is two-tap (confirm-required) because the action
 * is irreversible — wipes Seed Vault + user data.
 *
 * Each action's executor lives in IncidentResponse so the UI is purely a
 * dispatch surface, not a logic surface.
 */
@Composable
fun IncidentResponseCard() {
    val ctx = LocalContext.current
    var lastResult by remember { mutableStateOf<String?>(null) }
    var burnConfirm by remember { mutableStateOf(false) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                "Incident response",
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                fontSize = 13.sp,
            )
            for (action in IncidentAction.values()) {
                Button(
                    onClick = {
                        // Burn requires a second tap to confirm — the first
                        // press latches burnConfirm and prints a warning;
                        // the second press within the same recomposition
                        // window actually fires the action.
                        if (action == IncidentAction.Burn && !burnConfirm) {
                            burnConfirm = true
                            lastResult = "Tap BURN again to confirm — this wipes the device."
                        } else {
                            lastResult = IncidentResponse.execute(ctx, action)
                            burnConfirm = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (action == IncidentAction.Burn) Color(0xFFFF5D62)
                                         else MaterialTheme.colorScheme.primary,
                    ),
                ) {
                    Text(action.displayName, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                }
                Text(
                    action.description,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                    fontSize = 10.sp,
                )
            }
            if (lastResult != null) {
                Text(
                    lastResult!!,
                    color = MaterialTheme.colorScheme.primary,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}
