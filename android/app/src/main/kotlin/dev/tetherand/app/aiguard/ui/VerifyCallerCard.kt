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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.aiguard.voiceprint.VoiceprintVault

@Composable
fun VerifyCallerCard() {
    val ctx = LocalContext.current
    val vault = remember { VoiceprintVault(ctx) }
    var phone by remember { mutableStateOf("") }
    var safeword by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<String?>(null) }
    var trustedList by remember { mutableStateOf(vault.list()) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Verify-caller handshake",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            Text("Safe-word challenge per spec. Trust a number first, then verify on call.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 10.sp)
            OutlinedTextField(value = phone, onValueChange = { phone = it },
                              modifier = Modifier.fillMaxWidth(),
                              label = { Text("phone (E.164)", fontSize = 10.sp) })
            OutlinedTextField(value = safeword, onValueChange = { safeword = it },
                              modifier = Modifier.fillMaxWidth(),
                              label = { Text("safe-word (stored as SHA-256)", fontSize = 10.sp) })
            Button(modifier = Modifier.fillMaxWidth(), onClick = {
                val h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(safeword.trim().lowercase().toByteArray())
                    .joinToString("") { "%02x".format(it) }
                vault.trust(phone.trim())
                vault.storeVoiceprint(phone.trim(), h)
                trustedList = vault.list()
                status = "Trusted ${phone.trim()} with safe-word hash."
                safeword = ""
            }) { Text("Trust this caller", fontSize = 12.sp, fontFamily = FontFamily.Monospace) }

            if (trustedList.isNotEmpty()) {
                Text("Trusted contacts (${trustedList.size}):", fontSize = 11.sp,
                     color = MaterialTheme.colorScheme.onSurface)
                for (c in trustedList) {
                    Text("  ${c.phoneE164} — safeword:${c.voiceprintHash?.take(8) ?: "none"}",
                         fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                         color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
                }
            }
            if (status != null) {
                Text(status!!, fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                     color = MaterialTheme.colorScheme.primary)
            }
        }
    }
}
