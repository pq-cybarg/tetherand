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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.aiguard.osint.OsintExposureProbe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun OsintCard() {
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<String?>(null) }
    var running by remember { mutableStateOf(false) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("OSINT exposure (opt-in)",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            Text("HIBP k-anonymity password check (uses only the SHA-1 prefix; no full hash leaves the device). " +
                 "Recommended via your active Privacy Chain.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 10.sp)
            OutlinedTextField(
                value = password, onValueChange = { password = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("password to check (not transmitted)", fontSize = 10.sp) },
            )
            Button(modifier = Modifier.fillMaxWidth(), enabled = !running, onClick = {
                running = true
                scope.launch {
                    val r = withContext(Dispatchers.IO) { OsintExposureProbe.isPasswordPwned(password) }
                    status = if (r.pwned) "PWNED — seen in ${r.occurrences} breaches. Rotate now."
                             else "Not seen in HIBP."
                    running = false
                    password = ""
                }
            }) { Text(if (running) "Checking…" else "Check", fontSize = 12.sp, fontFamily = FontFamily.Monospace) }
            if (status != null) {
                Text(status!!, fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                     color = MaterialTheme.colorScheme.primary)
            }
        }
    }
}
