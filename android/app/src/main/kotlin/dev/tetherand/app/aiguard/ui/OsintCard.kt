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
    // The password lives only on the UI thread, in a TextField that
    // requires a `String` for IME interop. We treat the String as a
    // transient credential: best-effort wiped via reflection as soon
    // as the check completes, AND the form is cleared.
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
                visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                label = { Text("password to check (not transmitted)", fontSize = 10.sp) },
            )
            Button(modifier = Modifier.fillMaxWidth(), enabled = !running, onClick = {
                running = true
                scope.launch {
                    val captured = password
                    // Drop the Compose-state copy immediately so the
                    // form clears even if the network call hangs.
                    password = ""
                    val r = try {
                        withContext(Dispatchers.IO) { OsintExposureProbe.isPasswordPwned(captured) }
                    } finally {
                        // Wipe the captured-String value field via
                        // reflection. Best-effort: the String may
                        // have been interned, and recomposition may
                        // hold another copy. Both narrow but do not
                        // close the heap-residency window.
                        dev.tetherand.app.crypto.SecureBytes.bestEffortWipeString(captured)
                    }
                    status = if (r.pwned) "PWNED — seen in ${r.occurrences} breaches. Rotate now."
                             else "Not seen in HIBP."
                    running = false
                }
            }) { Text(if (running) "Checking…" else "Check", fontSize = 12.sp, fontFamily = FontFamily.Monospace) }
            if (status != null) {
                Text(status!!, fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                     color = MaterialTheme.colorScheme.primary)
            }
        }
    }
}
