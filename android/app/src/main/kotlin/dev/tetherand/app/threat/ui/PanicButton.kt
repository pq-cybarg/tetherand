package dev.tetherand.app.threat.ui

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun PanicButton() {
    val ctx = LocalContext.current
    Button(
        onClick = {
            // Drop the user at the Airplane-mode toggle; one tap away.
            // Programmatic airplane-mode toggle requires WRITE_SETTINGS +
            // root on Android 10+, so we don't promise to flip it directly.
            try {
                ctx.startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            } catch (_: Throwable) {}
        },
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF5D62)),
    ) {
        Text("PANIC — open airplane mode", color = Color.White, fontSize = 14.sp)
    }
}
