package dev.tetherand.app.aiguard.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Single row inside the AI tab summarising one defense. */
@Composable
fun DefenseRow(name: String, subtitle: String, state: String) {
    val color = when {
        state == "Active" || state.startsWith("Loaded") -> Color(0xFF00D68F)
        state.contains("Not bundled")                    -> Color(0xFFFFC857)
        state.contains("failed", ignoreCase = true)      -> Color(0xFFFF5D62)
        else                                             -> MaterialTheme.colorScheme.onSurface
    }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(12.dp)) {
            Row {
                Text("●", color = color, fontFamily = FontFamily.Monospace, fontSize = 12.sp,
                     modifier = Modifier.padding(end = 6.dp))
                Text(name, fontWeight = FontWeight.SemiBold,
                     color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
            }
            Text(subtitle, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 10.sp)
            Text(state, color = color, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
        }
    }
}
