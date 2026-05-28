package dev.tetherand.app.aiguard.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import dev.tetherand.app.aiguard.fieldguide.ConferenceFieldGuide

@Composable
fun FieldGuideCard() {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("AI-era field guide (DEFCON 34)",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            for (e in ConferenceFieldGuide.STATIC) {
                val sevColor = when (e.severity) {
                    "high"   -> Color(0xFFFF5D62)
                    "medium" -> Color(0xFFFFC857)
                    else     -> MaterialTheme.colorScheme.onSurface
                }
                Column {
                    Text("● ${e.title}", color = sevColor, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                    Text(e.body, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.85f), fontSize = 10.sp)
                }
            }
        }
    }
}
