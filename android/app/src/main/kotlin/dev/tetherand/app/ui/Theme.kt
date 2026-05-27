package dev.tetherand.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

@Composable
fun TetherandTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary       = Color(0xFF00D68F),
            onPrimary     = Color(0xFF001F11),
            secondary     = Color(0xFF5CDFFF),
            onSecondary   = Color(0xFF002B33),
            background    = Color(0xFF0A0E14),
            onBackground  = Color(0xFFC0C8D4),
            surface       = Color(0xFF11161D),
            onSurface     = Color(0xFFC0C8D4),
        ),
        content = content,
    )
}
