package dev.tetherand.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily

@Composable
fun TabbedRoot(
    onTetherStart: () -> Unit,
    onTetherStop: () -> Unit,
    onChainStart: (String, Boolean) -> Unit,
    onChainStop: () -> Unit,
) {
    var selected by remember { mutableStateOf(0) }
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding(),
        ) {
            TabRow(selectedTabIndex = selected, containerColor = MaterialTheme.colorScheme.background) {
                Tab(selected = selected == 0, onClick = { selected = 0 }, text = { Text("Tether", fontFamily = FontFamily.Monospace) })
                Tab(selected = selected == 1, onClick = { selected = 1 }, text = { Text("Privacy", fontFamily = FontFamily.Monospace) })
            }
            when (selected) {
                0 -> TetherScreen(onStart = onTetherStart, onStop = onTetherStop)
                1 -> PrivacyScreen(onStart = onChainStart, onStop = onChainStop)
            }
        }
    }
}
