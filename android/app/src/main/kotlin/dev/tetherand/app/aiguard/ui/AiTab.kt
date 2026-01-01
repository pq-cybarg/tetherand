package dev.tetherand.app.aiguard.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import dev.tetherand.app.aiguard.runtime.AiGuardRuntime

@Composable
fun AiTab() {
    val ctx = LocalContext.current
    val runtime = remember { AiGuardRuntime.get(ctx) }
    LaunchedEffect(Unit) { runtime.loadAll() }
    val statuses by runtime.statuses.collectAsState()

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "AI GUARD", color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.Bold, fontSize = 22.sp,
                fontFamily = FontFamily.Monospace,
            )
            Spacer(Modifier.weight(1f))
            val loaded = statuses.count { it.state == AiGuardRuntime.ModelStatus.State.Loaded }
            Text(
                "models $loaded/${statuses.size}",
                fontFamily = FontFamily.Monospace, fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }

        // Deterministic-primary defenses — always engaged. Each renders
        // a green ● because the deterministic core needs no model.
        Text("Deterministic primaries (always engaged)",
             fontWeight = FontWeight.SemiBold, fontSize = 12.sp,
             color = MaterialTheme.colorScheme.onBackground)
        DefenseRow("Prompt-injection clipboard scrubber", "regex-only", "Active")
        DefenseRow("Phishing message scorer", "URL + keyword + typo-squat", "Active")
        DefenseRow("Pseudo-perplexity AI-text badge", "word-length + function-word density", "Active")
        DefenseRow("Provenance check (C2PA / SynthID)", "JUMBF marker scan", "Active")
        DefenseRow("Egress LLM-API SNI watch", "exact + suffix matchlist", "Active")
        DefenseRow("MTK NPU sysfs watcher", "/sys/devices/platform/mtk_apu", "Active")
        DefenseRow("Voiceprint vault (safe-word handshake)", "user-initiated", "Active")

        // Contributory classifier statuses.
        Text("Contributory classifiers (model-driven)",
             fontWeight = FontWeight.SemiBold, fontSize = 12.sp,
             color = MaterialTheme.colorScheme.onBackground)
        for (s in statuses) {
            val state = when (s.state) {
                AiGuardRuntime.ModelStatus.State.Loaded     -> "Loaded (${s.backend})"
                AiGuardRuntime.ModelStatus.State.NotPresent -> "Not bundled — deterministic core in effect"
                AiGuardRuntime.ModelStatus.State.LoadFailed -> "Load failed"
            }
            DefenseRow(s.id, "${s.sizeMb} MB", state)
        }

        // Action cards.
        ModelUpdaterCard()
        EgressWatchCard()
        VerifyCallerCard()
        OsintCard()
        FieldGuideCard()
    }
}
