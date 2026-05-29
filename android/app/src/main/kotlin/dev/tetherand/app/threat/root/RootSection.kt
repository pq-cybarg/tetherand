package dev.tetherand.app.threat.root

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Threat-tab root-tier section. Surfaces:
 *   - root capability (dormant / active)
 *   - on-active: live ccci_md1_status read
 */
@Composable
fun RootSection() {
    var rooted by remember { mutableStateOf(false) }
    var ccciSnapshot by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        rooted = RootCheck.isRooted()
        if (rooted) {
            val r = CcciMd1Reader.snapshot()
            ccciSnapshot = when (r) {
                is CcciMd1Reader.Result.Snapshot -> "state=${r.state}; ${r.intrCount.size} IRQ counters"
                is CcciMd1Reader.Result.Failed   -> "failed: ${r.reason}"
                CcciMd1Reader.Result.Dormant     -> null
            }
        }
    }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Root tier — MTK modem readers",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            if (!rooted) {
                Text("● Dormant — device is not rooted",
                     color = Color(0xFFFFC857),
                     fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                Text("These readers automatically activate the moment root is granted: " +
                     "/proc/ccci_md1_* (modem state + IRQ counters), mdlog parser " +
                     "(LTE RRC + paging + IRAT reselection records), AT-command channel " +
                     "over /dev/ttyMT0 (3GPP TS 27.007 + MTK extensions: AT+EMRSS for " +
                     "neighbor-cell measurements). No-op on un-rooted devices.",
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                     fontSize = 10.sp)
            } else {
                Text("● Active — root capabilities detected",
                     color = Color(0xFF00D68F),
                     fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                if (ccciSnapshot != null) {
                    Text(ccciSnapshot!!,
                         color = MaterialTheme.colorScheme.onSurface,
                         fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                }
            }
        }
    }
}
