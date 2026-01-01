package dev.tetherand.app.threat.sdr

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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Threat-tab SDR section. Surfaces:
 *   - Status: present / absent (USB-OTG scan)
 *   - Each detected device's name + vendor:product ID + capability tier
 *   - Help text pointing to the cross-compile recipe for the librtlsdr +
 *     srsRAN LTE control-channel decoder
 */
@Composable
fun SdrSection() {
    val ctx = LocalContext.current
    var devices by remember { mutableStateOf<List<SdrDetector.SdrDevice>>(emptyList()) }
    LaunchedEffect(Unit) { devices = SdrDetector.scan(ctx) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("SDR — software-defined radio",
                 fontWeight = FontWeight.SemiBold,
                 color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
            if (devices.isEmpty()) {
                Text("● No SDR dongle detected",
                     color = Color(0xFFFFC857),
                     fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                Text("Plug in an RTL-SDR (~\$30) or HackRF One (~\$300) over USB-OTG. " +
                     "Once attached, the LTE control-channel decoder (M7b.x librtlsdr + srsRAN " +
                     "build) parses SIB/MIB broadcasts for IMSI-catcher / paging-storm " +
                     "detection at a much lower false-positive rate than the cellular heuristics.",
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                     fontSize = 10.sp)
            } else {
                Text("● ${devices.size} SDR device(s) attached",
                     color = Color(0xFF00D68F),
                     fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                for (d in devices) {
                    Text(
                        "  ${d.name}  0x%04x:0x%04x  ${d.capable}".format(d.vendorId, d.productId),
                        color = MaterialTheme.colorScheme.onSurface,
                        fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                    )
                }
                Text("LTE control-channel decoder ships via scripts/build-rtlsdr-android.sh.",
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                     fontSize = 10.sp)
            }
        }
    }
}
