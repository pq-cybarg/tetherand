package dev.tetherand.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

@Composable
fun PrivacyScreen(onStart: (String, Boolean) -> Unit, onStop: () -> Unit) {
    var running by remember { mutableStateOf(false) }
    var wgText by remember { mutableStateOf(SAMPLE_WG_CONFIG) }
    var account by remember { mutableStateOf("") }
    var servers by remember { mutableStateOf<List<dev.tetherand.app.mullvad.MullvadWgServer>>(emptyList()) }
    var picked by remember { mutableStateOf<dev.tetherand.app.mullvad.MullvadWgServer?>(null) }
    var pqEnabled by remember { mutableStateOf(true) }
    var mullvadError by remember { mutableStateOf<String?>(null) }
    // M4d multihop
    var multihop by remember { mutableStateOf(false) }
    var exitServer by remember { mutableStateOf<dev.tetherand.app.mullvad.MullvadWgServer?>(null) }
    // M4e DAITA
    var daita by remember { mutableStateOf(false) }
    // M4f obfuscation
    var obfsMode by remember { mutableStateOf(dev.tetherand.app.mullvad.ObfuscationMode.Plain) }
    var bridgeHost by remember { mutableStateOf("") }
    var bridgePort by remember { mutableStateOf("") }
    var bridgeCipher by remember { mutableStateOf("chacha20-ietf-poly1305") }
    var bridgePassword by remember { mutableStateOf("") }
    // M4g split-tunnel
    val ctx = LocalContext.current
    val splitStore = remember { dev.tetherand.app.splittunnel.SplitTunnelStore(ctx) }
    var disallowed by remember { mutableStateOf(splitStore.disallowed()) }
    var showAppPicker by remember { mutableStateOf(false) }
    // M6 Tor hop config — bridges + vanguards + PQ-NTor preference.
    val torStore = remember { dev.tetherand.app.tor.TorBridges(ctx) }
    val initialTor = remember { torStore.load() }
    var torEnabled by remember { mutableStateOf(false) }
    var torBridges by remember { mutableStateOf(initialTor.bridges.joinToString("\n")) }
    var torVanguards by remember { mutableStateOf(initialTor.vanguards) }
    var torPreferPq by remember { mutableStateOf(initialTor.preferPqHandshake) }
    var torStatus by remember { mutableStateOf<String?>(null) }
    val scroll = rememberScrollState()
    val scope = androidx.compose.runtime.rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "PRIVACY CHAIN",
                color = MaterialTheme.colorScheme.secondary,
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp,
                fontFamily = FontFamily.Monospace,
            )
            Spacer(Modifier.weight(1f))
            ChainStatusPill(running)
        }
        Text(
            "Compose hops the phone's traffic flows through before reaching the internet.",
            color = MaterialTheme.colorScheme.onBackground,
        )

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Chain", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    HopCard("Apps")
                    Arrow()
                    HopCard("WireGuard", active = running, accent = MaterialTheme.colorScheme.primary)
                    Arrow()
                    HopCard("Internet")
                }
                Text(
                    "M3: single WireGuard hop. Mullvad PQ (M4), NymVPN (M5), and Tor (M6) join the picker as their hop types ship.",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
            }
        }

        // Mullvad card
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Mullvad", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                OutlinedTextField(
                    value = account,
                    onValueChange = { account = it.filter { c -> c.isDigit() }.take(16) },
                    label = { Text("Mullvad account number (16 digits)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace),
                )
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            scope.launch {
                                try {
                                    val api = dev.tetherand.app.mullvad.MullvadApi()
                                    servers = api.listRelays().wireguard.relays.filter { it.active }
                                    mullvadError = null
                                } catch (t: Throwable) { mullvadError = t.message }
                            }
                        },
                        enabled = account.length == 16,
                    ) { Text("Fetch servers") }
                    if (servers.isNotEmpty()) {
                        Text("${servers.size} active", color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp)
                    }
                }
                if (servers.isNotEmpty()) {
                    // Simple scrollable Column rather than LazyColumn —
                    // server lists are ~50 items so virtualization is
                    // overkill, and avoids the LazyListScope.items import.
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(180.dp)
                            .verticalScroll(rememberScrollState()),
                    ) {
                        for (s in servers) {
                            Text(
                                s.display,
                                color = if (s == picked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { picked = s }
                                    .padding(vertical = 4.dp),
                            )
                        }
                    }
                }
                // M4d multihop: switch + exit server picker.
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = multihop, onCheckedChange = { multihop = it })
                    Spacer(Modifier.padding(end = 8.dp))
                    Text("Multihop (separate entry + exit server)", color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                }
                if (multihop && servers.isNotEmpty()) {
                    Text("Exit server:", color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    Column(Modifier.fillMaxWidth().height(140.dp).verticalScroll(rememberScrollState())) {
                        for (s in servers) {
                            Text(
                                s.display,
                                color = if (s == exitServer) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                modifier = Modifier.fillMaxWidth().clickable { exitServer = s }.padding(vertical = 4.dp),
                            )
                        }
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = pqEnabled, onCheckedChange = { pqEnabled = it })
                    Spacer(Modifier.padding(end = 8.dp))
                    Text("Post-quantum tunnel (ML-KEM-1024)", color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                }

                // M4e DAITA toggle.
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = daita, onCheckedChange = { daita = it })
                    Spacer(Modifier.padding(end = 8.dp))
                    Text("DAITA — traffic shaping vs. ML fingerprinting", color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                }

                // M4f obfuscation transport picker.
                Text("Obfuscation transport", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    for (m in dev.tetherand.app.mullvad.ObfuscationMode.values()) {
                        AssistChip(
                            onClick = { obfsMode = m },
                            label = { Text(m.displayName, fontSize = 10.sp) },
                            modifier = if (obfsMode == m) Modifier.border(2.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(8.dp)) else Modifier,
                        )
                    }
                }
                if (obfsMode != dev.tetherand.app.mullvad.ObfuscationMode.Plain) {
                    OutlinedTextField(
                        value = bridgeHost, onValueChange = { bridgeHost = it },
                        label = { Text("Bridge host") },
                        modifier = Modifier.fillMaxWidth(), singleLine = true,
                        textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                    )
                    OutlinedTextField(
                        value = bridgePort,
                        onValueChange = { bridgePort = it.filter { c -> c.isDigit() }.take(5) },
                        label = { Text("Bridge port") },
                        modifier = Modifier.fillMaxWidth(), singleLine = true,
                        textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                    )
                    if (obfsMode == dev.tetherand.app.mullvad.ObfuscationMode.Shadowsocks) {
                        OutlinedTextField(
                            value = bridgeCipher, onValueChange = { bridgeCipher = it },
                            label = { Text("SS cipher (e.g. chacha20-ietf-poly1305)") },
                            modifier = Modifier.fillMaxWidth(), singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                        )
                        OutlinedTextField(
                            value = bridgePassword, onValueChange = { bridgePassword = it },
                            label = { Text("SS password") },
                            modifier = Modifier.fillMaxWidth(), singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                        )
                    }
                }

                // M4g split-tunnel app picker entry point.
                Button(onClick = { showAppPicker = true }) {
                    Text("Exclude apps from VPN (${disallowed.size} selected)")
                }

                Button(
                    onClick = {
                        scope.launch {
                            try {
                                val server = picked ?: return@launch
                                val api = dev.tetherand.app.mullvad.MullvadApi()
                                val (rawCfg, _) = if (multihop && exitServer != null)
                                    dev.tetherand.app.mullvad.MullvadConfigBuilder.buildMultihop(api, account, server, exitServer!!)
                                else
                                    dev.tetherand.app.mullvad.MullvadConfigBuilder.build(api, account, server)
                                val cfg = rawCfg.copy(
                                    obfuscation = obfsMode,
                                    obfuscationBridge = if (obfsMode != dev.tetherand.app.mullvad.ObfuscationMode.Plain
                                            && bridgeHost.isNotEmpty() && bridgePort.isNotEmpty()) {
                                        dev.tetherand.app.mullvad.ObfuscationBridge(
                                            host = bridgeHost,
                                            port = bridgePort.toInt(),
                                            cipher = bridgeCipher.takeIf { obfsMode == dev.tetherand.app.mullvad.ObfuscationMode.Shadowsocks },
                                            password = bridgePassword.takeIf { obfsMode == dev.tetherand.app.mullvad.ObfuscationMode.Shadowsocks },
                                        )
                                    } else null,
                                    daita = daita,
                                )
                                wgText = configToText(cfg)
                                mullvadError = null
                            } catch (t: Throwable) { mullvadError = t.message }
                        }
                    },
                    enabled = picked != null && account.length == 16 && (!multihop || exitServer != null),
                ) { Text("Build config from Mullvad") }
                if (mullvadError != null) {
                    Text(mullvadError!!, color = MaterialTheme.colorScheme.error, fontSize = 11.sp)
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("WireGuard config", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "Paste a standard [Interface]/[Peer] config. Mullvad classic-WG configs work out of the box.",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                )
                OutlinedTextField(
                    value = wgText,
                    onValueChange = { wgText = it },
                    modifier = Modifier.fillMaxWidth().height(260.dp),
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
                    label = { Text("conf") },
                )
            }
        }

        // M6 Tor hop card — config + save. The chain orchestrator wiring
        // (Tor as an additional hop alongside WG) ships in M6.x once the
        // per-flow IP→arti DataStream forwarder lands. v1 surfaces the
        // config + persists it under EncryptedSharedPreferences so the
        // moment the forwarder lands the user's config is already there.
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Tor (Arti)", fontWeight = FontWeight.SemiBold,
                         color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
                    Spacer(Modifier.weight(1f))
                    Switch(checked = torEnabled, onCheckedChange = { torEnabled = it })
                }
                Text("Tor as a chain hop, backed by an embedded arti-client 0.27. " +
                     "Pluggable transports (obfs4 / snowflake / meek / webtunnel / conjure) ship as M6.x sub-plans.",
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f), fontSize = 11.sp)
                OutlinedTextField(
                    value = torBridges, onValueChange = { torBridges = it },
                    label = { Text("Bridge lines (BridgeDB format, one per line)") },
                    modifier = Modifier.fillMaxWidth().height(120.dp),
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = torVanguards, onCheckedChange = { torVanguards = it })
                    Spacer(Modifier.padding(end = 8.dp))
                    Text("Vanguards — entry-guard hardening", color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = torPreferPq, onCheckedChange = { torPreferPq = it })
                    Spacer(Modifier.padding(end = 8.dp))
                    Text("Prefer PQ-NTor handshake (prop362 / NTor-ML-KEM-v1)", color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp)
                }
                Button(modifier = Modifier.fillMaxWidth(), onClick = {
                    val lines = torBridges.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
                    torStore.save(dev.tetherand.app.tor.TorConfig(
                        bridges = lines,
                        vanguards = torVanguards,
                        preferPqHandshake = torPreferPq,
                    ))
                    torStatus = "Saved ${lines.size} bridge(s); vanguards=$torVanguards; pq=$torPreferPq"
                }) { Text("Save Tor config", fontSize = 12.sp, fontFamily = FontFamily.Monospace) }
                if (torStatus != null) {
                    Text(torStatus!!, fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                         color = MaterialTheme.colorScheme.primary)
                }
            }
        }

        if (!running) {
            Button(
                onClick = { running = true; onStart(wgText, pqEnabled) },
                enabled = wgText.contains("[Interface]") && wgText.contains("[Peer]"),
            ) { Text("Start chain") }
        } else {
            Button(onClick = { running = false; onStop() }) { Text("Stop chain") }
        }
    }

    // M4g split-tunnel app picker dialog.
    if (showAppPicker) {
        val apps = remember { dev.tetherand.app.splittunnel.InstalledApps.list(ctx) }
        AlertDialog(
            onDismissRequest = { showAppPicker = false },
            confirmButton = {
                Button(onClick = {
                    splitStore.setDisallowed(disallowed)
                    showAppPicker = false
                }) { Text("Save") }
            },
            dismissButton = { Button(onClick = { showAppPicker = false }) { Text("Cancel") } },
            title = { Text("Exclude apps from VPN") },
            text = {
                Column(Modifier.height(400.dp).verticalScroll(rememberScrollState())) {
                    for (app in apps) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = app.pkg in disallowed,
                                onCheckedChange = { checked ->
                                    disallowed = if (checked) disallowed + app.pkg else disallowed - app.pkg
                                },
                            )
                            Text(app.label, fontSize = 12.sp, modifier = Modifier.padding(start = 4.dp))
                        }
                    }
                }
            },
        )
    }
}

private fun configToText(c: dev.tetherand.app.chain.WireGuardConfig): String {
    val priv = android.util.Base64.encodeToString(c.privateKey, android.util.Base64.NO_WRAP)
    val pub  = android.util.Base64.encodeToString(c.peerPublicKey, android.util.Base64.NO_WRAP)
    val dns  = c.dns.joinToString(", ")
    val ips  = c.allowedIps.joinToString(", ")
    return """
        [Interface]
        PrivateKey = $priv
        Address    = ${c.address}
        DNS        = $dns

        [Peer]
        PublicKey  = $pub
        AllowedIPs = $ips
        Endpoint   = ${c.endpointHost}:${c.endpointPort}
        PersistentKeepalive = ${c.persistentKeepaliveSecs}
    """.trimIndent()
}

@Composable
private fun ChainStatusPill(active: Boolean) {
    val color = if (active) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.onSurface
    val label = if (active) "ROUTING" else "OFFLINE"
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, color, RoundedCornerShape(50))
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Text(label, color = color, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun HopCard(label: String, active: Boolean = false, accent: Color = MaterialTheme.colorScheme.onSurface) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.background)
            .border(1.dp, if (active) accent else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Text(label, color = if (active) accent else MaterialTheme.colorScheme.onSurface, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
}

@Composable
private fun Arrow() {
    Text("→", color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f), fontFamily = FontFamily.Monospace)
}

private val SAMPLE_WG_CONFIG = """
[Interface]
PrivateKey = <paste your WireGuard private key here, base64>
Address    = 10.66.0.2/32
DNS        = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey  = <paste the peer's public key here, base64>
AllowedIPs = 0.0.0.0/0
Endpoint   = your.wg.endpoint:51820
PersistentKeepalive = 25
""".trimIndent()
