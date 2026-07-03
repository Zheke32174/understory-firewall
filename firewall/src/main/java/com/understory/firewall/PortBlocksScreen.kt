package com.understory.firewall

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.understory.security.Diagnostics

/**
 * Custom port-blocking screen.
 *
 * Phase-1 (this commit): the user's port list is stored and displayed,
 * but the firewall VPN doesn't yet inspect packets to drop matching
 * destinations. The current FirewallVpnService captures ALL traffic
 * from blocked apps and drops it; per-port filtering across ALL apps
 * needs userspace packet parsing + a forward path for non-matching
 * traffic. Phase-2 wires that.
 *
 * Until then, this screen is honest: a yellow banner says "settings
 * stored, enforcement pending." The user's port list survives in
 * SharedPreferences so phase-2 can pick it up without UI churn.
 *
 * Design choices:
 * - Free-form numeric entry, not a dropdown of well-known ports. The
 *   user might want to block 6881 (BitTorrent), 25 (SMTP), 23 (Telnet),
 *   or any custom port. A dropdown would constrain pointlessly.
 * - Validation: 1..65535. We strip whitespace and reject non-numerics
 *   silently rather than throwing — user types fast, no need to scold.
 * - List display is sorted ascending so duplicates are obvious and
 *   ordering is stable across recompositions.
 * - "Add port" appends; "Remove" per-row removes. No bulk-add (paste a
 *   list) — phase-2 can add that if real users want it.
 */
@Composable
fun PortBlocksScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var refreshKey by remember { mutableStateOf(0) }
    val ports = remember(refreshKey) { FirewallSettings.getBlockedPorts(ctx).sorted() }
    var inputText by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("custom port blocking", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "List specific TCP/UDP destination ports to block across all " +
                "apps. Useful for stopping known-bad ports (BitTorrent, " +
                "Telnet, SMB) without having to identify every app that " +
                "speaks them.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
        )

        // Honest scope banner. Phase-2 enforces the list via /proc/net
        // discovery — apps observably using a blocked port are auto-
        // added to the firewall blocklist within ~10s, then the VPN
        // drops their traffic. Phase-3 added a DNS-redirect mode for
        // DNSCrypt; while THAT mode is active, port blocks are paused
        // (they can't share one tun without a userspace TCP forwarder).
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF332A14), RoundedCornerShape(6.dp))
                .padding(12.dp),
        ) {
            Text(
                "Enforcement: app-derivation via /proc/net (active when the " +
                    "firewall VPN is on AND no DNSCrypt provider is selected). " +
                    "Re-scans every 10s. Apps observably using a blocked port " +
                    "are auto-added to the firewall's blocklist; their traffic " +
                    "is then dropped via the existing tun. On Android 10+ " +
                    "/proc/net visibility is restricted, so matches may be 0 " +
                    "even with traffic flowing.\n\n" +
                    "If you've selected a DNSCrypt provider, the VPN is in " +
                    "DNS-redirect mode and port-blocking is paused — phase 4 " +
                    "(userspace TCP forwarder) lets these coexist.",
                color = Color(0xFFFFB74D), fontSize = 11.sp,
            )
        }

        Spacer(Modifier.height(4.dp))

        // Add row: numeric input + Add button.
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = inputText,
                onValueChange = {
                    inputText = it.filter { c -> c.isDigit() }
                    error = null
                },
                label = { Text("Port (1..65535)") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = {
                    val n = inputText.toIntOrNull()
                    if (n == null || n !in 1..65_535) {
                        error = "Port must be 1..65535"
                        return@Button
                    }
                    val updated = ports.toSet() + n
                    FirewallSettings.setBlockedPorts(ctx, updated)
                    Diagnostics.log("firewall.PortBlocks", "added port: $n")
                    inputText = ""
                    error = null
                    refreshKey++
                },
                enabled = inputText.isNotBlank(),
            ) { Text("Add") }
        }
        error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 11.sp) }

        Spacer(Modifier.height(4.dp))

        // Live discovery verdict. Recomputed on each refreshKey bump
        // (after Add/Remove); not periodic — phase-2's /proc/net scan
        // happens inside FirewallVpnService on its own 10s tick. This
        // surface is a manual-refresh "what does discovery see right
        // now" check, useful for verifying a port rule actually
        // catches the app you're targeting.
        if (ports.isNotEmpty()) {
            val verdict = remember(refreshKey) { PortBlockDiscovery.verdict(ctx) }
            val (verdictText, verdictColor) = when (verdict) {
                is PortBlockDiscovery.Verdict.NoPortsConfigured ->
                    "Discovery: no ports configured." to Color(0xFF9E9E9E)
                is PortBlockDiscovery.Verdict.Found ->
                    "Discovery: ${verdict.packages.size} app(s) using a " +
                        "blocked port — auto-blocked. " +
                        verdict.packages.joinToString(", ").take(120) to
                        Color(0xFF66BB6A)
                is PortBlockDiscovery.Verdict.NoMatches ->
                    "Discovery: no matches. Either no app is using these " +
                        "ports right now, OR Android 10+ /proc/net " +
                        "restrictions hide them. Phase 3 (packet forwarder) " +
                        "removes that limitation." to Color(0xFFFFB74D)
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF141414), RoundedCornerShape(6.dp))
                    .padding(12.dp),
            ) {
                Text(verdictText, color = verdictColor, fontSize = 11.sp)
            }
            OutlinedButton(
                onClick = { refreshKey++ },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Re-scan now") }
        }

        if (ports.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF141414), RoundedCornerShape(6.dp))
                    .padding(20.dp),
            ) {
                Text(
                    "No ports blocked. Add one above.",
                    color = Color(0xFF707070), fontSize = 12.sp,
                )
            }
        } else {
            Text(
                "${ports.size} port${if (ports.size == 1) "" else "s"} blocked",
                color = Color(0xFF707070), fontSize = 11.sp,
            )
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(4.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                items(ports, key = { "port-$it" }) { port ->
                    PortRow(
                        port = port,
                        onRemove = {
                            val updated = ports.toSet() - port
                            FirewallSettings.setBlockedPorts(ctx, updated)
                            Diagnostics.log("firewall.PortBlocks", "removed port: $port")
                            refreshKey++
                        },
                    )
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text("Back")
        }
    }
}

@Composable
private fun PortRow(port: Int, onRemove: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text("Port $port", color = Color(0xFFE0E0E0), fontSize = 13.sp)
            Text(wellKnownLabel(port), color = Color(0xFF9E9E9E), fontSize = 11.sp)
        }
        OutlinedButton(onClick = onRemove) { Text("Remove") }
    }
}

/** Cosmetic only — known port names so the user sees what they're blocking. */
private fun wellKnownLabel(port: Int): String = when (port) {
    20, 21 -> "FTP"
    22 -> "SSH"
    23 -> "Telnet"
    25, 587, 465 -> "SMTP / mail submission"
    53 -> "DNS"
    67, 68 -> "DHCP"
    80 -> "HTTP"
    110 -> "POP3"
    119 -> "NNTP"
    123 -> "NTP"
    143 -> "IMAP"
    161, 162 -> "SNMP"
    179 -> "BGP"
    389 -> "LDAP"
    443 -> "HTTPS"
    445 -> "SMB"
    465 -> "SMTPS"
    514 -> "syslog"
    636 -> "LDAPS"
    993 -> "IMAPS"
    995 -> "POP3S"
    1080 -> "SOCKS"
    1194 -> "OpenVPN"
    1433 -> "MSSQL"
    1701 -> "L2TP"
    1723 -> "PPTP"
    1900 -> "SSDP / UPnP"
    3306 -> "MySQL"
    3389 -> "RDP"
    5060, 5061 -> "SIP"
    5432 -> "PostgreSQL"
    5900 -> "VNC"
    6379 -> "Redis"
    6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889 -> "BitTorrent"
    8080 -> "HTTP alt"
    8443 -> "HTTPS alt"
    8888 -> "HTTP proxy alt"
    9000 -> "Various"
    9050 -> "Tor SOCKS"
    11211 -> "Memcached"
    27017 -> "MongoDB"
    in 1..1023 -> "Well-known port"
    in 1024..49151 -> "Registered port"
    else -> "Dynamic / private port"
}
