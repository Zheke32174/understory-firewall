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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.understory.overlay.i2p.I2pStatus
import com.understory.overlay.lokinet.LokinetStatus
import com.understory.overlay.yggdrasil.YggdrasilStatus
import com.understory.security.Diagnostics

/**
 * Overlay routing screen — phase α scaffold.
 *
 * What works today: storing the user's choice of "which overlay should
 * the firewall route blocked apps through" plus an enforce-routing
 * toggle. Both persist via [FirewallSettings].
 *
 * What doesn't work yet: the [FirewallVpnService] currently DROPS
 * blocked-app traffic (Phase B posture). To route through an overlay's
 * SOCKS proxy it needs a TCP/UDP parser + a SOCKS5 client + per-flow
 * relay loop — that's Phase C and lands in a follow-up commit. Until
 * then the toggle stores the user's intent but doesn't change the
 * blocked-traffic outcome.
 *
 * What this screen does today:
 *   1. Shows live status of all three overlay networks (I2P from
 *      browser's running daemon, Lokinet/Yggdrasil from their
 *      BinaryMissing scaffolds).
 *   2. Lets the user pick which overlay would be the routing target.
 *   3. Lets the user toggle Enforce-routing on/off (stored only).
 *   4. Surfaces a clear "Phase α: stored intent only — see
 *      RELEASE_BLOCKERS.md" banner so no one mistakes the toggle for
 *      live behavior.
 */
@Composable
fun OverlayRoutingScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scrollState = rememberScrollState()

    var selectedNetwork by remember {
        mutableStateOf(FirewallSettings.getOverlayNetwork(ctx))
    }
    var routingEnabled by remember {
        mutableStateOf(FirewallSettings.isOverlayRoutingEnabled(ctx))
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("overlay routing", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Pick which overlay network the firewall should route blocked-app " +
                "traffic through. Today the firewall drops blocked traffic; this " +
                "screen stores your routing intent so the SOCKS-relay path can " +
                "consume it when it lands.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
        )

        // Phase α banner: don't let users assume the toggle changes
        // live behavior. The text is verbose for a reason — surprise
        // is worse than a long line.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF332A14), RoundedCornerShape(6.dp))
                .padding(12.dp),
        ) {
            Text(
                "Phase α scaffold — toggling stores your choice but does NOT yet " +
                    "route traffic. Daemons for Lokinet / Yggdrasil aren't bundled. " +
                    "Tracked in RELEASE_BLOCKERS.md.",
                color = Color(0xFFFFB74D), fontSize = 11.sp,
            )
        }

        Spacer(Modifier.height(4.dp))

        // Network selector — three rows.
        OverlayNetworkRow(
            id = "i2p",
            label = "I2P",
            statusLabel = i2pLabel(),
            isSelected = selectedNetwork == "i2p",
            onSelect = {
                FirewallSettings.setOverlayNetwork(ctx, "i2p")
                selectedNetwork = "i2p"
                Diagnostics.log("firewall.OverlayRouting", "selected I2P")
            },
        )
        OverlayNetworkRow(
            id = "lokinet",
            label = "Lokinet",
            statusLabel = lokinetLabel(),
            isSelected = selectedNetwork == "lokinet",
            onSelect = {
                FirewallSettings.setOverlayNetwork(ctx, "lokinet")
                selectedNetwork = "lokinet"
                Diagnostics.log("firewall.OverlayRouting", "selected Lokinet")
            },
        )
        OverlayNetworkRow(
            id = "yggdrasil",
            label = "Yggdrasil",
            statusLabel = yggdrasilLabel(),
            isSelected = selectedNetwork == "yggdrasil",
            onSelect = {
                FirewallSettings.setOverlayNetwork(ctx, "yggdrasil")
                selectedNetwork = "yggdrasil"
                Diagnostics.log("firewall.OverlayRouting", "selected Yggdrasil")
            },
        )

        Spacer(Modifier.height(8.dp))

        // Enforce-routing toggle.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier
                .fillMaxWidth(0.85f)) {
                Text(
                    "Enforce overlay routing",
                    color = Color(0xFFE0E0E0), fontSize = 13.sp,
                )
                Text(
                    if (routingEnabled) {
                        "Stored: ON. Routing not active until Phase C lands."
                    } else {
                        "Stored: OFF. Blocked apps still have traffic dropped."
                    },
                    color = Color(0xFF9E9E9E), fontSize = 11.sp,
                )
            }
            Spacer(Modifier.fillMaxWidth(0.0f))
            Switch(
                checked = routingEnabled,
                onCheckedChange = {
                    routingEnabled = it
                    FirewallSettings.setOverlayRoutingEnabled(ctx, it)
                    Diagnostics.log("firewall.OverlayRouting",
                        "enforce-routing toggled: ${if (it) "ON" else "OFF"}")
                },
            )
        }

        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text("Back")
        }
    }
}

@Composable
private fun OverlayNetworkRow(
    id: String,
    label: String,
    statusLabel: Pair<String, Color>,
    isSelected: Boolean,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (isSelected) Color(0xFF1A2A1A) else Color(0xFF1C1C1C),
                RoundedCornerShape(6.dp),
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.fillMaxWidth(0.7f)) {
            Text(label, color = Color(0xFFE0E0E0), fontSize = 13.sp)
            Text(statusLabel.first, color = statusLabel.second, fontSize = 11.sp)
        }
        OutlinedButton(
            onClick = onSelect,
            enabled = !isSelected,
        ) {
            Text(if (isSelected) "Selected" else "Select")
        }
    }
}

@Composable
private fun i2pLabel(): Pair<String, Color> = when (val s = I2pStatus.state) {
    I2pStatus.State.Idle -> "Idle (browser idle)" to Color(0xFF9E9E9E)
    I2pStatus.State.BinaryMissing ->
        "Browser i2pd binary missing" to Color(0xFFFFB74D)
    I2pStatus.State.Starting -> "Browser i2pd starting" to Color(0xFF90CAF9)
    is I2pStatus.State.Ready ->
        "Ready · http :${s.httpPort} · socks :${s.socksPort}" to Color(0xFF66BB6A)
    is I2pStatus.State.Error -> "Error: ${s.reason}" to Color(0xFFEF5350)
}

@Composable
private fun lokinetLabel(): Pair<String, Color> = when (val s = LokinetStatus.state) {
    LokinetStatus.State.Idle -> "Idle" to Color(0xFF9E9E9E)
    LokinetStatus.State.BinaryMissing ->
        "Scaffold only — lokinet binary not bundled" to Color(0xFFFFB74D)
    LokinetStatus.State.Starting -> "Starting" to Color(0xFF90CAF9)
    is LokinetStatus.State.Ready -> "Ready · socks :${s.socksPort}" to Color(0xFF66BB6A)
    is LokinetStatus.State.Error -> "Error: ${s.reason}" to Color(0xFFEF5350)
}

@Composable
private fun yggdrasilLabel(): Pair<String, Color> = when (val s = YggdrasilStatus.state) {
    YggdrasilStatus.State.Idle -> "Idle" to Color(0xFF9E9E9E)
    YggdrasilStatus.State.BinaryMissing ->
        "Scaffold only — yggdrasil binary not bundled" to Color(0xFFFFB74D)
    YggdrasilStatus.State.Starting -> "Starting" to Color(0xFF90CAF9)
    is YggdrasilStatus.State.Ready ->
        "Ready · ${s.meshIp} (${s.peerCount} peers)" to Color(0xFF66BB6A)
    is YggdrasilStatus.State.Error -> "Error: ${s.reason}" to Color(0xFFEF5350)
}
