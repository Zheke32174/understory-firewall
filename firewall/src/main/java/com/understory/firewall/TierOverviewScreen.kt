package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.understory.firewall.policy.BackendManager
import com.understory.firewall.root.RootDetector
import com.understory.firewall.tunnel.BlocklistRepository
import com.understory.security.secureClickable
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The coherence-pass tier/mode overview (the "which firewall am I using?" map).
 * One honest row per tier, each stating: whether it is active, its Tailscale-
 * coexistence status, and a one-line caveat. This is the surface that makes the
 * four tiers legible as one product without overclaiming any of them.
 *
 * Tiers (honest one-liners):
 *   Unprivileged (Companion) — observe/advise/route; blocks nothing; always on.
 *   Slot-free Shizuku policy  — per-app block on all networks; NO slot, NO
 *                               routing; coexists with Tailscale.
 *   DNS-filter tunnel (S6)    — adblock-DNS routing; TAKES the slot; XOR Tailscale.
 *   Root iptables (S8)        — granular per-net/LAN/port; DORMANT (needs root).
 */
@Composable
fun TierOverviewScreen(
    onOpenPolicy: () -> Unit,
    onOpenTunnel: () -> Unit,
    onOpenDns: () -> Unit,
    onOpenRoot: () -> Unit,
    onOpenElevation: () -> Unit,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current

    var vpnUp by remember { mutableStateOf<Boolean?>(null) }
    var tailscaleHoldsSlot by remember { mutableStateOf(false) }
    var policyAvailable by remember { mutableStateOf(false) }
    var policyBlockedCount by remember { mutableStateOf(0) }
    var tunnelArmed by remember { mutableStateOf(false) }
    var rooted by remember { mutableStateOf<Boolean?>(null) }
    var blocklistDomains by remember { mutableStateOf(0) }

    LaunchedEffect(Unit) {
        val vpnActive = withContext(Dispatchers.IO) { VpnSlotProbe.isAnotherVpnActive(ctx) }
        vpnUp = vpnActive
        tailscaleHoldsSlot = withContext(Dispatchers.IO) {
            val alwaysOn = VpnSlotProbe.alwaysOnVpnApp(ctx)
            vpnActive && alwaysOn == VpnSlotProbe.TAILSCALE_PKG
        }
        val bm = BackendManager.get(ctx)
        policyAvailable = withContext(Dispatchers.IO) { bm.isAvailable() }
        policyBlockedCount = withContext(Dispatchers.IO) { bm.blockedPackages().size }
        tunnelArmed = FirewallSettings.getMode(ctx) == FirewallMode.STANDALONE &&
            FirewallSettings.isEngineArmed(ctx)
        rooted = withContext(Dispatchers.IO) { RootDetector.detect(ctx).rooted }
        withContext(Dispatchers.IO) { BlocklistRepository.reload(ctx) }
        blocklistDomains = BlocklistRepository.stats().totalDomains
    }

    SuiteScaffold(title = "Firewall tiers", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))

            // Coexistence banner — the single most important line for a Tailscale phone.
            SuiteCard {
                Text(
                    when {
                        tailscaleHoldsSlot ->
                            "Tailscale holds the VPN slot. Use the slot-free tiers " +
                                "(policy + Private DNS); the DNS-filter tunnel stays off " +
                                "(it can't run alongside Tailscale)."
                        vpnUp == true ->
                            "A VPN holds the VPN slot. The DNS-filter tunnel can't run " +
                                "until it's off; the slot-free tiers work regardless."
                        vpnUp == false ->
                            "No VPN is up. Any tier is available, including the DNS-filter " +
                                "tunnel."
                        else -> "Reading VPN slot…"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            TierRow(
                icon = Icons.Filled.Shield,
                title = "Unprivileged (always on)",
                active = true,
                status = "Active — observe, advise, route. Blocks nothing itself.",
                caveat = "Coexists with everything. No VPN slot, no root.",
                onClick = onOpenElevation,
            )

            TierRow(
                icon = Icons.Filled.AdminPanelSettings,
                title = "Slot-free policy (Shizuku)",
                active = policyBlockedCount > 0,
                status = if (policyAvailable)
                    "Available · $policyBlockedCount app(s) blocked on all networks"
                else "Needs Shizuku (not granted)",
                caveat = "Per-app block on every network. NO slot, NO routing — " +
                    "coexists with Tailscale.",
                onClick = onOpenPolicy,
            )

            TierRow(
                icon = Icons.Filled.VpnKey,
                title = "DNS-filter tunnel (S6)",
                active = tunnelArmed,
                status = when {
                    tunnelArmed -> "Active · filtering DNS ($blocklistDomains domains)"
                    vpnUp == true -> "Off — a VPN holds the slot (XOR Tailscale)"
                    else -> "Off — available (no VPN up)"
                },
                caveat = "Adblock-DNS routing. TAKES the VPN slot — mutually exclusive " +
                    "with Tailscale. Upstream is cleartext (pair with Private DNS).",
                onClick = onOpenTunnel,
            )

            TierRow(
                icon = Icons.Filled.Dns,
                title = "Encrypted DNS (system)",
                active = false,
                status = "Slot-free · sets Android Private DNS (DoT)",
                caveat = "Encrypts the system resolver upstream. Composes with any tier " +
                    "and with Tailscale. A DNS destination lever, not content filtering.",
                onClick = onOpenDns,
            )

            TierRow(
                icon = Icons.Filled.AdminPanelSettings,
                title = "Root iptables (advanced)",
                active = false,
                status = when (rooted) {
                    true -> "Root available — advanced tier can run"
                    false -> "Dormant — requires root (unavailable on this device)"
                    null -> "Checking for root…"
                },
                caveat = "Granular per-network / LAN / per-port rules. Needs root (uid 0). " +
                    "Never faked.",
                onClick = onOpenRoot,
            )

            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

@Composable
private fun TierRow(
    icon: ImageVector,
    title: String,
    active: Boolean,
    status: String,
    caveat: String,
    onClick: () -> Unit,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurface,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = Modifier
            .fillMaxWidth()
            .secureClickable(onClick)
            .semantics(mergeDescendants = true) { role = Role.Button },
    ) {
        Row(
            modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (active) UnderstoryTheme.semantic.success
                else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(28.dp),
            )
            Spacer(Modifier.size(UnderstoryTheme.spacing.md))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(title, style = MaterialTheme.typography.titleMedium)
                    if (active) {
                        Spacer(Modifier.size(UnderstoryTheme.spacing.sm))
                        Text("● on", style = MaterialTheme.typography.labelSmall,
                            color = UnderstoryTheme.semantic.success)
                    }
                }
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(status, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(caveat, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.size(UnderstoryTheme.spacing.sm))
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
