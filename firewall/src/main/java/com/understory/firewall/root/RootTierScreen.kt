package com.understory.firewall.root

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.understory.firewall.BoundaryText
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * S8 — the root iptables tier, shown as an HONEST DORMANT STUB. This device is
 * unrooted, so the granular per-network-type / LAN / per-port controls this tier
 * WOULD offer are listed as capabilities and marked clearly as "requires root —
 * unavailable on this device". Nothing here is faked or wired to a no-op toggle:
 * the controls are described, not presented as live switches. A clean
 * [RootDetector] drives the availability banner.
 */
@Composable
fun RootTierScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var state by remember { mutableStateOf<RootDetector.RootState?>(null) }
    LaunchedEffect(Unit) { state = RootDetector.detect(ctx) }

    SuiteScaffold(title = "Root firewall (advanced)", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            AvailabilityBanner(state)

            SuiteCard {
                Text("What the root tier would add", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    "With root (uid 0), an on-device iptables/nftables firewall can enforce " +
                        "rules the slot-free and tunnel tiers cannot — all without the VPN " +
                        "slot:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                for (cap in ROOT_CAPS) {
                    Text("• $cap", style = MaterialTheme.typography.bodyMedium)
                }
            }

            SuiteCard {
                Text("Why it's dormant here", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    state?.reason ?: "Checking for root…",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                BoundaryText(
                    "We do not fake root controls. This tier stays fully disabled — no " +
                        "hidden no-op toggles — until this app runs on a rooted device (a su " +
                        "binary, or root-mode Shizuku running as uid 0). The probe is " +
                        "read-only and never runs `su`, so it can't trigger a root prompt.",
                )
            }
        }
    }
}

@Composable
private fun AvailabilityBanner(state: RootDetector.RootState?) {
    val available = state?.rooted == true
    val (container, content, label) = if (available) {
        Triple(
            UnderstoryTheme.semantic.successContainer,
            UnderstoryTheme.semantic.success,
            "Root available — the advanced tier can run",
        )
    } else {
        Triple(
            UnderstoryTheme.semantic.warningContainer,
            UnderstoryTheme.semantic.warning,
            "Requires root — unavailable on this device",
        )
    }
    Surface(
        color = container,
        contentColor = content,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(label, style = MaterialTheme.typography.titleMedium)
        }
    }
}

private val ROOT_CAPS = listOf(
    "Per-network-type rules — block an app on mobile data but allow it on Wi-Fi " +
        "(or vice versa), enforced in the kernel.",
    "LAN / local-subnet isolation — block an app from reaching 10.0.0.0/8, " +
        "192.168.0.0/16, and link-local, while still allowing the internet.",
    "Per-port and per-protocol rules — block outbound to specific ports " +
        "(e.g. SMTP, plaintext DNS on :53, QUIC on :443/udp).",
    "True boot persistence — rules re-applied from an init hook at boot, before " +
        "any app runs (the slot-free tier can't, and re-arms only after Shizuku).",
    "Roaming / tether / hotspot scoping — distinct rule sets per interface.",
)
