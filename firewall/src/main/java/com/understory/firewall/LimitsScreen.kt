package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Limits & Diagnostics (design-v2/firewall.md §5.8). The Limits card
 * renders the "what this app can't do" list verbatim — a doctrine feature
 * (CD-4b), not fine print. Diagnostics is reached from here (the three old
 * full-width buttons collapse into this row).
 */
@Composable
fun LimitsScreen(onBack: () -> Unit, onDiagnostics: () -> Unit) {
    SuiteScaffold(title = "Limits & diagnostics", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            SuiteCard {
                Text("What this app can't do", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                for (limit in LIMITS) {
                    Text(
                        "• $limit",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(vertical = UnderstoryTheme.spacing.xs),
                    )
                }
            }
            SecureOutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
                Text("Diagnostics")
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

private val LIMITS = listOf(
    "No per-app blocking / packet drop without the VPN slot (Tailscale holds it); we " +
        "route you to Android's own per-app data restriction instead.",
    "We cannot read Tailscale internals: no ACLs, exit-node, MagicDNS state, peer list, " +
        "or tailnet name. Tailscale ships no public local API; we infer \"installed + a " +
        "VPN is up + (maybe) always-on/lockdown.\"",
    "We cannot tell the up VPN is Tailscale unless always_on_vpn_app == com.tailscale.ipn; " +
        "otherwise we say \"a VPN is active\" + \"Tailscale installed,\" no false green.",
    "We cannot enforce DNS for other apps (network-security-config binds to the owning " +
        "APK); Private DNS is the device-global lever, which we drive.",
    "We cannot toggle airplane mode / always-on / lockdown / exit-node — those are user " +
        "actions behind deep-links.",
    "NetworkStats is accounting, not interception — who talked and how much, " +
        "retrospectively; no hosts, no contents, no blocking.",
    "Port-block discovery is dead on every supported device (/proc/net is restricted on " +
        "Android 10+; our minSdk is 33), so we don't offer it.",
)
