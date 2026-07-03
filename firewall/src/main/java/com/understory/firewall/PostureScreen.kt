package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Network Posture (design-v2/firewall.md §5.7). Rewritten to coexistence:
 * the doctrine-hostile "turn the firewall off to run another tunnel"
 * section is DELETED; "works alongside Tailscale" is added. "Blind by
 * default / no telemetry / no cloud" are kept — the true differentiator.
 */
@Composable
fun PostureScreen(onBack: () -> Unit) {
    SuiteScaffold(title = "Network posture", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            PostureSection(
                "Works alongside Tailscale",
                "We never take the VPN slot. Tailscale keeps it; we read your tunnel's " +
                    "posture and route you to the OS controls you already have. For the " +
                    "minority who run no VPN at all, an opt-in Standalone mode can do real " +
                    "per-app blocking — and it refuses to start whenever a VPN is present.",
            )
            PostureSection(
                "Blind by default",
                "There is no exported control component that accepts commands from other " +
                    "UIDs, no IPC server on a socket. The only control surface is the in-app " +
                    "UI on the unlocked device. Breaking this would need a new exported " +
                    "component — visible in the manifest diff at update time.",
            )
            PostureSection(
                "No telemetry",
                "No analytics SDK, no crash reporter, no feature-flag service. Any diagnostic " +
                    "detail stays on this device; nothing is shipped off-device. The egress " +
                    "canaries only fire on an explicit tap, to a host named on the button.",
            )
            PostureSection(
                "No cloud",
                "The app talks to no backend of ours. The only network it makes is your " +
                    "own: the DoT reachability + egress-IP canaries you trigger, each to a " +
                    "host you can see before tapping.",
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

@Composable
private fun PostureSection(title: String, body: String) {
    SuiteCard {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
