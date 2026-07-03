package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * What this app can't do (design-v2/firewall.md §5.8). The Limits card renders
 * the honest "boundaries" list verbatim — a doctrine feature (CD-4b), framed as
 * a plain capability statement rather than an apology.
 *
 * The Diagnostics affordance is ENG-ONLY: it is wrapped in a
 * `BuildConfig.FLAVOR == "eng"` guard so the shipping (prod) build shows no
 * button, no logs link, and no route into [com.understory.security.DiagnosticsScreen].
 * In eng builds the button remains, so QA can still reach the log dump.
 */
@Composable
fun LimitsScreen(onBack: () -> Unit, onDiagnostics: () -> Unit) {
    val isEng = BuildConfig.FLAVOR == "eng"
    val title = if (isEng) "Limits & diagnostics" else "Limits"
    SuiteScaffold(title = title, onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(40.dp),
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    "Net Audit is deliberately honest about its edges. " +
                        "Here is exactly where the tool stops — by design.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
            SuiteCard {
                Text("Where the tool stops", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                for (limit in LIMITS) {
                    Text(
                        "•  $limit",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(vertical = UnderstoryTheme.spacing.xs),
                    )
                }
            }
            if (isEng) {
                // ENG-ONLY: the Diagnostics log surface never ships in prod.
                SecureOutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
                    Text("Diagnostics")
                }
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
