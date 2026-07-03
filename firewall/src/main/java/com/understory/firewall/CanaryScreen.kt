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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.understory.security.SecureButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Egress Canaries (design-v2/firewall.md §5.6). The empirical "is my
 * DNS/egress actually what I think" proof. Explicit-tap-only; each probe
 * names its exact host on the button face; all calls on Dispatchers.IO.
 */
@Composable
fun CanaryScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    // The DoT canary targets the configured Private DNS host (if any).
    val dotHost = remember {
        val cur = PrivateDnsApplier.current(ctx)
        if (cur.mode == "hostname") cur.specifier?.takeIf { it.isNotBlank() } else null
    }

    var egress by remember { mutableStateOf<CanaryProbes.ProbeResult?>(null) }
    var resolver by remember { mutableStateOf<CanaryProbes.ProbeResult?>(null) }
    var dot by remember { mutableStateOf<CanaryProbes.ProbeResult?>(null) }
    var running by remember { mutableStateOf<String?>(null) }

    SuiteScaffold(title = "Egress canaries", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            BoundaryText(
                "These probes send one request each to the named host when you tap. " +
                    "Nothing else leaves your device. We can't read Tailscale's DNS " +
                    "settings directly — this checks what actually happens on the wire."
            )

            ProbeCard(
                probe = CanaryProbes.Probe.EGRESS_IP,
                result = egress,
                running = running == "egress",
            ) {
                running = "egress"
                scope.launch {
                    egress = withContext(Dispatchers.IO) { CanaryProbes.egressIp() }
                    running = null
                }
            }

            ProbeCard(
                probe = CanaryProbes.Probe.RESOLVER_IDENTITY,
                result = resolver,
                running = running == "resolver",
            ) {
                running = "resolver"
                scope.launch {
                    resolver = withContext(Dispatchers.IO) { CanaryProbes.resolverIdentity() }
                    running = null
                }
            }

            ProbeCard(
                probe = CanaryProbes.Probe.DOT_REACH,
                result = dot,
                running = running == "dot",
                hostOverride = dotHost?.let { "$it:853" },
                enabled = dotHost != null,
            ) {
                val host = dotHost ?: return@ProbeCard
                running = "dot"
                scope.launch {
                    dot = withContext(Dispatchers.IO) { CanaryProbes.dotReachability(host) }
                    running = null
                }
            }
            if (dotHost == null) {
                BoundaryText(
                    "No Private DNS host is configured, so the DoT reachability probe is " +
                        "unavailable. Set one under DNS hardening first."
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

@Composable
private fun ProbeCard(
    probe: CanaryProbes.Probe,
    result: CanaryProbes.ProbeResult?,
    running: Boolean,
    hostOverride: String? = null,
    enabled: Boolean = true,
    onRun: () -> Unit,
) {
    SuiteCard {
        Text(probe.title, style = MaterialTheme.typography.titleMedium)
        Text(
            probe.description,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureButton(
            onClick = onRun,
            enabled = enabled && !running,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                if (running) "Checking ${hostOverride ?: probe.host}…"
                else "Check ${hostOverride ?: probe.host}"
            )
        }
        result?.let { r ->
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                r.detail,
                style = MaterialTheme.typography.bodyMedium,
                color = if (r.ok) UnderstoryTheme.semantic.success
                else MaterialTheme.colorScheme.error,
            )
        }
    }
}
