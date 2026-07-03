package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.understory.security.A11yProbe
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The Egress Dashboard (design-v2/firewall.md §2.1). The primary surface
 * has NO VPN switch in Companion — it can never imply we hold or want the
 * slot. Cards trace to rootless reads; the tools row routes to the sub
 * screens and the walled-off Standalone hub.
 */
@Composable
fun EgressDashboardScreen(onOpen: (FirewallRoute) -> Unit) {
    val ctx = LocalContext.current
    val title = stringResource(R.string.app_name)

    var posture by remember { mutableStateOf<TunnelPosture?>(null) }
    var auditCount by remember { mutableStateOf<Int?>(null) }
    var dnsSummary by remember { mutableStateOf<String?>(null) }
    var trafficGranted by remember { mutableStateOf(false) }
    var refreshTick by remember { mutableStateOf(0) }
    val a11y = remember { A11yProbe.check(ctx) }

    suspend fun refresh() {
        posture = withContext(Dispatchers.IO) { TunnelPosture.read(ctx) }
        val findings = withContext(Dispatchers.IO) { RemoteAdminAudit.scan(ctx) }
        val ack = FirewallSettings.getAuditAcknowledged(ctx)
        auditCount = findings.count { it.packageName !in ack }
        dnsSummary = withContext(Dispatchers.IO) { dnsOneLine(ctx) }
        trafficGranted = withContext(Dispatchers.IO) { TrafficAccounting.hasUsageAccess(ctx) }
    }

    LaunchedEffect(Unit) { refresh() }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) {
                // Recompute on resume via a fire-and-forget effect trigger.
                refreshTick++
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(refreshTick) { if (refreshTick > 0) refresh() }

    SuiteScaffold(title = title) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            // 1. Live one-line posture summary (no switch).
            Text(
                text = summaryLine(posture, dnsSummary, auditCount),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // 2. A11y warning banner (A6) — only when non-system services exist.
            if (a11y.activeServiceCount > 0) {
                Surface(
                    color = UnderstoryTheme.semantic.warningContainer,
                    contentColor = UnderstoryTheme.semantic.warning,
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        "⚠  ${a11y.activeServiceCount} third-party accessibility service(s) " +
                            "active. An a11y service can read this screen.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(UnderstoryTheme.spacing.md),
                    )
                }
            }

            // 3. Tunnel Posture card.
            SuiteCard(onClick = { onOpen(FirewallRoute.TunnelPosture) }) {
                Text("Tunnel posture", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                val p = posture
                if (p == null) {
                    Text("Reading…", style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    val (chip, tone) = tunnelChip(p)
                    VerdictChip(chip, tone)
                }
            }

            // 4. Remote-Admin Audit card.
            SuiteCard(onClick = { onOpen(FirewallRoute.Audit) }) {
                Text("Remote-admin audit", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    when (val c = auditCount) {
                        null -> "Scanning…"
                        0 -> "No apps need review."
                        else -> "$c app(s) can control this device — review"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if ((auditCount ?: 0) > 0) UnderstoryTheme.semantic.warning
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // 5. DNS Hardening card.
            SuiteCard(onClick = { onOpen(FirewallRoute.Dns) }) {
                Text("DNS hardening", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    dnsSummary ?: "Reading…",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // 6. Traffic card — granted vs opt-in affordance (never dead chart).
            SuiteCard(onClick = { onOpen(FirewallRoute.Traffic) }) {
                Text("Traffic by app", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    if (trafficGranted) "See who talked and how much (accounting, not blocking)."
                    else "Grant Usage access to see per-app traffic — nothing leaves your device.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // 7. Tools rows.
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            SuiteListRow(
                headline = "Restrict worklist",
                supporting = "Apps you've flagged — open Android's own per-app controls.",
                onClick = { onOpen(FirewallRoute.Restrict) },
            )
            SuiteListRow(
                headline = "Egress canaries",
                supporting = "Prove on the wire what your DNS / exit IP actually is.",
                onClick = { onOpen(FirewallRoute.Canary) },
            )
            SuiteListRow(
                headline = "Network posture",
                supporting = "What this app is, and how it works alongside Tailscale.",
                onClick = { onOpen(FirewallRoute.Posture) },
            )
            SuiteListRow(
                headline = "Limits & diagnostics",
                supporting = "The exact edge of the tool + logs.",
                onClick = { onOpen(FirewallRoute.Limits) },
            )
            SuiteListRow(
                headline = "Standalone mode…",
                supporting = "Opt-in real blocking for no-VPN devices. Off by default.",
                onClick = { onOpen(FirewallRoute.StandaloneHub) },
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

/** Compose the header one-line summary. */
private fun summaryLine(p: TunnelPosture?, dns: String?, audit: Int?): String {
    if (p == null) return "Reading your network posture…"
    val slot = when {
        p.aVpnIsUp == Tri.YES && p.alwaysOnIsTailscale == Tri.YES ->
            "Tailscale holds the VPN slot ✓"
        p.aVpnIsUp == Tri.YES -> "A VPN holds the slot ✓"
        p.aVpnIsUp == Tri.NO -> "No VPN is up"
        else -> "VPN state unknown"
    }
    val dnsPart = dns ?: "DNS: reading"
    val auditPart = when (audit) {
        null, 0 -> null
        else -> "$audit app(s) to review"
    }
    return listOfNotNull(slot, dnsPart, auditPart).joinToString(" · ")
}

/** The dashboard's compact DNS line. */
internal fun dnsOneLine(ctx: android.content.Context): String {
    val cur = PrivateDnsApplier.current(ctx)
    return when (cur.mode) {
        "hostname" -> "DNS encrypted → ${cur.specifier ?: "(no host set)"} ✓"
        "off" -> "DNS off (unencrypted)"
        else -> "DNS opportunistic"
    }
}

/** Map a TunnelPosture verdict to a chip label + tone (§5.1 ladder). */
internal fun tunnelChip(p: TunnelPosture): Pair<String, ChipTone> = when (p.verdict) {
    TunnelPosture.Verdict.NO_TAILSCALE -> "No Tailscale detected" to ChipTone.NEUTRAL
    TunnelPosture.Verdict.STRONG -> "Tunnel posture: strong" to ChipTone.PRIMARY
    TunnelPosture.Verdict.HARDENING -> "Tunnel up — hardening available" to ChipTone.WARNING
    TunnelPosture.Verdict.INSTALLED_NO_VPN -> "Tailscale installed but no VPN is up" to ChipTone.WARNING
    TunnelPosture.Verdict.UNKNOWN -> "Tunnel state unknown" to ChipTone.UNKNOWN
}
