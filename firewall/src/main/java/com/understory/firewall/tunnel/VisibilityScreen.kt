package com.understory.firewall.tunnel

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
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
import com.understory.firewall.FirewallMode
import com.understory.firewall.FirewallSettings
import com.understory.firewall.policy.BackendManager
import com.understory.net.engine.DropStats
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Connection visibility (S7). Two honest data sources, never mixed into a false
 * whole:
 *
 *   TUNNEL ON (S6 DNS-filter armed): a LIVE event log — DNS queries with the
 *     resolved domain, the owning app, and allow/block, plus per-app counts and
 *     clear/export. This is REAL per-flow data (the tun sees the query + we
 *     attribute via getConnectionOwnerUid).
 *
 *   TUNNEL OFF: the slot-free policy tier has no tun and cannot see domains, so
 *     we show the policy BLOCK COUNTERS (how many packets the app-drop path
 *     dropped this session, and how many apps the slot-free policy currently
 *     blocks) — NOT a fabricated per-domain log. We NEVER market slot-free
 *     packet capture: that needs the tun or root, and the copy says so.
 */
@Composable
fun VisibilityScreen(onBack: () -> Unit, onOpenTunnel: () -> Unit) {
    val ctx = LocalContext.current

    var tunnelActive by remember { mutableStateOf(isTunnelActive(ctx)) }
    var events by remember { mutableStateOf(DnsEventLog.recent(200)) }
    var perApp by remember { mutableStateOf(DnsEventLog.perAppCounts()) }
    var refresh by remember { mutableStateOf(0) }

    LaunchedEffect(refresh) {
        while (true) {
            tunnelActive = isTunnelActive(ctx)
            events = DnsEventLog.recent(200)
            perApp = DnsEventLog.perAppCounts()
            kotlinx.coroutines.delay(1200)
        }
    }

    SuiteScaffold(title = "Connection log", onBack = onBack, showSuiteFooter = false) { pad ->
        LazyColumn(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            if (tunnelActive || DnsEventLog.hasData()) {
                item { TunnelSummaryCard(perApp = perApp) }
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                        SecureOutlinedButton(onClick = {
                            copyToClipboard(ctx, "DNS event log", DnsEventLog.exportText())
                            refresh++
                        }) { Text("Export (copy)") }
                        SecureButton(onClick = {
                            DnsEventLog.clear()
                            refresh++
                        }) { Text("Clear") }
                    }
                }
                if (events.isEmpty()) {
                    item {
                        SuiteCard {
                            Text(
                                if (tunnelActive) "No DNS seen yet — traffic will appear here."
                                else "The tunnel is off; showing the last session's events.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                } else {
                    items(events, key = { it.seq }) { e ->
                        EventRow(e)
                    }
                }
            } else {
                item { PolicyCountersCard(ctx = ctx, onOpenTunnel = onOpenTunnel) }
            }
            item { Spacer(Modifier.height(UnderstoryTheme.spacing.lg)) }
        }
    }
}

@Composable
private fun TunnelSummaryCard(perApp: List<DnsEventLog.AppCount>) {
    SuiteCard {
        Text("DNS filtering — this session", style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            "${DnsEventLog.totalQueries()} queries · ${DnsEventLog.totalBlocked()} blocked",
            style = MaterialTheme.typography.bodyMedium,
        )
        if (perApp.isNotEmpty()) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text("By app:", style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            for (a in perApp.take(12)) {
                Text(
                    "• ${a.label} — ${a.queries} quer${if (a.queries == 1L) "y" else "ies"}, " +
                        "${a.blocked} blocked",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun EventRow(e: DnsEventLog.Event) {
    val time = remember(e.timestampMillis) {
        SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(e.timestampMillis))
    }
    SuiteCard {
        Row(modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
            Text(
                if (e.blocked) "BLOCK" else "allow",
                style = MaterialTheme.typography.labelMedium,
                color = if (e.blocked) UnderstoryTheme.semantic.warning
                else UnderstoryTheme.semantic.success,
            )
            Column(Modifier.weight(1f)) {
                Text(e.domain, style = MaterialTheme.typography.bodyMedium)
                Text("${e.appLabel} · $time",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun PolicyCountersCard(ctx: Context, onOpenTunnel: () -> Unit) {
    val blockedApps = remember {
        runCatching { BackendManager.get(ctx).blockedPackages().size }.getOrDefault(0)
    }
    SuiteCard {
        Text("The DNS-filter tunnel is off", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            "Per-domain visibility needs the tunnel (it reads DNS on the tun and " +
                "attributes each query to an app). With the tunnel off, we can't show a " +
                "per-domain log — the slot-free policy tier has no tunnel and can't see " +
                "domains.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        Text(
            "Slot-free policy: $blockedApps app(s) currently blocked on all networks.",
            style = MaterialTheme.typography.bodyMedium,
        )
        val dropped = DropStats.totalPackets()
        if (dropped > 0L) {
            Text(
                "Legacy app-drop tunnel: $dropped packet(s) dropped this session.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        BoundaryText(
            "We never claim slot-free packet capture — that needs the VPN tunnel or root. " +
                "Turn on the DNS-filter tunnel for a live per-domain, per-app log.",
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureButton(onClick = onOpenTunnel, modifier = Modifier.fillMaxWidth()) {
            Text("Open the DNS-filter tunnel")
        }
    }
}

/** True iff the S6 DNS-filter tunnel is armed right now. */
private fun isTunnelActive(ctx: Context): Boolean =
    FirewallSettings.getMode(ctx) == FirewallMode.STANDALONE &&
        FirewallSettings.isEngineArmed(ctx) &&
        FirewallSettings.getTunnelMode(ctx) == com.understory.firewall.TunnelMode.DNS_FILTER

private fun copyToClipboard(ctx: Context, label: String, text: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    cm?.setPrimaryClip(ClipData.newPlainText(label, text))
}
