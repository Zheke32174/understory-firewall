package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Insights
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.QueryStats
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SupervisorAccount
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.understory.security.A11yProbe
import com.understory.security.SuiteStatusFooter
import com.understory.security.secureClickable
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The Egress Dashboard (design-v2/firewall.md §2.1). A polished, three-section
 * product surface — Overview / Tools / About — driven by a Material3
 * [NavigationBar]. The primary surface has NO VPN switch in Companion: it can
 * never imply we hold or want the VPN slot. Every card traces to a rootless read
 * and routes into a detail screen.
 *
 * The Diagnostics dev surface and the dim suite-status smoke-test strip are
 * ENG-ONLY: both are gated on `BuildConfig.FLAVOR == "eng"`, so the shipping
 * (prod) build presents a clean product face with no dev affordance.
 */

/** Top-level dashboard sections shown in the [NavigationBar]. */
private enum class DashboardTab(
    val label: String,
    val icon: ImageVector,
) {
    Overview("Overview", Icons.Filled.Shield),
    Tools("Tools", Icons.Filled.NetworkCheck),
    About("About", Icons.Filled.Info),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EgressDashboardScreen(onOpen: (FirewallRoute) -> Unit) {
    val ctx = LocalContext.current
    val title = stringResource(R.string.app_name)
    val isEng = BuildConfig.FLAVOR == "eng"

    var posture by remember { mutableStateOf<TunnelPosture?>(null) }
    var auditCount by remember { mutableStateOf<Int?>(null) }
    var dnsSummary by remember { mutableStateOf<String?>(null) }
    var trafficGranted by remember { mutableStateOf(false) }
    var watchEnabled by remember { mutableStateOf(false) }
    var watchLastRun by remember { mutableStateOf(0L) }
    var refreshTick by remember { mutableStateOf(0) }
    val a11y = remember { A11yProbe.check(ctx) }

    var tabName by rememberSaveable { mutableStateOf(DashboardTab.Overview.name) }
    val tab = remember(tabName) { DashboardTab.valueOf(tabName) }

    suspend fun refresh() {
        posture = withContext(Dispatchers.IO) { TunnelPosture.read(ctx) }
        val findings = withContext(Dispatchers.IO) { RemoteAdminAudit.scan(ctx) }
        val ack = FirewallSettings.getAuditAcknowledged(ctx)
        auditCount = findings.count { it.packageName !in ack }
        dnsSummary = withContext(Dispatchers.IO) { dnsOneLine(ctx) }
        trafficGranted = withContext(Dispatchers.IO) { TrafficAccounting.hasUsageAccess(ctx) }
        watchEnabled = withContext(Dispatchers.IO) { PostureWatch.isEnabled(ctx) }
        watchLastRun = withContext(Dispatchers.IO) { PostureWatch.getLastRunMillis(ctx) }
    }

    LaunchedEffect(Unit) { refresh() }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) {
                refreshTick++
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(refreshTick) { if (refreshTick > 0) refresh() }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(title, style = MaterialTheme.typography.titleLarge)
                        Text(
                            tab.label,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
            ) {
                for (t in DashboardTab.entries) {
                    NavigationBarItem(
                        selected = t == tab,
                        onClick = { tabName = t.name },
                        icon = {
                            Icon(
                                imageVector = t.icon,
                                contentDescription = null,
                            )
                        },
                        label = { Text(t.label) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.onPrimaryContainer,
                            selectedTextColor = MaterialTheme.colorScheme.onSurface,
                            indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                            unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        ),
                    )
                }
            }
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            when (tab) {
                DashboardTab.Overview -> OverviewSection(
                    posture = posture,
                    dnsSummary = dnsSummary,
                    auditCount = auditCount,
                    trafficGranted = trafficGranted,
                    watchEnabled = watchEnabled,
                    watchLastRun = watchLastRun,
                    a11yServiceCount = a11y.activeServiceCount,
                    onOpen = onOpen,
                )
                DashboardTab.Tools -> ToolsSection(onOpen = onOpen)
                DashboardTab.About -> AboutSection(isEng = isEng, onOpen = onOpen)
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.xl))

            // ENG-ONLY: the suite smoke-test strip is a dev/debug surface — it
            // never appears in the shipping (prod) chrome. In eng it also keeps
            // its triple-tap "mark the log" gesture (see SuiteStatusFooter).
            if (isEng) {
                SuiteStatusFooter(
                    Modifier.padding(bottom = UnderstoryTheme.spacing.md),
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Overview — the live security posture at a glance.
// ---------------------------------------------------------------------------

@Composable
private fun OverviewSection(
    posture: TunnelPosture?,
    dnsSummary: String?,
    auditCount: Int?,
    trafficGranted: Boolean,
    watchEnabled: Boolean,
    watchLastRun: Long,
    a11yServiceCount: Int,
    onOpen: (FirewallRoute) -> Unit,
) {
    // Hero summary line — the one-glance verdict.
    Text(
        text = summaryLine(posture, dnsSummary, auditCount),
        style = MaterialTheme.typography.bodyLarge,
        color = MaterialTheme.colorScheme.onSurface,
    )

    // A11y warning banner (A6) — only when a non-system a11y service exists.
    if (a11yServiceCount > 0) {
        Surface(
            color = UnderstoryTheme.semantic.warningContainer,
            contentColor = UnderstoryTheme.semantic.warning,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier.padding(UnderstoryTheme.spacing.md),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Filled.Security,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.size(UnderstoryTheme.spacing.sm))
                Text(
                    "$a11yServiceCount third-party accessibility service(s) active. " +
                        "An a11y service can read this screen.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }

    // Tunnel posture.
    val (tunnelVerdict, tunnelTone) = when (val p = posture) {
        null -> "Reading…" to StatusTone.NEUTRAL
        else -> tunnelChip(p).let { (label, chip) -> label to chip.toStatusTone() }
    }
    StatusCard(
        icon = Icons.Filled.VpnKey,
        title = "Tunnel posture",
        verdict = tunnelVerdict,
        tone = tunnelTone,
        onClick = { onOpen(FirewallRoute.TunnelPosture) },
    )

    // DNS hardening.
    StatusCard(
        icon = Icons.Filled.Dns,
        title = "DNS hardening",
        verdict = dnsSummary ?: "Reading…",
        tone = dnsTone(dnsSummary),
        onClick = { onOpen(FirewallRoute.Dns) },
    )

    // Data usage (traffic accounting).
    StatusCard(
        icon = Icons.Filled.QueryStats,
        title = "Data usage",
        verdict = if (trafficGranted) "Per-app accounting on — see who talked and how much."
        else "Grant Usage access to see per-app traffic. Nothing leaves your device.",
        tone = if (trafficGranted) StatusTone.NEUTRAL else StatusTone.INFO,
        onClick = { onOpen(FirewallRoute.Traffic) },
    )

    // Remote-admin audit.
    val auditVerdict = when (val c = auditCount) {
        null -> "Scanning…"
        0 -> "No apps can remotely control this device."
        else -> "$c app(s) can control this device — review"
    }
    StatusCard(
        icon = Icons.Filled.SupervisorAccount,
        title = "Remote-admin audit",
        verdict = auditVerdict,
        tone = if ((auditCount ?: 0) > 0) StatusTone.WARNING else StatusTone.NEUTRAL,
        onClick = { onOpen(FirewallRoute.Audit) },
    )

    // Scheduled posture re-check — opt-in background watcher.
    StatusCard(
        icon = Icons.Filled.Schedule,
        title = "Posture watch",
        verdict = if (watchEnabled) {
            if (watchLastRun > 0L) "On — re-checking in the background. Alerts on new findings."
            else "On — baseline recorded. Alerts on new findings."
        } else "Off — turn on periodic re-checks that alert you when posture worsens.",
        tone = if (watchEnabled) StatusTone.GOOD else StatusTone.INFO,
        onClick = { onOpen(FirewallRoute.PostureWatch) },
    )
}

// ---------------------------------------------------------------------------
// Tools — the active, opt-in surfaces.
// ---------------------------------------------------------------------------

@Composable
private fun ToolsSection(onOpen: (FirewallRoute) -> Unit) {
    ToolRow(
        icon = Icons.Filled.Shield,
        title = "App firewall (slot-free)",
        supporting = "Block apps on every network without the VPN slot. Needs Shizuku; " +
            "coexists with Tailscale. Not a routing tunnel.",
        onClick = { onOpen(FirewallRoute.AppFirewall) },
    )
    ToolRow(
        icon = Icons.Filled.Lock,
        title = "Firewall policy",
        supporting = "Default policy (allow-all vs lockdown), block-when-screen-off, and " +
            "saved profiles. Adds a Quick-Settings Lockdown tile.",
        onClick = { onOpen(FirewallRoute.PolicyControls) },
    )
    ToolRow(
        icon = Icons.AutoMirrored.Filled.List,
        title = "Restrict worklist",
        supporting = "Apps you've flagged — open Android's own per-app data controls.",
        onClick = { onOpen(FirewallRoute.Restrict) },
    )
    ToolRow(
        icon = Icons.Filled.Radar,
        title = "Egress canaries",
        supporting = "Prove on the wire what your DNS and exit IP actually are.",
        onClick = { onOpen(FirewallRoute.Canary) },
    )
    ToolRow(
        icon = Icons.Filled.Router,
        title = "ARP spoof guard",
        supporting = "Watch the LAN neighbor table for MITM",
        onClick = { onOpen(FirewallRoute.ArpGuard) },
    )
    ToolRow(
        icon = Icons.Filled.Shield,
        title = "DNS rebinding audit",
        supporting = "Flag public names that resolve to private IPs",
        onClick = { onOpen(FirewallRoute.Rebinding) },
    )
    ToolRow(
        icon = Icons.Filled.LocationOn,
        title = "Mock location",
        supporting = "Feed a fake GPS location to apps",
        onClick = { onOpen(FirewallRoute.MockLocation) },
    )
    ToolRow(
        icon = Icons.Filled.Lock,
        title = "Standalone mode",
        supporting = "Opt-in real blocking for no-VPN devices. Off by default; " +
            "refuses to start while any VPN is up.",
        onClick = { onOpen(FirewallRoute.StandaloneHub) },
    )
    ToolRow(
        icon = Icons.Filled.AdminPanelSettings,
        title = "Elevation (optional)",
        supporting = "Rootless by default. Optionally grant Shizuku or Dhizuku to " +
            "turn advisory controls into real per-app enforcement — no VPN slot used.",
        onClick = { onOpen(FirewallRoute.Elevation) },
    )
}

// ---------------------------------------------------------------------------
// About — how the tool works, and where it stops.
// ---------------------------------------------------------------------------

@Composable
private fun AboutSection(isEng: Boolean, onOpen: (FirewallRoute) -> Unit) {
    ToolRow(
        icon = Icons.Filled.Insights,
        title = "Network posture",
        supporting = "What this app is, and how it works alongside Tailscale.",
        onClick = { onOpen(FirewallRoute.Posture) },
    )
    ToolRow(
        icon = Icons.Filled.Info,
        title = if (isEng) "Limits & diagnostics" else "Limits",
        supporting = if (isEng) "The exact edge of the tool, plus dev logs."
        else "The exact edge of the tool — what it deliberately can't do.",
        onClick = { onOpen(FirewallRoute.Limits) },
    )
}

// ---------------------------------------------------------------------------
// Reusable presentation pieces.
// ---------------------------------------------------------------------------

/** Verdict tone → icon tint + verdict text color for a [StatusCard]. */
private enum class StatusTone { NEUTRAL, INFO, WARNING, GOOD }

@Composable
private fun StatusTone.tint(): androidx.compose.ui.graphics.Color = when (this) {
    StatusTone.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
    StatusTone.INFO -> MaterialTheme.colorScheme.primary
    StatusTone.WARNING -> UnderstoryTheme.semantic.warning
    StatusTone.GOOD -> UnderstoryTheme.semantic.success
}

private fun ChipTone.toStatusTone(): StatusTone = when (this) {
    ChipTone.PRIMARY -> StatusTone.GOOD
    ChipTone.WARNING -> StatusTone.WARNING
    ChipTone.NEUTRAL -> StatusTone.NEUTRAL
    ChipTone.UNKNOWN -> StatusTone.NEUTRAL
}

private fun dnsTone(dns: String?): StatusTone = when {
    dns == null -> StatusTone.NEUTRAL
    dns.contains("encrypted") -> StatusTone.GOOD
    dns.contains("off") -> StatusTone.WARNING
    else -> StatusTone.NEUTRAL
}

/**
 * A polished Overview status card: a leading icon, the section title, a one-line
 * verdict in a tone-appropriate color, and a trailing chevron into the detail
 * screen. The whole card is [secureClickable] with `Role.Button` semantics.
 */
@Composable
private fun StatusCard(
    icon: ImageVector,
    title: String,
    verdict: String,
    tone: StatusTone,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurface,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = modifier
            .fillMaxWidth()
            .secureClickable(onClick)
            .semantics(mergeDescendants = true) { role = Role.Button },
    ) {
        Row(
            modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier.size(40.dp),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = tone.tint(),
                    modifier = Modifier.size(28.dp),
                )
            }
            Spacer(Modifier.size(UnderstoryTheme.spacing.md))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    verdict,
                    style = MaterialTheme.typography.bodyMedium,
                    color = tone.tint(),
                )
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

/**
 * A Tools/About row rendered as a card with a leading icon, a headline, a
 * supporting line, and a trailing chevron. Whole-row [secureClickable].
 */
@Composable
private fun ToolRow(
    icon: ImageVector,
    title: String,
    supporting: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurface,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = modifier
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
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(28.dp),
            )
            Spacer(Modifier.size(UnderstoryTheme.spacing.md))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    supporting,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
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
