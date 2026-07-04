package com.understory.firewall

import android.Manifest
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Router
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.understory.elevation.Elevation
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * ARP spoof guard (companion-first, detect-and-warn). See [ArpGuard] for the
 * doctrine: this DETECTS ARP spoofing and never claims to prevent it, and it
 * needs the OPTIONAL Shizuku grant to read the kernel neighbor table.
 *
 * When not elevated we explain that plainly and route to [FirewallRoute.Elevation]
 * (via [onOpenElevation]) — never a dead scan button. When elevated: a Scan
 * button (off-main), the neighbor table, findings in a warning-toned card,
 * set/clear baseline, and a best-effort background Watch.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ArpGuardScreen(onBack: () -> Unit, onOpenElevation: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var canRun by remember { mutableStateOf(Elevation.canRunShell(ctx)) }
    var scanResult by remember { mutableStateOf<ArpGuard.ScanResult?>(null) }
    var hasBaseline by remember { mutableStateOf(ArpGuard.hasBaseline(ctx)) }
    var statusLine by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    // Watch state.
    var watchEnabled by remember { mutableStateOf(ArpGuardWatch.isEnabled(ctx)) }
    var watchInterval by remember { mutableStateOf(ArpGuardWatch.getIntervalHours(ctx)) }
    var watchLastRun by remember { mutableStateOf(ArpGuardWatch.getLastRunMillis(ctx)) }
    var watchLastResult by remember { mutableStateOf(ArpGuardWatch.getLastResult(ctx)) }
    var canNotify by remember { mutableStateOf(ArpGuardNotifier.canNotify(ctx)) }

    fun refreshState() {
        canRun = Elevation.canRunShell(ctx)
        hasBaseline = ArpGuard.hasBaseline(ctx)
        watchEnabled = ArpGuardWatch.isEnabled(ctx)
        watchInterval = ArpGuardWatch.getIntervalHours(ctx)
        watchLastRun = ArpGuardWatch.getLastRunMillis(ctx)
        watchLastResult = ArpGuardWatch.getLastResult(ctx)
        canNotify = ArpGuardNotifier.canNotify(ctx)
    }

    // Re-read on resume: the user may have granted Shizuku or notifications while
    // we were backgrounded.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_START) refreshState()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val notifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { canNotify = ArpGuardNotifier.canNotify(ctx) }

    fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            runCatching {
                ctx.startActivity(
                    Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                        .putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            }
        }
    }

    fun doScan() {
        busy = true
        statusLine = null
        scope.launch {
            val r = withContext(Bg.io) { ArpGuard.scan(ctx) }
            scanResult = r
            hasBaseline = ArpGuard.hasBaseline(ctx)
            busy = false
        }
    }

    fun doSetBaseline() {
        busy = true
        scope.launch {
            val outcome = withContext(Bg.io) { ArpGuard.setBaseline(ctx) }
            statusLine = when (outcome) {
                is ArpGuard.Outcome.Ok -> outcome.detail
                is ArpGuard.Outcome.Failed -> outcome.message
                ArpGuard.Outcome.NeedsElevation ->
                    "Grant Shizuku first — the gateway MAC can't be read without it."
            }
            hasBaseline = ArpGuard.hasBaseline(ctx)
            // Re-scan so findings reflect the new baseline immediately.
            val r = withContext(Bg.io) { ArpGuard.scan(ctx) }
            scanResult = r
            busy = false
        }
    }

    fun doClearBaseline() {
        ArpGuard.clearBaseline(ctx)
        hasBaseline = false
        statusLine = "Baseline cleared."
        // Re-scan so the removed gateway-change finding disappears.
        doScan()
    }

    fun setWatch(on: Boolean) {
        busy = true
        scope.launch {
            withContext(Bg.io) {
                if (on) ArpGuardWatch.enable(ctx) else ArpGuardWatch.disable(ctx)
            }
            refreshState()
            busy = false
        }
    }

    fun setWatchInterval(hours: Int) {
        ArpGuardWatch.setIntervalHours(ctx, hours)
        watchInterval = ArpGuardWatch.getIntervalHours(ctx)
        if (watchEnabled) {
            scope.launch { withContext(Bg.io) { ArpGuardWatchScheduler.schedule(ctx) } }
        }
    }

    SuiteScaffold(
        title = stringResource(R.string.arpguard_title),
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

            Text(
                stringResource(R.string.arpguard_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (!canRun) {
                NeedsElevationCard(onOpenElevation = onOpenElevation)
                BoundaryCard()
                Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
                return@Column
            }

            // --- Scan control ---
            SuiteCard {
                SecureButton(
                    onClick = { doScan() },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (busy) stringResource(R.string.arpguard_scanning)
                        else stringResource(R.string.arpguard_scan)
                    )
                }
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    stringResource(R.string.arpguard_scan_hint),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            statusLine?.let { line ->
                Text(
                    line,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            when (val r = scanResult) {
                null -> Unit // nothing scanned yet
                is ArpGuard.ScanResult.NeedsElevation -> {
                    // Grant was revoked between the gate and the scan.
                    NeedsElevationCard(onOpenElevation = onOpenElevation)
                }
                is ArpGuard.ScanResult.Failed -> {
                    Surface(
                        color = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        shape = MaterialTheme.shapes.medium,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            r.message,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
                        )
                    }
                }
                is ArpGuard.ScanResult.Ok -> {
                    FindingsSection(r.findings)
                    BaselineSection(
                        hasBaseline = hasBaseline,
                        gatewayIp = r.gatewayIp,
                        busy = busy,
                        onSet = { doSetBaseline() },
                        onClear = { doClearBaseline() },
                    )
                    NeighborTableSection(r)
                }
            }

            // --- Watch ---
            WatchSection(
                enabled = watchEnabled,
                interval = watchInterval,
                lastRun = watchLastRun,
                lastResult = watchLastResult,
                canNotify = canNotify,
                busy = busy,
                onToggle = { setWatch(it) },
                onInterval = { setWatchInterval(it) },
                onRequestNotifications = { requestNotifications() },
            )

            BoundaryCard()
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

// ---------------------------------------------------------------------------
// Not-elevated affordance (routes to Elevation, never a dead control)
// ---------------------------------------------------------------------------

@Composable
private fun NeedsElevationCard(onOpenElevation: () -> Unit) {
    Surface(
        color = UnderstoryTheme.semantic.warningContainer,
        contentColor = UnderstoryTheme.semantic.warning,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(
                stringResource(R.string.arpguard_needs_shizuku_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                stringResource(R.string.arpguard_needs_shizuku_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureButton(
                onClick = onOpenElevation,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.arpguard_open_elevation)) }
        }
    }
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

@Composable
private fun FindingsSection(findings: List<ArpGuard.Finding>) {
    SuiteSectionHeader(stringResource(R.string.arpguard_findings_header))
    if (findings.isEmpty()) {
        SuiteCard {
            Text(
                stringResource(R.string.arpguard_no_findings_title),
                style = MaterialTheme.typography.titleMedium,
                color = UnderstoryTheme.semantic.success,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                stringResource(R.string.arpguard_no_findings_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        return
    }
    for (f in findings) {
        val sevLabel = when (f.severity) {
            ArpGuard.Severity.HIGH -> stringResource(R.string.arpguard_sev_high)
            ArpGuard.Severity.MEDIUM -> stringResource(R.string.arpguard_sev_medium)
        }
        Surface(
            color = UnderstoryTheme.semantic.warningContainer,
            contentColor = UnderstoryTheme.semantic.warning,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(UnderstoryTheme.spacing.lg)) {
                Text(
                    "$sevLabel · ${f.title}",
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    f.detail,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

@Composable
private fun BaselineSection(
    hasBaseline: Boolean,
    gatewayIp: String?,
    busy: Boolean,
    onSet: () -> Unit,
    onClear: () -> Unit,
) {
    SuiteSectionHeader(stringResource(R.string.arpguard_baseline_header))
    SuiteCard {
        if (!hasBaseline) {
            Text(
                stringResource(R.string.arpguard_baseline_none),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (gatewayIp != null) {
            Text(
                gatewayIp,
                style = MaterialTheme.typography.bodyLarge,
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
            SecureOutlinedButton(onClick = onSet, enabled = !busy) {
                Text(stringResource(R.string.arpguard_baseline_set))
            }
            if (hasBaseline) {
                SecureOutlinedButton(onClick = onClear, enabled = !busy) {
                    Text(stringResource(R.string.arpguard_baseline_clear))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Neighbor table
// ---------------------------------------------------------------------------

@Composable
private fun NeighborTableSection(ok: ArpGuard.ScanResult.Ok) {
    SuiteSectionHeader(stringResource(R.string.arpguard_table_header))
    if (ok.neighbors.isEmpty()) {
        SuiteCard {
            Text(
                stringResource(R.string.arpguard_empty_table),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        return
    }
    val gatewayTag = stringResource(R.string.arpguard_gateway_tag)
    val noMac = stringResource(R.string.arpguard_no_mac)
    for (n in ok.neighbors) {
        val isGateway = ok.gatewayIp != null && n.ip == ok.gatewayIp
        val headline = if (isGateway) "${n.ip}  ($gatewayTag)" else n.ip
        val macPart = if (n.mac.isBlank()) noMac else n.mac
        SuiteListRow(
            headline = headline,
            supporting = "$macPart · ${n.dev} · ${n.state}",
            leading = {
                if (isGateway) {
                    androidx.compose.material3.Icon(
                        imageVector = Icons.Filled.Router,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
        )
    }
    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
    Text(
        "${stringResource(R.string.arpguard_source_prefix)} ${ok.source}",
        style = MaterialTheme.typography.labelSmall,
        fontFamily = FontFamily.Monospace,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

// ---------------------------------------------------------------------------
// Background watch
// ---------------------------------------------------------------------------

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun WatchSection(
    enabled: Boolean,
    interval: Int,
    lastRun: Long,
    lastResult: String?,
    canNotify: Boolean,
    busy: Boolean,
    onToggle: (Boolean) -> Unit,
    onInterval: (Int) -> Unit,
    onRequestNotifications: () -> Unit,
) {
    SuiteSectionHeader(stringResource(R.string.arpguard_watch_header))
    SuiteCard {
        SwitchRow(
            label = stringResource(R.string.arpguard_watch_label),
            checked = enabled,
            enabled = !busy,
            onCheckedChange = onToggle,
            supporting = if (enabled)
                stringResource(R.string.arpguard_watch_on, intervalLabelArp(interval))
            else stringResource(R.string.arpguard_watch_off),
        )
    }

    if (!enabled) return

    if (!canNotify) {
        Surface(
            color = UnderstoryTheme.semantic.warningContainer,
            contentColor = UnderstoryTheme.semantic.warning,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(UnderstoryTheme.spacing.lg)) {
                Text(
                    stringResource(R.string.arpguard_notif_off_title),
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    stringResource(R.string.arpguard_notif_off_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                SecureButton(
                    onClick = onRequestNotifications,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.arpguard_allow_notifications)) }
            }
        }
    }

    SuiteCard {
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
        ) {
            for (h in ArpGuardWatch.INTERVAL_CHOICES) {
                SecureOutlinedButton(onClick = { onInterval(h) }) {
                    Text(if (h == interval) "• ${intervalLabelArp(h)}" else intervalLabelArp(h))
                }
            }
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            stringResource(R.string.arpguard_watch_note),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    SuiteSectionHeader(stringResource(R.string.arpguard_watch_last))
    SuiteCard {
        Text(
            if (lastRun > 0L) relativeTimeArp(lastRun)
            else stringResource(R.string.arpguard_watch_not_run),
            style = MaterialTheme.typography.bodyLarge,
        )
        if (lastResult != null) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                lastResult,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Boundary
// ---------------------------------------------------------------------------

@Composable
private fun BoundaryCard() {
    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.xs),
    ) {
        androidx.compose.material3.Icon(
            imageVector = Icons.Filled.Info,
            contentDescription = null,
            tint = UnderstoryTheme.semantic.dim,
            modifier = Modifier.padding(end = UnderstoryTheme.spacing.sm),
        )
        Text(
            stringResource(R.string.arpguard_boundary),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
    }
}

/** "6 hours" / "1 day" / "3 days" for an hour count. */
private fun intervalLabelArp(hours: Int): String = when {
    hours < 24 -> "$hours hours"
    hours == 24 -> "1 day"
    else -> "${hours / 24} days"
}

/** Coarse relative-time label for the last-run stamp. No seconds precision. */
private fun relativeTimeArp(millis: Long): String {
    val delta = System.currentTimeMillis() - millis
    if (delta < 0) return "just now"
    val mins = delta / 60000L
    return when {
        mins < 1 -> "just now"
        mins < 60 -> "$mins min ago"
        mins < 60 * 24 -> "${mins / 60} h ago"
        else -> "${mins / (60 * 24)} d ago"
    }
}
