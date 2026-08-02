package com.understory.godwall.ui

import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.understory.godwall.R
import com.understory.godwall.core.EngineState
import com.understory.godwall.core.GodwallVpnService
import com.understory.godwall.mesh.Mesh
import com.understory.godwall.ward.Canary
import com.understory.godwall.ward.ChildLock
import com.understory.godwall.ward.EnforcementBackend
import com.understory.godwall.ward.GatedCapability
import com.understory.godwall.ward.HealthCheck
import com.understory.godwall.ward.KillSwitch
import com.understory.godwall.ward.Lockdown
import com.understory.godwall.ward.Pause
import com.understory.godwall.ward.WardMode
import com.understory.godwall.ward.WardModeStore
import com.understory.godwall.ward.WardStatus
import com.understory.godwall.ward.DnsLeak
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * WARD — the home screen.
 *
 * ## Ported, not redesigned
 *
 * The layout is RethinkDNS's `HomeScreenFragment` with InviZible's module-state honesty and
 * Tailscale's tunnel line folded in, in the spec's order: master switch, mode chips, enforcement
 * badge, status cards, health banner, quick actions, overflow. Rethink's chip row is three modes;
 * two more are added because Godwall carries a tailnet node instead of deferring to one.
 *
 * ## The rule this screen is written against
 *
 * Every control here either does the thing it names, or is rendered disabled next to the sentence
 * saying why it cannot. There is no third case. Where the donor's mechanism needs a payload this
 * build was not given (Tor's control port, InviZible's busybox), the control is present, disabled,
 * and says which payload is missing — see [GatedCapability] and `docs/DONOR-ASSETS.md`.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WardScreen(
    padding: PaddingValues,
    onOpenDns: () -> Unit,
    onOpenApps: () -> Unit,
    onOpenMesh: () -> Unit,
    onOpenChain: () -> Unit,
    onOpenLog: () -> Unit,
    onOpenEnforcement: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val engine by EngineState.state.collectAsStateWithLifecycle()
    val pauseUntil by Pause.until.collectAsStateWithLifecycle()

    // Two clocks, deliberately. The status read runs privileged probes and a package-manager
    // pass, so it must not run every second; the pause countdown must. Conflating them would
    // either make the countdown stutter or make the probes thrash.
    var refresh by remember { mutableIntStateOf(0) }
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1_000)
            nowMs = System.currentTimeMillis()
        }
    }
    LaunchedEffect(Unit) {
        while (true) {
            delay(10_000)
            refresh++
        }
    }

    val status by produceState<WardStatus.Snapshot?>(initialValue = null, engine, refresh) {
        value = withContext(Bg.io) { WardStatus.read(ctx) }
    }

    // Android requires an explicit consent dialog before any app may hold the VPN slot, so
    // engaging is a two-step flow and a denial leaves the engine DOWN saying so rather than
    // silently no-opping.
    val consent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            GodwallVpnService.start(ctx)
        } else {
            EngineState.publish(
                EngineState.Phase.DOWN,
                ctx.getString(R.string.ward_consent_declined),
            )
        }
    }

    var mode by remember { mutableStateOf(WardModeStore.current(ctx)) }
    var lockdown by remember { mutableStateOf(Lockdown.isEnabled(ctx)) }
    var showMore by remember { mutableStateOf(false) }
    var showModeSheet by remember { mutableStateOf(false) }
    var childLockDialog by remember { mutableStateOf(false) }
    var canaryRunning by remember { mutableStateOf(false) }
    var canaryResults by remember { mutableStateOf<List<Canary.Result>?>(null) }
    var toast by remember { mutableStateOf("") }

    val locked = status?.childLockEngaged == true
    val lockedNotice = stringResource(R.string.ward_locked_notice)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {

        // ── Master switch ─────────────────────────────────────────────────────────────────
        val stateLine = when (engine.phase) {
            EngineState.Phase.UP -> stringResource(R.string.ward_state_up)
            EngineState.Phase.STARTING -> stringResource(R.string.ward_state_starting)
            EngineState.Phase.FAILED -> stringResource(R.string.ward_state_failed, engine.detail)
            EngineState.Phase.DOWN ->
                if (engine.detail.isBlank()) stringResource(R.string.ward_state_down)
                else stringResource(R.string.ward_state_down_detail, engine.detail)
        }
        SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(stateLine, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                text = stringResource(R.string.ward_scope_note),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            status?.logs?.let { l ->
                if (engine.phase == EngineState.Phase.UP) {
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    Text(
                        stringResource(R.string.ward_counts, l.queries, l.blocked),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (locked) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    lockedNotice,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            SecureButton(
                onClick = {
                    if (engine.armed) {
                        GodwallVpnService.stop(ctx)
                    } else {
                        val prepare = VpnService.prepare(ctx)
                        if (prepare != null) consent.launch(prepare) else GodwallVpnService.start(ctx)
                    }
                },
                enabled = !locked,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (engine.armed) stringResource(R.string.ward_stand_down)
                    else stringResource(R.string.ward_engage),
                )
            }
        }

        // ── Mode chips ────────────────────────────────────────────────────────────────────
        SuiteSectionHeader(stringResource(R.string.ward_mode_header))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            WardMode.entries.forEach { m ->
                FilterChip(
                    selected = m == mode,
                    enabled = !locked,
                    onClick = {
                        mode = m
                        WardModeStore.set(ctx, m)
                        // The DNS tier is read per query, so it is already in force; this only
                        // reconciles the firewall and tailnet tiers, and only when engaged.
                        GodwallVpnService.applyMode(ctx)
                        refresh++
                    },
                    label = { Text(modeLabel(m)) },
                )
            }
        }
        Column(Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(
                modeDescription(mode),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                stringResource(
                    if (engine.armed) R.string.ward_mode_applied_live
                    else R.string.ward_mode_applied_on_engage,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // ── Enforcement badge ─────────────────────────────────────────────────────────────
        val selection = status?.enforcement
        Row(modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg)) {
            AssistChip(
                onClick = onOpenEnforcement,
                label = {
                    Text(
                        when {
                            status == null -> stringResource(R.string.ward_enforcement_probing)
                            selection?.chosen == null -> stringResource(R.string.ward_enforcement_none)
                            else -> stringResource(
                                R.string.ward_enforcement_badge,
                                backendLabel(selection.chosen),
                            )
                        },
                    )
                },
                colors = AssistChipDefaults.assistChipColors(),
            )
        }
        if (selection != null && selection.manualOverridden && selection.manual != null) {
            Text(
                stringResource(
                    R.string.ward_enforcement_pin_failed,
                    backendLabel(selection.manual),
                    selection.chosen?.let { backendLabel(it) }
                        ?: stringResource(R.string.ward_enforcement_none),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(
                    horizontal = UnderstoryTheme.spacing.lg,
                    vertical = UnderstoryTheme.spacing.xs,
                ),
            )
        }

        // ── Health & alerts banner ────────────────────────────────────────────────────────
        SuiteSectionHeader(stringResource(R.string.ward_health_header))
        HealthBanner(status?.alerts ?: emptyList())

        // ── Status cards ──────────────────────────────────────────────────────────────────
        SuiteSectionHeader(stringResource(R.string.ward_cards_header))
        val s = status
        SuiteListRow(
            headline = stringResource(R.string.card_tunnel),
            supporting = s?.let { tunnelLine(it.tunnel) } ?: "",
            onClick = onOpenMesh,
        )
        SuiteListRow(
            headline = stringResource(R.string.card_dns),
            supporting = s?.let { dnsLine(it.dns) } ?: "",
            onClick = onOpenDns,
        )
        SuiteListRow(
            headline = stringResource(R.string.card_firewall),
            supporting = s?.let { firewallLine(it.firewall) } ?: "",
            onClick = onOpenApps,
        )
        SuiteListRow(
            headline = stringResource(R.string.card_proxy),
            supporting = s?.let { proxyLine(it.proxy) } ?: "",
            onClick = onOpenChain,
        )
        SuiteListRow(
            headline = stringResource(R.string.card_logs),
            supporting = s?.let { logsLine(it.logs) } ?: "",
            onClick = onOpenLog,
        )
        SuiteListRow(
            headline = stringResource(R.string.card_apps),
            supporting = s?.let {
                stringResource(
                    R.string.card_apps_counts,
                    it.apps.total,
                    it.apps.withInternet,
                    it.apps.blocked,
                )
            } ?: "",
            onClick = onOpenApps,
        )

        // ── Quick actions ─────────────────────────────────────────────────────────────────
        SuiteSectionHeader(stringResource(R.string.ward_quick_header))

        // Pause — the donor keeps the tunnel and counts down; so does this.
        val paused = pauseUntil > nowMs
        SuiteCard(
            modifier = Modifier.padding(
                horizontal = UnderstoryTheme.spacing.lg,
                vertical = UnderstoryTheme.spacing.xs,
            ),
        ) {
            Text(
                if (paused) {
                    stringResource(R.string.qa_paused_remaining, Pause.format(pauseUntil - nowMs))
                } else {
                    stringResource(R.string.qa_pause)
                },
                style = MaterialTheme.typography.titleSmall,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                text = when {
                    locked -> lockedNotice
                    !engine.armed -> stringResource(R.string.qa_pause_unavailable)
                    else -> stringResource(R.string.qa_pause_help)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                if (paused) {
                    SecureOutlinedButton(
                        onClick = { Pause.adjust(-Pause.STEP_MS) },
                        enabled = !locked,
                    ) { Text(stringResource(R.string.qa_pause_sub)) }
                    SecureOutlinedButton(
                        onClick = { Pause.adjust(Pause.STEP_MS) },
                        enabled = !locked,
                    ) { Text(stringResource(R.string.qa_pause_add)) }
                    SecureButton(
                        onClick = { Pause.resume() },
                        enabled = !locked,
                    ) { Text(stringResource(R.string.qa_resume)) }
                } else {
                    SecureButton(
                        onClick = { Pause.pause() },
                        enabled = !locked && engine.armed,
                    ) { Text(stringResource(R.string.qa_pause)) }
                }
            }
        }

        // Lockdown.
        SuiteCard(
            modifier = Modifier.padding(
                horizontal = UnderstoryTheme.spacing.lg,
                vertical = UnderstoryTheme.spacing.xs,
            ),
        ) {
            Text(
                if (lockdown) stringResource(R.string.qa_lockdown_on)
                else stringResource(R.string.qa_lockdown),
                style = MaterialTheme.typography.titleSmall,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                if (locked) lockedNotice else stringResource(R.string.qa_lockdown_help),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            // The flag is real and persisted, but with no tun there is no lookup to answer. Say
            // that rather than let the "Lockdown is ON" line imply coverage that is not running.
            if (!engine.armed) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    stringResource(R.string.qa_lockdown_not_engaged),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureButton(
                onClick = {
                    lockdown = !lockdown
                    Lockdown.setEnabled(ctx, lockdown)
                    refresh++
                },
                enabled = !locked,
            ) {
                Text(
                    if (lockdown) stringResource(R.string.qa_resume)
                    else stringResource(R.string.qa_lockdown),
                )
            }
        }

        // Kill switch — Android owns it; we report and open.
        SuiteCard(
            modifier = Modifier.padding(
                horizontal = UnderstoryTheme.spacing.lg,
                vertical = UnderstoryTheme.spacing.xs,
            ),
        ) {
            Text(stringResource(R.string.qa_killswitch), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(killSwitchLine(status?.killSwitch), style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                stringResource(R.string.qa_killswitch_help),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            val noScreen = stringResource(R.string.qa_killswitch_no_screen)
            SecureButton(onClick = {
                if (!KillSwitch.openSystemVpnSettings(ctx)) toast = noScreen
            }) { Text(stringResource(R.string.qa_killswitch)) }
        }

        // Canary run.
        SuiteCard(
            modifier = Modifier.padding(
                horizontal = UnderstoryTheme.spacing.lg,
                vertical = UnderstoryTheme.spacing.xs,
            ),
        ) {
            Text(stringResource(R.string.qa_canary), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                stringResource(R.string.qa_canary_help),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureButton(
                onClick = {
                    canaryRunning = true
                    scope.launch {
                        val r = withContext(Bg.io) { Canary.run(ctx) }
                        canaryResults = r
                        canaryRunning = false
                    }
                },
                enabled = !canaryRunning,
            ) {
                Text(
                    if (canaryRunning) stringResource(R.string.qa_canary_running)
                    else stringResource(R.string.qa_canary),
                )
            }
        }

        // New Tor identity — the payload is absent, so the control reports absent.
        GatedRow(
            title = stringResource(R.string.qa_tor_identity),
            reason = stringResource(R.string.gated_tor),
        )

        // ── Overflow ──────────────────────────────────────────────────────────────────────
        SuiteListRow(
            headline = stringResource(R.string.ward_more),
            supporting = stringResource(R.string.cd_ward_more),
            onClick = { showMore = true },
        )

        if (toast.isNotBlank()) {
            Text(
                toast,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
    }

    // ── Overflow sheet ───────────────────────────────────────────────────────────────────
    if (showMore) {
        ModalBottomSheet(
            onDismissRequest = { showMore = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            containerColor = MaterialTheme.colorScheme.surface,
        ) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(bottom = UnderstoryTheme.spacing.md),
            ) {
                SuiteListRow(
                    headline = stringResource(R.string.of_choose_mode),
                    supporting = modeLabel(mode),
                    onClick = {
                        showMore = false
                        showModeSheet = true
                    },
                )
                SuiteListRow(
                    headline = stringResource(R.string.of_child_lock),
                    supporting = if (status?.childLockEngaged == true) {
                        stringResource(R.string.of_child_lock_on)
                    } else {
                        stringResource(R.string.of_child_lock_off)
                    },
                    onClick = {
                        showMore = false
                        childLockDialog = true
                    },
                )
                SuiteListRow(
                    headline = stringResource(R.string.of_enforcement),
                    supporting = status?.enforcement?.chosen?.let { backendLabel(it) }
                        ?: stringResource(R.string.ward_enforcement_none),
                    onClick = {
                        showMore = false
                        onOpenEnforcement()
                    },
                )
                GatedRow(
                    title = stringResource(R.string.of_hotspot),
                    reason = stringResource(R.string.gated_hotspot),
                )
                GatedRow(
                    title = stringResource(R.string.of_search),
                    reason = stringResource(R.string.ward_search_absent),
                )
            }
        }
    }

    // "Choose mode" — the same five modes as the chip row, as a list for reachability.
    if (showModeSheet) {
        ModalBottomSheet(
            onDismissRequest = { showModeSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            containerColor = MaterialTheme.colorScheme.surface,
        ) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(bottom = UnderstoryTheme.spacing.md),
            ) {
                SuiteSectionHeader(stringResource(R.string.ward_mode_header))
                WardMode.entries.forEach { m ->
                    SuiteListRow(
                        headline = modeLabel(m),
                        supporting = modeDescription(m),
                        onClick = {
                            mode = m
                            WardModeStore.set(ctx, m)
                            GodwallVpnService.applyMode(ctx)
                            refresh++
                            showModeSheet = false
                        },
                    )
                }
            }
        }
    }

    if (childLockDialog) {
        ChildLockDialog(
            configured = status?.childLockConfigured == true,
            engaged = status?.childLockEngaged == true,
            onDismiss = { childLockDialog = false },
            onChanged = { refresh++ },
        )
    }

    canaryResults?.let { results ->
        AlertDialog(
            onDismissRequest = { canaryResults = null },
            title = { Text(stringResource(R.string.canary_title)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    results.forEach { r ->
                        Text(
                            "${canaryLabel(r.check)} — ${canaryStatus(r.status)}",
                            style = MaterialTheme.typography.titleSmall,
                            color = when (r.status) {
                                Canary.Status.PASS -> MaterialTheme.colorScheme.primary
                                Canary.Status.FAIL -> MaterialTheme.colorScheme.error
                                Canary.Status.SKIPPED -> MaterialTheme.colorScheme.onSurfaceVariant
                            },
                        )
                        Text(
                            r.detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { canaryResults = null }) {
                    Text(stringResource(R.string.canary_close))
                }
            },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// Pieces
// ─────────────────────────────────────────────────────────────────────────────────────────

/**
 * The health strip. Empty means "operating normally", said in those words rather than by an
 * absence — an empty banner reads as a rendering failure, not as an all-clear.
 */
@Composable
private fun HealthBanner(alerts: List<HealthCheck.Alert>) {
    val worst = HealthCheck.worst(alerts)
    val container = when (worst) {
        HealthCheck.Severity.CRITICAL -> MaterialTheme.colorScheme.errorContainer
        HealthCheck.Severity.WARNING -> MaterialTheme.colorScheme.tertiaryContainer
        HealthCheck.Severity.INFO -> MaterialTheme.colorScheme.surfaceVariant
        null -> MaterialTheme.colorScheme.surfaceVariant
    }
    val onContainer = when (worst) {
        HealthCheck.Severity.CRITICAL -> MaterialTheme.colorScheme.onErrorContainer
        HealthCheck.Severity.WARNING -> MaterialTheme.colorScheme.onTertiaryContainer
        else -> MaterialTheme.colorScheme.onSurface
    }
    Surface(
        color = container,
        contentColor = onContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = UnderstoryTheme.spacing.lg),
    ) {
        Column(Modifier.padding(UnderstoryTheme.spacing.lg)) {
            if (alerts.isEmpty()) {
                Text(stringResource(R.string.ward_health_ok), style = MaterialTheme.typography.bodyMedium)
            } else {
                alerts.forEach { a ->
                    Text(alertText(a), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                }
            }
        }
    }
}

/**
 * A control whose donor mechanism needs a payload this build does not have.
 *
 * Rendered greyed and non-interactive with the reason underneath, per `docs/DONOR-ASSETS.md`:
 * absent capabilities report absent, they do not degrade quietly into a control that no-ops.
 */
@Composable
private fun GatedRow(title: String, reason: String) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(
                horizontal = UnderstoryTheme.spacing.lg,
                vertical = UnderstoryTheme.spacing.sm,
            ),
    ) {
        Text(
            title,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
        )
        if (reason.isNotBlank()) {
            Text(
                reason,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ChildLockDialog(
    configured: Boolean,
    engaged: Boolean,
    onDismiss: () -> Unit,
    onChanged: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val wrong = stringResource(R.string.of_child_lock_wrong)
    val tooShort = stringResource(R.string.of_child_lock_too_short, ChildLock.MIN_PIN_LENGTH)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.of_child_lock)) },
        text = {
            Column {
                Text(
                    stringResource(R.string.of_child_lock_help),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.md))
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it.filter(Char::isDigit); error = "" },
                    label = {
                        Text(stringResource(R.string.of_child_lock_pin, ChildLock.MIN_PIN_LENGTH))
                    },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = KeyboardType.NumberPassword,
                    ),
                )
                if (error.isNotBlank()) {
                    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                    Text(error, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            // PBKDF2 at 120k rounds is deliberately slow, so every branch runs on Bg.cpu and the
            // button disables while it does rather than freezing the dialog.
            TextButton(
                enabled = !busy,
                onClick = {
                    busy = true
                    scope.launch {
                        val ok = withContext(Bg.cpu) {
                            when {
                                !configured -> ChildLock.setPin(ctx, pin)
                                engaged -> ChildLock.unlock(ctx, pin)
                                else -> ChildLock.engage(ctx)
                            }
                        }
                        busy = false
                        if (ok) {
                            pin = ""
                            onChanged()
                            onDismiss()
                        } else {
                            error = if (!configured && pin.length < ChildLock.MIN_PIN_LENGTH) {
                                tooShort
                            } else {
                                wrong
                            }
                        }
                    }
                },
            ) {
                Text(
                    when {
                        !configured -> stringResource(R.string.of_child_lock_set)
                        engaged -> stringResource(R.string.of_child_lock_unlock)
                        else -> stringResource(R.string.of_child_lock_engage)
                    },
                )
            }
        },
        dismissButton = {
            Row {
                if (configured && !engaged) {
                    TextButton(
                        enabled = !busy,
                        onClick = {
                            busy = true
                            scope.launch {
                                val ok = withContext(Bg.cpu) { ChildLock.clear(ctx, pin) }
                                busy = false
                                if (ok) {
                                    onChanged()
                                    onDismiss()
                                } else {
                                    error = wrong
                                }
                            }
                        },
                    ) { Text(stringResource(R.string.of_child_lock_remove)) }
                }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.ward_cancel)) }
            }
        },
    )
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// Copy mapping. Engines carry facts; every user-visible sentence resolves here.
// ─────────────────────────────────────────────────────────────────────────────────────────

@Composable
internal fun modeLabel(m: WardMode): String = stringResource(
    when (m) {
        WardMode.DNS_ONLY -> R.string.ward_mode_dns_only
        WardMode.FIREWALL_ONLY -> R.string.ward_mode_firewall_only
        WardMode.DNS_FIREWALL -> R.string.ward_mode_dns_firewall
        WardMode.TAILNET_ONLY -> R.string.ward_mode_tailnet_only
        WardMode.FULL_STACK -> R.string.ward_mode_full_stack
    },
)

@Composable
private fun modeDescription(m: WardMode): String = stringResource(
    when (m) {
        WardMode.DNS_ONLY -> R.string.ward_mode_desc_dns_only
        WardMode.FIREWALL_ONLY -> R.string.ward_mode_desc_firewall_only
        WardMode.DNS_FIREWALL -> R.string.ward_mode_desc_dns_firewall
        WardMode.TAILNET_ONLY -> R.string.ward_mode_desc_tailnet_only
        WardMode.FULL_STACK -> R.string.ward_mode_desc_full_stack
    },
)

@Composable
internal fun backendLabel(b: EnforcementBackend): String = stringResource(
    when (b) {
        EnforcementBackend.IPTABLES -> R.string.enf_iptables
        EnforcementBackend.CONNECTIVITY_MANAGER -> R.string.enf_connectivity
        EnforcementBackend.NETWORK_POLICY_MANAGER -> R.string.enf_netpolicy
        EnforcementBackend.VPN -> R.string.enf_vpn
        EnforcementBackend.PROXY -> R.string.enf_proxy
    },
)

@Composable
private fun canaryLabel(c: Canary.Check): String = stringResource(
    when (c) {
        Canary.Check.SLOT -> R.string.canary_check_slot
        Canary.Check.UPSTREAM -> R.string.canary_check_upstream
        Canary.Check.FILTER -> R.string.canary_check_filter
        Canary.Check.LEAK -> R.string.canary_check_leak
        Canary.Check.CHAIN -> R.string.canary_check_chain
        Canary.Check.ENFORCEMENT -> R.string.canary_check_enforcement
    },
)

@Composable
private fun canaryStatus(s: Canary.Status): String = stringResource(
    when (s) {
        Canary.Status.PASS -> R.string.canary_pass
        Canary.Status.FAIL -> R.string.canary_fail
        Canary.Status.SKIPPED -> R.string.canary_skipped
    },
)

@Composable
private fun alertText(a: HealthCheck.Alert): String = when (a.kind) {
    HealthCheck.HealthAlert.ENGINE_FAILED ->
        stringResource(R.string.ward_alert_engine_failed, a.args.firstOrNull()?.toString().orEmpty())
    HealthCheck.HealthAlert.CONFLICTING_VPN -> stringResource(R.string.ward_alert_conflicting_vpn)
    HealthCheck.HealthAlert.DNS_LEAK -> stringResource(R.string.ward_alert_dns_leak)
    HealthCheck.HealthAlert.SELF_BLOCK ->
        stringResource(R.string.ward_alert_self_block, a.args.firstOrNull() as? Int ?: 0)
    HealthCheck.HealthAlert.FIREWALL_TIER_INERT -> stringResource(R.string.ward_alert_firewall_inert)
    HealthCheck.HealthAlert.TAILNET_TIER_INERT -> stringResource(R.string.ward_alert_tailnet_inert)
    HealthCheck.HealthAlert.REFUSED_DENIALS ->
        stringResource(R.string.ward_alert_refused_denials, a.args.firstOrNull() as? Int ?: 0)
    HealthCheck.HealthAlert.MITM_USER_CA ->
        stringResource(R.string.ward_alert_mitm, a.args.firstOrNull() as? Int ?: 0)
    HealthCheck.HealthAlert.FILTER_EMPTY -> stringResource(R.string.ward_alert_filter_empty)
    HealthCheck.HealthAlert.PAUSED -> stringResource(R.string.ward_alert_paused)
    HealthCheck.HealthAlert.LOCKDOWN_ON -> stringResource(R.string.ward_alert_lockdown)
    HealthCheck.HealthAlert.CHILD_LOCK_ON -> stringResource(R.string.ward_alert_child_lock)
}

@Composable
private fun tunnelLine(t: WardStatus.TunnelCard): String {
    val state = stringResource(R.string.card_tunnel_state, t.state.name.lowercase())
    val exit = if (t.exitNode.isBlank()) {
        stringResource(R.string.card_tunnel_no_exit)
    } else {
        stringResource(R.string.card_tunnel_exit, t.exitNode)
    }
    val posture = if (t.postureWarnings.isEmpty()) {
        stringResource(R.string.card_tunnel_posture_ok)
    } else {
        stringResource(R.string.card_tunnel_posture_warn, t.postureWarnings.joinToString("; "))
    }
    val absent = if (!Mesh.compiledIn) " — " + stringResource(R.string.ward_alert_tailnet_inert) else ""
    return "$state · $exit · $posture$absent"
}

@Composable
private fun dnsLine(d: WardStatus.DnsCard): String {
    val filter = if (d.filterEnabled) {
        stringResource(R.string.card_dns_filter_on, d.blocklistDomains)
    } else {
        stringResource(R.string.card_dns_filter_off)
    }
    val leak = when (d.leak.verdict) {
        DnsLeak.Verdict.OK -> stringResource(R.string.card_dns_leak_ok)
        DnsLeak.Verdict.LEAK -> stringResource(R.string.card_dns_leak_fail)
        else -> stringResource(R.string.card_dns_leak_na)
    }
    return "${d.resolver} · $filter · $leak"
}

@Composable
private fun firewallLine(f: WardStatus.FirewallCard): String {
    val counts = stringResource(
        R.string.card_firewall_counts,
        f.blocked,
        f.isolated,
        f.excluded,
        f.refused,
    )
    return if (f.unavailableReason != null) {
        counts + " — " + stringResource(R.string.card_firewall_unavailable, f.unavailableReason)
    } else {
        counts
    }
}

@Composable
private fun proxyLine(p: WardStatus.ProxyCard): String {
    val head = if (p.hops > 0 && !p.chainEnabled) {
        stringResource(R.string.card_proxy_off, p.path)
    } else {
        p.path
    }
    if (p.gated.isEmpty()) return head
    // forEachIndexed rather than joinToString: the transform lambda of joinToString is not
    // inline, so a @Composable string lookup cannot be called from inside it.
    val names = StringBuilder()
    p.gated.forEachIndexed { i, c ->
        if (i > 0) names.append(", ")
        names.append(gatedShortLabel(c))
    }
    return head + " · " + stringResource(R.string.card_proxy_gated, names.toString())
}

@Composable
private fun gatedShortLabel(c: GatedCapability): String = stringResource(
    when (c) {
        GatedCapability.TOR -> R.string.gated_short_tor
        GatedCapability.I2P -> R.string.gated_short_i2p
        else -> R.string.gated_short_dnscrypt
    },
)

@Composable
private fun logsLine(l: WardStatus.LogsCard): String =
    stringResource(R.string.card_logs_rate, l.perMinute, l.blockedPerMinute) + " · " +
        stringResource(R.string.card_logs_totals, l.queries, l.blocked)

@Composable
private fun killSwitchLine(k: KillSwitch.State?): String = when {
    k == null || !k.observed -> stringResource(R.string.qa_killswitch_state_unknown)
    k.alwaysOn && k.lockdown -> stringResource(R.string.qa_killswitch_state_on)
    k.alwaysOn -> stringResource(R.string.qa_killswitch_state_alwayson)
    else -> stringResource(R.string.qa_killswitch_state_off)
}
