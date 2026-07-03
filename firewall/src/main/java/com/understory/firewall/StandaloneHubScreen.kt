package com.understory.firewall

import android.app.Activity
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.understory.security.Diagnostics
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Standalone hub (design-v2/firewall.md §3): the walled-off engine. Two
 * regions — the mode-state region (enable/disable + guardrail verdict) and
 * the engine region (arm switch + drop counter), the latter present only
 * when Standalone is enabled AND the guardrail PASSes. On a FAIL the arm
 * switch is ABSENT (not disabled-and-present), so there is zero dead control.
 */
@Composable
fun StandaloneHubScreen(activity: ComponentActivity, onBack: () -> Unit) {
    val ctx = LocalContext.current

    var mode by remember { mutableStateOf(FirewallSettings.getMode(ctx)) }
    var armed by remember { mutableStateOf(FirewallSettings.isEngineArmed(ctx)) }
    var autoStopped by remember { mutableStateOf(FirewallSettings.isAutoStopped(ctx)) }
    var slot by remember { mutableStateOf(VpnSlotProbe.evaluate(ctx)) }
    var showExplainer by remember { mutableStateOf(false) }

    fun reprobe() { slot = VpnSlotProbe.evaluate(ctx) }

    // Refresh state + guardrail on resume (slot may have changed).
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_START) {
                mode = FirewallSettings.getMode(ctx)
                armed = FirewallSettings.isEngineArmed(ctx)
                autoStopped = FirewallSettings.isAutoStopped(ctx)
                reprobe()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // Live slot-watcher while armed (§4 point 3): if a VPN network that is
    // not ours appears, proactively disarm before onRevoke fires.
    DisposableEffect(armed, mode) {
        if (armed && mode == FirewallMode.STANDALONE) {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    // A VPN-transport network appeared. If we didn't just
                    // establish our own, the incumbent won — disarm.
                    if (VpnSlotProbe.isAnotherVpnActive(ctx)) {
                        Diagnostics.log("firewall.StandaloneHub",
                            "slot-watcher: another VPN appeared → disarming")
                        FirewallSettings.setEngineArmed(ctx, false)
                        FirewallSettings.setAutoStopped(ctx, true)
                        stopEngine(ctx)
                        armed = false
                        autoStopped = true
                        reprobe()
                    }
                }
            }
            runCatching { cm?.registerNetworkCallback(VpnSlotProbe.vpnNetworkRequest(), cb) }
            onDispose { runCatching { cm?.unregisterNetworkCallback(cb) } }
        } else {
            onDispose { }
        }
    }

    val consentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            FirewallSettings.setEngineArmed(ctx, true)
            FirewallSettings.setAutoStopped(ctx, false)
            armed = true
            autoStopped = false
            startEngine(ctx)
            reprobe()
        }
    }

    fun armEngine() {
        // Re-run the guardrail before touching anything (§3.2).
        val s = VpnSlotProbe.evaluate(ctx)
        slot = s
        if (!s.isPass) {
            // Do not launch consent; leave disarmed; show the guardrail card.
            FirewallSettings.setEngineArmed(ctx, false)
            armed = false
            return
        }
        val prepare = VpnService.prepare(ctx)
        if (prepare != null) {
            consentLauncher.launch(prepare)
        } else {
            FirewallSettings.setEngineArmed(ctx, true)
            FirewallSettings.setAutoStopped(ctx, false)
            armed = true
            autoStopped = false
            startEngine(ctx)
        }
    }

    if (showExplainer) {
        StandaloneExplainer(
            onCancel = { showExplainer = false },
            onEnable = {
                FirewallSettings.setMode(ctx, FirewallMode.STANDALONE)
                FirewallSettings.setStandaloneExplained(ctx, true)
                mode = FirewallMode.STANDALONE
                showExplainer = false
                reprobe()
            },
        )
        return
    }

    SuiteScaffold(title = "Standalone mode", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            // ---- Mode-state region ----
            SuiteCard {
                Text(
                    "Standalone blocking uses Android's one VPN slot to drop blocked apps' " +
                        "traffic. It's off by default and only works when no other VPN is " +
                        "running.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                SwitchRow(
                    label = "Standalone blocking (no VPN)",
                    checked = mode == FirewallMode.STANDALONE,
                    onCheckedChange = { wantOn ->
                        if (wantOn) {
                            // Guardrail probe BEFORE changing anything (§3.1).
                            val s = VpnSlotProbe.evaluate(ctx)
                            slot = s
                            if (!s.isPass) {
                                // FAIL: switch does not flip; guardrail card shows.
                                Diagnostics.log("firewall.StandaloneHub",
                                    "enable blocked by guardrail (incumbent=${s.incumbentName})")
                                return@SwitchRow
                            }
                            // PASS: show the explainer (first time), else enable.
                            if (!FirewallSettings.isStandaloneExplained(ctx)) {
                                showExplainer = true
                            } else {
                                FirewallSettings.setMode(ctx, FirewallMode.STANDALONE)
                                mode = FirewallMode.STANDALONE
                            }
                        } else {
                            // Disable: stop engine if armed; back to COMPANION.
                            if (armed) stopEngine(ctx)
                            FirewallSettings.setEngineArmed(ctx, false)
                            FirewallSettings.setAutoStopped(ctx, false)
                            FirewallSettings.setMode(ctx, FirewallMode.COMPANION)
                            mode = FirewallMode.COMPANION
                            armed = false
                            autoStopped = false
                        }
                    },
                )
            }

            // Guardrail verdict card.
            if (!slot.isPass) {
                GuardrailCard(slot) { reprobe() }
            }

            // ---- Engine region — only when enabled AND guardrail PASS ----
            if (mode == FirewallMode.STANDALONE && slot.isPass) {
                SuiteCard {
                    Text("Blocking engine", style = MaterialTheme.typography.titleMedium)
                    if (autoStopped) {
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        Text(
                            "Standalone blocking stopped because a VPN is now using the VPN " +
                                "slot. It will resume when you turn that VPN off.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    SwitchRow(
                        label = "Block enabled apps now",
                        checked = armed,
                        onCheckedChange = { wantOn ->
                            if (wantOn) {
                                armEngine()
                            } else {
                                stopEngine(ctx)
                                FirewallSettings.setEngineArmed(ctx, false)
                                armed = false
                            }
                        },
                    )
                    if (armed) {
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        DropCounter()
                        BoundaryText(
                            "Uses the restrict worklist as the block list. Flag apps in " +
                                "Restrict or in the Remote-admin audit; they carry over here."
                        )
                    }
                }
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

@Composable
private fun GuardrailCard(slot: VpnSlotProbe.VpnSlotState, onRecheck: () -> Unit) {
    Surface(
        color = UnderstoryTheme.semantic.warningContainer,
        contentColor = UnderstoryTheme.semantic.warning,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(
                "A VPN is already using the slot",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                "Standalone blocking can't start because " +
                    (slot.incumbentName?.let { "$it is" } ?: "another app is") +
                    " using Android's one VPN slot. That's expected on a Tailscale phone — " +
                    "we never evict it. Turn that VPN off if you want to use Standalone " +
                    "blocking; the app stays audit-only until then.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureOutlinedButton(onClick = onRecheck) { Text("Re-check") }
        }
    }
}

@Composable
private fun DropCounter() {
    val ctx = LocalContext.current
    var total by remember { mutableStateOf(0L) }
    var last by remember { mutableStateOf(0L) }
    LaunchedEffect(Unit) {
        while (true) {
            total = com.understory.net.engine.DropStats.totalPackets()
            last = com.understory.net.engine.DropStats.lastDropAt()
            kotlinx.coroutines.delay(1000)
        }
    }
    // Only render a meaningful counter once something was actually dropped;
    // an armed-but-idle tun shows the neutral line, no fake "0 dropped."
    Text(
        if (total > 0L) formatDropStatus(total, last) else "Armed · no apps blocked yet",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun StandaloneExplainer(onCancel: () -> Unit, onEnable: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
        contentColor = MaterialTheme.colorScheme.onBackground,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.xl),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                "Standalone blocking uses Android's VPN slot",
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                "This mode routes your blocked apps through a local, on-device tunnel to " +
                    "drop their traffic. It uses the one Android VPN slot, so you can only " +
                    "use it if you are not running another VPN. If you later turn on " +
                    "Tailscale or any VPN, Standalone blocking stops automatically and this " +
                    "app returns to audit-only mode. Your block list is kept.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            SecureButton(onClick = onEnable, modifier = Modifier.fillMaxWidth()) {
                Text("Enable Standalone")
            }
            SecureOutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
                Text("Not now")
            }
        }
    }
}

/** Human drop-status line. */
internal fun formatDropStatus(total: Long, lastMillis: Long): String {
    val ago = if (lastMillis == 0L) "" else {
        val secs = ((System.currentTimeMillis() - lastMillis) / 1000L).coerceAtLeast(0L)
        when {
            secs < 5 -> " · just now"
            secs < 60 -> " · ${secs}s ago"
            secs < 3600 -> " · ${secs / 60}m ago"
            else -> " · ${secs / 3600}h ago"
        }
    }
    return "dropped $total packet${if (total == 1L) "" else "s"}$ago"
}
