package com.understory.firewall

import android.content.Intent
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
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Remote-Admin Audit (design-v2/firewall.md §5.4). Crown jewel kept
 * verbatim in mechanism; three fixes: MODE_DEFAULT tri-state (in
 * RemoteAdminAudit), "Block"→"Revoke"/"Add to watchlist" (+"Hard-block" in
 * Standalone), and first-run copy phrased as "review N apps."
 */
@Composable
fun AuditScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var findings by remember { mutableStateOf<List<AuditFinding>>(emptyList()) }
    var restricted by remember { mutableStateOf(FirewallSettings.getRestrictedPackages(ctx)) }
    var acknowledged by remember { mutableStateOf(FirewallSettings.getAuditAcknowledged(ctx)) }
    var loading by remember { mutableStateOf(true) }
    val standalone = remember { FirewallSettings.getMode(ctx) == FirewallMode.STANDALONE }

    LaunchedEffect(Unit) {
        findings = withContext(Dispatchers.IO) { RemoteAdminAudit.scan(ctx) }
        loading = false
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_START) {
                restricted = FirewallSettings.getRestrictedPackages(ctx)
                acknowledged = FirewallSettings.getAuditAcknowledged(ctx)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    SuiteScaffold(title = "Remote-admin audit", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(
                "Revoking a capability in Android Settings is the strongest fix — it " +
                    "stops on-device actions, not just network. Add-to-watchlist is a " +
                    "reminder; Standalone hard-block additionally drops the app's traffic.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (loading) {
                Text("Scanning…", style = MaterialTheme.typography.bodyMedium)
                return@Column
            }
            if (findings.isEmpty()) {
                Text(
                    "No installed apps hold remote-admin-class grants.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = UnderstoryTheme.semantic.success,
                )
                return@Column
            }

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                modifier = Modifier.fillMaxWidth(),
            ) {
                items(findings, key = { "audit-${it.packageName}" }) { finding ->
                    AuditFindingCard(
                        finding = finding,
                        isWatched = finding.packageName in restricted,
                        isAcknowledged = finding.packageName in acknowledged,
                        standalone = standalone,
                        onToggleWatch = {
                            FirewallSettings.setRestricted(ctx, finding.packageName, it)
                            restricted = FirewallSettings.getRestrictedPackages(ctx)
                            // If armed in Standalone, re-establish so the
                            // hard-block set takes effect immediately — but only
                            // if the VPN slot is still ours (fail-closed: never
                            // start the engine while another VPN holds the slot;
                            // self-heal stale armed state if it isn't).
                            if (standalone && FirewallSettings.isEngineArmed(ctx)) {
                                if (VpnSlotProbe.evaluate(ctx).isPass) {
                                    startEngine(ctx)
                                } else {
                                    FirewallSettings.setEngineArmed(ctx, false)
                                    FirewallSettings.setAutoStopped(ctx, true)
                                }
                            }
                        },
                        onToggleAck = {
                            FirewallSettings.setAuditAcknowledged(ctx, finding.packageName, it)
                            acknowledged = FirewallSettings.getAuditAcknowledged(ctx)
                        },
                    )
                }
                item { Spacer(Modifier.height(UnderstoryTheme.spacing.lg)) }
            }
        }
    }
}

@Composable
private fun AuditFindingCard(
    finding: AuditFinding,
    isWatched: Boolean,
    isAcknowledged: Boolean,
    standalone: Boolean,
    onToggleWatch: (Boolean) -> Unit,
    onToggleAck: (Boolean) -> Unit,
) {
    val ctx = LocalContext.current
    SuiteCard {
        Text(finding.label, style = MaterialTheme.typography.titleMedium)
        Text(
            finding.packageName,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

        for (cap in finding.capabilities) {
            CapRow(cap.display, cap.explanation, confirmed = true)
        }
        for (cap in finding.unknownCapabilities) {
            CapRow(cap.display + " (unknown — couldn't confirm)", cap.explanation, confirmed = false)
        }

        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            // The real action: revoke at the source.
            val revoke = finding.capabilities.firstOrNull()?.revokeAction
                ?: finding.unknownCapabilities.firstOrNull()?.revokeAction
            if (revoke != null) {
                SecureButton(
                    onClick = {
                        runCatching {
                            ctx.startActivity(Intent(revoke).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                        }.recoverCatching {
                            ctx.startActivity(
                                Intent(android.provider.Settings.ACTION_SETTINGS)
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    },
                    modifier = Modifier,
                ) { Text("Revoke in Settings") }
            }
            SecureOutlinedButton(onClick = { onToggleWatch(!isWatched) }) {
                Text(if (isWatched) "On watchlist" else "Add to watchlist")
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            if (standalone) {
                // The one place blocking is real: hard-block adds to the
                // engine block list (same restrict set).
                SecureOutlinedButton(onClick = { onToggleWatch(true) }) {
                    Text("Hard-block")
                }
            }
            SecureOutlinedButton(onClick = { onToggleAck(!isAcknowledged) }) {
                Text(if (isAcknowledged) "Un-acknowledge" else "Acknowledge")
            }
        }
    }
}

@Composable
private fun CapRow(display: String, explanation: String, confirmed: Boolean) {
    Column(Modifier.padding(vertical = UnderstoryTheme.spacing.xs)) {
        Text(
            display,
            style = MaterialTheme.typography.bodyLarge,
            color = if (confirmed) UnderstoryTheme.semantic.warning
            else UnderstoryTheme.semantic.dim,
        )
        Text(
            explanation,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
