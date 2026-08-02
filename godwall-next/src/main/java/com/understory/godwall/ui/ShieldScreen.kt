package com.understory.godwall.ui

import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.understory.godwall.R
import com.understory.godwall.chain.EndpointChain
import com.understory.godwall.core.EngineState
import com.understory.godwall.core.GodwallVpnService
import com.understory.godwall.dns.BlocklistRepository
import com.understory.godwall.dns.DnsEventLog
import com.understory.godwall.dns.DnsSettings
import com.understory.godwall.mesh.Mesh
import com.understory.godwall.privilege.Privilege
import com.understory.security.SecureButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.withContext

/**
 * The landing screen: one plain sentence about what is and is not protected, the arm control,
 * and a route into each subsystem showing its real state.
 *
 * The status line is driven by [EngineState], which only the service writes. The predecessor
 * drove its shield from the toggle the user tapped, so it read "protected" even when consent
 * was denied or the slot was later revoked.
 */
@Composable
fun ShieldScreen(
    padding: PaddingValues,
    onOpenDns: () -> Unit,
    onOpenApps: () -> Unit,
    onOpenMesh: () -> Unit,
    onOpenChain: () -> Unit,
    onOpenPrivilege: () -> Unit,
) {
    val ctx = LocalContext.current
    val engine by EngineState.state.collectAsStateWithLifecycle()

    // Android requires an explicit consent dialog before any app may hold the VPN slot. Arming
    // is therefore a two-step flow, and the second step only runs if consent actually came back
    // RESULT_OK — a denial leaves the engine DOWN and says so rather than silently no-opping.
    val consent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            GodwallVpnService.start(ctx)
        } else {
            EngineState.publish(
                EngineState.Phase.DOWN,
                ctx.getString(R.string.shield_consent_declined),
            )
        }
    }

    val status = when (engine.phase) {
        EngineState.Phase.UP -> stringResource(R.string.shield_state_up)
        EngineState.Phase.STARTING -> stringResource(R.string.shield_state_starting)
        EngineState.Phase.FAILED -> stringResource(R.string.shield_state_failed, engine.detail)
        EngineState.Phase.DOWN ->
            if (engine.detail.isBlank()) stringResource(R.string.shield_state_down)
            else stringResource(R.string.shield_state_down_detail, engine.detail)
    }

    // Subsystem summaries, read off the main thread — several touch SharedPreferences and the
    // package manager.
    val dnsSummary by produceState(initialValue = "", engine) {
        value = withContext(Bg.io) { DnsSettings.describe(ctx) }
    }
    val filterSummary by produceState(initialValue = "", engine) {
        value = withContext(Bg.io) {
            if (!BlocklistRepository.isFilterEnabled(ctx)) {
                ctx.getString(R.string.shield_filter_off)
            } else {
                val n = BlocklistRepository.stats().totalDomains
                ctx.getString(R.string.shield_filter_on, n)
            }
        }
    }
    val chainSummary by produceState(initialValue = "", engine) {
        value = withContext(Bg.io) { EndpointChain.describe(ctx) }
    }
    val meshSummary by produceState(initialValue = "", engine) {
        value = withContext(Bg.io) { Mesh.status(ctx).detail.ifBlank { Mesh.status(ctx).state.name } }
    }
    val privilegeSummary by produceState(initialValue = "", engine) {
        value = withContext(Bg.io) { Privilege.explain(ctx) }
    }
    val queries by produceState(initialValue = 0L to 0L, engine) {
        value = withContext(Bg.io) { DnsEventLog.totalQueries() to DnsEventLog.totalBlocked() }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {
        SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(
                text = status,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            // Said plainly, on the landing screen, every time. Godwall denies by NAME; it is not
            // a packet firewall without a privileged shell, and a security tool that lets the
            // user infer more coverage than it has is the failure mode worth designing against.
            Text(
                text = stringResource(R.string.shield_scope_note),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (engine.phase == EngineState.Phase.UP) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    text = stringResource(R.string.shield_counts, queries.first, queries.second),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
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
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (engine.armed) stringResource(R.string.shield_disarm)
                    else stringResource(R.string.shield_arm),
                )
            }
        }

        SuiteSectionHeader(stringResource(R.string.shield_subsystems))
        SuiteListRow(
            headline = stringResource(R.string.title_dns),
            supporting = "$dnsSummary — $filterSummary",
            onClick = onOpenDns,
        )
        SuiteListRow(
            headline = stringResource(R.string.title_apps),
            supporting = stringResource(R.string.shield_apps_summary),
            onClick = onOpenApps,
        )
        SuiteListRow(
            headline = stringResource(R.string.title_chain),
            supporting = chainSummary,
            onClick = onOpenChain,
        )
        SuiteListRow(
            headline = stringResource(R.string.title_mesh),
            supporting = meshSummary,
            onClick = onOpenMesh,
        )
        SuiteListRow(
            headline = stringResource(R.string.title_privilege),
            supporting = privilegeSummary,
            onClick = onOpenPrivilege,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
    }
}
