package com.understory.firewall

import android.content.Intent
import android.provider.Settings
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
 * Tunnel Posture (design-v2/firewall.md §5.1). The Tailscale-native
 * surface: reads what a rootless app can, renders the exact verdict ladder,
 * never green on an inference gap, and offers route-only actions.
 */
@Composable
fun TunnelPostureScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var posture by remember { mutableStateOf<TunnelPosture?>(null) }
    var tick by remember { mutableStateOf(0) }

    LaunchedEffect(tick) {
        posture = withContext(Dispatchers.IO) { TunnelPosture.read(ctx) }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_START) tick++
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    SuiteScaffold(title = "Tunnel posture", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            val p = posture
            if (p == null) {
                Text("Reading…", style = MaterialTheme.typography.bodyMedium)
                return@Column
            }

            val (chip, tone) = tunnelChip(p)
            VerdictChip(chip, tone)

            SuiteCard {
                val v = if (p.tailscaleInstalled) Tri.YES else Tri.NO
                TriRow(
                    label = if (p.tailscaleInstalled)
                        "Tailscale installed${p.tailscaleVersion?.let { " · v$it" } ?: ""}"
                    else "Tailscale not installed",
                    tri = v,
                )
                TriRow(
                    label = "A VPN tunnel is active",
                    tri = p.aVpnIsUp,
                    subtitle = if (p.aVpnIsUp == Tri.YES && p.alwaysOnIsTailscale != Tri.YES)
                        "We can see a tunnel is up but can't confirm it's Tailscale on this build."
                    else null,
                )
                TriRow(label = "Always-on VPN is Tailscale", tri = p.alwaysOnIsTailscale)
                TriRow(label = "Lockdown (block without VPN)", tri = p.lockdown)
            }

            when (p.verdict) {
                TunnelPosture.Verdict.NO_TAILSCALE -> BoundaryText(
                    "Works with or without Tailscale. The DNS, traffic, and audit " +
                        "tools work regardless — we won't push you to install anything."
                )
                TunnelPosture.Verdict.UNKNOWN -> BoundaryText(
                    "Your device build doesn't expose always-on VPN status to other " +
                        "apps — check it yourself in VPN settings."
                )
                else -> {}
            }

            // Actions — route only. Primary CTA is VPN settings when
            // lockdown/always-on aren't confirmed.
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            val vpnSettingsPrimary = p.lockdown != Tri.YES || p.alwaysOnIsTailscale != Tri.YES
            if (vpnSettingsPrimary) {
                SecureButton(
                    onClick = { openSettings(ctx, Settings.ACTION_VPN_SETTINGS) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Open VPN settings") }
            } else {
                SecureOutlinedButton(
                    onClick = { openSettings(ctx, Settings.ACTION_VPN_SETTINGS) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Open VPN settings") }
            }
            SecureOutlinedButton(
                onClick = { openTailscale(ctx) },
                enabled = p.tailscaleInstalled,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (p.tailscaleInstalled) "Open Tailscale"
                    else "Open Tailscale (not installed)"
                )
            }
            SecureOutlinedButton(
                onClick = { tick++ },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Re-check") }
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

private fun openSettings(ctx: android.content.Context, action: String) {
    runCatching {
        ctx.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }.recoverCatching {
        ctx.startActivity(
            Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }
}

private fun openTailscale(ctx: android.content.Context) {
    // Honest: launch Tailscale's own entry point; no fake deep-link into a
    // specific Tailscale screen we can't address.
    val launch = ctx.packageManager.getLaunchIntentForPackage(VpnSlotProbe.TAILSCALE_PKG)
    if (launch != null) {
        runCatching { ctx.startActivity(launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
    }
}
