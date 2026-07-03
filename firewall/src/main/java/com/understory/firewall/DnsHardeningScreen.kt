package com.understory.firewall

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.understory.elevation.Elevation
import com.understory.elevation.Outcome
import com.understory.elevation.PrivateDnsMode
import com.understory.security.Diagnostics
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * DNS Hardening (design-v2/firewall.md §5.3). Flagship, kept: the doctrine-
 * model feature — WRITE_SECURE_SETTINGS configures the platform's own
 * Private DNS. DoT only (DNSCrypt removed, A8). NextDNS config-ID field
 * (D11); numbered steps; Tailscale advisory line.
 */
@Composable
fun DnsHardeningScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var selectedId by remember { mutableStateOf(FirewallSettings.getDnsProviderId(ctx)) }
    val selected = remember(selectedId) { DnsProvider.byId(selectedId) }
    var nextDnsId by remember { mutableStateOf("") }

    SuiteScaffold(title = "DNS hardening", onBack = onBack, showSuiteFooter = false) { pad ->
        LazyColumn(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            item { DnsActiveNowCard() }

            item {
                BoundaryText(
                    "Private DNS composes with Tailscale — with a Tailscale exit node or " +
                        "MagicDNS enabled, Tailscale may override the system resolver; " +
                        "verify with the DNS canary."
                )
            }

            items(DnsProvider.ALL, key = { "dns-${it.id}" }) { provider ->
                DnsProviderRow(
                    provider = provider,
                    isSelected = provider.id == selectedId,
                    onSelect = {
                        FirewallSettings.setDnsProviderId(ctx, provider.id)
                        selectedId = provider.id
                    },
                )
            }

            if (selected.requiresConfigId) {
                item {
                    SuiteCard {
                        Text("NextDNS config ID", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "From your NextDNS dashboard (hex, 6+ chars). The specifier " +
                                "becomes <id>.dns.nextdns.io.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                        OutlinedTextField(
                            value = nextDnsId,
                            onValueChange = { nextDnsId = it },
                            singleLine = true,
                            label = { Text("config ID") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            }

            item {
                DnsApplyCard(
                    selected = selected,
                    nextDnsId = nextDnsId,
                )
            }
            item { Spacer(Modifier.height(UnderstoryTheme.spacing.lg)) }
        }
    }
}

@Composable
private fun DnsActiveNowCard() {
    val ctx = LocalContext.current
    var current by remember { mutableStateOf(PrivateDnsApplier.current(ctx)) }
    LaunchedEffect(Unit) {
        while (true) {
            current = PrivateDnsApplier.current(ctx)
            delay(1500)
        }
    }
    SuiteCard {
        Text("Active now", style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            when (current.mode) {
                "hostname" -> "System Private DNS: ${current.specifier ?: "(no host set)"} ✓"
                "off" -> "System Private DNS: off — cleartext resolver from the network"
                else -> "System Private DNS: automatic (opportunistic DoT)"
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun DnsProviderRow(
    provider: DnsProvider,
    isSelected: Boolean,
    onSelect: () -> Unit,
) {
    SuiteListRow(
        headline = if (isSelected) "● ${provider.name}" else "○ ${provider.name}",
        supporting = provider.privacyNote,
        onClick = onSelect,
    )
}

@Composable
private fun DnsApplyCard(selected: DnsProvider, nextDnsId: String) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf<String?>(null) }
    val hasGrant = remember(status) { PrivateDnsApplier.hasGrant(ctx) }
    // OPTIONAL elevation: Shizuku shell or Dhizuku DPM can write secure settings
    // even without a direct WRITE_SECURE_SETTINGS ADB grant. Capability-gated,
    // not tier-gated. Rootless users (and users who used the ADB grant instead)
    // are unaffected — this only adds a one-tap path when a tier is granted.
    val canElevateDns = remember(status) { !hasGrant && Elevation.canWriteSecureSettings(ctx) }

    // Resolve the effective specifier: NextDNS templates from the config id.
    val configIdValid = !selected.requiresConfigId ||
        DnsProvider.isValidNextDnsConfigId(nextDnsId)
    val specifier: String = when {
        selected.requiresConfigId && configIdValid -> DnsProvider.nextDnsHostname(nextDnsId)
        else -> selected.dotHostname
    }

    SuiteCard {
        Text("Apply your selection", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))

        if (specifier.isEmpty()) {
            Text(
                if (selected.requiresConfigId)
                    "Enter a valid NextDNS config ID above to enable Apply."
                else
                    "System default has no DoT hostname to apply. Choose a provider above.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@SuiteCard
        }

        if (hasGrant) {
            Text(
                "ADB grant present. Apply now sets Android's Private DNS to $specifier " +
                    "directly — no Settings round-trip.",
                style = MaterialTheme.typography.bodyMedium,
                color = UnderstoryTheme.semantic.success,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                SecureButton(onClick = {
                    Diagnostics.log("firewall.Dns", "Apply Private DNS: $specifier")
                    status = when (val r = PrivateDnsApplier.apply(ctx, specifier)) {
                        is PrivateDnsApplier.Result.Applied -> "Applied. Private DNS is now ${r.hostname}."
                        is PrivateDnsApplier.Result.NeedsAdbGrant -> "Grant missing — run: ${r.adbCommand}"
                        is PrivateDnsApplier.Result.Failed -> "Apply failed: ${r.reason}"
                    }
                }) { Text("Apply now") }
                SecureOutlinedButton(onClick = {
                    status = when (val r = PrivateDnsApplier.clear(ctx)) {
                        is PrivateDnsApplier.Result.Applied -> "Private DNS disabled."
                        is PrivateDnsApplier.Result.NeedsAdbGrant -> "Grant missing — run: ${r.adbCommand}"
                        is PrivateDnsApplier.Result.Failed -> "Clear failed: ${r.reason}"
                    }
                }) { Text("Disable") }
            }
        } else {
            if (canElevateDns) {
                Text(
                    "Elevation is on. Apply now sets Android's Private DNS to " +
                        "$specifier directly via the granted tier — no ADB grant, no " +
                        "Settings round-trip.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = UnderstoryTheme.semantic.success,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                    SecureButton(onClick = {
                        Diagnostics.log("firewall.Dns", "Apply Private DNS (elevation): $specifier")
                        scope.launch {
                            status = when (val r = Elevation.setPrivateDns(
                                ctx, PrivateDnsMode.HOSTNAME, specifier,
                            )) {
                                is Outcome.Success -> "Applied. Private DNS is now $specifier."
                                is Outcome.Unsupported -> "Not available: ${r.reason}"
                                is Outcome.Failed -> "Apply failed: ${r.message}"
                            }
                        }
                    }) { Text("Apply Private DNS now") }
                    SecureOutlinedButton(onClick = {
                        scope.launch {
                            status = when (val r = Elevation.setPrivateDns(
                                ctx, PrivateDnsMode.OFF,
                            )) {
                                is Outcome.Success -> "Private DNS disabled."
                                is Outcome.Unsupported -> "Not available: ${r.reason}"
                                is Outcome.Failed -> "Disable failed: ${r.message}"
                            }
                        }
                    }) { Text("Disable") }
                }
                Spacer(Modifier.height(UnderstoryTheme.spacing.md))
                BoundaryText("Or use one of the manual paths below.")
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            }
            Text(
                "Two options:\n\n" +
                    "1. One-time (automated): grant WRITE_SECURE_SETTINGS via ADB, then " +
                    "Apply now works from here on.\n" +
                    "     adb shell pm grant ${ctx.packageName} android.permission.WRITE_SECURE_SETTINGS\n\n" +
                    "2. Manual: open Private DNS settings, pick \"Private DNS provider " +
                    "hostname\", and paste:\n     $specifier",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                SecureButton(onClick = {
                    val primary = Intent("android.settings.PRIVATE_DNS_SETTINGS")
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    runCatching { ctx.startActivity(primary) }.recoverCatching {
                        ctx.startActivity(
                            Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                    }
                }) { Text("Open Private DNS settings") }
                SecureOutlinedButton(onClick = {
                    copyToClipboard(ctx, "DoT hostname", specifier)
                    status = "Hostname copied."
                }) { Text("Copy hostname") }
            }
            SecureOutlinedButton(
                onClick = {
                    copyToClipboard(
                        ctx, "ADB grant",
                        "adb shell pm grant ${ctx.packageName} android.permission.WRITE_SECURE_SETTINGS",
                    )
                    status = "ADB command copied."
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Copy ADB grant command") }
        }

        status?.let {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(it, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun copyToClipboard(ctx: Context, label: String, text: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    cm?.setPrimaryClip(ClipData.newPlainText(label, text))
}
