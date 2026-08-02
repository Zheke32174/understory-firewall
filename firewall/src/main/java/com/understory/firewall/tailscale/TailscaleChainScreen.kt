package com.understory.firewall.tailscale

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.understory.firewall.BoundaryText
import com.understory.firewall.chain.EndpointChain
import com.understory.firewall.chain.ProxyChainController
import com.understory.firewall.chain.ProxyHop
import com.understory.firewall.chain.TransportCapability
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch

/**
 * Configure Godwall's Tailscale node and the egress [EndpointChain]. Honest by
 * construction: the Tailscale status and per-hop readiness reflect whether the
 * real backends are linked; nothing here implies a live tailnet or a running
 * chain unless the controllers say so.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TailscaleChainScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    // Measured transport-tier availability. Starts as the last cached probe (honestly
    // "not probed yet" on a cold start) and is refreshed only on explicit request —
    // probing shells out, so it must not run on every recomposition.
    var tierSnapshot by remember { mutableStateOf(TransportCapability.snapshot()) }
    var probing by remember { mutableStateOf(false) }

    var tsEnabled by remember { mutableStateOf(TailscaleSettings.isEnabled(ctx)) }
    var loginServer by remember { mutableStateOf(TailscaleSettings.loginServer(ctx)) }
    var authKey by remember { mutableStateOf(TailscaleSettings.authKey(ctx)) }
    var exitNode by remember { mutableStateOf(TailscaleSettings.exitNode(ctx)) }
    var acceptRoutes by remember { mutableStateOf(TailscaleSettings.acceptRoutes(ctx)) }
    var acceptDns by remember { mutableStateOf(TailscaleSettings.acceptDns(ctx)) }
    var advertiseExit by remember { mutableStateOf(TailscaleSettings.advertiseExit(ctx)) }
    var hostname by remember { mutableStateOf(TailscaleSettings.hostname(ctx)) }
    var tsSaved by remember { mutableStateOf<String?>(null) }

    var chainEnabled by remember { mutableStateOf(EndpointChain.isEnabled(ctx)) }
    var hops by remember { mutableStateOf(EndpointChain.hops(ctx)) }
    var addDialog by remember { mutableStateOf<AddKind?>(null) }

    val tsStatus = remember(tsEnabled, loginServer) { TailscaleController.status(ctx) }

    fun refreshHops() { hops = EndpointChain.hops(ctx) }

    SuiteScaffold(title = "Tailscale + egress chain", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))

            // --- Tailscale node ---
            SuiteCard {
                Text("Tailscale node", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    "Godwall runs the tailnet inside its own VPN — one slot for mesh + firewall, " +
                        "instead of yielding the slot to the Tailscale app.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    "Status: ${tsStatus.state}" + if (tsStatus.detail.isBlank()) "" else " — ${tsStatus.detail}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                SwitchRow(
                    label = "Bring up the tailnet in Godwall's VPN",
                    checked = tsEnabled,
                    onCheckedChange = { tsEnabled = it; TailscaleSettings.setEnabled(ctx, it) },
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                OutlinedTextField(loginServer, { loginServer = it }, singleLine = true,
                    label = { Text("Control server (Tailscale / Headscale)") },
                    modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                OutlinedTextField(authKey, { authKey = it }, singleLine = true,
                    label = { Text("Auth key (tskey-auth-…, optional)") },
                    modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                OutlinedTextField(exitNode, { exitNode = it }, singleLine = true,
                    label = { Text("Exit node (blank = none)") },
                    modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                OutlinedTextField(hostname, { hostname = it }, singleLine = true,
                    label = { Text("Hostname (blank = derive)") },
                    modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                SwitchRow(label = "Accept subnet routes", checked = acceptRoutes,
                    onCheckedChange = { acceptRoutes = it })
                SwitchRow(label = "Accept MagicDNS", checked = acceptDns,
                    onCheckedChange = { acceptDns = it })
                SwitchRow(label = "Advertise this device as an exit node", checked = advertiseExit,
                    onCheckedChange = { advertiseExit = it })
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                SecureButton(onClick = {
                    TailscaleSettings.setLoginServer(ctx, loginServer)
                    TailscaleSettings.setAuthKey(ctx, authKey)
                    TailscaleSettings.setExitNode(ctx, exitNode)
                    TailscaleSettings.setHostname(ctx, hostname)
                    TailscaleSettings.setAcceptRoutes(ctx, acceptRoutes)
                    TailscaleSettings.setAcceptDns(ctx, acceptDns)
                    TailscaleSettings.setAdvertiseExit(ctx, advertiseExit)
                    tsSaved = if (TailscaleController.isLinked(ctx))
                        "Saved. Re-arm the VPN to apply." else
                        "Saved. Tailnet not established — data plane not linked in this build."
                }) { Text("Save node config") }
                tsSaved?.let {
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    Text(it, style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }

            // --- Egress chain ---
            SuiteCard {
                Text("Egress chain", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(EndpointChain.describe(ctx), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(ProxyChainController.summary(ctx), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                SwitchRow(label = "Apply chain to egress (off = direct)", checked = chainEnabled,
                    onCheckedChange = { chainEnabled = it; EndpointChain.setEnabled(ctx, it) })
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

                val statuses = ProxyChainController.status(ctx)
                statuses.forEachIndexed { i, st ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("${i + 1}. ${st.hop.label()}", style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "${st.readiness} · ${st.note}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        TextButton(enabled = i > 0, onClick = { EndpointChain.move(ctx, i, i - 1); refreshHops() }) { Text("↑") }
                        TextButton(enabled = i < statuses.lastIndex, onClick = { EndpointChain.move(ctx, i, i + 1); refreshHops() }) { Text("↓") }
                        TextButton(onClick = { EndpointChain.remove(ctx, st.hop.id); refreshHops() }) { Text("✕") }
                    }
                }
                if (hops.isEmpty()) BoundaryText("No hops — traffic egresses directly.")

                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                // Measured transport tiers — what this device can actually reach beyond
                // a normal userspace VPN. Probed on demand, never assumed.
                Text("Transport tiers", style = MaterialTheme.typography.labelLarge)
                Text(
                    "Userspace: ready (SOCKS5 / HTTP CONNECT implemented)\n" +
                        "Kernel: ${tierSnapshot.kernelDetail()}\n" +
                        "Container: ${tierSnapshot.containerDetail()}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                SecureOutlinedButton(
                    enabled = !probing,
                    onClick = {
                        probing = true
                        scope.launch {
                            tierSnapshot = TransportCapability.refresh(ctx)
                            probing = false
                        }
                    },
                ) { Text(if (probing) "Probing…" else "Probe transports") }

                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text("Add hop:", style = MaterialTheme.typography.labelLarge)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                    AddKind.entries.forEach { k ->
                        AssistChip(onClick = {
                            if (k.needsDialog) addDialog = k
                            else { EndpointChain.add(ctx, k.build("", 0, "", "")); refreshHops() }
                        }, label = { Text(k.label) })
                    }
                }
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }

    addDialog?.let { kind -> AddHopDialog(kind, onDismiss = { addDialog = null }, onAdd = { a, b, c, d ->
        EndpointChain.add(ctx, kind.build(a, b, c, d)); refreshHops(); addDialog = null
    }) }
}

/** Hop kinds offered in the "add" row. Parameterless kinds build directly; others open a dialog. */
private enum class AddKind(val label: String, val needsDialog: Boolean) {
    TAILSCALE("Tailscale node", false),
    SOCKS5("SOCKS5…", true),
    HTTP("HTTP…", true),
    CONTAINER("Container…", true),
    TOR("Tor", false),
    DIRECT("Direct", false);

    fun build(a: String, b: Int, c: String, d: String): ProxyHop {
        val id = EndpointChain.newId("$name-$a-$b-${System.nanoTime()}")
        return when (this) {
            TAILSCALE -> ProxyHop.Tailscale(id)
            SOCKS5 -> ProxyHop.Socks5(id, a, b, c, d)
            HTTP -> ProxyHop.HttpConnect(id, a, b, c, d)
            CONTAINER -> ProxyHop.Container(id, a, c)
            TOR -> ProxyHop.Tor(id)
            DIRECT -> ProxyHop.Direct(id)
        }
    }
}

@Composable
private fun AddHopDialog(kind: AddKind, onDismiss: () -> Unit, onAdd: (String, Int, String, String) -> Unit) {
    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    val isContainer = kind == AddKind.CONTAINER
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add ${kind.label.trimEnd('…')}") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                OutlinedTextField(host, { host = it }, singleLine = true,
                    label = { Text(if (isContainer) "Container name" else "Host / IP") },
                    modifier = Modifier.fillMaxWidth())
                OutlinedTextField(port, { port = it.filter(Char::isDigit) }, singleLine = true,
                    label = { Text(if (isContainer) "Inner target (host:port, optional)" else "Port") },
                    modifier = Modifier.fillMaxWidth())
                if (!isContainer) {
                    OutlinedTextField(user, { user = it }, singleLine = true,
                        label = { Text("Username (optional)") }, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(pass, { pass = it }, singleLine = true,
                        label = { Text("Password (optional)") }, modifier = Modifier.fillMaxWidth())
                }
            }
        },
        confirmButton = {
            SecureButton(onClick = {
                if (isContainer) onAdd(host.trim(), 0, port.trim(), "")
                else onAdd(host.trim(), port.toIntOrNull() ?: 0, user.trim(), pass)
            }) { Text("Add") }
        },
        dismissButton = { SecureOutlinedButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
