package com.understory.firewall.tunnel

import android.app.Activity
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.AssistChip
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.understory.firewall.BoundaryText
import com.understory.firewall.FirewallMode
import com.understory.firewall.FirewallSettings
import com.understory.firewall.TunnelMode
import com.understory.firewall.VpnSlotProbe
import com.understory.firewall.startEngine
import com.understory.firewall.stopEngine
import com.understory.net.engine.DnsMessage
import com.understory.net.engine.crypto.CryptoSelfTest
import com.understory.security.Diagnostics
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * DNS-filter tunnel hub (S6): the honest "adblock-DNS VPN tunnel". This tier
 * TAKES the one VPN slot (unlike the slot-free policy tier), so it is:
 *   - gated behind [VpnSlotProbe] — refuses to arm while ANY VpnService holds
 *     the slot (Tailscale on the operator's phone), never auto-seizes it;
 *   - consented — a full-screen explainer states the XOR-Tailscale trade before
 *     the first enable;
 *   - reversible — disarms neutrally the moment a VPN appears (slot-watcher).
 *
 * The arm control is ABSENT (not merely disabled) on a guardrail FAIL, so there
 * is zero dead control on a Tailscale phone.
 */
@Composable
fun DnsFilterHubScreen(
    activity: ComponentActivity,
    onBack: () -> Unit,
    onOpenVisibility: () -> Unit,
) {
    val ctx = LocalContext.current

    var mode by remember { mutableStateOf(FirewallSettings.getMode(ctx)) }
    var armed by remember { mutableStateOf(FirewallSettings.isEngineArmed(ctx)) }
    var autoStopped by remember { mutableStateOf(FirewallSettings.isAutoStopped(ctx)) }
    var slot by remember { mutableStateOf(VpnSlotProbe.evaluate(ctx)) }
    var showExplainer by remember { mutableStateOf(false) }

    fun reprobe() { slot = VpnSlotProbe.evaluate(ctx) }

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

    // Live slot-watcher while armed: disarm the instant a foreign VPN appears.
    DisposableEffect(armed, mode) {
        if (armed && mode == FirewallMode.STANDALONE) {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (VpnSlotProbe.isAnotherVpnActive(ctx)) {
                        Diagnostics.log("firewall.DnsFilterHub",
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
        val s = VpnSlotProbe.evaluate(ctx)
        slot = s
        if (!s.isPass) {
            FirewallSettings.setEngineArmed(ctx, false)
            armed = false
            return
        }
        // The DNS-filter tunnel is the tunnel flavor we arm here.
        FirewallSettings.setTunnelMode(ctx, TunnelMode.DNS_FILTER)
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
        XorTailscaleExplainer(
            onCancel = { showExplainer = false },
            onEnable = {
                FirewallSettings.setMode(ctx, FirewallMode.STANDALONE)
                FirewallSettings.setTunnelMode(ctx, TunnelMode.DNS_FILTER)
                FirewallSettings.setStandaloneExplained(ctx, true)
                mode = FirewallMode.STANDALONE
                showExplainer = false
                reprobe()
            },
        )
        return
    }

    SuiteScaffold(title = "DNS-filter tunnel", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            // ---- What this is ----
            SuiteCard {
                Text(
                    "Adblock-DNS tunnel",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    "Routes your device's DNS through a local, on-device tunnel that " +
                        "sinkholes ads, trackers, and malware domains from an on-device " +
                        "blocklist, and forwards the rest. Every query is attributed to the " +
                        "app that made it.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                BoundaryText(
                    "This tier TAKES Android's one VPN slot, so it is mutually exclusive " +
                        "with Tailscale (or any VPN). The slot-free App firewall does not — " +
                        "use that if you run Tailscale. Upstream DNS is forwarded in " +
                        "cleartext UDP; for an encrypted upstream, also set system Private " +
                        "DNS (DoT) on the DNS hardening screen.",
                )
            }

            // ---- Enable region ----
            SuiteCard {
                SwitchRow(
                    label = "Use the DNS-filter tunnel",
                    checked = mode == FirewallMode.STANDALONE,
                    onCheckedChange = { wantOn ->
                        if (wantOn) {
                            val s = VpnSlotProbe.evaluate(ctx)
                            slot = s
                            if (!s.isPass) {
                                Diagnostics.log("firewall.DnsFilterHub",
                                    "enable blocked by guardrail (incumbent=${s.incumbentName})")
                                return@SwitchRow
                            }
                            if (!FirewallSettings.isStandaloneExplained(ctx)) {
                                showExplainer = true
                            } else {
                                FirewallSettings.setMode(ctx, FirewallMode.STANDALONE)
                                FirewallSettings.setTunnelMode(ctx, TunnelMode.DNS_FILTER)
                                mode = FirewallMode.STANDALONE
                            }
                        } else {
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

            // Guardrail FAIL card (XOR-Tailscale).
            if (!slot.isPass) {
                GuardrailCard(slot) { reprobe() }
            }

            // ---- Arm region — only when enabled AND guardrail PASS ----
            if (mode == FirewallMode.STANDALONE && slot.isPass) {
                SuiteCard {
                    Text("Filtering engine", style = MaterialTheme.typography.titleMedium)
                    if (autoStopped) {
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        Text(
                            "The DNS-filter tunnel stopped because a VPN is now using the " +
                                "VPN slot. It will resume when you turn that VPN off.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    SwitchRow(
                        label = "Filter DNS now",
                        checked = armed,
                        onCheckedChange = { wantOn ->
                            if (wantOn) armEngine() else {
                                stopEngine(ctx)
                                FirewallSettings.setEngineArmed(ctx, false)
                                armed = false
                            }
                        },
                    )
                    if (armed) {
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        LiveCounts()
                        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                        SecureOutlinedButton(
                            onClick = onOpenVisibility,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Open connection log") }
                    }
                }

                BlocklistCard()
                UpstreamCard()
                DnscryptCard()
                AnonRoutingCard()
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
            Text("A VPN is already using the slot", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                "The DNS-filter tunnel can't start because " +
                    (slot.incumbentName?.let { "$it is" } ?: "another app is") +
                    " using Android's one VPN slot. That's expected on a Tailscale phone — " +
                    "we never evict it. This tunnel and Tailscale are mutually exclusive; " +
                    "pick one. To use DNS filtering while Tailscale is up, use the slot-free " +
                    "App firewall (per-app block) plus system Private DNS instead.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureOutlinedButton(onClick = onRecheck) { Text("Re-check") }
        }
    }
}

@Composable
private fun LiveCounts() {
    var queries by remember { mutableStateOf(0L) }
    var blocked by remember { mutableStateOf(0L) }
    LaunchedEffect(Unit) {
        while (true) {
            queries = DnsEventLog.totalQueries()
            blocked = DnsEventLog.totalBlocked()
            kotlinx.coroutines.delay(1000)
        }
    }
    Text(
        if (queries > 0L) "Filtered $queries DNS quer${if (queries == 1L) "y" else "ies"} · " +
            "blocked $blocked"
        else "Armed · waiting for DNS traffic",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun BlocklistCard() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var stats by remember { mutableStateOf(BlocklistRepository.stats()) }
    var url by remember { mutableStateOf(BlocklistRepository.updateUrl(ctx)) }
    var status by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) { BlocklistRepository.reload(ctx) }
        stats = BlocklistRepository.stats()
    }

    SuiteCard {
        Text("Blocklist", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            "${stats.totalDomains} domains loaded" +
                (if (stats.fetchedListPresent) " (bundled seed + your fetched list)"
                else " (bundled curated seed)") + ".",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
        stats.cappedNote?.let {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(it, style = MaterialTheme.typography.bodySmall,
                color = UnderstoryTheme.semantic.warning)
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        BoundaryText(
            "The bundled list is a curated seed (~100 domain roots, each blocking its " +
                "subtree) — not exhaustive. Add a public blocklist URL (https only) to " +
                "expand it. Blocks by DOMAIN only: it can't block a connection to a raw " +
                "IP, and can't see an app's own DoH that bypasses the system resolver.",
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        OutlinedTextField(
            value = url,
            onValueChange = { url = it },
            singleLine = true,
            label = { Text("Blocklist URL (https://…)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
            SecureButton(onClick = {
                if (busy) return@SecureButton
                BlocklistRepository.setUpdateUrl(ctx, url)
                busy = true
                status = "Fetching…"
                scope.launch {
                    val r = withContext(Dispatchers.IO) { BlocklistRepository.fetchAndCache(ctx) }
                    stats = BlocklistRepository.stats()
                    status = r
                    busy = false
                }
            }) { Text("Update now") }
            SecureOutlinedButton(onClick = {
                scope.launch {
                    val r = withContext(Dispatchers.IO) { BlocklistRepository.clearFetched(ctx) }
                    stats = BlocklistRepository.stats()
                    status = r
                }
            }) { Text("Use bundled only") }
        }
        status?.let {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(it, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun UpstreamCard() {
    val ctx = LocalContext.current
    var ip by remember { mutableStateOf(FirewallSettings.getUpstreamDnsIp(ctx)) }
    var dotHost by remember { mutableStateOf(FirewallSettings.getDotHostname(ctx)) }
    // Transport: "plaintext" | "dot" | "doh". A blank hostname always means plaintext, so the
    // selector is only meaningful once a hostname is set.
    var mode by remember { mutableStateOf(FirewallSettings.getUpstreamMode(ctx)) }
    var dohPath by remember { mutableStateOf(FirewallSettings.getDohPath(ctx)) }
    var style by remember { mutableStateOf(BlocklistRepository.answerStyle(ctx)) }
    var saved by remember { mutableStateOf<String?>(null) }

    val effectiveMode = if (dotHost.isBlank()) "plaintext" else mode
    SuiteCard {
        Text("Upstream resolver", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            when (effectiveMode) {
                "doh" ->
                    "Allowed queries forward over VERIFIED DNS-over-HTTPS (RFC 8484) to the " +
                        "resolver IP on :443, authenticated against the hostname — fail-closed on " +
                        "a bad certificate. DoH rides ordinary HTTPS, so a network that blocks " +
                        ":853 to force plaintext DNS cannot single it out."
                "dot" ->
                    "Allowed queries forward over VERIFIED DNS-over-TLS (RFC 7858) to the resolver " +
                        "IP on :853, authenticated against the hostname — fail-closed on a bad " +
                        "certificate. Encryption inside the tunnel itself, independent of system " +
                        "Private DNS."
                else ->
                    "Allowed queries forward over PLAINTEXT UDP. To encrypt the in-tunnel upstream, " +
                        "set a hostname below (pick a preset) and choose DoT or DoH. Leaving the " +
                        "hostname blank keeps plaintext UDP."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        OutlinedTextField(
            value = ip,
            onValueChange = { ip = it },
            singleLine = true,
            label = { Text("Resolver IP (e.g. 1.1.1.1)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        OutlinedTextField(
            value = dotHost,
            onValueChange = { dotHost = it },
            singleLine = true,
            label = { Text("Verification hostname (blank = plaintext UDP)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        // Transport selector — only DoT/DoH matter once a hostname is present.
        Text("Encrypted transport", style = MaterialTheme.typography.labelLarge)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
            listOf("dot" to "DoT (:853)", "doh" to "DoH (:443)", "plaintext" to "Plaintext")
                .forEach { (key, label) ->
                    FilterChip(
                        selected = effectiveMode == key,
                        onClick = { mode = key },
                        enabled = key == "plaintext" || dotHost.isNotBlank(),
                        label = { Text(label) },
                    )
                }
        }
        if (effectiveMode == "doh") {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            OutlinedTextField(
                value = dohPath,
                onValueChange = { dohPath = it },
                singleLine = true,
                label = { Text("DoH path (default /dns-query)") },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        // One-tap encrypted presets: fill IP + verified hostname together so they always match.
        val presets = if (mode == "doh") DnsFilterTun.UpstreamResolver.DOH_PRESETS
            else DnsFilterTun.UpstreamResolver.DOT_PRESETS
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
        ) {
            presets.forEach { (name, presetIp, host) ->
                AssistChip(
                    onClick = { ip = presetIp; dotHost = host },
                    label = { Text(name.substringBefore(" (")) },
                )
            }
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SwitchRow(
            label = "Sinkhole with NXDOMAIN (off = 0.0.0.0)",
            checked = style == DnsMessage.BlockAnswer.NXDOMAIN,
            onCheckedChange = { nx ->
                style = if (nx) DnsMessage.BlockAnswer.NXDOMAIN else DnsMessage.BlockAnswer.ZERO_IP
                BlocklistRepository.setAnswerStyle(ctx, style)
                saved = "Saved. Re-arm the tunnel to apply."
            },
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureButton(onClick = {
            FirewallSettings.setUpstreamDnsIp(ctx, ip)
            FirewallSettings.setDotHostname(ctx, dotHost)
            FirewallSettings.setUpstreamMode(ctx, effectiveMode)
            FirewallSettings.setDohPath(ctx, dohPath)
            saved = when (effectiveMode) {
                "doh" -> "Saved — verified DoH. Re-arm the tunnel to apply."
                "dot" -> "Saved — verified DoT. Re-arm the tunnel to apply."
                else -> "Saved — plaintext UDP. Re-arm the tunnel to apply."
            }
        }) { Text("Save resolver") }
        saved?.let {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(it, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DnscryptCard() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var enabled by remember { mutableStateOf(DnscryptResolvers.isEnabled(ctx)) }
    var reqNoLog by remember { mutableStateOf(DnscryptResolvers.requireNoLog(ctx)) }
    var reqDnssec by remember { mutableStateOf(DnscryptResolvers.requireDnssec(ctx)) }
    var reqNoFilter by remember { mutableStateOf(DnscryptResolvers.requireNoFilter(ctx)) }
    var query by remember { mutableStateOf("") }
    var resolvers by remember { mutableStateOf<List<DnscryptResolvers.Resolver>>(emptyList()) }
    var selected by remember { mutableStateOf(DnscryptResolvers.selectedResolver(ctx)) }
    var status by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val selfTest = remember { CryptoSelfTest.result() }

    fun reload() {
        scope.launch {
            val list = withContext(Dispatchers.IO) { DnscryptResolvers.load(ctx) }
            resolvers = list
            selected = withContext(Dispatchers.IO) { DnscryptResolvers.selectedResolver(ctx) }
        }
    }
    LaunchedEffect(reqNoLog, reqDnssec, reqNoFilter) { reload() }

    SuiteCard {
        Text("DNSCrypt (InviZible-style)", style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            "Encrypts your DNS with native DNSCrypt v2 — the resolver's certificate is verified " +
                "(Ed25519) and each query is encrypted to an ephemeral key, done in-process with no " +
                "bundled daemon. When on, this REPLACES the plaintext/DoT/DoH upstream above.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            selfTest.summary(),
            style = MaterialTheme.typography.bodySmall,
            color = if (selfTest.anyReady) UnderstoryTheme.semantic.success else UnderstoryTheme.semantic.warning,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SwitchRow(
            label = "Use DNSCrypt as the upstream",
            checked = enabled,
            onCheckedChange = {
                enabled = it && selfTest.anyReady
                DnscryptResolvers.setEnabled(ctx, enabled)
                if (it && !selfTest.anyReady) status = "This device's DNSCrypt crypto self-test failed — cannot enable."
                if (enabled) reload()
            },
        )
        if (enabled) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text("Selected: ${selected?.name ?: "(choosing a default…)"}",
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
            selected?.stamp?.let {
                Text(
                    "${it.proto} · ${if (it.noLogs) "no-log" else "logs"} · " +
                        "${if (it.dnssec) "DNSSEC" else "no DNSSEC"} · ${if (it.noFilter) "unfiltered" else "filtered"}",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text("Requirements", style = MaterialTheme.typography.labelLarge)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                FilterChip(selected = reqNoLog, onClick = {
                    reqNoLog = !reqNoLog; DnscryptResolvers.setRequireNoLog(ctx, reqNoLog)
                }, label = { Text("No logs") })
                FilterChip(selected = reqDnssec, onClick = {
                    reqDnssec = !reqDnssec; DnscryptResolvers.setRequireDnssec(ctx, reqDnssec)
                }, label = { Text("DNSSEC") })
                FilterChip(selected = reqNoFilter, onClick = {
                    reqNoFilter = !reqNoFilter; DnscryptResolvers.setRequireNoFilter(ctx, reqNoFilter)
                }, label = { Text("Unfiltered") })
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            OutlinedTextField(
                value = query, onValueChange = { query = it }, singleLine = true,
                label = { Text("Search ${resolvers.size} resolvers") },
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            val matches = remember(query, resolvers) {
                (if (query.isBlank()) resolvers else resolvers.filter { it.name.contains(query, true) }).take(24)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                matches.forEach { r ->
                    FilterChip(
                        selected = selected?.stamp?.raw == r.stamp.raw,
                        onClick = {
                            DnscryptResolvers.setSelectedStamp(ctx, r.stamp.raw)
                            selected = r
                            status = "Selected ${r.name}. Re-arm the tunnel to apply."
                        },
                        label = { Text(r.name) },
                    )
                }
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                SecureOutlinedButton(onClick = {
                    if (busy) return@SecureOutlinedButton
                    busy = true; status = "Refreshing list…"
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { DnscryptResolvers.refresh(ctx) }
                        reload(); status = r; busy = false
                    }
                }) { Text("Refresh list") }
                SecureOutlinedButton(onClick = {
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { DnscryptResolvers.clearRefreshed(ctx) }
                        reload(); status = r
                    }
                }) { Text("Use bundled") }
            }
            BoundaryText(
                "The resolver LIST isn't minisign-verified (dnscrypt-proxy verifies it); a tampered " +
                    "list could only swap WHICH resolver you reach, not forge one — the per-query " +
                    "certificate check catches a substituted resolver.",
            )
        }
        status?.let {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AnonRoutingCard() {
    val ctx = LocalContext.current
    var enabled by remember { mutableStateOf(AnonRouting.isDnsRoutedThroughProxy(ctx)) }
    var mode by remember { mutableStateOf(AnonRouting.mode(ctx)) }
    var target by remember { mutableStateOf(AnonRouting.targetResolver(ctx)) }
    var customHost by remember { mutableStateOf(AnonRouting.customHost(ctx)) }
    var customPort by remember { mutableStateOf(AnonRouting.customPort(ctx).toString()) }
    var saved by remember { mutableStateOf<String?>(null) }
    val orbot = remember { AnonRouting.isOrbotInstalled(ctx) }
    val i2p = remember { AnonRouting.isI2pInstalled(ctx) }

    SuiteCard {
        Text("Anonymize DNS (Tor / I2P)", style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            "Route the tunnel's DNS over Tor (Orbot) or I2P as DNS-over-TCP through their SOCKS proxy. " +
                "No daemon is bundled — you run Orbot / the I2P router in proxy mode. If the proxy " +
                "isn't answering, DNS falls back to the normal upstream instead of failing.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            "Detected: Orbot ${if (orbot) "✓" else "—"} · I2P ${if (i2p) "✓" else "—"}",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SwitchRow(
            label = "Route DNS through the proxy",
            checked = enabled,
            onCheckedChange = { enabled = it; AnonRouting.setDnsRoutedThroughProxy(ctx, it) },
        )
        if (enabled) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                listOf(
                    AnonRouting.MODE_TOR to "Tor (9050)",
                    AnonRouting.MODE_I2P to "I2P (4447)",
                    AnonRouting.MODE_CUSTOM to "Custom",
                ).forEach { (key, label) ->
                    FilterChip(selected = mode == key, onClick = { mode = key; AnonRouting.setMode(ctx, key) },
                        label = { Text(label) })
                }
            }
            if (mode == AnonRouting.MODE_CUSTOM) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                OutlinedTextField(value = customHost, onValueChange = { customHost = it }, singleLine = true,
                    label = { Text("SOCKS5 host") }, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                OutlinedTextField(value = customPort, onValueChange = { customPort = it.filter { c -> c.isDigit() } },
                    singleLine = true, label = { Text("SOCKS5 port") }, modifier = Modifier.fillMaxWidth())
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            OutlinedTextField(value = target, onValueChange = { target = it }, singleLine = true,
                label = { Text("Resolver IP reached via the proxy (DNS-over-TCP)") },
                modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureButton(onClick = {
                AnonRouting.setTargetResolver(ctx, target)
                AnonRouting.setCustomHost(ctx, customHost)
                AnonRouting.setCustomPort(ctx, customPort.toIntOrNull() ?: 1080)
                saved = "Saved. Re-arm the tunnel to apply."
            }) { Text("Save routing") }
        }
        saved?.let {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** The full-screen XOR-Tailscale consent explainer shown before first enable. */
@Composable
private fun XorTailscaleExplainer(onCancel: () -> Unit, onEnable: () -> Unit) {
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
                "The DNS-filter tunnel uses Android's one VPN slot",
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                "This tunnel captures your DNS locally and sinkholes ad, tracker, and " +
                    "malware domains. Because Android allows only ONE active VPN, this " +
                    "tunnel and Tailscale (or any VPN) are mutually exclusive — you pick " +
                    "one. We NEVER take the slot from another VPN: if one is running, this " +
                    "won't start.\n\n" +
                    "If you later turn on Tailscale or any VPN, this tunnel stops " +
                    "automatically and the app returns to audit-only mode; your blocklist " +
                    "and settings are kept.\n\n" +
                    "Prefer to keep Tailscale up? Use the slot-free App firewall (per-app " +
                    "block on every network) plus system Private DNS instead — no slot used.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            SecureButton(onClick = onEnable, modifier = Modifier.fillMaxWidth()) {
                Text("Enable the DNS-filter tunnel")
            }
            SecureOutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
                Text("Not now")
            }
        }
    }
}
